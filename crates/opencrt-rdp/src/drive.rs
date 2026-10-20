//! A local folder shared with the remote computer as a drive (RDPDR file
//! system redirection): it appears there under "This PC" and files can be
//! copied both ways. Every path the server sends is confined to the folder.

use std::collections::{HashMap, VecDeque};
use std::fs::{File, Metadata, OpenOptions};
use std::io::{Read as _, Seek as _, SeekFrom, Write as _};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use ironrdp::pdu::PduResult;
use ironrdp::rdpdr::RdpdrBackend;
use ironrdp::rdpdr::pdu::RdpdrPdu;
use ironrdp::rdpdr::pdu::efs::*;
use ironrdp::rdpdr::pdu::esc::{ScardCall, ScardIoCtlCode};
use ironrdp::svc::SvcMessage;

/// The device id the drive is announced under.
pub const DEVICE_ID: u32 = 1;

/// Access rights that mean the server wants to change the file: write and
/// append data, delete, and the generic write / all / maximum rights.
const WRITE_ACCESS: u32 = 0x0000_0002 | 0x0000_0004 | 0x0001_0000 | 0x4000_0000 | 0x1000_0000 | 0x0200_0000;

/// Reported as the drive's size and free space (std cannot ask the file system
/// portably; Windows only uses them to show the drive and to check that a
/// copy fits).
const REPORTED_BYTES: i64 = 1 << 40;

#[derive(Debug)]
struct Handle {
    path: PathBuf,
    /// None for a folder.
    file: Option<File>,
    /// What is left to list of a directory query, and the folder listed.
    listing: VecDeque<String>,
    listed: PathBuf,
    delete_on_close: bool,
}

#[derive(Debug)]
pub struct Drive {
    root: PathBuf,
    next_id: u32,
    open: HashMap<u32, Handle>,
}

ironrdp::core::impl_as_any!(Drive);

impl Drive {
    pub fn new(root: PathBuf) -> Self {
        Drive { root, next_id: 1, open: HashMap::new() }
    }

    /// `\dir\file` as a path inside the shared folder; None for anything that
    /// would leave it (`..`, a drive or stream name) or is not a name at all.
    /// With no folder shared (an empty root) nothing resolves.
    fn resolve(&self, remote: &str) -> Option<PathBuf> {
        if self.root.as_os_str().is_empty() {
            return None;
        }
        let mut path = self.root.clone();
        for part in remote.split(['\\', '/']).filter(|p| !p.is_empty() && *p != ".") {
            if part == ".." || part.contains([':', '\0']) || (cfg!(windows) && is_device_name(part)) {
                return None;
            }
            path.push(part);
        }
        Some(path)
    }

    fn create(&mut self, req: DeviceCreateRequest) -> Vec<SvcMessage> {
        let reply = |status: NtStatus, file_id: u32, information: Information| {
            vec![SvcMessage::from(RdpdrPdu::DeviceCreateResponse(DeviceCreateResponse {
                device_io_reply: DeviceIoResponse::new(req.device_io_request.clone(), status),
                file_id,
                information,
            }))]
        };
        let Some(path) = self.resolve(&req.path) else {
            return reply(NtStatus::ACCESS_DENIED, 0, Information::empty());
        };
        let options = req.create_options;
        let disposition = req.create_disposition;
        let existing = std::fs::metadata(&path).ok();
        let opened = match &existing {
            Some(meta) if meta.is_dir() => {
                if disposition == CreateDisposition::FILE_CREATE {
                    Err(NtStatus::OBJECT_NAME_COLLISION)
                } else if options.contains(CreateOptions::FILE_NON_DIRECTORY_FILE) {
                    Err(NtStatus::ACCESS_DENIED)
                } else {
                    Ok((None, Information::FILE_OPENED))
                }
            }
            Some(_) if options.contains(CreateOptions::FILE_DIRECTORY_FILE) => Err(NtStatus::NOT_A_DIRECTORY),
            None if options.contains(CreateOptions::FILE_DIRECTORY_FILE) => {
                if disposition == CreateDisposition::FILE_CREATE || disposition == CreateDisposition::FILE_OPEN_IF {
                    std::fs::create_dir(&path).map(|()| (None, created())).map_err(|e| status(&e))
                } else {
                    Err(NtStatus::NO_SUCH_FILE)
                }
            }
            _ => open_file(&path, disposition, req.desired_access.bits() & WRITE_ACCESS != 0, existing.is_some())
                .map(|(file, information)| (Some(file), information)),
        };
        match opened {
            Ok((file, information)) => {
                let id = self.next_id;
                self.next_id = self.next_id.wrapping_add(1).max(1);
                let delete_on_close = options.contains(CreateOptions::FILE_DELETE_ON_CLOSE);
                let listed = path.clone();
                self.open.insert(id, Handle { path, file, listing: VecDeque::new(), listed, delete_on_close });
                reply(NtStatus::SUCCESS, id, information)
            }
            Err(status) => reply(status, 0, Information::empty()),
        }
    }

    fn close(&mut self, req: DeviceCloseRequest) -> Vec<SvcMessage> {
        if let Some(mut handle) = self.open.remove(&req.device_io_request.file_id)
            && handle.delete_on_close
        {
            drop(handle.file.take()); // Windows deletes no file that is still open
            let _ = if handle.path.is_dir() { std::fs::remove_dir(&handle.path) } else { std::fs::remove_file(&handle.path) };
        }
        vec![SvcMessage::from(RdpdrPdu::DeviceCloseResponse(DeviceCloseResponse {
            device_io_response: DeviceIoResponse::new(req.device_io_request, NtStatus::SUCCESS),
        }))]
    }

    fn read(&mut self, req: DeviceReadRequest) -> Vec<SvcMessage> {
        let file = self.open.get_mut(&req.device_io_request.file_id).and_then(|h| h.file.as_mut());
        let (status, read_data) = match file {
            Some(file) => {
                let mut data = vec![0; (req.length as usize).min(16 << 20)];
                match file.seek(SeekFrom::Start(req.offset)).and_then(|_| read_up_to(file, &mut data)) {
                    Ok(n) => {
                        data.truncate(n);
                        (NtStatus::SUCCESS, data)
                    }
                    Err(e) => (status(&e), Vec::new()),
                }
            }
            None => (NtStatus::NO_SUCH_FILE, Vec::new()),
        };
        vec![SvcMessage::from(RdpdrPdu::DeviceReadResponse(DeviceReadResponse {
            device_io_reply: DeviceIoResponse::new(req.device_io_request, status),
            read_data,
        }))]
    }

    fn write(&mut self, req: DeviceWriteRequest) -> Vec<SvcMessage> {
        let file = self.open.get_mut(&req.device_io_request.file_id).and_then(|h| h.file.as_mut());
        let (status, length) = match file {
            Some(file) => match file.seek(SeekFrom::Start(req.offset)).and_then(|_| file.write_all(&req.write_data)) {
                Ok(()) => (NtStatus::SUCCESS, req.write_data.len() as u32),
                Err(e) => (status(&e), 0),
            },
            None => (NtStatus::NO_SUCH_FILE, 0),
        };
        vec![SvcMessage::from(RdpdrPdu::DeviceWriteResponse(DeviceWriteResponse {
            device_io_reply: DeviceIoResponse::new(req.device_io_request, status),
            length,
        }))]
    }

    fn query_information(&mut self, req: ServerDriveQueryInformationRequest) -> Vec<SvcMessage> {
        let found = self.open.get(&req.device_io_request.file_id).map(|h| (h.path.clone(), h.delete_on_close));
        let meta = found.as_ref().map(|(path, _)| std::fs::metadata(path));
        let (status, buffer) = match (found, meta) {
            (Some((path, deleting)), Some(Ok(meta))) => {
                let attributes = attributes(&meta, &path);
                let class = req.file_info_class_lvl;
                let size = meta.len() as i64;
                if class == FileInformationClassLevel::FILE_BASIC_INFORMATION {
                    let [created, accessed, written] = times(&meta);
                    let info = FileBasicInformation {
                        creation_time: created,
                        last_access_time: accessed,
                        last_write_time: written,
                        change_time: written,
                        file_attributes: attributes,
                    };
                    (NtStatus::SUCCESS, Some(FileInformationClass::Basic(info)))
                } else if class == FileInformationClassLevel::FILE_STANDARD_INFORMATION {
                    let info = FileStandardInformation {
                        allocation_size: size,
                        end_of_file: size,
                        number_of_links: 1,
                        delete_pending: if deleting { Boolean::True } else { Boolean::False },
                        directory: if meta.is_dir() { Boolean::True } else { Boolean::False },
                    };
                    (NtStatus::SUCCESS, Some(FileInformationClass::Standard(info)))
                } else if class == FileInformationClassLevel::FILE_ATTRIBUTE_TAG_INFORMATION {
                    let info = FileAttributeTagInformation { file_attributes: attributes, reparse_tag: 0 };
                    (NtStatus::SUCCESS, Some(FileInformationClass::AttributeTag(info)))
                } else {
                    (NtStatus::NOT_SUPPORTED, None)
                }
            }
            (Some(_), Some(Err(e))) => (status(&e), None),
            _ => (NtStatus::NO_SUCH_FILE, None),
        };
        vec![SvcMessage::from(RdpdrPdu::ClientDriveQueryInformationResponse(ClientDriveQueryInformationResponse {
            device_io_response: DeviceIoResponse::new(req.device_io_request, status),
            buffer,
        }))]
    }

    fn query_volume(&mut self, req: ServerDriveQueryVolumeInformationRequest) -> Vec<SvcMessage> {
        let class = req.fs_info_class_lvl;
        let name = self.root.file_name().map_or("OpenCRT".into(), |n| n.to_string_lossy().into_owned());
        // 4 KiB clusters of 512-byte sectors, as an ordinary disk.
        let units = REPORTED_BYTES / 4096;
        let buffer = if class == FileSystemInformationClassLevel::FILE_FS_VOLUME_INFORMATION {
            Some(FileSystemInformationClass::FileFsVolumeInformation(FileFsVolumeInformation {
                volume_creation_time: 0,
                volume_serial_number: 0x0C47_0001,
                supports_objects: Boolean::False,
                volume_label: name,
            }))
        } else if class == FileSystemInformationClassLevel::FILE_FS_SIZE_INFORMATION {
            Some(FileSystemInformationClass::FileFsSizeInformation(FileFsSizeInformation {
                total_alloc_units: units,
                available_alloc_units: units,
                sectors_per_alloc_unit: 8,
                bytes_per_sector: 512,
            }))
        } else if class == FileSystemInformationClassLevel::FILE_FS_FULL_SIZE_INFORMATION {
            Some(FileSystemInformationClass::FileFsFullSizeInformation(FileFsFullSizeInformation {
                total_alloc_units: units,
                caller_available_alloc_units: units,
                actual_available_alloc_units: units,
                sectors_per_alloc_unit: 8,
                bytes_per_sector: 512,
            }))
        } else if class == FileSystemInformationClassLevel::FILE_FS_ATTRIBUTE_INFORMATION {
            let mut attributes = FileSystemAttributes::FILE_CASE_PRESERVED_NAMES | FileSystemAttributes::FILE_UNICODE_ON_DISK;
            if cfg!(not(any(windows, target_os = "macos"))) {
                attributes |= FileSystemAttributes::FILE_CASE_SENSITIVE_SEARCH;
            }
            // "NTFS", so programs do not assume FAT's 4 GB file limit.
            Some(FileSystemInformationClass::FileFsAttributeInformation(FileFsAttributeInformation {
                file_system_attributes: attributes,
                max_component_name_len: 255,
                file_system_name: "NTFS".into(),
            }))
        } else if class == FileSystemInformationClassLevel::FILE_FS_DEVICE_INFORMATION {
            const FILE_DEVICE_DISK: u32 = 0x07;
            Some(FileSystemInformationClass::FileFsDeviceInformation(FileFsDeviceInformation {
                device_type: FILE_DEVICE_DISK,
                characteristics: Characteristics::empty(),
            }))
        } else {
            None
        };
        let status = if buffer.is_some() { NtStatus::SUCCESS } else { NtStatus::NOT_SUPPORTED };
        vec![SvcMessage::from(RdpdrPdu::ClientDriveQueryVolumeInformationResponse(
            ClientDriveQueryVolumeInformationResponse {
                device_io_reply: DeviceIoResponse::new(req.device_io_request, status),
                buffer,
            },
        ))]
    }

    fn set_information(&mut self, req: ServerDriveSetInformationRequest) -> PduResult<Vec<SvcMessage>> {
        let status = match self.open.get(&req.device_io_request.file_id).map(|h| h.path.clone()) {
            None => NtStatus::NO_SUCH_FILE,
            Some(path) => match &req.set_buffer {
                FileInformationClass::Rename(info) => match self.resolve(&info.file_name) {
                    None => NtStatus::ACCESS_DENIED,
                    Some(to) if to.exists() && info.replace_if_exists == Boolean::False => NtStatus::OBJECT_NAME_COLLISION,
                    Some(to) => match std::fs::rename(&path, &to) {
                        Ok(()) => {
                            if let Some(handle) = self.open.get_mut(&req.device_io_request.file_id) {
                                handle.path = to;
                            }
                            NtStatus::SUCCESS
                        }
                        Err(e) => status(&e),
                    },
                },
                FileInformationClass::Disposition(info) => {
                    let deleting = info.delete_pending != 0;
                    let not_empty = deleting && path.is_dir() && std::fs::read_dir(&path).is_ok_and(|mut d| d.next().is_some());
                    match self.open.get_mut(&req.device_io_request.file_id) {
                        Some(_) if not_empty => NtStatus::DIRECTORY_NOT_EMPTY,
                        Some(handle) => {
                            handle.delete_on_close = deleting;
                            NtStatus::SUCCESS
                        }
                        None => NtStatus::NO_SUCH_FILE,
                    }
                }
                FileInformationClass::EndOfFile(info) => {
                    match self.open.get(&req.device_io_request.file_id).and_then(|h| h.file.as_ref()) {
                        Some(file) => file.set_len(info.end_of_file.max(0) as u64).map_or_else(|e| status(&e), |()| NtStatus::SUCCESS),
                        None => NtStatus::ACCESS_DENIED,
                    }
                }
                // Times, attributes and the space set aside: nothing to keep.
                _ => NtStatus::SUCCESS,
            },
        };
        Ok(vec![SvcMessage::from(RdpdrPdu::ClientDriveSetInformationResponse(
            ClientDriveSetInformationResponse::new(&req, status).map_err(|e| ironrdp::pdu::encode_err!(e))?,
        ))])
    }

    fn query_directory(&mut self, req: ServerDriveQueryDirectoryRequest) -> Vec<SvcMessage> {
        let reply = |status: NtStatus, buffer: Option<FileInformationClass>| {
            vec![SvcMessage::from(RdpdrPdu::ClientDriveQueryDirectoryResponse(ClientDriveQueryDirectoryResponse {
                device_io_reply: DeviceIoResponse::new(req.device_io_request.clone(), status),
                buffer,
            }))]
        };
        let id = req.device_io_request.file_id;
        if req.initial_query != 0 {
            // The query is `\dir\pattern`: list the folder's matching names.
            let (folder, pattern) = req.path.rsplit_once('\\').unwrap_or(("", req.path.as_str()));
            let Some((dir, entries)) = self.resolve(folder).and_then(|dir| Some((dir.clone(), std::fs::read_dir(dir).ok()?))) else {
                return reply(NtStatus::NO_SUCH_FILE, None);
            };
            let mut names: Vec<String> =
                entries.flatten().map(|e| e.file_name().to_string_lossy().into_owned()).filter(|n| matches(pattern, n)).collect();
            names.sort();
            let Some(handle) = self.open.get_mut(&id) else {
                return reply(NtStatus::NO_SUCH_FILE, None);
            };
            handle.listing = names.into();
            handle.listed = dir;
        }
        let Some(handle) = self.open.get_mut(&id) else {
            return reply(NtStatus::NO_SUCH_FILE, None);
        };
        let Some(name) = handle.listing.pop_front() else {
            let none = if req.initial_query != 0 { NtStatus::NO_SUCH_FILE } else { NtStatus::NO_MORE_FILES };
            return reply(none, None);
        };
        let path = handle.listed.join(&name);
        match std::fs::metadata(&path) {
            Ok(meta) => match entry(req.file_info_class_lvl, &meta, &path, name) {
                Some(info) => reply(NtStatus::SUCCESS, Some(info)),
                None => reply(NtStatus::NOT_SUPPORTED, None),
            },
            Err(e) => reply(status(&e), None),
        }
    }
}

impl RdpdrBackend for Drive {
    fn handle_server_device_announce_response(&mut self, _: ServerDeviceAnnounceResponse) -> PduResult<()> {
        Ok(())
    }

    fn handle_scard_call(&mut self, _: DeviceControlRequest<ScardIoCtlCode>, _: ScardCall) -> PduResult<()> {
        Ok(())
    }

    fn handle_drive_io_request(&mut self, req: ServerDriveIoRequest) -> PduResult<Vec<SvcMessage>> {
        Ok(match req {
            ServerDriveIoRequest::ServerCreateDriveRequest(req) => self.create(req),
            ServerDriveIoRequest::DeviceCloseRequest(req) => self.close(req),
            ServerDriveIoRequest::DeviceReadRequest(req) => self.read(req),
            ServerDriveIoRequest::DeviceWriteRequest(req) => self.write(req),
            ServerDriveIoRequest::ServerDriveQueryInformationRequest(req) => self.query_information(req),
            ServerDriveIoRequest::ServerDriveQueryVolumeInformationRequest(req) => self.query_volume(req),
            ServerDriveIoRequest::ServerDriveSetInformationRequest(req) => return self.set_information(req),
            ServerDriveIoRequest::ServerDriveQueryDirectoryRequest(req) => self.query_directory(req),
            ServerDriveIoRequest::DeviceControlRequest(req) => {
                vec![SvcMessage::from(RdpdrPdu::DeviceControlResponse(DeviceControlResponse {
                    device_io_reply: DeviceIoResponse::new(req.header, NtStatus::SUCCESS),
                    output_buffer: None,
                }))]
            }
            // Change notifications and byte-range locks are not offered: the
            // server simply waits for no answer, as with other simple clients.
            ServerDriveIoRequest::ServerDriveNotifyChangeDirectoryRequest(_)
            | ServerDriveIoRequest::ServerDriveLockControlRequest(_) => Vec::new(),
        })
    }
}

/// Windows opens a device, not a file, for these names (with any extension).
fn is_device_name(part: &str) -> bool {
    let stem = part.split('.').next().unwrap_or(part).trim_end().to_ascii_uppercase();
    matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || (stem.len() == 4 && (stem.starts_with("COM") || stem.starts_with("LPT")) && stem.as_bytes()[3].is_ascii_digit())
}

fn created() -> Information {
    Information::from_bits_retain(0x0000_0002) // FILE_CREATED
}

/// Open (or create) a file as `disposition` asks; read-write when `write`.
fn open_file(path: &Path, disposition: CreateDisposition, write: bool, exists: bool) -> Result<(File, Information), NtStatus> {
    let mut options = OpenOptions::new();
    options.read(true);
    let information = match disposition {
        d if d == CreateDisposition::FILE_OPEN => {
            options.write(write);
            Information::FILE_OPENED
        }
        d if d == CreateDisposition::FILE_CREATE => {
            options.write(true).create_new(true);
            created()
        }
        d if d == CreateDisposition::FILE_OPEN_IF => {
            options.write(true).create(true);
            if exists { Information::FILE_OPENED } else { created() }
        }
        d if d == CreateDisposition::FILE_OVERWRITE => {
            options.write(true).truncate(true);
            Information::FILE_OVERWRITTEN
        }
        d if d == CreateDisposition::FILE_OVERWRITE_IF => {
            options.write(true).truncate(true).create(true);
            if exists { Information::FILE_OVERWRITTEN } else { created() }
        }
        // FILE_SUPERSEDE: replace whatever is there.
        _ => {
            options.write(true).truncate(true).create(true);
            if exists { Information::FILE_SUPERSEDED } else { created() }
        }
    };
    options.open(path).map(|file| (file, information)).map_err(|e| status(&e))
}

/// Fill `buf` as far as the file goes.
fn read_up_to(file: &mut File, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        match file.read(&mut buf[filled..])? {
            0 => break,
            n => filled += n,
        }
    }
    Ok(filled)
}

/// The NT status Windows expects for a local error.
fn status(e: &std::io::Error) -> NtStatus {
    use std::io::ErrorKind::*;
    match e.kind() {
        NotFound => NtStatus::NO_SUCH_FILE,
        AlreadyExists => NtStatus::OBJECT_NAME_COLLISION,
        PermissionDenied | ReadOnlyFilesystem => NtStatus::ACCESS_DENIED,
        DirectoryNotEmpty => NtStatus::DIRECTORY_NOT_EMPTY,
        NotADirectory => NtStatus::NOT_A_DIRECTORY,
        _ => NtStatus::UNSUCCESSFUL,
    }
}

/// A local time as a Windows FILETIME (100 ns steps since 1601).
fn filetime(time: std::io::Result<SystemTime>) -> i64 {
    const UNIX_EPOCH_AS_FILETIME: i64 = 116_444_736_000_000_000;
    let since = time.ok().and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok()).unwrap_or_default();
    UNIX_EPOCH_AS_FILETIME + (since.as_nanos() / 100) as i64
}

/// Created, last read, last written.
fn times(meta: &Metadata) -> [i64; 3] {
    let written = filetime(meta.modified());
    let created = meta.created().map_or(written, |t| filetime(Ok(t)));
    [created, filetime(meta.accessed()), written]
}

fn attributes(meta: &Metadata, path: &Path) -> FileAttributes {
    let mut attributes = if meta.is_dir() { FileAttributes::FILE_ATTRIBUTE_DIRECTORY } else { FileAttributes::FILE_ATTRIBUTE_ARCHIVE };
    if meta.permissions().readonly() {
        attributes |= FileAttributes::FILE_ATTRIBUTE_READONLY;
    }
    // Unix hides dot files.
    if path.file_name().is_some_and(|n| n.to_string_lossy().starts_with('.')) {
        attributes |= FileAttributes::FILE_ATTRIBUTE_HIDDEN;
    }
    attributes
}

/// One directory entry in the form the server asked for.
fn entry(class: FileInformationClassLevel, meta: &Metadata, path: &Path, name: String) -> Option<FileInformationClass> {
    let [created, accessed, written] = times(meta);
    let (size, attributes) = (meta.len() as i64, attributes(meta, path));
    Some(if class == FileInformationClassLevel::FILE_BOTH_DIRECTORY_INFORMATION {
        FileInformationClass::BothDirectory(FileBothDirectoryInformation::new(created, accessed, written, written, size, attributes, name))
    } else if class == FileInformationClassLevel::FILE_FULL_DIRECTORY_INFORMATION {
        FileInformationClass::FullDirectory(FileFullDirectoryInformation::new(created, accessed, written, written, size, attributes, name))
    } else if class == FileInformationClassLevel::FILE_DIRECTORY_INFORMATION {
        FileInformationClass::Directory(FileDirectoryInformation::new(created, accessed, written, written, size, attributes, name))
    } else if class == FileInformationClassLevel::FILE_NAMES_INFORMATION {
        FileInformationClass::Names(FileNamesInformation::new(name))
    } else {
        return None;
    })
}

/// Windows wildcard matching (`*` and `?`, any case), as directory queries use.
fn matches(pattern: &str, name: &str) -> bool {
    fn go(p: &[char], n: &[char]) -> bool {
        match (p.first(), n.first()) {
            (None, None) => true,
            (Some('*'), _) => go(&p[1..], n) || (!n.is_empty() && go(p, &n[1..])),
            (Some('?'), Some(_)) => go(&p[1..], &n[1..]),
            (Some(a), Some(b)) => a.to_lowercase().eq(b.to_lowercase()) && go(&p[1..], &n[1..]),
            _ => false,
        }
    }
    let (p, n): (Vec<char>, Vec<char>) = (pattern.chars().collect(), name.chars().collect());
    // "*.*" means everything, dotted or not.
    pattern == "*.*" || go(&p, &n)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn io(file_id: u32, major_function: MajorFunction) -> DeviceIoRequest {
        DeviceIoRequest { device_id: DEVICE_ID, file_id, completion_id: 7, major_function, minor_function: MinorFunction::from(0) }
    }

    /// The reply's NT status and what follows it (I/O completion: header,
    /// device id and completion id, then the status).
    fn reply(messages: Vec<SvcMessage>) -> (NtStatus, Vec<u8>) {
        let bytes = messages[0].encode_unframed_pdu().unwrap();
        let code = u32::from_le_bytes(bytes[12..16].try_into().unwrap());
        let status = [
            NtStatus::SUCCESS,
            NtStatus::NO_SUCH_FILE,
            NtStatus::NO_MORE_FILES,
            NtStatus::ACCESS_DENIED,
            NtStatus::OBJECT_NAME_COLLISION,
            NtStatus::NOT_A_DIRECTORY,
            NtStatus::DIRECTORY_NOT_EMPTY,
        ]
        .into_iter()
        .find(|s| u32::from(*s) == code)
        .unwrap_or(NtStatus::UNSUCCESSFUL);
        (status, bytes[16..].to_vec())
    }

    fn create(drive: &mut Drive, path: &str, disposition: CreateDisposition, options: CreateOptions) -> (NtStatus, u32) {
        let (status, rest) = reply(drive.create(DeviceCreateRequest {
            device_io_request: io(0, MajorFunction::Create),
            desired_access: DesiredAccess::from_bits_retain(0x4000_0000 | 0x8000_0000),
            allocation_size: 0,
            file_attributes: FileAttributes::empty(),
            shared_access: SharedAccess::empty(),
            create_disposition: disposition,
            create_options: options,
            path: path.into(),
        }));
        (status, u32::from_le_bytes(rest[..4].try_into().unwrap()))
    }

    fn shared() -> (Drive, PathBuf) {
        static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!("opencrt-drive-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        (Drive::new(root.clone()), root)
    }

    #[test]
    fn paths_stay_inside_the_shared_folder() {
        let drive = Drive::new(PathBuf::from("/srv/share"));
        assert_eq!(drive.resolve(r"\docs\note.txt"), Some(PathBuf::from("/srv/share/docs/note.txt")));
        assert_eq!(drive.resolve(""), Some(PathBuf::from("/srv/share")));
        assert_eq!(drive.resolve(r"\.\docs\\x"), Some(PathBuf::from("/srv/share/docs/x")));
        assert_eq!(drive.resolve(r"\..\etc\passwd"), None);
        assert_eq!(drive.resolve(r"\docs\..\..\x"), None);
        assert_eq!(drive.resolve(r"C:\Windows"), None);
        assert_eq!(drive.resolve(r"\note.txt:hidden"), None, "no alternate data streams");
    }

    #[test]
    fn windows_device_names_are_not_files() {
        assert!(is_device_name("CON") && is_device_name("nul.txt") && is_device_name("COM1") && is_device_name("lpt9.log"));
        assert!(!is_device_name("console.txt") && !is_device_name("COM") && !is_device_name("notes"));
    }

    #[test]
    fn wildcards_match_as_on_windows() {
        assert!(matches("*", "anything.txt"));
        assert!(matches("*.*", "no-dot"));
        assert!(matches("*.TXT", "note.txt"));
        assert!(matches("n?te.txt", "Note.txt"));
        assert!(!matches("*.txt", "note.doc"));
        assert!(matches("note.txt", "NOTE.TXT"));
    }

    #[test]
    fn files_can_be_made_listed_renamed_and_deleted() {
        let (mut drive, root) = shared();
        // A folder, then a file in it, written and read back.
        assert_eq!(create(&mut drive, r"\docs", CreateDisposition::FILE_CREATE, CreateOptions::FILE_DIRECTORY_FILE).0, NtStatus::SUCCESS);
        let (status, file) = create(&mut drive, r"\docs\note.txt", CreateDisposition::FILE_OVERWRITE_IF, CreateOptions::FILE_NON_DIRECTORY_FILE);
        assert_eq!(status, NtStatus::SUCCESS);
        let written = drive.write(DeviceWriteRequest { device_io_request: io(file, MajorFunction::Write), offset: 0, write_data: b"hello".to_vec() });
        assert_eq!(reply(written).0, NtStatus::SUCCESS);
        let (status, rest) = reply(drive.read(DeviceReadRequest { device_io_request: io(file, MajorFunction::Read), length: 100, offset: 1 }));
        assert_eq!((status, &rest[..4], &rest[4..]), (NtStatus::SUCCESS, &4u32.to_le_bytes()[..], &b"ello"[..]));
        assert_eq!(std::fs::read(root.join("docs/note.txt")).unwrap(), b"hello");

        // The folder lists it (once), then has no more.
        let (_, folder) = create(&mut drive, r"\docs", CreateDisposition::FILE_OPEN, CreateOptions::FILE_DIRECTORY_FILE);
        let query = |drive: &mut Drive, initial: u8| {
            reply(drive.query_directory(ServerDriveQueryDirectoryRequest {
                device_io_request: io(folder, MajorFunction::DirectoryControl),
                file_info_class_lvl: FileInformationClassLevel::FILE_BOTH_DIRECTORY_INFORMATION,
                initial_query: initial,
                path: r"\docs\*".into(),
            }))
        };
        let (status, rest) = query(&mut drive, 1);
        let name: Vec<u8> = "note.txt".encode_utf16().flat_map(u16::to_le_bytes).collect();
        assert_eq!(status, NtStatus::SUCCESS);
        assert!(rest.windows(name.len()).any(|w| w == name), "the entry names note.txt");
        assert_eq!(query(&mut drive, 0).0, NtStatus::NO_MORE_FILES);

        // Renamed, then deleted when closed.
        let set = |drive: &mut Drive, set_buffer| {
            reply(drive.set_information(ServerDriveSetInformationRequest { device_io_request: io(file, MajorFunction::SetInformation), set_buffer }).unwrap()).0
        };
        let rename = FileRenameInformation { replace_if_exists: Boolean::False, file_name: r"\docs\renamed.txt".into() };
        assert_eq!(set(&mut drive, FileInformationClass::Rename(rename)), NtStatus::SUCCESS);
        assert!(root.join("docs/renamed.txt").exists());
        assert_eq!(set(&mut drive, FileInformationClass::Disposition(FileDispositionInformation { delete_pending: 1 })), NtStatus::SUCCESS);
        assert_eq!(reply(drive.close(DeviceCloseRequest { device_io_request: io(file, MajorFunction::Close) })).0, NtStatus::SUCCESS);
        assert!(!root.join("docs/renamed.txt").exists());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn the_server_cannot_reach_outside() {
        let (mut drive, root) = shared();
        let outside = format!(r"\..\{}-escaped.txt", root.file_name().unwrap().to_string_lossy());
        assert_eq!(create(&mut drive, &outside, CreateDisposition::FILE_CREATE, CreateOptions::empty()).0, NtStatus::ACCESS_DENIED);
        assert!(!root.parent().unwrap().join(format!("{}-escaped.txt", root.file_name().unwrap().to_string_lossy())).exists());
        // Existing names are not overwritten by FILE_CREATE, and missing ones are reported.
        std::fs::write(root.join("kept.txt"), b"x").unwrap();
        assert_eq!(create(&mut drive, r"\kept.txt", CreateDisposition::FILE_CREATE, CreateOptions::empty()).0, NtStatus::OBJECT_NAME_COLLISION);
        assert_eq!(create(&mut drive, r"\missing.txt", CreateDisposition::FILE_OPEN, CreateOptions::empty()).0, NtStatus::NO_SUCH_FILE);
        assert_eq!(std::fs::read(root.join("kept.txt")).unwrap(), b"x");
        std::fs::remove_dir_all(root).unwrap();
        // Offered for sound alone, with no folder: nothing is reachable.
        let mut none = Drive::new(PathBuf::new());
        assert_eq!(create(&mut none, r"\Cargo.toml", CreateDisposition::FILE_OPEN, CreateOptions::empty()).0, NtStatus::ACCESS_DENIED);
    }
}
