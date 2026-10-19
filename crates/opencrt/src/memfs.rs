//! In-memory SFTP file system, for the SFTP tests and the dev server: files by
//! absolute path, with `/` and `/home` as the only directories.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use russh_sftp::protocol::{Attrs, Data, File, FileAttributes, Handle, Name, OpenFlags, Status, StatusCode};

/// Files by absolute path, shared by every session of a server.
pub type Files = Arc<Mutex<HashMap<String, Vec<u8>>>>;

pub struct MemFs {
    files: Files,
    dirs: HashSet<String>,
    /// Open directory handles already listed.
    listed: HashSet<String>,
}

fn ok(id: u32) -> Status {
    Status { id, status_code: StatusCode::Ok, error_message: "Ok".into(), language_tag: "en-US".into() }
}

fn attrs(dir: bool, size: u64) -> FileAttributes {
    let mut a = FileAttributes::empty();
    a.size = Some(size);
    a.permissions = Some(if dir { 0o40755 } else { 0o100644 });
    a
}

impl MemFs {
    pub fn new(files: Files) -> Self {
        Self { files, dirs: ["/".to_string(), "/home".to_string()].into(), listed: HashSet::new() }
    }

    fn absolute(path: &str) -> String {
        match path {
            "" | "." => "/home".into(),
            p if p.starts_with('/') => p.trim_end_matches("/.").to_string(),
            p => format!("/home/{p}"),
        }
    }

    fn stat_of(&self, path: &str) -> Result<FileAttributes, StatusCode> {
        if self.dirs.contains(path) {
            return Ok(attrs(true, 0));
        }
        let files = self.files.lock().unwrap();
        files.get(path).map(|f| attrs(false, f.len() as u64)).ok_or(StatusCode::NoSuchFile)
    }
}

impl russh_sftp::server::Handler for MemFs {
    type Error = StatusCode;

    fn unimplemented(&self) -> Self::Error {
        StatusCode::OpUnsupported
    }

    async fn realpath(&mut self, id: u32, path: String) -> Result<Name, Self::Error> {
        Ok(Name { id, files: vec![File::dummy(Self::absolute(&path))] })
    }

    async fn stat(&mut self, id: u32, path: String) -> Result<Attrs, Self::Error> {
        Ok(Attrs { id, attrs: self.stat_of(&Self::absolute(&path))? })
    }

    async fn lstat(&mut self, id: u32, path: String) -> Result<Attrs, Self::Error> {
        self.stat(id, path).await
    }

    async fn fstat(&mut self, id: u32, handle: String) -> Result<Attrs, Self::Error> {
        Ok(Attrs { id, attrs: self.stat_of(&handle)? })
    }

    async fn opendir(&mut self, id: u32, path: String) -> Result<Handle, Self::Error> {
        let path = Self::absolute(&path);
        if !self.dirs.contains(&path) {
            return Err(StatusCode::NoSuchFile);
        }
        self.listed.remove(&path);
        Ok(Handle { id, handle: path })
    }

    async fn readdir(&mut self, id: u32, handle: String) -> Result<Name, Self::Error> {
        if !self.listed.insert(handle.clone()) {
            return Err(StatusCode::Eof);
        }
        let prefix = format!("{}/", handle.trim_end_matches('/'));
        let files = self.files.lock().unwrap();
        let entries = files
            .iter()
            .filter_map(|(p, data)| p.strip_prefix(&prefix).map(|name| File::new(name, attrs(false, data.len() as u64))))
            .collect();
        Ok(Name { id, files: entries })
    }

    async fn open(&mut self, id: u32, filename: String, pflags: OpenFlags, _: FileAttributes) -> Result<Handle, Self::Error> {
        let path = Self::absolute(&filename);
        let mut files = self.files.lock().unwrap();
        if pflags.contains(OpenFlags::CREATE) {
            files.insert(path.clone(), Vec::new());
        } else if !files.contains_key(&path) {
            return Err(StatusCode::NoSuchFile);
        }
        Ok(Handle { id, handle: path })
    }

    async fn read(&mut self, id: u32, handle: String, offset: u64, len: u32) -> Result<Data, Self::Error> {
        let files = self.files.lock().unwrap();
        let data = files.get(&handle).ok_or(StatusCode::NoSuchFile)?;
        let start = offset as usize;
        if start >= data.len() {
            return Err(StatusCode::Eof);
        }
        let end = (start + len as usize).min(data.len());
        Ok(Data { id, data: data[start..end].to_vec() })
    }

    async fn write(&mut self, id: u32, handle: String, offset: u64, data: Vec<u8>) -> Result<Status, Self::Error> {
        let mut files = self.files.lock().unwrap();
        let file = files.get_mut(&handle).ok_or(StatusCode::NoSuchFile)?;
        let end = offset as usize + data.len();
        if file.len() < end {
            file.resize(end, 0);
        }
        file[offset as usize..end].copy_from_slice(&data);
        Ok(ok(id))
    }

    async fn close(&mut self, id: u32, _handle: String) -> Result<Status, Self::Error> {
        Ok(ok(id))
    }

    async fn remove(&mut self, id: u32, filename: String) -> Result<Status, Self::Error> {
        let removed = self.files.lock().unwrap().remove(&Self::absolute(&filename));
        removed.map(|_| ok(id)).ok_or(StatusCode::NoSuchFile)
    }
}
