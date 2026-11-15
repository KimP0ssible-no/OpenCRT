//! The Windows taskbar jump list (a right-click on OpenCRT's taskbar button):
//! the recent saved sessions. Choosing one starts OpenCRT with `/T /S path`,
//! which opens the session in the window already running (see `instance`).

use std::path::PathBuf;

/// One jump list entry.
#[cfg(any(windows, test))]
#[derive(Debug, PartialEq)]
struct Entry {
    /// The session's name, or its whole path when another entry has that name.
    title: String,
    /// The session's path, as the tooltip.
    path: String,
    /// The command line that opens it.
    arguments: String,
}

/// The entries for the recent sessions (by path, newest first); `folder` is
/// the configuration folder when `/F` named one, which the new start needs too.
#[cfg(any(windows, test))]
fn entries(recent: &[String], folder: Option<&std::path::Path>) -> Vec<Entry> {
    let name = |path: &str| path.rsplit('/').next().unwrap_or(path).to_string();
    let folder = folder.map(|f| format!("/F {} ", quoted(&f.display().to_string()))).unwrap_or_default();
    let entry = |path: &String| {
        let shared = recent.iter().filter(|other| name(other) == name(path)).count() > 1;
        Entry { title: if shared { path.clone() } else { name(path) }, path: path.clone(), arguments: format!("{folder}/T /S {}", quoted(path)) }
    };
    recent.iter().map(entry).collect()
}

/// `arg` as one argument of a Windows command line: in quotes, a quote inside
/// it behind a backslash, and the backslashes before a quote doubled.
#[cfg(any(windows, test))]
fn quoted(arg: &str) -> String {
    let (mut out, mut backslashes) = (String::from('"'), 0);
    for c in arg.chars() {
        match c {
            '\\' => backslashes += 1,
            '"' => {
                out.extend(std::iter::repeat_n('\\', backslashes + 1));
                backslashes = 0;
            }
            _ => backslashes = 0,
        }
        out.push(c);
    }
    out.extend(std::iter::repeat_n('\\', backslashes));
    out + "\""
}

/// Show `recent` (saved sessions by path, newest first) as the jump list's
/// "Recent Sessions"; none removes the list. Only Windows has one.
#[cfg(not(windows))]
pub fn update(_recent: &[String], _folder: Option<PathBuf>) {}

/// Show `recent` (saved sessions by path, newest first) as the jump list's
/// "Recent Sessions"; none removes the list. A failure changes nothing: the
/// list is a convenience.
#[cfg(windows)]
pub fn update(recent: &[String], folder: Option<PathBuf>) {
    use windows::Win32::System::Com::{COINIT_APARTMENTTHREADED, CoInitializeEx, CoUninitialize};
    let entries = entries(recent, folder.as_deref());
    let category = crate::tr!("Recent Sessions");
    let Ok(exe) = std::env::current_exe() else {
        return;
    };
    // A thread and a COM apartment of its own: the shell can take a while,
    // and the window's thread keeps the COM state winit gave it.
    std::thread::spawn(move || {
        // SAFETY: COM is initialised on this thread alone and released on it
        // once every COM object `show` made is gone.
        unsafe {
            if CoInitializeEx(None, COINIT_APARTMENTTHREADED).is_ok() {
                let _ = show(&entries, &category, &exe);
                CoUninitialize();
            }
        }
    });
}

/// Replace the jump list's custom category with `entries`.
#[cfg(windows)]
fn show(entries: &[Entry], category: &str, exe: &std::path::Path) -> windows::core::Result<()> {
    use windows::Win32::Foundation::PROPERTYKEY;
    use windows::Win32::System::Com::StructuredStorage::PROPVARIANT;
    use windows::Win32::System::Com::{CLSCTX_INPROC_SERVER, CoCreateInstance};
    use windows::Win32::System::Variant::VT_LPWSTR;
    use windows::Win32::UI::Shell::Common::{IObjectArray, IObjectCollection};
    use windows::Win32::UI::Shell::PropertiesSystem::IPropertyStore;
    use windows::Win32::UI::Shell::{DestinationList, EnumerableObjectCollection, ICustomDestinationList, IShellLinkW, ShellLink};
    use windows::core::{GUID, HSTRING, Interface, PCWSTR, PWSTR};

    /// System.Title (PKEY_Title): the text a jump list shows for a link.
    const TITLE: PROPERTYKEY = PROPERTYKEY { fmtid: GUID::from_u128(0xf29f85e0_4ff9_1068_ab91_08002b27b3d9), pid: 2 };
    let exe = HSTRING::from(exe);

    // SAFETY: plain COM calls on objects created here, on a thread with COM
    // initialised (see `update`); every pointer passed outlives its call.
    unsafe {
        let list: ICustomDestinationList = CoCreateInstance(&DestinationList, None, CLSCTX_INPROC_SERVER)?;
        if entries.is_empty() {
            // No application ID of our own: Windows keys the list to the program.
            return list.DeleteList(PCWSTR::null());
        }
        let mut slots = 0u32;
        let removed: IObjectArray = list.BeginList(&mut slots)?;
        // What the user took off the list must not come back in this round.
        let mut gone = Vec::new();
        for i in 0..removed.GetCount()? {
            let mut arguments = [0u16; 1024];
            if let Ok(link) = removed.GetAt::<IShellLinkW>(i)
                && link.GetArguments(&mut arguments).is_ok()
            {
                let end = arguments.iter().position(|c| *c == 0).unwrap_or(arguments.len());
                gone.push(String::from_utf16_lossy(&arguments[..end]));
            }
        }
        let links: IObjectCollection = CoCreateInstance(&EnumerableObjectCollection, None, CLSCTX_INPROC_SERVER)?;
        for entry in entries.iter().filter(|e| !gone.contains(&e.arguments)) {
            let link: IShellLinkW = CoCreateInstance(&ShellLink, None, CLSCTX_INPROC_SERVER)?;
            link.SetPath(&exe)?;
            link.SetArguments(&HSTRING::from(entry.arguments.as_str()))?;
            link.SetIconLocation(&exe, 0)?;
            let _ = link.SetDescription(&HSTRING::from(entry.path.as_str()));
            // The title as a VT_LPWSTR value. The store copies it, and it is
            // not dropped as a PROPVARIANT: its text belongs to `title`.
            let mut title: Vec<u16> = entry.title.encode_utf16().chain([0]).collect();
            let mut value = std::mem::ManuallyDrop::new(PROPVARIANT::default());
            (*value.Anonymous.Anonymous).vt = VT_LPWSTR;
            (*value.Anonymous.Anonymous).Anonymous.pwszVal = PWSTR(title.as_mut_ptr());
            let store: IPropertyStore = link.cast()?;
            store.SetValue(&TITLE, &*value)?;
            store.Commit()?;
            links.AddObject(&link)?;
        }
        list.AppendCategory(&HSTRING::from(category), &links)?;
        list.CommitList()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recent_sessions_as_jump_list_entries() {
        let recent = ["Lab/core sw1".to_string(), "web1".into(), "Office/web1".into()];
        let shown = entries(&recent, None);
        assert_eq!(shown[0], Entry { title: "core sw1".into(), path: "Lab/core sw1".into(), arguments: "/T /S \"Lab/core sw1\"".into() });
        // Two sessions with one name show their paths.
        assert_eq!((shown[1].title.as_str(), shown[2].title.as_str()), ("web1", "Office/web1"));
        // A configuration folder from the command line goes along.
        assert_eq!(entries(&recent[1..2], Some(std::path::Path::new("D:\\my crt\\")))[0].arguments, "/F \"D:\\my crt\\\\\" /T /S \"web1\"");
        assert_eq!(quoted("say \"hi\\\" now"), "\"say \\\"hi\\\\\\\" now\"");
        assert!(entries(&[], None).is_empty());
    }
}
