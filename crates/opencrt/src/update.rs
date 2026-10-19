//! New versions: the latest release on GitHub, and how this copy was installed
//! (which decides what the user is told to do about it).

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, anyhow, bail};
use sha2::Digest;

/// Every OpenCRT release, newest first; `/latest` redirects to the newest tag.
pub const RELEASES: &str = "https://github.com/KimP0ssible-no/OpenCRT/releases";

/// `v1.2.3` or `1.2.3`; anything else (pre-releases included) is not a version.
pub fn parse_version(tag: &str) -> Option<(u32, u32, u32)> {
    let mut parts = tag.strip_prefix('v').unwrap_or(tag).split('.').map(|p| p.parse().ok());
    let version = (parts.next()??, parts.next()??, parts.next()??);
    parts.next().is_none().then_some(version)
}

pub fn is_newer(latest: &str, current: &str) -> bool {
    matches!((parse_version(latest), parse_version(current)), (Some(l), Some(c)) if l > c)
}

/// The tag in a `…/releases/tag/<tag>` address.
fn tag_from_location(location: &str) -> Option<&str> {
    let (_, tag) = location.rsplit_once("/releases/tag/")?;
    (!tag.is_empty() && !tag.contains('/')).then_some(tag)
}

/// HTTPS through the system's certificate store (so corporate TLS inspection
/// works) and the system or `HTTPS_PROXY` proxy, on the aws-lc crypto the
/// rest of OpenCRT uses.
fn agent(max_redirects: u32) -> ureq::Agent {
    use ureq::tls::{RootCerts, TlsConfig, TlsProvider};
    let tls = TlsConfig::builder()
        .provider(TlsProvider::Rustls)
        .root_certs(RootCerts::PlatformVerifier)
        .unversioned_rustls_crypto_provider(Arc::new(rustls::crypto::aws_lc_rs::default_provider()))
        .build();
    ureq::Agent::config_builder()
        .tls_config(tls)
        .max_redirects(max_redirects)
        .timeout_global(Some(Duration::from_secs(15)))
        .user_agent(concat!("OpenCRT/", env!("CARGO_PKG_VERSION")))
        .build()
        .new_agent()
}

/// The newest release's tag, read from where `{releases}/latest` redirects:
/// a web address, not the REST API, so no API rate limit applies.
pub fn latest_tag(releases: &str) -> anyhow::Result<String> {
    let response = agent(0).head(format!("{releases}/latest")).call()?;
    let location = response.headers().get("location").and_then(|v| v.to_str().ok()).unwrap_or_default();
    tag_from_location(location).map(str::to_string).ok_or_else(|| anyhow!("no release found"))
}

/// The OpenCRT repository is set up for apt, dnf, zypper or pacman under `root`,
/// as the setup page (`packaging/linux/repo-index.html`) does it.
fn repo_configured(root: &Path) -> bool {
    let etc = root.join("etc");
    etc.join("yum.repos.d/opencrt.repo").is_file()
        || etc.join("zypp/repos.d/opencrt.repo").is_file()
        || std::fs::read_dir(etc.join("apt/sources.list.d")).is_ok_and(|d| d.flatten().any(|e| e.file_name().to_string_lossy().starts_with("opencrt")))
        || std::fs::read_to_string(etc.join("pacman.conf")).is_ok_and(|c| c.lines().any(|l| l.trim() == "[opencrt]"))
}

/// The public half of the key that signs every release's `SHA256SUMS`.
pub const RELEASE_KEY: &str = include_str!("../../../packaging/minisign.pub");

/// Where downloads wait until they are installed; emptied at the next start.
fn download_dir() -> PathBuf {
    std::env::temp_dir().join("opencrt-update")
}

/// Download `asset` of release `tag` into `dir`, but only if `SHA256SUMS` is
/// signed by `key` and lists the file with the same checksum.
pub fn download_verified(releases: &str, tag: &str, asset: &str, dir: &Path, key: &str) -> anyhow::Result<PathBuf> {
    let base = format!("{releases}/download/{tag}");
    let agent = agent(10);
    let small = |name: &str| -> anyhow::Result<Vec<u8>> {
        let response = agent.get(format!("{base}/{name}")).call().with_context(|| format!("cannot download {name}"))?;
        Ok(response.into_body().into_with_config().limit(1 << 20).read_to_vec()?)
    };
    let sums = small("SHA256SUMS")?;
    let signature = String::from_utf8(small("SHA256SUMS.minisig")?)?;
    let signed = minisign_verify::PublicKey::decode(key)
        .and_then(|key| key.verify(&sums, &minisign_verify::Signature::decode(&signature)?, false));
    if signed.is_err() {
        bail!("SHA256SUMS is not signed with the OpenCRT release key");
    }
    let sums = String::from_utf8(sums)?;
    let expected = sums
        .lines()
        .find_map(|line| line.split_once("  ").filter(|(_, name)| *name == asset).map(|(hash, _)| hash.to_ascii_lowercase()))
        .ok_or_else(|| anyhow!("{asset} is not in SHA256SUMS"))?;

    std::fs::create_dir_all(dir)?;
    let path = dir.join(asset);
    let response = agent.get(format!("{base}/{asset}")).call().with_context(|| format!("cannot download {asset}"))?;
    let mut body = response.into_body().into_with_config().limit(512 << 20).reader();
    let (mut file, mut hash) = (std::fs::File::create(&path)?, sha2::Sha256::new());
    let mut buf = vec![0; 64 * 1024];
    let copied = loop {
        match body.read(&mut buf) {
            Ok(0) => break file.flush(),
            Ok(n) => {
                hash.update(&buf[..n]);
                if let Err(e) = file.write_all(&buf[..n]) {
                    break Err(e);
                }
            }
            Err(e) => break Err(e),
        }
    };
    let actual: String = hash.finalize().iter().map(|b| format!("{b:02x}")).collect();
    if let Err(e) = copied.map_err(anyhow::Error::from).and_then(|()| match actual == expected {
        true => Ok(()),
        false => Err(anyhow!("{asset} does not match its checksum in SHA256SUMS")),
    }) {
        let _ = std::fs::remove_file(&path);
        return Err(e.context(format!("cannot download {asset}")));
    }
    Ok(path)
}

/// Download the new version and get it ready; returns what [`launch`] starts.
/// Windows: the verified setup program. macOS: the new `OpenCRT.app`, already
/// in place of this one.
pub fn prepare(kind: InstallKind, version: &str, exe: &Path) -> anyhow::Result<PathBuf> {
    let asset = kind.asset(version).ok_or_else(|| anyhow!("this copy of OpenCRT cannot update itself"))?;
    let file = download_verified(RELEASES, &format!("v{version}"), &asset, &download_dir(), RELEASE_KEY)?;
    match kind {
        InstallKind::MacBundle => {
            let app = exe.ancestors().nth(3).ok_or_else(|| anyhow!("cannot find OpenCRT.app"))?;
            swap_bundle(&file, app)?;
            Ok(app.to_path_buf())
        }
        _ => Ok(file),
    }
}

/// Start what [`prepare`] returned; OpenCRT should quit straight after.
pub fn launch(kind: InstallKind, path: &Path) -> anyhow::Result<()> {
    match kind {
        InstallKind::InnoSetup => run_setup(path),
        _ => {
            std::process::Command::new("open").arg("-n").arg(path).spawn()?;
            Ok(())
        }
    }
}

/// ShellExecute rather than CreateProcess, so that a setup program that needs
/// administrator rights gets its elevation prompt.
#[cfg(windows)]
fn run_setup(setup: &Path) -> anyhow::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::UI::Shell::ShellExecuteW;
    use windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;
    // No questions, close OpenCRT if it is still running, start it again
    // afterwards (/RELAUNCH=1, see packaging/windows/opencrt.iss). CI runs the
    // setup program with the same switches.
    const ARGS: &str = "/VERYSILENT /SUPPRESSMSGBOXES /NORESTART /CLOSEAPPLICATIONS /RELAUNCH=1";
    let wide = |s: &std::ffi::OsStr| s.encode_wide().chain([0]).collect::<Vec<u16>>();
    let (file, args) = (wide(setup.as_os_str()), wide(std::ffi::OsStr::new(ARGS)));
    // SAFETY: both strings are NUL-terminated and outlive the call.
    let started = unsafe { ShellExecuteW(std::ptr::null_mut(), std::ptr::null(), file.as_ptr(), args.as_ptr(), std::ptr::null(), SW_SHOWNORMAL) };
    // Values up to 32 are errors (ShellExecute's documented convention).
    if started as usize <= 32 {
        bail!("the setup program did not start (error {})", started as usize);
    }
    Ok(())
}

#[cfg(not(windows))]
fn run_setup(_: &Path) -> anyhow::Result<()> {
    bail!("the setup program only runs on Windows")
}

/// Replace `app` with the `OpenCRT.app` on disk image `dmg`. The old bundle
/// is kept beside it as `.OpenCRT.app.old` (and put back if the swap fails)
/// until the next start. Copies made here carry no quarantine attribute, so
/// Gatekeeper does not hold up the new version.
fn swap_bundle(dmg: &Path, app: &Path) -> anyhow::Result<()> {
    let parent = app.parent().ok_or_else(|| anyhow!("cannot find the folder OpenCRT.app is in"))?;
    let run = |program: &str, args: &[&std::ffi::OsStr]| -> anyhow::Result<()> {
        let status = std::process::Command::new(program).args(args).stdout(std::process::Stdio::null()).status()?;
        if !status.success() {
            bail!("{program} failed ({status})");
        }
        Ok(())
    };
    let mount = dmg.with_extension("mount");
    std::fs::create_dir_all(&mount)?;
    run("hdiutil", &["attach".as_ref(), "-nobrowse".as_ref(), "-readonly".as_ref(), "-noautoopen".as_ref(), "-mountpoint".as_ref(), mount.as_os_str(), dmg.as_os_str()])?;
    let (new, old) = (parent.join(".OpenCRT.app.new"), parent.join(".OpenCRT.app.old"));
    let swapped = (|| {
        let _ = std::fs::remove_dir_all(&new);
        let _ = std::fs::remove_dir_all(&old);
        run("ditto", &[mount.join("OpenCRT.app").as_os_str(), new.as_os_str()]).context("cannot copy the new version (is the Applications folder writable?)")?;
        std::fs::rename(app, &old)?;
        std::fs::rename(&new, app).inspect_err(|_| {
            let _ = std::fs::rename(&old, app);
        })?;
        anyhow::Ok(())
    })();
    let _ = run("hdiutil", &["detach".as_ref(), "-quiet".as_ref(), mount.as_os_str()]);
    let _ = std::fs::remove_dir(&mount);
    if swapped.is_err() {
        let _ = std::fs::remove_dir_all(&new);
    }
    swapped
}

/// At start-up: remove what the last update left behind.
pub fn clean_up(exe: &Path) {
    let _ = std::fs::remove_dir_all(download_dir());
    if InstallKind::of(exe) == InstallKind::MacBundle
        && let Some(parent) = exe.ancestors().nth(4)
    {
        let _ = std::fs::remove_dir_all(parent.join(".OpenCRT.app.old"));
    }
}

/// How this copy of OpenCRT was installed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InstallKind {
    /// The Windows setup program (its uninstaller sits beside the program).
    InnoSetup,
    /// `OpenCRT.app` from the disk image.
    MacBundle,
    /// A .deb, .rpm or Arch package: the package manager owns it, and gets
    /// new versions if the OpenCRT repository is set up (`repo`).
    Package { repo: bool },
    /// The MSI, a copied folder or a development build.
    Manual,
}

impl InstallKind {
    pub fn of(exe: &Path) -> Self {
        let dir = exe.parent().unwrap_or(Path::new(""));
        if dir.join("unins000.exe").is_file() {
            Self::InnoSetup
        } else if dir.ends_with("Contents/MacOS") && dir.parent().and_then(Path::parent).is_some_and(|app| app.extension().is_some_and(|e| e == "app")) {
            Self::MacBundle
        } else if exe.starts_with("/usr/") {
            Self::Package { repo: repo_configured(Path::new("/")) }
        } else {
            Self::Manual
        }
    }

    /// What to do about a new version, after "OpenCRT X is available.".
    pub fn advice(self) -> &'static str {
        match self {
            Self::InnoSetup | Self::MacBundle => "Update Now installs it and restarts OpenCRT.",
            Self::Package { repo: true } => "Update it with your system's package manager.",
            Self::Package { repo: false } => {
                "To get it, and later versions, with your system's updates, set up the OpenCRT package repository once: kimp0ssible-no.github.io/OpenCRT"
            }
            Self::Manual => "Download it from the release page.",
        }
    }

    /// The release file this kind of install updates itself from.
    pub fn asset(self, version: &str) -> Option<String> {
        match self {
            Self::InnoSetup => Some(format!("opencrt-{version}-x64-setup.exe")),
            Self::MacBundle => Some("OpenCRT.dmg".to_string()),
            Self::Package { .. } | Self::Manual => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions() {
        assert_eq!(parse_version("v0.1.10"), Some((0, 1, 10)));
        assert_eq!(parse_version("0.2.0"), Some((0, 2, 0)));
        assert_eq!(parse_version("v0.2.0-rc1"), None);
        assert_eq!(parse_version("v1.2"), None);
        assert_eq!(parse_version("v1.2.3.4"), None);
        assert!(is_newer("v0.1.10", "0.1.9"));
        assert!(is_newer("v1.0.0", "0.9.9"));
        assert!(!is_newer("v0.1.1", "0.1.1"));
        assert!(!is_newer("v0.1.0", "0.1.1"));
        assert!(!is_newer("nightly", "0.1.1"));
    }

    #[test]
    fn location() {
        assert_eq!(tag_from_location("https://github.com/o/r/releases/tag/v0.1.1"), Some("v0.1.1"));
        assert_eq!(tag_from_location("https://github.com/o/r/releases"), None);
        assert_eq!(tag_from_location("https://github.com/o/r/releases/tag/"), None);
    }

    #[test]
    fn install_kinds() {
        let dir = std::env::temp_dir().join(format!("opencrt-kind-{}", std::process::id()));
        let inno = dir.join("OpenCRT");
        let mac = dir.join("Applications/OpenCRT.app/Contents/MacOS");
        std::fs::create_dir_all(&inno).unwrap();
        std::fs::create_dir_all(&mac).unwrap();
        std::fs::write(inno.join("unins000.exe"), b"").unwrap();
        assert_eq!(InstallKind::of(&inno.join("opencrt.exe")), InstallKind::InnoSetup);
        assert_eq!(InstallKind::of(&mac.join("opencrt")), InstallKind::MacBundle);
        assert!(matches!(InstallKind::of(Path::new("/usr/bin/opencrt")), InstallKind::Package { .. }));
        assert_eq!(InstallKind::of(&dir.join("target/release/opencrt")), InstallKind::Manual);
        assert_eq!(InstallKind::of(&dir.join("MacOS/opencrt")), InstallKind::Manual);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn repository_set_up() {
        let root = std::env::temp_dir().join(format!("opencrt-repo-{}", std::process::id()));
        let etc = root.join("etc");
        std::fs::create_dir_all(etc.join("apt/sources.list.d")).unwrap();
        std::fs::create_dir_all(etc.join("yum.repos.d")).unwrap();
        std::fs::write(etc.join("pacman.conf"), "[core]\nInclude = /etc/pacman.d/mirrorlist\n").unwrap();
        assert!(!repo_configured(&root));
        std::fs::write(etc.join("pacman.conf"), "[core]\n\n[opencrt]\nServer = https://example.invalid/arch\n").unwrap();
        assert!(repo_configured(&root));
        std::fs::remove_file(etc.join("pacman.conf")).unwrap();
        std::fs::write(etc.join("apt/sources.list.d/opencrt.list"), "deb …").unwrap();
        assert!(repo_configured(&root));
        std::fs::remove_file(etc.join("apt/sources.list.d/opencrt.list")).unwrap();
        std::fs::write(etc.join("yum.repos.d/opencrt.repo"), "[opencrt]").unwrap();
        assert!(repo_configured(&root));
        std::fs::remove_dir_all(&root).unwrap();
    }

    /// A local server standing in for github.com: answers each request for
    /// `/<name>` from `files`, 404 for anything else, until `requests` are served.
    fn serve(files: Vec<(&'static str, Vec<u8>)>, requests: usize) -> String {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        std::thread::spawn(move || {
            for _ in 0..requests {
                let (mut stream, _) = listener.accept().unwrap();
                let mut request = [0u8; 2048];
                let n = stream.read(&mut request).unwrap();
                let line = String::from_utf8_lossy(&request[..n]).lines().next().unwrap_or_default().to_string();
                let path = line.split(' ').nth(1).unwrap_or_default().to_string();
                match files.iter().find(|(name, _)| path == format!("/r/download/v1.2.3/{name}")) {
                    Some((_, body)) => {
                        write!(stream, "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).unwrap();
                        stream.write_all(body).unwrap();
                    }
                    None => write!(stream, "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").unwrap(),
                }
            }
        });
        format!("{base}/r")
    }

    const SUMS: &[u8] = include_bytes!("../testdata/update/SHA256SUMS");
    const SIG: &[u8] = include_bytes!("../testdata/update/SHA256SUMS.minisig");
    const TEST_KEY: &str = include_str!("../testdata/update/test.pub");
    const OTHER_KEY: &str = include_str!("../testdata/update/other.pub");
    const ASSET: &[u8] = b"OpenCRT test asset\n";

    fn download(files: Vec<(&'static str, Vec<u8>)>, requests: usize, key: &str) -> (anyhow::Result<PathBuf>, PathBuf) {
        static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("opencrt-dl-{}-{n}", std::process::id()));
        (download_verified(&serve(files, requests), "v1.2.3", "asset.bin", &dir, key), dir)
    }

    #[test]
    fn downloads_only_what_the_signed_list_vouches_for() {
        let good = || vec![("SHA256SUMS", SUMS.to_vec()), ("SHA256SUMS.minisig", SIG.to_vec()), ("asset.bin", ASSET.to_vec())];
        let (ok, dir) = download(good(), 3, TEST_KEY);
        assert_eq!(std::fs::read(ok.unwrap()).unwrap(), ASSET);
        std::fs::remove_dir_all(dir).unwrap();

        // Wrong key, edited list, swapped file: nothing is left on disk.
        let (wrong_key, _) = download(good(), 2, OTHER_KEY);
        assert!(wrong_key.unwrap_err().to_string().contains("not signed"));
        let mut edited = good();
        edited[0].1 = String::from_utf8_lossy(SUMS).replace("b9c3", "b9c4").into_bytes();
        assert!(download(edited, 2, TEST_KEY).0.unwrap_err().to_string().contains("not signed"));
        let mut swapped = good();
        swapped[2].1 = b"something else".to_vec();
        let (bad, dir) = download(swapped, 3, TEST_KEY);
        assert!(format!("{:#}", bad.unwrap_err()).contains("does not match"));
        assert!(!dir.join("asset.bin").exists());
        let unlisted = download_verified(&serve(good(), 2), "v1.2.3", "other.bin", &std::env::temp_dir(), TEST_KEY);
        assert!(unlisted.unwrap_err().to_string().contains("not in SHA256SUMS"));
    }

    #[test]
    fn release_key_is_a_minisign_key() {
        assert!(minisign_verify::PublicKey::decode(RELEASE_KEY).is_ok());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn swaps_the_bundle_from_a_disk_image() {
        let dir = std::env::temp_dir().join(format!("opencrt-swap-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let bundle = |root: &Path, version: &str| {
            std::fs::create_dir_all(root.join("OpenCRT.app/Contents/MacOS")).unwrap();
            std::fs::write(root.join("OpenCRT.app/Contents/Info.plist"), version).unwrap();
        };
        bundle(&dir.join("image"), "new");
        bundle(&dir.join("Applications"), "old");
        let dmg = dir.join("OpenCRT.dmg");
        let made = std::process::Command::new("hdiutil")
            .args(["create", "-quiet", "-volname", "OpenCRT", "-format", "UDZO", "-srcfolder"])
            .arg(dir.join("image"))
            .arg(&dmg)
            .status()
            .unwrap();
        assert!(made.success());
        let app = dir.join("Applications/OpenCRT.app");
        swap_bundle(&dmg, &app).unwrap();
        assert_eq!(std::fs::read_to_string(app.join("Contents/Info.plist")).unwrap(), "new");
        assert_eq!(std::fs::read_to_string(dir.join("Applications/.OpenCRT.app.old/Contents/Info.plist")).unwrap(), "old");
        let quarantine = std::process::Command::new("xattr").args(["-p", "com.apple.quarantine"]).arg(&app).output().unwrap();
        assert!(!quarantine.status.success(), "the new bundle must not be quarantined");
        clean_up(&app.join("Contents/MacOS/opencrt"));
        assert!(!dir.join("Applications/.OpenCRT.app.old").exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// One HTTP exchange with a local server standing in for github.com.
    #[test]
    fn latest_tag_follows_nothing_and_reads_the_redirect() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}/o/r/releases", listener.local_addr().unwrap());
        let location = format!("{base}/tag/v9.9.9");
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0u8; 1024];
            let n = stream.read(&mut request).unwrap();
            write!(stream, "HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").unwrap();
            String::from_utf8_lossy(&request[..n]).lines().next().unwrap_or_default().to_string()
        });
        assert_eq!(latest_tag(&base).unwrap(), "v9.9.9");
        assert_eq!(server.join().unwrap(), "HEAD /o/r/releases/latest HTTP/1.1");
    }
}
