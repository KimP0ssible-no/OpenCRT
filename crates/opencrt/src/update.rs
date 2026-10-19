//! New versions: the latest release on GitHub, and how this copy was installed
//! (which decides what the user is told to do about it).

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::anyhow;

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

/// How this copy of OpenCRT was installed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InstallKind {
    /// The Windows setup program (its uninstaller sits beside the program).
    InnoSetup,
    /// `OpenCRT.app` from the disk image.
    MacBundle,
    /// A .deb, .rpm or Arch package: the package manager owns it.
    Package,
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
            Self::Package
        } else {
            Self::Manual
        }
    }

    /// What to do about a new version, after "OpenCRT X is available.".
    pub fn advice(self) -> &'static str {
        match self {
            Self::Package => "Update it with your system's package manager.",
            Self::InnoSetup | Self::MacBundle | Self::Manual => "Download it from the release page.",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

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
        assert_eq!(InstallKind::of(Path::new("/usr/bin/opencrt")), InstallKind::Package);
        assert_eq!(InstallKind::of(&dir.join("target/release/opencrt")), InstallKind::Manual);
        assert_eq!(InstallKind::of(&dir.join("MacOS/opencrt")), InstallKind::Manual);
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
