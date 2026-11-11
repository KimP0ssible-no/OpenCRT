//! Saved passwords under a master password: the `secrets` file in the
//! settings folder, used instead of the system keychain once a master
//! password is set. One line per password, so Settings Sync merges it by line
//! like the host keys:
//!
//! ```text
//! opencrt-secrets 1 <salt> <nonce> <check>
//! <account> <nonce> <ciphertext>
//! ```
//!
//! All fields are base64. The key is Argon2id(master password, salt); each
//! password is AES-256-GCM with its account name as associated data, so lines
//! cannot be swapped; `check` is the header text encrypted, to tell a wrong
//! master password. The key is kept in memory once unlocked, until exit.

use std::path::Path;
use std::sync::Mutex;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::Aes256Gcm;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;

pub const FILE: &str = "secrets";
/// The error while no master password has been entered this run.
pub const LOCKED: &str = "saved passwords are locked by the master password";
const HEADER: &str = "opencrt-secrets";
const CHECK: &[u8] = b"opencrt-secrets 1";

/// The unlocked key and the salt it belongs to.
static KEY: Mutex<Option<(String, [u8; 32])>> = Mutex::new(None);

fn derive(password: &str, salt: &[u8]) -> Result<[u8; 32], String> {
    let mut key = [0u8; 32];
    argon2::Argon2::default().hash_password_into(password.as_bytes(), salt, &mut key).map_err(|e| e.to_string())?;
    Ok(key)
}

fn seal(key: &[u8; 32], aad: &[u8], plain: &[u8]) -> (String, String) {
    let nonce: [u8; 12] = rand::random();
    let sealed = Aes256Gcm::new(&(*key).into()).encrypt(&nonce.into(), Payload { msg: plain, aad }).expect("AES-GCM encrypts any length here");
    (B64.encode(nonce), B64.encode(sealed))
}

fn open(key: &[u8; 32], aad: &[u8], nonce: &str, sealed: &str) -> Option<Vec<u8>> {
    let nonce: [u8; 12] = B64.decode(nonce).ok()?.try_into().ok()?;
    Aes256Gcm::new(&(*key).into()).decrypt(&nonce.into(), Payload { msg: &B64.decode(sealed).ok()?, aad }).ok()
}

/// The file's lines: the headers (salt, nonce, check) and the entries
/// (account, nonce, ciphertext). After a Settings Sync merge an account can
/// appear twice; the first line wins (this computer's).
#[allow(clippy::type_complexity)]
fn read(dir: &Path) -> (Vec<(String, String, String)>, Vec<(String, String, String)>) {
    let text = std::fs::read_to_string(dir.join(FILE)).unwrap_or_default();
    let (mut headers, mut entries) = (Vec::new(), Vec::new());
    for line in text.lines() {
        match line.split(' ').collect::<Vec<_>>()[..] {
            [HEADER, "1", salt, nonce, check] => headers.push((salt.into(), nonce.into(), check.into())),
            [account, nonce, sealed] => {
                if let Ok(account) = B64.decode(account).map(|a| String::from_utf8_lossy(&a).into_owned()) {
                    entries.push((account, nonce.into(), sealed.into()));
                }
            }
            _ => {}
        }
    }
    (headers, entries)
}

fn write(dir: &Path, salt: &str, key: &[u8; 32], entries: &[(String, String)]) -> Result<(), String> {
    let (nonce, check) = seal(key, &[], CHECK);
    let mut text = format!("{HEADER} 1 {salt} {nonce} {check}\n");
    for (account, password) in entries {
        let (nonce, sealed) = seal(key, account.as_bytes(), password.as_bytes());
        text += &format!("{} {nonce} {sealed}\n", B64.encode(account));
    }
    // Written whole, then renamed, so a crash never leaves half a file.
    let (path, tmp) = (dir.join(FILE), dir.join(format!("{FILE}.tmp")));
    std::fs::write(&tmp, text).and_then(|()| std::fs::rename(&tmp, &path)).map_err(|e| format!("cannot write {}: {e}", path.display()))
}

/// A master password is set (the file is there, perhaps from another computer).
pub fn exists(dir: &Path) -> bool {
    dir.join(FILE).is_file()
}

pub fn unlocked() -> bool {
    KEY.lock().unwrap().is_some()
}

/// Check `password` against the file and keep the key for this run.
pub fn unlock(dir: &Path, password: &str) -> Result<(), String> {
    let (headers, _) = read(dir);
    for (salt, nonce, check) in headers {
        let key = derive(password, &B64.decode(&salt).map_err(|e| e.to_string())?)?;
        if open(&key, &[], &nonce, &check).as_deref() == Some(CHECK) {
            *KEY.lock().unwrap() = Some((salt, key));
            return Ok(());
        }
    }
    Err("That is not the master password.".into())
}

/// Every saved password, decrypted (the file must be unlocked).
pub fn all(dir: &Path) -> Result<Vec<(String, String)>, String> {
    let (salt, key) = KEY.lock().unwrap().clone().ok_or(LOCKED)?;
    let (headers, entries) = read(dir);
    if !headers.iter().any(|(s, ..)| *s == salt) {
        return Err(LOCKED.into());
    }
    let mut out: Vec<(String, String)> = Vec::new();
    for (account, nonce, sealed) in entries {
        if out.iter().any(|(a, _)| *a == account) {
            continue;
        }
        if let Some(plain) = open(&key, account.as_bytes(), &nonce, &sealed) {
            out.push((account, String::from_utf8_lossy(&plain).into_owned()));
        }
    }
    Ok(out)
}

pub fn get(dir: &Path, account: &str) -> Result<Option<String>, String> {
    Ok(all(dir)?.into_iter().find(|(a, _)| a == account).map(|(_, p)| p))
}

/// Save (Some) or forget (None) `account`'s password, rewriting the file.
pub fn set(dir: &Path, account: &str, password: Option<&str>) -> Result<(), String> {
    let mut entries = all(dir)?;
    entries.retain(|(a, _)| a != account);
    entries.extend(password.map(|p| (account.to_string(), p.to_string())));
    let (salt, key) = KEY.lock().unwrap().clone().ok_or(LOCKED)?;
    write(dir, &salt, &key, &entries)
}

/// Start the file with `password` as the master password, holding `entries`
/// (the passwords moved out of the keychain), and keep it unlocked.
pub fn create(dir: &Path, password: &str, entries: &[(String, String)]) -> Result<(), String> {
    let salt = B64.encode(rand::random::<[u8; 16]>());
    let key = derive(password, &B64.decode(&salt).map_err(|e| e.to_string())?)?;
    write(dir, &salt, &key, entries)?;
    *KEY.lock().unwrap() = Some((salt, key));
    Ok(())
}

/// Remove the master password: every password, decrypted, and the file gone.
pub fn remove(dir: &Path) -> Result<Vec<(String, String)>, String> {
    let entries = all(dir)?;
    std::fs::remove_file(dir.join(FILE)).map_err(|e| e.to_string())?;
    *KEY.lock().unwrap() = None;
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn master_password_round_trip() {
        let dir = std::env::temp_dir().join(format!("opencrt-vault-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        create(&dir, "correct horse", &[("credential:web".into(), "pä55".into())]).unwrap();
        set(&dir, "firewall:office", Some("fw")).unwrap();
        assert_eq!(get(&dir, "credential:web").unwrap().as_deref(), Some("pä55"));
        let text = std::fs::read_to_string(dir.join(FILE)).unwrap();
        assert!(!text.contains("pä55") && !text.contains("fw "), "nothing in clear: {text}");

        // Another run: locked until the right master password.
        *KEY.lock().unwrap() = None;
        assert_eq!(get(&dir, "credential:web").unwrap_err(), LOCKED);
        assert!(unlock(&dir, "wrong").is_err());
        unlock(&dir, "correct horse").unwrap();
        assert_eq!(get(&dir, "firewall:office").unwrap().as_deref(), Some("fw"));

        // A swapped line does not decrypt as the other account.
        let swapped = text.replace(&B64.encode("credential:web"), &B64.encode("credential:other"));
        std::fs::write(dir.join(FILE), swapped).unwrap();
        assert_eq!(get(&dir, "credential:other").unwrap(), None);
        std::fs::write(dir.join(FILE), &text).unwrap();

        set(&dir, "firewall:office", None).unwrap();
        assert_eq!(remove(&dir).unwrap(), [("credential:web".to_string(), "pä55".to_string())]);
        assert!(!exists(&dir));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
