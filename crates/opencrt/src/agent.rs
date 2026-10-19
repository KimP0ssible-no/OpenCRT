//! OpenCRT's built-in SSH agent (Tools > Agent Keys): keys held in memory,
//! served by russh's agent on its own thread and reached through in-process
//! pipes. While it holds keys, logins and agent forwarding use it instead of
//! the system's agent.

use std::sync::OnceLock;
use std::sync::atomic::{AtomicUsize, Ordering};

use russh::keys::PrivateKey;
use russh::keys::agent::client::AgentClient;
use tokio::io::DuplexStream;
use tokio::sync::mpsc::{UnboundedSender, unbounded_channel};

struct Agent {
    connections: UnboundedSender<DuplexStream>,
    runtime: tokio::runtime::Handle,
}

static AGENT: OnceLock<Agent> = OnceLock::new();
static KEYS: AtomicUsize = AtomicUsize::new(0);

fn agent() -> &'static Agent {
    AGENT.get_or_init(|| {
        let (connections, mut incoming) = unbounded_channel::<DuplexStream>();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().expect("agent runtime");
            let _ = tx.send(runtime.handle().clone());
            let listener = Box::pin(futures::stream::poll_fn(move |cx| incoming.poll_recv(cx).map(|s| s.map(Ok))));
            let _ = runtime.block_on(russh::keys::agent::server::serve(listener, ()));
        });
        Agent { connections, runtime: rx.recv().expect("agent thread started") }
    })
}

/// A new connection to the built-in agent (it speaks the SSH agent protocol).
pub fn connect() -> DuplexStream {
    let (ours, theirs) = tokio::io::duplex(64 * 1024);
    let _ = agent().connections.send(theirs);
    ours
}

/// Whether the built-in agent holds any keys (then it is used instead of the system's).
pub fn has_keys() -> bool {
    KEYS.load(Ordering::Relaxed) > 0
}

fn with_client<T>(f: impl AsyncFnOnce(&mut AgentClient<DuplexStream>) -> Result<T, russh::keys::Error>) -> Result<T, String> {
    let agent = agent();
    agent.runtime.block_on(async {
        let mut client = AgentClient::connect(connect());
        f(&mut client).await.map_err(|e| e.to_string())
    })
}

pub fn add(key: &PrivateKey) -> Result<(), String> {
    with_client(async |c| c.add_identity(key, &[]).await)?;
    KEYS.fetch_add(1, Ordering::Relaxed);
    Ok(())
}

pub fn remove(key: &russh::keys::PublicKey) -> Result<(), String> {
    with_client(async |c| c.remove_identity(key).await)?;
    let _ = KEYS.try_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_sub(1));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use russh::keys::agent::AgentIdentity;

    #[test]
    fn holds_and_drops_keys() {
        let key = PrivateKey::random(&mut rand::rng(), russh::keys::Algorithm::Ed25519).unwrap();
        add(&key).unwrap();
        assert!(has_keys());
        let listed = with_client(async |c| c.request_identities().await).unwrap();
        assert!(listed.iter().any(|id| matches!(id, AgentIdentity::PublicKey { key: k, .. } if k == key.public_key())));
        remove(key.public_key()).unwrap();
        let listed = with_client(async |c| c.request_identities().await).unwrap();
        assert!(listed.is_empty());
        assert!(!has_keys());
    }
}
