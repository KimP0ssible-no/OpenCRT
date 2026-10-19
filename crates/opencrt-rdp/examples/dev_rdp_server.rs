//! Local RDP server for trying OpenCRT's RDP tab. Not for real use.
//!
//!     cargo run --manifest-path crates/opencrt-rdp/Cargo.toml --target-dir target --example dev_rdp_server [port]
//!
//! Listens on 127.0.0.1 (default port 3390), user `demo`, password `demo`,
//! with NLA and a self-signed certificate kept in the temp folder. Shows a test
//! picture at the size the client asks for and prints the input it receives.

#[path = "../src/testserver.rs"]
mod testserver;

fn main() -> anyhow::Result<()> {
    let port: u16 = std::env::args().nth(1).map_or(Ok(3390), |p| p.parse())?;
    let (tx, rx) = std::sync::mpsc::channel();
    let dir = std::env::temp_dir().join("opencrt-dev-rdp");
    let port = testserver::start(([127, 0, 0, 1], port).into(), "demo", "demo", &dir, tx)?;
    println!("dev RDP server on 127.0.0.1:{port} (user demo, password demo)");
    for event in rx {
        println!("{event}");
    }
    Ok(())
}
