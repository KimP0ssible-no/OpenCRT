//! Server load for the status bar: CPU, memory, disk and network of a Linux
//! host, read every few seconds over the tab's logged-in SSH connection.

use std::sync::mpsc::{Receiver, Sender};
use std::time::Instant;

use crate::ssh;

/// Prints the counters every 3 s, each reading after a `@@` line. Run through
/// `sh` so a login shell such as fish does not have to understand it.
const SCRIPT: &str = "exec sh -c 'while :; do echo @@; cat /proc/stat /proc/meminfo /proc/net/dev 2>/dev/null; df -P / 2>/dev/null | tail -n 1; sleep 3; done'";

/// What the status bar shows: percentages, and network bytes per second.
#[derive(Clone, Debug, PartialEq)]
pub struct Load {
    pub cpu: u32,
    pub memory: u32,
    pub disk: Option<u32>,
    pub down: u64,
    pub up: u64,
}

impl Load {
    pub fn text(&self) -> String {
        let disk = self.disk.map(|d| format!("  Disk {d}%")).unwrap_or_default();
        let rate = |b: u64| crate::sftp::human(b).replace(" bytes", " B");
        format!("CPU {}%  Mem {}%{disk}  \u{2193}{}/s \u{2191}{}/s", self.cpu, self.memory, rate(self.down), rate(self.up))
    }
}

/// One reading of the host's counters.
#[derive(Clone, Debug, Default, PartialEq)]
struct Sample {
    cpu_busy: u64,
    cpu_total: u64,
    mem_total: u64,
    mem_available: u64,
    disk: Option<u32>,
    rx: u64,
    tx: u64,
}

/// A reading from the script's output; None without a `cpu` line (no /proc: not Linux).
fn parse(block: &str) -> Option<Sample> {
    let mut s = Sample::default();
    let mut has_cpu = false;
    for line in block.lines() {
        let words: Vec<&str> = line.split_whitespace().collect();
        let num = |i: usize| words.get(i).and_then(|w| w.parse::<u64>().ok()).unwrap_or(0);
        match words.first().copied() {
            Some("cpu") => {
                // user nice system idle iowait irq softirq steal: idle and iowait are not busy.
                let all: Vec<u64> = (1..=8).map(num).collect();
                s.cpu_total = all.iter().sum();
                s.cpu_busy = s.cpu_total - all[3] - all[4];
                has_cpu = true;
            }
            Some("MemTotal:") => s.mem_total = num(1),
            Some("MemAvailable:") => s.mem_available = num(1),
            // `df -P /`: device, blocks, used, available, capacity, mount point.
            _ if words.len() == 6 && words[5] == "/" && words[4].ends_with('%') => s.disk = words[4].trim_end_matches('%').parse().ok(),
            _ => {
                // /proc/net/dev: `iface: rx_bytes ... (8 fields) tx_bytes ...`; loopback left out.
                if let Some((name, rest)) = line.split_once(':').map(|(n, r)| (n.trim(), r))
                    && !name.is_empty()
                    && !name.contains(' ')
                    && name != "lo"
                {
                    let fields: Vec<u64> = rest.split_whitespace().filter_map(|w| w.parse().ok()).collect();
                    if fields.len() >= 9 {
                        s.rx += fields[0];
                        s.tx += fields[8];
                    }
                }
            }
        }
    }
    has_cpu.then_some(s)
}

/// The load between two readings `secs` apart.
fn between(old: &Sample, new: &Sample, secs: f64) -> Load {
    let total = new.cpu_total.saturating_sub(old.cpu_total);
    let busy = new.cpu_busy.saturating_sub(old.cpu_busy);
    let pct = |part: u64, whole: u64| (part * 100).checked_div(whole).unwrap_or(0) as u32;
    let rate = |a: u64, b: u64| (b.saturating_sub(a) as f64 / secs.max(0.1)) as u64;
    Load {
        cpu: pct(busy, total),
        memory: pct(new.mem_total.saturating_sub(new.mem_available), new.mem_total),
        disk: new.disk,
        down: rate(old.rx, new.rx),
        up: rate(old.tx, new.tx),
    }
}

/// Readings for a tab; dropping it stops them within a few seconds.
pub struct Watch {
    pub loads: Receiver<Load>,
}

/// Start reading the load of the host behind `link`. The thread holds only the
/// channel, never the connection itself, so the tab can still close it. The
/// receiver disconnects when the host has no /proc or the connection ends.
pub fn watch(link: ssh::Link) -> Watch {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let Ok(runtime) = ssh::runtime() else { return };
        runtime.block_on(read(link, tx));
    });
    Watch { loads: rx }
}

async fn read(link: ssh::Link, tx: Sender<Load>) {
    let channel = match link.upgrade() {
        Some(session) => session.channel_open_session().await,
        None => return,
    };
    let Ok(mut channel) = channel else { return };
    if channel.exec(true, SCRIPT).await.is_err() {
        return;
    }
    let (mut text, mut last): (String, Option<(Sample, Instant)>) = (String::new(), None);
    // A reading comes every 3 s; ten silent seconds means a host that cannot run the script.
    while let Ok(Some(message)) = tokio::time::timeout(std::time::Duration::from_secs(10), channel.wait()).await {
        let russh::ChannelMsg::Data { data } = message else { continue };
        text.push_str(&String::from_utf8_lossy(&data));
        for block in complete_blocks(&mut text) {
            let Some(sample) = parse(&block) else { return };
            let now = Instant::now();
            if let Some((old, at)) = &last
                && tx.send(between(old, &sample, now.duration_since(*at).as_secs_f64())).is_err()
            {
                return;
            }
            last = Some((sample, now));
        }
    }
}

/// Take the readings that are whole (each ends where the next `@@` line
/// starts) out of `text`, leaving the one still arriving.
fn complete_blocks(text: &mut String) -> Vec<String> {
    let mut blocks = Vec::new();
    while let Some(start) = text.find("@@\n") {
        match text[start + 3..].find("@@\n") {
            Some(len) => {
                blocks.push(text[start + 3..start + 3 + len].to_string());
                text.drain(..start + 3 + len);
            }
            None => break,
        }
    }
    blocks
}

#[cfg(test)]
mod tests {
    use super::*;

    const READING: &str = "cpu  100 0 50 800 50 0 0 0 0 0
cpu0 50 0 25 400 25 0 0 0 0 0
MemTotal:        8000000 kB
MemFree:         1000000 kB
MemAvailable:    6000000 kB
Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo:  999999     10    0    0    0     0          0         0   999999     10    0    0    0     0       0          0
  eth0: 1000000    100    0    0    0     0          0         0   200000     50    0    0    0     0       0          0
/dev/sda1        41152736 29629584  9409616      76% /
";

    #[test]
    fn readings_are_split_as_they_arrive() {
        let mut text = String::from("@@\ncpu 1\n@@\ncpu");
        assert_eq!(complete_blocks(&mut text), ["cpu 1\n"]);
        assert_eq!(text, "@@\ncpu");
        text.push_str(" 2\n@@\n");
        assert_eq!(complete_blocks(&mut text), ["cpu 2\n"]);
        assert_eq!(complete_blocks(&mut text), Vec::<String>::new());
    }

    #[test]
    fn readings_parse_and_turn_into_load() {
        let first = parse(READING).unwrap();
        assert_eq!((first.cpu_busy, first.cpu_total, first.disk, first.rx, first.tx), (150, 1000, Some(76), 1_000_000, 200_000));
        // Three seconds later: 300 more ticks, 150 of them busy; 3 MB down, 300 KB up.
        let later = READING.replace("cpu  100 0 50 800 50", "cpu  200 0 100 950 50").replace("eth0: 1000000", "eth0: 4000000").replace("   200000     50", "   500000     50");
        let load = between(&first, &parse(&later).unwrap(), 3.0);
        assert_eq!(load, Load { cpu: 50, memory: 25, disk: Some(76), down: 1_000_000, up: 100_000 });
        assert_eq!(load.text(), "CPU 50%  Mem 25%  Disk 76%  \u{2193}976.6 KB/s \u{2191}97.7 KB/s");
        // A router's CLI or a BSD box has no /proc/stat.
        assert_eq!(parse("% Invalid input detected at '^' marker.\n"), None);
    }
}
