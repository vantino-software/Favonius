// Favonius — high-performance file transfer over UDP
// Copyright (c) 2025-2026 Vantino SàRL
// SPDX-License-Identifier: Apache-2.0

//! End-to-end loopback transfers of sparse files with zero runs.
//!
//! Every arm byte-compares the destination with the source *and* asserts how
//! many chunks were skipped as holes: a byte-compare alone cannot tell "the
//! holes did not cross the wire" from "the feature was never on". The source
//! file's allocation is checked too, because reading a hole through a
//! mapping fills it in on tmpfs, which is where the temporary directory
//! usually is.

use ahp_cli::net_sender::{send_file, TransferStats};
use ahp_compression::CompressionProfile;
use ahp_congestion::CongestionProfile;
use ahp_proto::data::AckMode;
use std::io::{Seek, SeekFrom, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

/// A scratch directory that removes itself.
///
/// Deliberately hand-rolled: this workspace has no `tempfile` dependency,
/// and one test is a poor reason to add one.
struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Option<Self> {
        let dir = std::env::temp_dir()
            .join(format!("favonius-test-{tag}-{:016x}", rand::random::<u64>()));
        std::fs::create_dir_all(&dir).ok()?;
        Some(Scratch(dir))
    }
    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Find `n` consecutive free UDP ports by binding them all at once, then
/// releasing. Racy in principle — another process may take one in the
/// window — which is why the caller retries a few bases before giving up.
fn free_port_run(n: u16) -> Option<u16> {
    for _ in 0..32 {
        // A high, randomised base keeps concurrent test binaries (and the
        // developer's own daemon on 7801) out of each other's way.
        let base: u16 = 20_000 + (rand::random::<u16>() % 40_000);
        if base.checked_add(n).is_none() {
            continue;
        }
        let mut held = Vec::new();
        let mut ok = true;
        for i in 0..n {
            match std::net::UdpSocket::bind(("127.0.0.1", base + i)) {
                Ok(s) => held.push(s),
                Err(_) => {
                    ok = false;
                    break;
                }
            }
        }
        drop(held);
        if ok {
            return Some(base);
        }
    }
    None
}

struct Daemon {
    control: SocketAddr,
    // Held for its `Drop`: the destination files live here.
    _scratch: Scratch,
    dest_root: PathBuf,
}

/// Start a daemon on loopback. `data_ports` is how many *extra* contiguous
/// data ports to give it — 0 is a daemon with no `--data-port-range`, which
/// advertises no capability and is the compatibility case.
async fn start_daemon(data_ports: u16) -> Option<Daemon> {
    // control, data, then the range.
    let base = free_port_run(2 + data_ports)?;
    let control: SocketAddr = format!("127.0.0.1:{base}").parse().unwrap();
    let data: SocketAddr = format!("127.0.0.1:{}", base + 1).parse().unwrap();
    let range = (data_ports > 0).then(|| (base + 2, base + 1 + data_ports));

    let dir = Scratch::new("daemon")?;
    let dest_root = dir.path().to_path_buf();
    let root = dest_root.clone();
    tokio::spawn(async move {
        let _ = ahp_daemon::net_receiver::run_protocol_listener(
            control, data, 4, range, None, vec![root], None, Default::default(),
        )
        .await;
    });
    // The listener binds before it serves; a short settle is enough on
    // loopback and the sender retries HELLO for 30 s regardless.
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    Some(Daemon { control, _scratch: dir, dest_root })
}

/// Bytes the filesystem has allocated for `path`.
#[cfg(unix)]
fn allocated(path: &Path) -> u64 {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(path).unwrap().blocks() * 512
}

/// 32 MiB: 1 MiB of data, a hole, one byte at the end; plus a second data
/// island in the middle so there are two holes.
fn sparse_source(dir: &Path) -> (PathBuf, blake3::Hash) {
    let path = dir.join("thin.img");
    let size = 32u64 << 20;
    let mut f = std::fs::File::create(&path).unwrap();
    let head: Vec<u8> = (0..1u32 << 20).map(|i| i.wrapping_mul(2654435761) as u8).collect();
    f.write_all(&head).unwrap();
    f.seek(SeekFrom::Start(16 << 20)).unwrap();
    f.write_all(&head[..300_000]).unwrap();
    f.seek(SeekFrom::Start(size - 1)).unwrap();
    f.write_all(b"x").unwrap();
    drop(f);
    let hash = blake3::hash(&std::fs::read(&path).unwrap());
    (path, hash)
}

async fn send(
    daemon_control: SocketAddr,
    source: &Path,
    dest: &Path,
    encrypt: bool,
    compression: CompressionProfile,
    resume: bool,
) -> TransferStats {
    tokio::time::timeout(
        std::time::Duration::from_secs(120),
        send_file(
            daemon_control, source, dest.to_str().unwrap(),
            Some(CongestionProfile::Classic), AckMode::Bitmap, 4, "auto",
            encrypt, compression, resume, None, false, None, None, None, false,
        ),
    )
    .await
    .expect("transfer timed out")
    .expect("transfer failed")
}

fn same(dest: &Path, hash: blake3::Hash, label: &str) {
    let got = std::fs::read(dest).unwrap_or_else(|e| panic!("{label}: destination unreadable: {e}"));
    assert_eq!(blake3::hash(&got), hash, "{label}: destination differs from the source");
}

/// One function, deliberately: `FAVONIUS_ZERO_RUNS` is process-wide, so the
/// arm that declines cannot run in parallel with the others.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn holes_do_not_cross_the_wire() {
    let Some(daemon) = start_daemon(0).await else {
        eprintln!("skipping: no free ports on this machine");
        return;
    };
    let src_dir = Scratch::new("sparse-src").expect("scratch dir");
    let (source, hash) = sparse_source(src_dir.path());
    let holes = {
        let f = std::fs::File::open(&source).unwrap();
        ahp_cli::holes::holes(&f, 32 << 20)
    };
    if holes.is_empty() {
        eprintln!("skipping: the temporary filesystem does not report holes");
        return;
    }
    #[cfg(unix)]
    let src_allocated = allocated(&source);
    let total_chunks = (32u64 << 20).div_ceil(1350);

    // Plain.
    let dest = daemon.dest_root.join("plain.img");
    let stats = send(daemon.control, &source, &dest, false, CompressionProfile::None, false).await;
    same(&dest, hash, "plain");
    assert!(
        stats.zero_chunks_skipped > total_chunks * 9 / 10,
        "plain: only {} of {total_chunks} chunks skipped",
        stats.zero_chunks_skipped
    );
    assert!(stats.packets_sent < total_chunks / 5, "plain: {} packets sent", stats.packets_sent);
    #[cfg(unix)]
    {
        assert!(
            allocated(&source) <= src_allocated + (1 << 20),
            "sending filled the source in: {} allocated, was {src_allocated}",
            allocated(&source)
        );
        assert!(allocated(&dest) < 8 << 20, "the destination is not sparse: {}", allocated(&dest));
    }

    // Encryption and compression ride the same skip.
    let dest = daemon.dest_root.join("sealed.img");
    let stats = send(daemon.control, &source, &dest, true, CompressionProfile::ZstdBalanced, false).await;
    same(&dest, hash, "sealed");
    assert!(stats.zero_chunks_skipped > total_chunks * 9 / 10, "sealed: {}", stats.zero_chunks_skipped);

    // Resume onto an earlier copy whose holes hold stale bytes: the data is
    // right, but [2 MiB, 10 MiB) was written over since. The resume diff
    // finds those chunks differ, but they are zero runs and are not sent,
    // so the daemon has to zero those ranges itself or the stale bytes
    // survive.
    let dest = daemon.dest_root.join("resumed.img");
    let mut earlier = std::fs::read(&source).unwrap();
    earlier[2 << 20..10 << 20].fill(0xEE);
    std::fs::write(&dest, &earlier).unwrap();
    let stats = send(daemon.control, &source, &dest, false, CompressionProfile::None, true).await;
    same(&dest, hash, "resumed");
    assert!(stats.zero_chunks_skipped > 0, "resumed: no zero runs used");

    // Resume onto a same-size file that has nothing in common with the
    // source and no Merkle cache beside it. The daemon builds a tree from
    // what is there and the sender diffs against it; every chunk is
    // replaced, holes included.
    let dest = daemon.dest_root.join("stale.img");
    std::fs::write(&dest, vec![0xEEu8; 32 << 20]).unwrap();
    send(daemon.control, &source, &dest, false, CompressionProfile::None, true).await;
    same(&dest, hash, "stale");

    // A file that is one hole: nothing to send at all.
    let empty = src_dir.path().join("all-hole.img");
    std::fs::File::create(&empty).unwrap().set_len(10 << 20).unwrap();
    let empty_hash = blake3::hash(&vec![0u8; 10 << 20]);
    let dest = daemon.dest_root.join("all-hole.img");
    let stats = send(daemon.control, &empty, &dest, false, CompressionProfile::None, false).await;
    same(&dest, empty_hash, "all-hole");
    assert_eq!(stats.zero_chunks_skipped, (10u64 << 20).div_ceil(1350), "all-hole: every chunk is a hole");

    // The sender declines: everything is sent, and still arrives.
    std::env::set_var("FAVONIUS_ZERO_RUNS", "0");
    let dest = daemon.dest_root.join("declined.img");
    let stats = send(daemon.control, &source, &dest, false, CompressionProfile::None, false).await;
    std::env::remove_var("FAVONIUS_ZERO_RUNS");
    same(&dest, hash, "declined");
    assert_eq!(stats.zero_chunks_skipped, 0, "declined: runs were used anyway");
    assert!(stats.packets_sent >= total_chunks, "declined: {} packets for {total_chunks} chunks", stats.packets_sent);

    // The same stale resume without zero runs: the diff alone must catch
    // every chunk, the zeros of the holes included.
    std::env::set_var("FAVONIUS_ZERO_RUNS", "0");
    let dest = daemon.dest_root.join("stale-declined.img");
    std::fs::write(&dest, vec![0xEEu8; 32 << 20]).unwrap();
    send(daemon.control, &source, &dest, false, CompressionProfile::None, true).await;
    std::env::remove_var("FAVONIUS_ZERO_RUNS");
    same(&dest, hash, "stale-declined");
}
