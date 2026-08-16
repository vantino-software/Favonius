// Favonius — high-performance file transfer over UDP
// Copyright (c) 2025-2026 Vantino SàRL
// SPDX-License-Identifier: Apache-2.0

//! End-to-end loopback transfers across a per-stream data port run.
//!
//! Per-stream data ports (Part 4a) split one transfer's streams across N
//! daemon sockets. That change lands in the **receive path**, where a
//! half-conversion loses bytes rather than throughput — so every arm here
//! byte-compares the destination against the source, and none of them
//! asserts anything about speed.
//!
//! The arms were a shell script in a scratch directory during development,
//! which is the same mistake as keeping a benchmark result there: it would
//! have disappeared with the session that wrote it. See
//! the project engineering log.

use ahp_cli::net_sender::send_file;
use ahp_compression::CompressionProfile;
use ahp_congestion::CongestionProfile;
use ahp_proto::data::AckMode;
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
            control, data, 4, range, None, Some(root), None, Default::default(),
        )
        .await;
    });
    // The listener binds before it serves; a short settle is enough on
    // loopback and the sender retries HELLO for 30 s regardless.
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    Some(Daemon { control, _scratch: dir, dest_root })
}

/// One transfer, byte-compared, with the number of destination ports it
/// actually used asserted.
///
/// `expect_ports` is not decoration. The first version of this test
/// asserted only that the bytes arrived, and it passed against a daemon
/// deliberately rewired to poll one socket while the sender split across
/// four — because the daemon's pool could not spare a run in the first
/// place, so no arm had ever exercised the split. A byte-compare cannot
/// tell "the feature worked" from "the feature was never on".
#[allow(clippy::too_many_arguments)]
async fn transfer(
    daemon: &Daemon,
    label: &str,
    source: &Path,
    src_hash: blake3::Hash,
    streams: u32,
    encrypt: bool,
    compression: CompressionProfile,
    header_protect: bool,
    expect_ports: usize,
) {
    let dest = daemon.dest_root.join(format!("{label}.bin"));
    let stats = tokio::time::timeout(
        std::time::Duration::from_secs(120),
        send_file(
            daemon.control,
            source,
            dest.to_str().unwrap(),
            Some(CongestionProfile::Classic),
            AckMode::Bitmap,
            streams,
            "auto",
            encrypt,
            compression,
            false,
            None,
            header_protect,
            None,
            None,
            false,
        ),
    )
    .await
    .unwrap_or_else(|_| panic!("{label}: transfer timed out"))
    .unwrap_or_else(|e| panic!("{label}: transfer failed: {e}"));

    assert_eq!(
        stats.data_ports, expect_ports,
        "{label}: expected {expect_ports} destination port(s), used {} — the split did not \
happen as intended, so whatever else this arm proves, it does not prove that",
        stats.data_ports
    );

    let written = std::fs::read(&dest)
        .unwrap_or_else(|e| panic!("{label}: destination unreadable: {e}"));
    assert_eq!(
        blake3::hash(&written),
        src_hash,
        "{label}: destination differs from source ({} bytes written, {} sent)",
        written.len(),
        stats.bytes_sent
    );
}

/// The whole matrix in one test function, deliberately.
///
/// `FAVONIUS_PER_STREAM_PORTS` is process-wide, so the arm that declines the
/// run cannot be a separate `#[test]` — cargo would run it in parallel with
/// the others in this binary and the env var would leak between them.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn per_stream_ports_transfer_every_byte() {
    // Small enough to stay quick on loopback, large enough to span many
    // chunks per stream: 4 MiB / 1414 B is ~2966 chunks over 4 streams.
    const SIZE: usize = 4 * 1024 * 1024;
    let payload: Vec<u8> = (0..SIZE).map(|i| (i as u32).wrapping_mul(2654435761) as u8).collect();
    let src_hash = blake3::hash(&payload);
    let src_dir = Scratch::new("src").expect("scratch dir");
    let source = src_dir.path().join("source.bin");
    std::fs::write(&source, &payload).expect("write source");

    // ── A daemon whose pool can actually spare a run ─────────────────────
    // 8 ports against a concurrency of 4: the allocator holds back one
    // socket per admission that might still happen, so a pool sized to the
    // concurrency yields no run at all. That is what silently defeated the
    // first version of this test.
    let Some(daemon) = start_daemon(8).await else {
        eprintln!("skipping: no free port run on this machine");
        return;
    };

    // Split active: 4 streams over 4 ports.
    transfer(&daemon, "split_plain", &source, src_hash, 4, false, CompressionProfile::None, false, 4).await;
    // Encryption and header protection ride the same split.
    transfer(&daemon, "split_encrypted", &source, src_hash, 4, true, CompressionProfile::None, true, 4).await;
    // Compression too — the receive path decompresses per chunk.
    transfer(&daemon, "split_compressed", &source, src_hash, 4, true, CompressionProfile::ZstdBalanced, false, 4).await;
    // Back-to-back with NO delay, which is the regression test for
    // returning the run when the receive thread joins.
    //
    // This arm used to need a 400 ms settle: the sockets came back only
    // when `handle_transfer` returned, i.e. after the whole-file hash and
    // writeback, while the sender had already left — the receive thread
    // answers FINISH before any of that. A transfer starting the instant
    // its predecessor's sender exited found the pool short and was given a
    // single socket. Nothing reads those sockets once the thread is
    // joined, so they go back there instead, and this arm gets its run
    // with no delay at all.
    transfer(&daemon, "split_again", &source, src_hash, 4, false, CompressionProfile::None, false, 4).await;
    // One stream: the degenerate case of the same mapping.
    transfer(&daemon, "split_one_stream", &source, src_hash, 1, false, CompressionProfile::None, false, 1).await;
    // MORE streams than ports. Streams past the end of the run share the
    // last port; if that mapping is wrong they vanish and this hangs.
    //
    // 4, not 12: one transfer may hold at most half the pool, so 8 ports
    // means a run of 4 however many streams ask for one. Two independent
    // limits meet here — the fairness cap and the daemon publishing a run
    // length before it knows `num_streams` — and both resolve by the
    // sender taking the minimum.
    transfer(&daemon, "split_many_streams", &source, src_hash, 12, false, CompressionProfile::None, false, 4).await;

    // `--congestion auto`: the profile is resolved after the probe from
    // the policy's per-link-type default, so the send path must survive
    // being handed no profile at all. On loopback that resolves to the
    // Loopback row; what it picks is the policy's business, that the
    // transfer completes is this test's.
    {
        let dest = daemon.dest_root.join("auto_congestion.bin");
        let stats = tokio::time::timeout(
            std::time::Duration::from_secs(120),
            send_file(
                daemon.control, &source, dest.to_str().unwrap(),
                None, // auto
                AckMode::Bitmap, 4, "auto", false, CompressionProfile::None,
                false, None, false, None, None, false,
            ),
        )
        .await
        .expect("auto: timed out")
        .expect("auto: transfer failed");
        let written = std::fs::read(&dest).expect("auto: destination unreadable");
        assert_eq!(blake3::hash(&written), src_hash, "auto: destination differs");
        assert_eq!(stats.data_ports, 4, "auto must not disturb the port split");
    }

    // ── The sender declines the run ──────────────────────────────────────
    // Same daemon, same binary, one socket — the control arm of the A/B
    // that shipped this, and the fallback if it ever misbehaves.
    std::env::set_var("FAVONIUS_PER_STREAM_PORTS", "0");
    transfer(&daemon, "declined_plain", &source, src_hash, 4, false, CompressionProfile::None, false, 1).await;
    transfer(&daemon, "declined_encrypted", &source, src_hash, 4, true, CompressionProfile::None, true, 1).await;
    std::env::remove_var("FAVONIUS_PER_STREAM_PORTS");

    // ── A daemon with no port range at all ───────────────────────────────
    // Advertises no capability, exactly like a daemon built before this
    // existed. The sender must fall back to the single data port.
    let Some(plain_daemon) = start_daemon(0).await else {
        eprintln!("skipping compat arm: no free port run");
        return;
    };
    transfer(&plain_daemon, "compat_plain", &source, src_hash, 4, false, CompressionProfile::None, false, 1).await;
    transfer(&plain_daemon, "compat_encrypted", &source, src_hash, 4, true, CompressionProfile::None, true, 1).await;
}

/// More senders than sockets: everyone still finishes.
///
/// This is the admission policy end-to-end. The daemon takes a data socket
/// *before* it starts a transfer, and a HELLO that cannot be given one is
/// declined — so the third sender here waits and retries rather than being
/// quietly put on the daemon's shared data socket, where it would have
/// stolen DATA from a transfer already running.
///
/// No env var is touched, so this is safe to run in parallel with the
/// matrix above.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn more_senders_than_sockets_all_complete() {
    const SIZE: usize = 2 * 1024 * 1024;
    let payload: Vec<u8> = (0..SIZE).map(|i| (i as u32).wrapping_mul(40503) as u8).collect();
    let src_hash = blake3::hash(&payload);
    let src_dir = Scratch::new("src-concurrent").expect("scratch dir");
    let source = src_dir.path().join("source.bin");
    std::fs::write(&source, &payload).expect("write source");

    // Two data ports, three senders. The cap is 1 socket per transfer at
    // this pool size, so two run at once and one is always waiting.
    let Some(daemon) = start_daemon(2).await else {
        eprintln!("skipping: no free port run on this machine");
        return;
    };

    // One OS thread with its own current-thread runtime per sender, which
    // is also what three `favonius send` processes are. `send_file`'s future
    // is not `Send` — the batched send backends hold raw pointers across
    // await points — so it cannot be `tokio::spawn`ed regardless.
    let mut handles = Vec::new();
    for i in 0..3 {
        let control = daemon.control;
        let dest = daemon.dest_root.join(format!("concurrent_{i}.bin"));
        let src = source.clone();
        handles.push(std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("runtime");
            let r = rt.block_on(async {
                tokio::time::timeout(
                    std::time::Duration::from_secs(180),
                    send_file(
                        control, &src, dest.to_str().unwrap(),
                        Some(CongestionProfile::Classic), AckMode::Bitmap, 2, "auto",
                        false, CompressionProfile::None, false, None, false, None, None, false,
                    ),
                )
                .await
            });
            match r {
                Err(_) => Err(format!("sender {i}: timed out waiting for a slot")),
                Ok(Err(e)) => Err(format!("sender {i}: {e}")),
                Ok(Ok(_)) => Ok((i, dest)),
            }
        }));
    }

    // Join off the async workers so the daemon keeps running while we wait.
    let results = tokio::task::spawn_blocking(move || {
        handles.into_iter().map(|h| h.join().expect("sender thread panicked")).collect::<Vec<_>>()
    })
    .await
    .expect("join task");

    for r in results {
        let (i, dest) = r.unwrap_or_else(|e| panic!("{e}"));
        let written = std::fs::read(&dest)
            .unwrap_or_else(|e| panic!("sender {i}: destination unreadable: {e}"));
        assert_eq!(
            blake3::hash(&written), src_hash,
            "sender {i}: destination differs from source"
        );
    }
}
