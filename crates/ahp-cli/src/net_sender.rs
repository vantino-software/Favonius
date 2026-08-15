// Favonius — high-performance file transfer over UDP
// Copyright (c) 2025-2026 Vantino SàRL
// SPDX-License-Identifier: Apache-2.0

//! AHP network file sender — UDP-based high-speed transfer.
//!
//! Sends a file directly to a remote favonius-daemon over UDP using the AHP
//! wire protocol (ahp-proto) and congestion-controlled reliability.
//!
//! Before transferring data, the sender probes the path to classify the link
//! (loopback, Ethernet LAN, WiFi LAN, WAN) and sets a minimum congestion
//! window floor so that WiFi jitter cannot collapse throughput.

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::path::Path;
use std::time::{Duration, Instant};

use bytes::Bytes;
use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;

// Linux-only imports for the specialized send paths (zero-copy sendmmsg,
// io_uring, AF_XDP, paced sendmsg). The cross-platform `Platform` variant
// of `PacketSender` does not need any of these — it goes through the
// `ahp-platform-net` trait.
#[cfg(target_os = "linux")]
use std::io::IoSlice;
#[cfg(target_os = "linux")]
use std::os::unix::io::AsRawFd;
#[cfg(target_os = "linux")]
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};
#[cfg(target_os = "linux")]
use std::sync::Arc;
#[cfg(target_os = "linux")]
use nix::sys::socket::{sendmmsg, MsgFlags, MultiHeaders, SockaddrStorage};

/// Cross-platform handle conversion for `ahp_platform_net::create_best_sender`.
#[cfg(unix)]
fn raw_socket_handle(s: &UdpSocket) -> ahp_platform_net::RawSocket {
    use std::os::unix::io::AsRawFd;
    s.as_raw_fd()
}

#[cfg(windows)]
fn raw_socket_handle(s: &UdpSocket) -> ahp_platform_net::RawSocket {
    use std::os::windows::io::AsRawSocket;
    s.as_raw_socket()
}

use ahp_compression::{CompressionProfile, zstd_impl::create_compressor};
use ahp_congestion::metrics::RttEstimator;
use ahp_congestion::{create_controller, AckInfo as CcAckInfo, CongestionController, CongestionProfile};
use ahp_crypto::control::{seal_control, CONTROL_TAG_LEN};
use ahp_crypto::header_protection::HeaderProtector;
use ahp_platform_net::{create_best_sender, PacketBatchSender};
use ahp_crypto::key_exchange::{generate_keypair, diffie_hellman};
use ahp_crypto::key_schedule::derive_session_keys;
use ahp_crypto::key_update::{KeyEpoch, encode_key_update};
use ahp_crypto::packet_protection::Aes256GcmProtector;
use ahp_crypto::session_ticket::{derive_resumed_keys, decode_ticket};
use ahp_crypto::{NonceGenerator, SessionKeys};
use ahp_policy::{AdaptivePolicy, NetworkContext, PolicyParams};
use ahp_proto::*;
use ahp_proto::data::{AckMode, DATA_PAYLOAD_HEADER_SIZE};
use socket2::SockRef;

use crate::net_probe::{self, NetworkProfile, TransferMetrics};

/// Default data payload per UDP packet (leaves room for IP/UDP headers + tunnels).
const DEFAULT_PAYLOAD: usize = 1350;
/// Maximum wire packet size.
const MAX_PACKET: usize = 1500;
/// Per-packet wire overhead: 42-byte header + 22-byte DataPayload header.
const WIRE_OVERHEAD: usize = HEADER_SIZE + DATA_PAYLOAD_HEADER_SIZE;

pub struct TransferStats {
    pub bytes_sent: u64,
    pub elapsed: Duration,
    pub packets_sent: u64,
    pub retransmits: u64,
    pub profile: NetworkProfile,
    /// The policy parameters that were actually used for this transfer (if adaptive).
    pub policy_params: Option<PolicyParams>,
    /// How many distinct daemon data ports this transfer sent to. 1 unless
    /// the daemon advertised a per-stream port run and the sender took it.
    ///
    /// Reported because the split is otherwise invisible from outside: a
    /// daemon whose pool cannot spare a run falls back to one socket and
    /// everything still works, just slower. An end-to-end test asserting
    /// only that the bytes arrived passed against a daemon that was
    /// deliberately broken, because it never noticed the split had silently
    /// not happened.
    pub data_ports: usize,
}

impl TransferStats {
    pub fn throughput_mbps(&self) -> f64 {
        if self.elapsed.as_secs_f64() > 0.0 {
            self.bytes_sent as f64 / self.elapsed.as_secs_f64() / (1024.0 * 1024.0)
        } else {
            0.0
        }
    }
}

/// File manifest exchanged during handshake.
#[derive(serde::Serialize, serde::Deserialize)]
pub struct FileManifest {
    pub file_name: String,
    pub file_size: u64,
    pub dest_path: String,
    pub payload_size: usize,
    pub total_chunks: u64,
    /// Acknowledgement mode: bitmap (default) or nack.
    #[serde(default = "default_ack_mode")]
    pub ack_mode: AckMode,
    /// Number of parallel streams (default 1 for backward compatibility).
    #[serde(default = "default_num_streams")]
    pub num_streams: u32,
    /// Whether DATA payloads are encrypted (AES-256-GCM).
    #[serde(default)]
    pub encrypted: bool,
    /// Whether DATA payloads are compressed (zstd).
    #[serde(default)]
    pub compressed: bool,
    /// Whether packet headers are protected (connection_id + packet_number masked).
    #[serde(default)]
    pub header_protected: bool,
    /// Resume mode: "none", "bitmap" (zero-check), "merkle" (tree diff).
    #[serde(default = "default_resume_mode")]
    pub resume_mode: String,
    /// BLAKE3 hash of the entire source file (hex string).
    #[serde(default)]
    pub file_hash: Option<String>,
    /// Merkle tree root hash (hex, 64 chars). Present when resume_mode = "merkle".
    #[serde(default)]
    pub merkle_root: Option<String>,
    /// Features the sender has selected for this transfer, as free-form
    /// tags. The other half of the capability handshake: the daemon
    /// advertises what it *can* do in HELLO_ACK (`capabilities`), and the
    /// sender states here what it *will* do.
    ///
    /// Free-form strings rather than a bitfield on purpose. This side needs
    /// no wire change to extend — the manifest is JSON with
    /// `#[serde(default)]` and no `deny_unknown_fields`, so an old daemon
    /// ignores tags it has never heard of and a new one ignores tags it no
    /// longer implements. A bitfield would have to keep bit assignments
    /// stable forever; a tag that disappears simply stops being sent.
    ///
    /// Empty is the correct default and means "nothing beyond the base
    /// protocol", which is what every existing peer implicitly says.
    ///
    /// A daemon MUST NOT fail a transfer because of an unrecognised tag. A
    /// tag that changes the wire format has to be gated on the matching
    /// HELLO_ACK capability bit, which the sender has already seen by the
    /// time it sends this — that ordering is the whole reason capabilities
    /// live in HELLO_ACK and selections live here.
    /// See the per-stream data ports section of the README.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub features: Vec<String>,
}

fn default_resume_mode() -> String { "none".into() }

fn default_ack_mode() -> AckMode {
    AckMode::Bitmap
}

fn default_num_streams() -> u32 {
    1
}

/// Upper bound on the adaptive retransmit timer. A pathological RTT
/// estimate must not park unacked chunks for minutes; the stall detector
/// aborts at 30 s of no progress, so the timer stays well inside that.
const RETX_TIMEOUT_MAX: Duration = Duration::from_secs(5);

/// Pacing debt a single batch-mode burst is allowed to accumulate before it
/// is flushed.
///
/// Batch mode stages packets, flushes them all in one syscall, then sleeps
/// for the pacing debt it just incurred. The burst size therefore sets how
/// bursty the send is, and the debt sets the average rate; only the second
/// was ever bounded. With `batch_size` at its 256 default, a burst is ~384
/// KB — larger than the entire bandwidth-delay product of a 100 Mbit
/// cross-country path (312 KB), so the burst alone overran a one-BDP
/// buffer no matter what average rate the following sleep implied.
///
/// Capping the burst by *time* rather than packet count makes the quantum
/// scale with the commanded rate: ~8 packets at 100 Mbit, the full batch at
/// 10 Gbit where GSO efficiency is what matters, and one packet at the
/// progress floor.
/// Sampling interval for `FAVONIUS_CC_DEBUG`. Short enough to resolve a
/// window collapse (the one under investigation happened inside a second)
/// without turning the log into the thing being measured.
const CC_DEBUG_INTERVAL: Duration = Duration::from_millis(200);

const PACING_BURST: Duration = Duration::from_millis(1);

/// Sweep override for `PACING_BURST`, in microseconds.
///
/// Every congestion-controller parameter has been swept against Model's
/// ~330 Mbit attractor — probe gain, cwnd gain, bandwidth filter window,
/// delivery window — and none of them moves it. That points at the send
/// path rather than the controller, and this is its one scale parameter:
/// each pass stages `PACING_BURST / pacing_interval` packets, flushes them
/// in one syscall, then waits out the debt. Fixed per-pass cost is
/// therefore amortised over a burst that scales with this value, so if the
/// ceiling is per-pass overhead the attractor must scale with it.
fn pacing_burst() -> Duration {
    static B: std::sync::OnceLock<Duration> = std::sync::OnceLock::new();
    *B.get_or_init(|| {
        std::env::var("FAVONIUS_PACING_BURST_US")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .filter(|u| *u >= 100 && *u <= 20000)
            .map(Duration::from_micros)
            .unwrap_or(PACING_BURST)
    })
}

/// Upper bound on a single batch-mode pacing sleep.
///
/// This was 2 ms and was the reason the pacer could not rate-limit at all:
/// a 256-packet burst at 100 Mbit owes ~30 ms and paid 2 ms of it, so the
/// lowest rate batch mode could enforce was ~1.5 Gbit/s. Every transfer
/// below that was governed by `cwnd` alone, which made the congestion
/// controller's rate command decorative. `PACING_BURST` now keeps the debt
/// near 1 ms on fast paths, so this bound only binds at very low rates,
/// where it must be large enough to express the 8-packets-per-RTT progress
/// floor (37.5 ms per packet at 300 ms RTT).
///
/// The wait is not a blocking sleep — the loop polls the socket and
/// processes feedback while it waits — so a long bound costs no
/// responsiveness.
const PACING_SLEEP_MAX: Duration = Duration::from_millis(50);

/// This thread's consumed CPU time, for telling work from waiting.
///
/// `flush` is the largest single bucket in `PROFILE_SUMMARY` — 53.6% of the
/// send loop on the LAN rig — and wall-clock time inside a syscall does not
/// say which it is. If the `sendmmsg`/GSO call is burning CPU (copy, GSO
/// segmentation, qdisc locking) that is work, and the send path is the
/// limit. If it is off-CPU, it is blocking on socket or driver backpressure,
/// which means **the kernel is already pacing this sender** — and that would
/// reframe the userspace pacer as largely redundant on such a path, which is
/// the cheapest available explanation for why removing 29% of its sleep
/// neither cost nor bought anything measurable (the engineering log).
///
/// Wall minus CPU is the off-CPU time. Nothing else in the profile can
/// separate those two.
#[cfg(target_os = "linux")]
fn thread_cpu_us() -> u64 {
    let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    // SAFETY: `ts` is a valid, fully-initialised timespec and the clock id is
    // a documented constant; the call only writes through the pointer.
    let rc = unsafe { libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, &mut ts) };
    if rc != 0 {
        return 0;
    }
    ts.tv_sec as u64 * 1_000_000 + ts.tv_nsec as u64 / 1_000
}

#[cfg(not(target_os = "linux"))]
fn thread_cpu_us() -> u64 {
    0
}

/// How far *behind* the paced schedule the sender may fall and still send
/// without waiting — the credit bound on the carried-debt path.
///
/// Expressed as one `pacing_burst()`, which is the control path's own
/// maximum burst envelope, so both arms are allowed to burst exactly as
/// hard as each other and the A/B isolates the carrying, not the burst
/// size. A first version used 50 ms, chosen as "one `PACING_SLEEP_MAX`"
/// without converting it to bytes: at the rates this actually commands that
/// is ~3.9 MB, about six times the congestion window, so the bound
/// saturated permanently and the arm measured "pacing off" rather than
/// "debt carried". A credit bound has to be stated in the units of the
/// thing it bounds.
fn pacing_credit_max() -> Duration {
    pacing_burst()
}

/// Chunk is currently sitting in `retx_queue` awaiting a resend. Prevents
/// the timeout scan from queueing the same chunk once per scan while it
/// waits behind a full window (see `queue_timed_out`).
const CHUNK_IN_RETX: u8 = 0b01;

/// Chunk has been (re)transmitted more than once, so an ACK for it cannot
/// be attributed to a particular transmission. Karn's algorithm: such a
/// chunk never yields an RTT sample again.
const CHUNK_RETRANSMITTED: u8 = 0b10;

/// Per-stream state for multi-stream multiplexing.
struct StreamState {
    /// Stream identifier (0..num_streams).
    id: u32,
    /// First global chunk index owned by this stream.
    chunk_base: u64,
    /// Total number of chunks in this stream.
    chunk_count: u64,
    /// Next unsent local chunk index (0..chunk_count).
    next_local: u64,
    /// Per local chunk: has this chunk been acked?
    acked: Vec<bool>,
    /// Number of acked chunks in this stream.
    n_acked: u64,
    /// Seconds since transfer start at which this stream's last chunk was
    /// acked. Streams are given a **fixed contiguous range of chunks up
    /// front** (`build_streams`) and there is no work stealing, so the
    /// transfer ends when the slowest stream ends, not when the average
    /// one does. If one stream draws more loss the others finish and idle
    /// while it straggles. That is a `max` over streams where the design
    /// wants a `mean`, and the spread between these timestamps is the cost.
    done_at: Option<f64>,
    /// Per local chunk: when was it last sent, in microseconds since the
    /// transfer start (wrapping u32 — wraps every ~71.6 minutes, harmless
    /// because every unacked chunk is re-stamped when it is retransmitted,
    /// on at most a `RETX_TIMEOUT_MAX` cadence, so live deltas are always
    /// far below the ~35.8 min unambiguous window). 4 B/chunk instead of
    /// the 16 B of an `Instant`:
    /// ~300 MB instead of ~1.2 GB per 100 GB file. Microsecond resolution
    /// keeps loopback RTT measurements (~40 µs) intact for the CC.
    sent_us: Vec<u32>,
    /// Per local chunk: `CHUNK_IN_RETX | CHUNK_RETRANSMITTED`. One byte per
    /// chunk rather than two `Vec<bool>`, matching the RSS budget `sent_us`
    /// is written to.
    flags: Vec<u8>,
    /// Oldest local chunk index that may still be unacked: every chunk
    /// below this cursor is acked, so the periodic retransmit scan starts
    /// here instead of sweeping the whole chunk space (~20 ms cadence).
    scan_cursor: u64,
    /// Next local chunk index to apply from the receiver's contiguous
    /// prefix (highest_contiguous) in an ACK bitmap. The prefix is
    /// monotonic per stream, so already-applied indices are never
    /// re-iterated — this keeps per-ACK work proportional to newly acked
    /// chunks instead of O(chunk_count).
    hc_applied: u64,
    /// Local chunk indices queued for retransmission.
    retx_queue: VecDeque<u64>,
}

impl StreamState {
    fn new(id: u32, chunk_base: u64, chunk_count: u64) -> Self {
        Self {
            id,
            chunk_base,
            chunk_count,
            next_local: 0,
            acked: vec![false; chunk_count as usize],
            n_acked: 0,
            done_at: None,
            sent_us: vec![0; chunk_count as usize],
            flags: vec![0; chunk_count as usize],
            scan_cursor: 0,
            hc_applied: 0,
            retx_queue: VecDeque::new(),
        }
    }

    /// Whether this stream has work: retransmits or unsent chunks.
    fn has_work(&self) -> bool {
        !self.retx_queue.is_empty() || self.next_local < self.chunk_count
    }

    /// Convert a local chunk index to a global chunk index.
    fn to_global(&self, local_ci: u64) -> u64 {
        self.chunk_base + local_ci
    }

    /// Mark a local chunk acked. Returns true if it was newly acked.
    /// Advances the retransmit scan cursor over any contiguous acked run.
    fn mark_acked(&mut self, local_ci: usize) -> bool {
        if local_ci >= self.acked.len() || self.acked[local_ci] {
            return false;
        }
        self.acked[local_ci] = true;
        self.n_acked += 1;
        while (self.scan_cursor as usize) < self.acked.len()
            && self.acked[self.scan_cursor as usize]
        {
            self.scan_cursor += 1;
        }
        true
    }

    /// RTT sample for a chunk being acked, or `None` if the chunk has ever
    /// been retransmitted.
    ///
    /// Karn's algorithm: once a chunk exists in more than one copy on the
    /// wire, an ACK for it cannot be attributed to a particular send, and
    /// `sent_us` holds only the most recent one. Measuring against that
    /// yields a sample bounded by the retransmit interval rather than by
    /// the path — on a link whose RTT exceeds that interval the estimator
    /// collapses to a fraction of the true RTT, which then shortens the
    /// retransmit timer further and sustains the storm that caused it.
    fn rtt_sample(&self, local_ci: usize, now_us: u32) -> Option<Duration> {
        if self.flags[local_ci] & CHUNK_RETRANSMITTED != 0 {
            return None;
        }
        // Floored at 1 µs: a same-microsecond send/ACK must not feed a
        // zero RTT into the CC's estimator.
        Some(Duration::from_micros(
            now_us.wrapping_sub(self.sent_us[local_ci]).max(1) as u64,
        ))
    }

    /// Queue sent-but-unacked chunks whose last send is older than
    /// `retx_timeout_us` for retransmission; returns their global chunk
    /// indices (the CC's packet number space). Scans only the unacked tail
    /// from `scan_cursor` — chunks below it are all acked by construction.
    ///
    /// A chunk already queued is skipped: when the window is full a chunk
    /// can wait in `retx_queue` for longer than a whole timeout interval,
    /// and re-queueing it there would push a second copy that the send
    /// loop dutifully transmits again. That also double-counts the chunk
    /// in the `total_retx_pending` correction the caller applies to
    /// `in_flight`, which then saturates low and over-admits sends.
    fn queue_timed_out(&mut self, now_us: u32, retx_timeout_us: u32) -> Vec<u64> {
        let sent_count = self.next_local.min(self.chunk_count);
        let mut lost = Vec::new();
        for li in self.scan_cursor.min(sent_count)..sent_count {
            let li_us = li as usize;
            if self.acked[li_us] || self.flags[li_us] & CHUNK_IN_RETX != 0 {
                continue;
            }
            if now_us.wrapping_sub(self.sent_us[li_us]) > retx_timeout_us {
                self.retx_queue.push_back(li);
                // Karn's algorithm: this chunk is about to exist in two
                // copies on the wire, so an ACK for it can no longer be
                // attributed to a known send time. Note the flag is set
                // here rather than at resend: the ACK for the *original*
                // transmission may well arrive while the retransmit is
                // still queued, and it is just as ambiguous.
                self.flags[li_us] |= CHUNK_IN_RETX | CHUNK_RETRANSMITTED;
                lost.push(self.to_global(li));
            }
        }
        lost
    }
}

/// Microseconds since the transfer start, truncated to a wrapping u32.
/// Wrapping is harmless: all timeout math uses `wrapping_sub` against
/// deltas that stay far below the ~35.8-minute unambiguous window (every
/// unacked chunk is re-stamped when it is retransmitted, and the timer
/// that triggers that is capped at `RETX_TIMEOUT_MAX`).
fn elapsed_us(t0: Instant) -> u32 {
    t0.elapsed().as_micros() as u32
}

/// Drop the mapping's page-table entries over `[offset, offset+len)` so the
/// pages stop counting toward this process's RSS. The range is aligned
/// inward to whole pages (madvise requires a page-aligned address).
///
/// SAFETY: MADV_DONTNEED on anonymous private mappings zero-fills on the
/// next access, which is why memmap2 gates this behind `UncheckedAdvice`.
/// This mapping is read-only file-backed (MAP_PRIVATE, never written), so
/// a discarded page re-faults from the page cache with identical contents.
#[cfg(target_os = "linux")]
fn drop_mapping_pages(map: &memmap2::Mmap, offset: usize, len: usize) {
    const PAGE: usize = 4096;
    let start = offset.next_multiple_of(PAGE);
    let end = offset.saturating_add(len).min(map.len()) & !(PAGE - 1);
    if end > start {
        let _ = unsafe {
            map.unchecked_advise_range(memmap2::UncheckedAdvice::DontNeed, start, end - start)
        };
    }
}

/// Stops and joins the page-cache prefetch thread on drop, on every
/// `send_file` exit path (normal, error, stall abort).
#[cfg(target_os = "linux")]
struct PrefetchGuard<'a> {
    stop: &'a AtomicBool,
    join: Option<std::thread::JoinHandle<()>>,
}

#[cfg(target_os = "linux")]
impl Drop for PrefetchGuard<'_> {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

/// Build per-stream states by splitting total_chunks into num_streams ranges.
fn build_streams(total_chunks: u64, num_streams: u32) -> Vec<StreamState> {
    // Defensive clamp: a zero here would divide by zero below (e.g. an empty
    // file yields total_chunks == 0, which clamps num_streams to 0 at the
    // call site).
    let ns = (num_streams as u64).max(1);
    let chunks_per_stream = total_chunks / ns;
    let remainder = total_chunks % ns;
    let mut streams = Vec::with_capacity(num_streams as usize);
    let mut base: u64 = 0;
    for i in 0..num_streams {
        let count = chunks_per_stream + if (i as u64) < remainder { 1 } else { 0 };
        streams.push(StreamState::new(i, base, count));
        base += count;
    }
    streams
}

/// Parse a remote destination string: `host:port:/path/on/remote`.
/// Parse `host:port:/path`, resolving `host` if it is a name.
///
/// This used to be `format!("{host}:{port}").parse::<SocketAddr>()`, which
/// accepts **only IPv4 literals**. `myhost.example.com:7801:/tmp/f` and
/// `localhost:7801:/tmp/f` were both rejected, while the error text told
/// the user the form was `host:port:/path` — so the one thing the message
/// invited was the one thing that could not work. Every example in the
/// README uses a bare IP, which is why it never surfaced internally.
///
/// IPv6 is parsed in bracket form (`[::1]:7801:/path`) and then **rejected
/// with a reason**, because the send path does not implement it: several
/// backends `panic!("IPv6 not yet supported")` on a `SocketAddr::V6`. A
/// clear refusal here is the difference between an error and a crash.
pub fn parse_remote_dest(dest: &str) -> Option<(SocketAddr, String)> {
    parse_remote_dest_detailed(dest).ok()
}

/// As `parse_remote_dest`, but says why it failed.
pub fn parse_remote_dest_detailed(dest: &str) -> Result<(SocketAddr, String), String> {
    // Bracketed IPv6 literal: [addr]:port:/path
    let (host, rest) = if let Some(stripped) = dest.strip_prefix('[') {
        let close = stripped
            .find(']')
            .ok_or_else(|| format!("unterminated '[' in '{dest}'"))?;
        let h = &stripped[..close];
        let after = &stripped[close + 1..];
        let after = after
            .strip_prefix(':')
            .ok_or_else(|| format!("expected ':' after ']' in '{dest}'"))?;
        (h.to_string(), after.to_string())
    } else {
        let c = dest
            .find(':')
            .ok_or_else(|| format!("expected host:port:/path, got '{dest}'"))?;
        (dest[..c].to_string(), dest[c + 1..].to_string())
    };

    let colon = rest
        .find(':')
        .ok_or_else(|| format!("expected host:port:/path, got '{dest}'"))?;
    let port_str = &rest[..colon];
    let path = &rest[colon + 1..];

    if !path.starts_with('/') {
        return Err(format!("destination path must be absolute, got '{path}'"));
    }
    let port: u16 = port_str
        .parse()
        .map_err(|_| format!("'{port_str}' is not a port number"))?;

    // A literal first, then a name lookup. `to_socket_addrs` handles both,
    // but doing the literal case explicitly keeps the common path free of
    // a resolver call.
    let candidates: Vec<SocketAddr> = if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        vec![SocketAddr::new(ip, port)]
    } else {
        use std::net::ToSocketAddrs;
        (host.as_str(), port)
            .to_socket_addrs()
            .map_err(|e| format!("cannot resolve '{host}': {e}"))?
            .collect()
    };

    if candidates.is_empty() {
        return Err(format!("'{host}' resolved to no addresses"));
    }
    // Prefer IPv4 when both are offered — it is the better-tested path and
    // the one every backend implements. Fall back to IPv6 where the
    // platform supports it.
    if let Some(a) = candidates.iter().find(|a| a.is_ipv4()) {
        return Ok((*a, path.to_string()));
    }
    match candidates.first() {
        // Linux sends through GSO, sendmmsg or the zero-copy path, all of
        // which take a `SockaddrStorage` and handle both families.
        // `--pacing iouring` is the exception and errors for itself.
        Some(a) if cfg!(target_os = "linux") => Ok((*a, path.to_string())),
        // macOS and Windows still build a concrete IPv4 sockaddr in their
        // send backends. Refusing here is what keeps that from being a
        // `panic!` deep in a send loop.
        Some(a) => Err(format!(
            "'{host}' resolves only to IPv6 ({a}); Favonius's IPv6 support is \
             Linux-only for now"
        )),
        None => Err(format!("'{host}' resolved to no addresses")),
    }
}

fn make_header(ptype: PacketType, conn_id: u64, seq: u64, plen: u32) -> PacketHeader {
    PacketHeader {
        version: PROTOCOL_VERSION,
        packet_type: ptype,
        flags: PacketFlags::ACK_ELICITING,
        header_length: HEADER_SIZE as u16,
        connection_id: conn_id,
        stream_id: 0,
        packet_number: seq,
        timestamp: timestamp_us(),
        payload_length: plen,
        header_crc: 0,
    }
}

fn timestamp_us() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_micros() as u64
}

// Note: the local `BatchSender` (sendmmsg) and `GsoBatchSender` types were
// removed during the platform-net refactor. Their functionality is now provided by
// `ahp_platform_net::create_best_sender`, which selects between Linux GSO,
// Linux sendmmsg, Windows USO, and macOS parallel sendmsg at runtime.
// The cross-platform path is reached via `PacketSender::Platform`.

// ═══════════════════════════════════════════════════════════════════════════
// Linux-only specialized senders below.
//
// On non-Linux targets, the `Platform` variant of `PacketSender` (backed by
// `ahp_platform_net::create_best_sender`) is the only available batched send
// path. The Zero-copy / io_uring / AF_XDP / Paced backends below depend on
// nix::sendmmsg, io_uring, ahp_xdp, /sys/class/net, etc., all of which are
// Linux-only. They are therefore gated out of the build entirely on
// Windows and macOS.
// ═══════════════════════════════════════════════════════════════════════════

// ═══════════════════════════════════════════════════════════════════════════
// Zero-copy batch sender: uses 2-iovec sendmmsg to avoid copying payload.
// iovec[0] = packet header (64 bytes, constructed in a small buffer)
// iovec[1] = payload data pointing directly into mmap'd file memory
// ═══════════════════════════════════════════════════════════════════════════

/// Zero-copy batch sender for unencrypted, uncompressed transfers.
///
/// Instead of copying file data into a contiguous batch buffer, each packet
/// uses two iovecs: a small header buffer and a direct pointer into the
/// mmap'd source file. This eliminates the per-packet payload copy.
#[cfg(target_os = "linux")]
struct ZeroCopyBatchSender {
    /// Per-packet header buffers (WIRE_OVERHEAD bytes each).
    headers: Vec<u8>,
    /// (header_offset, header_len, data_ptr, data_len) per packet.
    packets: Vec<(usize, usize, *const u8, usize)>,
    batch_capacity: usize,
    count: usize,
    raw_fd: std::os::unix::io::RawFd,
    dest: SockaddrStorage,
}

// Safety: the data pointers come from a mmap'd file that outlives the sender.
#[cfg(target_os = "linux")]
unsafe impl Send for ZeroCopyBatchSender {}

#[cfg(target_os = "linux")]
impl ZeroCopyBatchSender {
    fn new(socket: &UdpSocket, remote: SocketAddr, batch_capacity: usize) -> Self {
        let dest = SockaddrStorage::from(remote);
        Self {
            headers: vec![0u8; batch_capacity * WIRE_OVERHEAD],
            packets: Vec::with_capacity(batch_capacity),
            batch_capacity,
            count: 0,
            raw_fd: socket.as_raw_fd(),
            dest,
        }
    }

    /// Stage a packet with header constructed in our buffer and payload
    /// pointing directly into the source file memory.
    fn stage_data_zerocopy(
        &mut self,
        conn_id: u64,
        packet_number: u64,
        stream_id: u32,
        file_id: u64,
        chunk_index: u64,
        chunk_offset: u32,
        ts: u64,
        file_data_ptr: *const u8,
        file_data_len: usize,
    ) -> usize {
        use ahp_proto::data::DATA_PAYLOAD_HEADER_SIZE;
        use ahp_proto::header::PROTOCOL_VERSION;

        let hdr_offset = self.count * WIRE_OVERHEAD;
        let hdr_buf = &mut self.headers[hdr_offset..hdr_offset + WIRE_OVERHEAD];

        // Encode the 42-byte packet header.
        let payload_len = DATA_PAYLOAD_HEADER_SIZE + file_data_len;
        let hdr = ahp_proto::PacketHeader {
            version: PROTOCOL_VERSION,
            packet_type: ahp_proto::packet_type::PacketType::Data,
            flags: ahp_proto::flags::PacketFlags::ACK_ELICITING,
            header_length: HEADER_SIZE as u16,
            connection_id: conn_id,
            stream_id,
            packet_number,
            timestamp: ts,
            payload_length: payload_len as u32,
            header_crc: 0,
        };
        hdr.encode_into(&mut hdr_buf[..HEADER_SIZE]);

        // Encode the 22-byte DataPayload header.
        let dp = &mut hdr_buf[HEADER_SIZE..];
        dp[0..8].copy_from_slice(&file_id.to_be_bytes());
        dp[8..16].copy_from_slice(&chunk_index.to_be_bytes());
        dp[16..20].copy_from_slice(&chunk_offset.to_be_bytes());
        dp[20..22].copy_from_slice(&(file_data_len as u16).to_be_bytes());

        self.packets.push((hdr_offset, WIRE_OVERHEAD, file_data_ptr, file_data_len));
        self.count += 1;

        WIRE_OVERHEAD + file_data_len
    }

    /// Flush via sendmmsg with 2-iovec per packet (header + data).
    fn flush(&mut self) -> std::io::Result<usize> {
        if self.count == 0 {
            return Ok(0);
        }

        let mut total_sent = 0;
        let mut offset = 0;

        while offset < self.count {
            let remaining = self.count - offset;

            // Build 2-element iovec arrays: [header, payload] per packet.
            let slices: Vec<[IoSlice<'_>; 2]> = (offset..self.count)
                .map(|i| {
                    let (ho, hl, dp, dl) = self.packets[i];
                    [
                        IoSlice::new(&self.headers[ho..ho + hl]),
                        IoSlice::new(unsafe { std::slice::from_raw_parts(dp, dl) }),
                    ]
                })
                .collect();

            let addrs: Vec<Option<SockaddrStorage>> = vec![Some(self.dest); remaining];

            // sendmmsg with 2-element iovecs.
            let mut multi = MultiHeaders::<SockaddrStorage>::preallocate(remaining, None);

            match sendmmsg(
                self.raw_fd,
                &mut multi,
                &slices,
                &addrs,
                &[],
                MsgFlags::empty(),
            ) {
                Ok(result) => {
                    let sent = result.count();
                    total_sent += sent;
                    offset += sent;
                }
                Err(nix::errno::Errno::EAGAIN) => {
                    std::thread::sleep(Duration::from_micros(100));
                }
                Err(e) => {
                    self.count = 0;
                    self.packets.clear();
                    return Err(std::io::Error::from_raw_os_error(e as i32));
                }
            }
        }

        self.count = 0;
        self.packets.clear();
        Ok(total_sent)
    }

    fn is_full(&self) -> bool {
        self.count >= self.batch_capacity
    }

    fn pending(&self) -> usize {
        self.count
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// io_uring batch sender: submits sendmsg operations to io_uring SQ.
// Reduces syscall overhead by batching all sends into one io_uring_enter(2).
// ═══════════════════════════════════════════════════════════════════════════

/// io_uring-based batch sender. Stages packets into a contiguous buffer
/// (like BatchSender), then submits them via io_uring for async kernel
/// processing. This overlaps kernel send processing with userspace staging.
#[cfg(all(target_os = "linux", any(target_arch = "x86_64", target_arch = "aarch64")))]
struct IoUringBatchSender {
    /// Contiguous buffer for packet data.
    buf: Vec<u8>,
    /// Per-packet actual lengths.
    lengths: Vec<usize>,
    max_packet_size: usize,
    batch_capacity: usize,
    count: usize,
    raw_fd: std::os::unix::io::RawFd,
    dest_addr: libc::sockaddr_in,
    /// io_uring instance.
    ring: io_uring::IoUring,
    /// Pre-allocated msghdr + iovec storage for sendmsg SQEs.
    msghdrs: Vec<libc::msghdr>,
    iovecs: Vec<libc::iovec>,
}

#[cfg(all(target_os = "linux", any(target_arch = "x86_64", target_arch = "aarch64")))]
impl IoUringBatchSender {
    fn new(socket: &UdpSocket, remote: SocketAddr, batch_capacity: usize, max_packet_size: usize) -> std::io::Result<Self> {
        let ring = io_uring::IoUring::builder()
            .build(batch_capacity as u32)?;

        let dest_addr = match remote {
            SocketAddr::V4(v4) => {
                let mut addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
                addr.sin_family = libc::AF_INET as u16;
                addr.sin_port = v4.port().to_be();
                addr.sin_addr.s_addr = u32::from(*v4.ip()).to_be();
                addr
            }
            // io_uring is the one backend still IPv4-only: it stores a raw
            // `libc::sockaddr_in`, and v6 needs `sockaddr_in6` plus a
            // length field threaded through every SQE. GSO, sendmmsg and
            // the zero-copy path all take a `SockaddrStorage` and handle
            // both families, so this is a gap in an opt-in mode
            // (`--pacing iouring`) rather than in the default path.
            //
            // An error, not a panic: the caller can fall back.
            _ => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    "io_uring pacing does not support IPv6 yet — use --pacing auto",
                ))
            }
        };

        Ok(Self {
            buf: vec![0u8; batch_capacity * max_packet_size],
            lengths: vec![0usize; batch_capacity],
            max_packet_size,
            batch_capacity,
            count: 0,
            raw_fd: socket.as_raw_fd(),
            dest_addr,
            ring,
            msghdrs: vec![unsafe { std::mem::zeroed() }; batch_capacity],
            iovecs: vec![libc::iovec { iov_base: std::ptr::null_mut(), iov_len: 0 }; batch_capacity],
        })
    }

    fn stage_data(
        &mut self,
        conn_id: u64,
        packet_number: u64,
        stream_id: u32,
        file_id: u64,
        chunk_index: u64,
        chunk_offset: u32,
        ts: u64,
        data: &[u8],
    ) -> usize {
        let slot_offset = self.count * self.max_packet_size;
        let dst = &mut self.buf[slot_offset..slot_offset + self.max_packet_size];
        let n = encode_data_packet_into(dst, conn_id, packet_number, ts, stream_id, file_id, chunk_index, chunk_offset, data);
        self.lengths[self.count] = n;
        self.count += 1;
        n
    }

    /// Flush all staged packets via io_uring sendmsg SQEs.
    fn flush(&mut self) -> std::io::Result<usize> {
        if self.count == 0 {
            return Ok(0);
        }

        let n = self.count;

        // Prepare iovecs and msghdrs for each packet.
        for i in 0..n {
            let start = i * self.max_packet_size;
            let len = self.lengths[i];

            self.iovecs[i] = libc::iovec {
                iov_base: self.buf[start..].as_ptr() as *mut _,
                iov_len: len,
            };

            self.msghdrs[i] = unsafe { std::mem::zeroed() };
            self.msghdrs[i].msg_name = &self.dest_addr as *const _ as *mut _;
            self.msghdrs[i].msg_namelen = std::mem::size_of::<libc::sockaddr_in>() as u32;
            self.msghdrs[i].msg_iov = &mut self.iovecs[i];
            self.msghdrs[i].msg_iovlen = 1;
        }

        // Submit all sendmsg SQEs.
        for i in 0..n {
            let sqe = io_uring::opcode::SendMsg::new(
                io_uring::types::Fd(self.raw_fd),
                &self.msghdrs[i] as *const _,
            )
            .build()
            .user_data(i as u64);

            unsafe {
                let mut sq = self.ring.submission();
                if sq.push(&sqe).is_err() {
                    break; // SQ full
                }
            }
        }

        // Single io_uring_enter to submit + wait for all completions.
        self.ring.submit_and_wait(n)?;

        // Drain completion queue. We don't track a per-flush count here —
        // the kernel guarantees one CQE per submitted SQE after submit_and_wait
        // returns, so the caller's `n` is authoritative.
        for cqe in self.ring.completion() {
            if cqe.result() < 0 {
                tracing::debug!(result = cqe.result(), "io_uring sendmsg cqe error");
            }
        }

        self.count = 0;
        Ok(n)
    }

    fn is_full(&self) -> bool {
        self.count >= self.batch_capacity
    }

    fn pending(&self) -> usize {
        self.count
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// AF_XDP batch sender: bypasses kernel network stack via XDP sockets.
// Constructs complete Ethernet + IPv4 + UDP + AHP frames in UMEM and submits
// them to the NIC driver directly via the TX ring.
// ═══════════════════════════════════════════════════════════════════════════

/// AF_XDP batch sender. Requires root + XDP-capable interface.
#[cfg(target_os = "linux")]
struct XdpBatchSender {
    umem: ahp_xdp::umem::Umem,
    socket: ahp_xdp::socket::XdpSocket,
    builder: ahp_xdp::packet::PacketBuilder,
    /// Pending staged frames (frame_addr, total_len) not yet submitted to ring.
    staged: Vec<(u64, u32)>,
    batch_capacity: usize,
    count: usize,
}

#[cfg(target_os = "linux")]
impl XdpBatchSender {
    fn new(
        ifname: &str,
        src_ip: std::net::Ipv4Addr,
        dst_ip: std::net::Ipv4Addr,
        src_port: u16,
        dst_port: u16,
        batch_capacity: usize,
    ) -> Result<Self, ahp_xdp::error::XdpError> {
        let ifindex = get_ifindex(ifname)
            .ok_or_else(|| ahp_xdp::error::XdpError::Socket(format!("interface {ifname} not found")))?;

        let mut umem = ahp_xdp::umem::Umem::new(&ahp_xdp::umem::UmemConfig {
            frame_size: 4096,
            frame_count: 4096,
            fill_size: 2048,
            comp_size: 2048,
        })?;

        let socket = ahp_xdp::socket::XdpSocket::new(&mut umem, &ahp_xdp::socket::XdpSocketConfig {
            ifindex,
            queue_id: 0,
            tx_size: 2048,
            fill_size: 2048,
            comp_size: 2048,
            zero_copy: false,
        })?;

        let src_mac = ahp_xdp::packet::get_interface_mac(ifname).unwrap_or([0; 6]);
        let dst_mac = ahp_xdp::packet::resolve_mac(dst_ip);

        let builder = ahp_xdp::packet::PacketBuilder {
            src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port,
        };

        Ok(Self {
            umem, socket, builder,
            staged: Vec::with_capacity(batch_capacity),
            batch_capacity,
            count: 0,
        })
    }

    fn stage_data(
        &mut self,
        conn_id: u64,
        packet_number: u64,
        stream_id: u32,
        file_id: u64,
        chunk_index: u64,
        chunk_offset: u32,
        ts: u64,
        data: &[u8],
    ) -> usize {
        // Allocate a UMEM frame. If we're out, drain completions first.
        let frame_idx = match self.umem.alloc_frame() {
            Ok(idx) => idx,
            Err(_) => {
                // Drain completions to free frames.
                let addrs = self.socket.tx_complete();
                for addr in &addrs {
                    let idx = (*addr / self.umem.frame_size() as u64) as u32;
                    self.umem.free_frame(idx);
                }
                match self.umem.alloc_frame() {
                    Ok(idx) => idx,
                    Err(_) => {
                        // No frames even after draining completions — the
                        // packet is dropped here while the caller's CC
                        // accounting still counts it as sent. Never silent.
                        tracing::warn!("xdp: UMEM frames exhausted, staged packet dropped");
                        return 0;
                    }
                }
            }
        };

        let frame_addr = self.umem.frame_addr(frame_idx);
        let frame = match self.umem.frame_slice_mut(frame_idx) {
            Some(f) => f,
            None => {
                // alloc_frame only hands out in-bounds indices; treat a
                // violation as exhaustion rather than panicking.
                self.umem.free_frame(frame_idx);
                return 0;
            }
        };

        // Build AHP packet at offset 42 (after L2+L3+L4 headers).
        let ahp_start = ahp_xdp::packet::L2_L3_L4_OVERHEAD;
        let ahp_buf = &mut frame[ahp_start..];
        let ahp_len = encode_data_packet_into(
            ahp_buf, conn_id, packet_number, ts, stream_id, file_id, chunk_index, chunk_offset, data,
        );

        // Build L2/L3/L4 headers in front.
        let total_len = self.builder.build_headers_only(frame, ahp_len);

        self.staged.push((frame_addr, total_len as u32));
        self.count += 1;
        total_len
    }

    fn flush(&mut self) -> std::io::Result<usize> {
        if self.staged.is_empty() {
            return Ok(0);
        }
        let n = self.staged.len();
        for (addr, len) in self.staged.drain(..) {
            if let Err(e) = self.socket.tx_submit(addr, len) {
                // Submission failed (TX ring full) — the frame was never
                // handed to the kernel, so return it to the allocator.
                // Without this, repeated ring-full failures leak every UMEM
                // frame until alloc_frame permanently fails.
                let idx = (addr / self.umem.frame_size() as u64) as u32;
                self.umem.free_frame(idx);
                tracing::debug!(error = %e, "xdp tx_submit failed; frame returned to UMEM");
            }
        }
        self.count = 0;

        // Kick the kernel to process submitted frames.
        if let Err(e) = self.socket.tx_kick() {
            return Err(std::io::Error::new(std::io::ErrorKind::Other, e.to_string()));
        }

        // Drain some completions to free frames for next batch.
        let addrs = self.socket.tx_complete();
        for addr in &addrs {
            let idx = (addr / self.umem.frame_size() as u64) as u32;
            self.umem.free_frame(idx);
        }

        Ok(n)
    }

    fn is_full(&self) -> bool {
        self.count >= self.batch_capacity
    }

    fn pending(&self) -> usize {
        self.count
    }
}

#[cfg(target_os = "linux")]
fn get_ifindex(name: &str) -> Option<u32> {
    let path = format!("/sys/class/net/{}/ifindex", name);
    std::fs::read_to_string(&path).ok()?.trim().parse().ok()
}

// `probe_gso` and `GsoBatchSender` were removed during the platform-net refactor — both are
// now provided by `ahp_platform_net::linux` and reached via the `Platform`
// PacketSender variant.

/// Per-packet paced sender using a dedicated OS thread.
///
/// Each packet is sent individually via `sendmsg(2)` with precise inter-packet
/// timing controlled by busy-wait. This avoids the burst→queue→RTT-inflation
/// pattern of batch senders, matching UDT's microsecond-precision pacing.
///
/// Uses a shared ring buffer for zero-copy packet transfer between the tokio
/// task and the pacer thread — no per-packet allocation. Slot ownership is
/// tracked by `ring_states` (SLOT_*): the producer only writes a slot it has
/// claimed (FREE → WRITING), publishes it to the consumer (READY) only after
/// all writes including header transforms, and the consumer releases it
/// (SENDING → FREE) only after `sendmsg` has returned. A slot is therefore
/// never rewritten while the pacer thread could still be reading it.
#[cfg(target_os = "linux")]
struct PacedSender {
    /// Channel carries slot indices into the shared ring buffer.
    tx: crossbeam_channel::Sender<usize>,
    /// Shared ring buffer: slot_count × MAX_PACKET bytes.
    ring_buf: Arc<Vec<u8>>,
    /// Per-slot actual packet lengths.
    ring_lens: Arc<Vec<AtomicU64>>,
    /// Per-slot lifecycle state (SLOT_*); the recycling handshake described above.
    ring_states: Arc<Vec<AtomicU8>>,
    /// Number of slots in the ring.
    slot_count: usize,
    /// Next slot to write into.
    write_head: usize,
    /// Pacing interval in nanoseconds, updated atomically by the CC.
    pacing_nanos: Arc<AtomicU64>,
    /// Stop signal for the sender thread.
    stop: Arc<AtomicBool>,
    /// Thread handle for cleanup.
    thread_handle: Option<std::thread::JoinHandle<()>>,
}

/// Ring slot lifecycle states for `PacedSender` (see the struct docs).
#[cfg(target_os = "linux")]
const SLOT_FREE: u8 = 0; // producer may claim
#[cfg(target_os = "linux")]
const SLOT_WRITING: u8 = 1; // producer owns: encode + header transforms
#[cfg(target_os = "linux")]
const SLOT_READY: u8 = 2; // published to the consumer via the channel
#[cfg(target_os = "linux")]
const SLOT_SENDING: u8 = 3; // consumer owns: sendmsg in progress

#[cfg(target_os = "linux")]
impl PacedSender {
    fn new(socket: &UdpSocket, remote: SocketAddr, slot_count: usize) -> Self {
        let raw_fd = socket.as_raw_fd();
        let dest = SockaddrStorage::from(remote);
        let (tx, rx) = crossbeam_channel::bounded(slot_count);
        let pacing_nanos = Arc::new(AtomicU64::new(20_000)); // ~20μs default
        let stop = Arc::new(AtomicBool::new(false));

        // Shared ring buffer: zero-copy packet staging.
        let ring_buf = Arc::new(vec![0u8; slot_count * MAX_PACKET]);
        let ring_lens: Arc<Vec<AtomicU64>> = Arc::new(
            (0..slot_count).map(|_| AtomicU64::new(0)).collect()
        );
        let ring_states: Arc<Vec<AtomicU8>> = Arc::new(
            (0..slot_count).map(|_| AtomicU8::new(SLOT_FREE)).collect()
        );

        let rb = ring_buf.clone();
        let rl = ring_lens.clone();
        let rs = ring_states.clone();
        let pn = pacing_nanos.clone();
        let st = stop.clone();
        let thread_handle = std::thread::Builder::new()
            .name("favonius-pacer".into())
            .spawn(move || {
                Self::send_loop(rx, raw_fd, dest, rb, rl, rs, pn, st);
            })
            .expect("failed to spawn pacer thread");

        Self {
            tx,
            ring_buf,
            ring_lens,
            ring_states,
            slot_count,
            write_head: 0,
            pacing_nanos,
            stop,
            thread_handle: Some(thread_handle),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn send_loop(
        rx: crossbeam_channel::Receiver<usize>,
        raw_fd: std::os::unix::io::RawFd,
        dest: SockaddrStorage,
        ring_buf: Arc<Vec<u8>>,
        ring_lens: Arc<Vec<AtomicU64>>,
        ring_states: Arc<Vec<AtomicU8>>,
        pacing_nanos: Arc<AtomicU64>,
        stop: Arc<AtomicBool>,
    ) {
        let slot_size = MAX_PACKET;
        let mut next_send = Instant::now();

        while !stop.load(Ordering::Relaxed) {
            let slot = match rx.recv_timeout(Duration::from_millis(5)) {
                Ok(s) => s,
                Err(crossbeam_channel::RecvTimeoutError::Timeout) => continue,
                Err(crossbeam_channel::RecvTimeoutError::Disconnected) => break,
            };

            // Claim the slot for reading. The producer published it with a
            // Release store to SLOT_READY before queueing the index, so this
            // Acquire CAS also makes the packet bytes visible here.
            if ring_states[slot]
                .compare_exchange(SLOT_READY, SLOT_SENDING, Ordering::Acquire, Ordering::Relaxed)
                .is_err()
            {
                continue; // stale index — cannot happen, but never read an unowned slot
            }

            let len = ring_lens[slot].load(Ordering::Relaxed) as usize;
            let offset = slot * slot_size;
            let pkt_data = &ring_buf[offset..offset + len];

            // Busy-wait until the target send time.
            let now = Instant::now();
            if next_send > now {
                let wait = next_send - now;
                if wait > Duration::from_micros(100) {
                    std::thread::sleep(wait.saturating_sub(Duration::from_micros(50)));
                }
                while Instant::now() < next_send {
                    std::hint::spin_loop();
                }
            }

            // Send one packet.
            let iov = [IoSlice::new(pkt_data)];
            loop {
                match nix::sys::socket::sendmsg::<SockaddrStorage>(
                    raw_fd,
                    &iov,
                    &[],
                    MsgFlags::MSG_DONTWAIT,
                    Some(&dest),
                ) {
                    Ok(_) => break,
                    Err(nix::errno::Errno::EAGAIN) => {
                        std::hint::spin_loop();
                        continue;
                    }
                    Err(_) => break,
                }
            }

            // Release the slot back to the producer: its next Acquire CAS on
            // this slot happens-after every read above (sendmsg has returned),
            // so it can never overwrite bytes we are still sending.
            ring_states[slot].store(SLOT_FREE, Ordering::Release);

            // Advance the target send time.
            let interval_ns = pacing_nanos.load(Ordering::Relaxed);
            next_send = Instant::now() + Duration::from_nanos(interval_ns);
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn stage_and_send(
        &mut self,
        conn_id: u64,
        packet_number: u64,
        stream_id: u32,
        file_id: u64,
        chunk_index: u64,
        chunk_offset: u32,
        ts: u64,
        data: &[u8],
        transforms: HeaderTransforms<'_>,
    ) -> usize {
        let slot = self.write_head;
        self.write_head = (self.write_head + 1) % self.slot_count;

        // Claim the slot. It is recycled only via the consumer's Release
        // store to SLOT_FREE after sendmsg returns; this Acquire CAS pairs
        // with it, so no pacer-thread read can still be in flight on the
        // bytes we are about to overwrite. If the slot is still owned by the
        // consumer the packet is dropped — the same backpressure outcome as
        // a full channel (the CC retransmits it on timeout).
        if self.ring_states[slot]
            .compare_exchange(SLOT_FREE, SLOT_WRITING, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            return 0;
        }

        let offset = slot * MAX_PACKET;
        // Safety: the CAS above gives this thread exclusive ownership of the
        // slot (state WRITING). The consumer only reads a slot after
        // observing SLOT_READY (stored below, after all writes) and holds it
        // until its sendmsg completes, so no other thread can touch these
        // bytes while we write them.
        let dst = unsafe {
            let ptr = (self.ring_buf.as_ptr() as *mut u8).add(offset);
            std::slice::from_raw_parts_mut(ptr, MAX_PACKET)
        };
        let n = encode_data_packet_into(
            dst, conn_id, packet_number, ts,
            stream_id, file_id, chunk_index, chunk_offset, data,
        );
        // Header transforms (header protection, per-packet flags) are applied
        // BEFORE publishing, so the pacer thread can never observe a
        // half-transformed header. This also makes the post-stage mutation
        // hooks (`protect_last_packet_header` / `set_last_packet_flag`)
        // no-ops for this backend.
        transforms.apply(&mut dst[..n]);
        self.ring_lens[slot].store(n as u64, Ordering::Relaxed);
        // Publish: the Release store pairs with the consumer's Acquire CAS,
        // making the packet bytes and length visible to it.
        self.ring_states[slot].store(SLOT_READY, Ordering::Release);

        // Hand the slot index to the pacer thread. On backpressure (channel
        // full) the index never reaches the consumer, so reclaim the slot
        // immediately; the caller treats the packet as lost.
        if self.tx.try_send(slot).is_err() {
            self.ring_states[slot].store(SLOT_FREE, Ordering::Release);
        }
        n
    }

    fn set_pacing_interval(&self, interval: Duration) {
        self.pacing_nanos.store(interval.as_nanos() as u64, Ordering::Relaxed);
    }

    fn is_full(&self) -> bool {
        self.tx.is_full()
    }
}

#[cfg(target_os = "linux")]
impl Drop for PacedSender {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(h) = self.thread_handle.take() {
            let _ = h.join();
        }
    }
}

/// Unified sender: per-packet paced, cross-platform batch, or specialized backends.
///
/// `Platform` is the cross-platform default — delegates to one of the
/// `ahp-platform-net` backends (Linux GSO/sendmmsg, Windows USO, macOS
/// parallel sendmsg). The other variants are Linux-only specializations
/// that bypass the trait abstraction for direct buffer manipulation.
enum PacketSender {
    /// Cross-platform batched sender (Linux GSO/sendmmsg, Windows USO, macOS parallel sendmsg).
    /// Second field is a reusable scratch buffer for packet encoding.
    Platform(Box<dyn PacketBatchSender>, Vec<u8>),
    #[cfg(target_os = "linux")]
    Paced(PacedSender),
    #[cfg(target_os = "linux")]
    ZeroCopy(ZeroCopyBatchSender),
    #[cfg(all(target_os = "linux", any(target_arch = "x86_64", target_arch = "aarch64")))]
    IoUring(IoUringBatchSender),
    #[cfg(target_os = "linux")]
    Xdp(XdpBatchSender),
}

/// One line of advice when a transfer lost enough packets to matter and the
/// controller in use treats loss as congestion.
///
/// Measured 2026-08-13 on a 38 ms path with 1% injected loss: the
/// rate-based profiles beat `classic` by 22-27% (`model` 106.5,
/// `cycle` 106.2, `wifi` 102.6 against `classic`'s 84.0 MB/s), and
/// `cycle` did it at cv 1.2% against classic's 18.2%. Nothing told the
/// user, so the default quietly cost a fifth of the throughput on any
/// lossy path.
///
/// It does **not** say "switch". Which profile is right depends on where
/// the loss comes from, and the probe cannot tell random loss from
/// congestion loss (measured; see the congestion-control notes): `classic` wins the congested cells
/// precisely because it backs off, and a sender that ignores loss on a
/// shared uplink is an unfriendly neighbour rather than a fast one. The
/// user knows whether their link is a satellite or an office uplink; this
/// gives them the number and the discriminator and lets them decide.
///
/// Returns `None` when there is nothing useful to say — below the
/// threshold, or already on a profile that tolerates loss.
fn loss_advice(retransmits: u64, packets_sent: u64, cc: CongestionProfile) -> Option<String> {
    /// Retransmit share below which this is noise, not a lossy path. A
    /// clean WAN measures 0.0-0.5% (measured).
    const HINT_THRESHOLD: f64 = 0.01;
    if packets_sent == 0 {
        return None;
    }
    if !matches!(cc, CongestionProfile::Classic | CongestionProfile::Udt) {
        return None;
    }
    let rate = retransmits as f64 / packets_sent as f64;
    if rate < HINT_THRESHOLD {
        return None;
    }
    Some(format!(
        "note: {:.1}% of packets were retransmitted. If this path drops packets at random \
(satellite, radio, a lossy tunnel), `--congestion cycle` measured about 25% faster than {} on a \
1% loss path. If the loss is congestion from a shared link, {} is the better neighbour and \
the right choice.",
        rate * 100.0,
        cc,
        cc,
    ))
}

/// Build the AEAD associated data for an encrypted DATA packet: the 42-byte
/// fixed header exactly as it will appear on the wire AFTER per-packet flag
/// mutation (e.g. COMPRESSED, OR-ed into bytes [2..4] post-encode) but
/// BEFORE header protection masks connection_id / packet_number.
///
/// The receiver recomputes the same bytes from the wire packet after HP
/// removal, so both sides authenticate the *logical* header (RFC §14.4):
/// stream_id, connection_id, key-phase/flags and connection routing fields
/// are integrity-protected, and flipping any of them fails the GCM tag
/// check instead of silently misrouting decrypted data into the wrong
/// stream. The header CRC covers the final post-flag bytes — mirroring the
/// wire, where the CRC is refreshed after the flag mutation.
fn data_header_aad(
    conn_id: u64,
    packet_number: u64,
    stream_id: u32,
    timestamp: u64,
    payload_len: usize,
    extra_flags: u16,
) -> [u8; HEADER_SIZE] {
    let hdr = PacketHeader {
        version: PROTOCOL_VERSION,
        packet_type: PacketType::Data,
        flags: PacketFlags::ACK_ELICITING,
        header_length: HEADER_SIZE as u16,
        connection_id: conn_id,
        stream_id,
        packet_number,
        timestamp,
        payload_length: payload_len as u32,
        header_crc: 0,
    };
    let mut aad = [0u8; HEADER_SIZE];
    hdr.encode_into(&mut aad);
    if extra_flags != 0 {
        let cur = u16::from_be_bytes([aad[2], aad[3]]);
        aad[2..4].copy_from_slice(&(cur | extra_flags).to_be_bytes());
        // The receiver authenticates the wire header including its CRC
        // field, which now covers the mutated flags — match it.
        update_crc(&mut aad);
    }
    aad
}

/// Final header transformations applied to an encoded packet before it goes
/// on the wire: header protection (masking connection_id and packet_number)
/// and per-packet flag updates (e.g. COMPRESSED).
///
/// Backends that support post-stage mutation apply these via
/// `modify_last_packet` after staging (`protect_last_packet_header` /
/// `set_last_packet_flag`). Backends that don't (macOS parallel sendmsg)
/// dispatch staged packets to worker threads immediately, so `stage_data`
/// applies them to the encoded bytes before `stage()` when
/// `supports_post_stage_mutation()` is false. Both paths run the same
/// operations in the same order — flags first (with a header CRC refresh),
/// then header protection — on byte-identical buffers (the payload is
/// encrypted before staging in both cases), so the wire bytes are identical
/// either way.
///
/// Order rationale: the header CRC must cover the final on-wire flag bits,
/// and it is computed over the *unprotected* header because the receiver
/// validates the CRC after HP removal. HP masks only the connection_id and
/// packet_number fields — never the flags or CRC bytes — so refreshing the
/// CRC before masking yields wire bytes a CRC-validating receiver accepts.
#[derive(Clone, Copy, Default)]
struct HeaderTransforms<'a> {
    /// Header protector, if header protection is enabled for this packet.
    /// Built once per key epoch by the caller — constructing a
    /// `HeaderProtector` per packet would pay an AES-128 key schedule each
    /// time.
    hp: Option<&'a HeaderProtector>,
    /// Flags to OR into the header flags field (bytes [2..4]).
    flags: u16,
}

impl HeaderTransforms<'_> {
    fn apply(&self, pkt: &mut [u8]) {
        if self.flags != 0 && pkt.len() >= HEADER_SIZE {
            let cur = u16::from_be_bytes([pkt[2], pkt[3]]);
            pkt[2..4].copy_from_slice(&(cur | self.flags).to_be_bytes());
            // The encode-time CRC does not cover the flags just OR-ed in.
            update_crc(&mut pkt[..HEADER_SIZE]);
        }
        if let Some(hp) = self.hp {
            if pkt.len() >= HEADER_SIZE {
                hp.protect(pkt, HEADER_SIZE);
            }
        }
    }
}

impl PacketSender {
    /// Linux-only. Every caller is inside the `cfg(target_os = "linux")`
    /// sender-selection block — the specialised backends fall back through
    /// here. Other targets construct `new_inner` directly, so without this
    /// gate the function is dead code there and `-D warnings` fails the
    /// build.
    #[cfg(target_os = "linux")]
    fn new(
        socket: &UdpSocket,
        remote: SocketAddr,
        batch_capacity: usize,
        segment_size: usize,
        max_packet_size: usize,
        use_paced: bool,
    ) -> Self {
        Self::new_inner(socket, remote, batch_capacity, segment_size, max_packet_size, use_paced, true)
    }

    /// `announce` prints the selected backend. A per-stream port run builds
    /// one sender per destination, all resolving the same backend, so only
    /// the first says so.
    fn new_inner(
        socket: &UdpSocket,
        remote: SocketAddr,
        batch_capacity: usize,
        segment_size: usize,
        #[cfg_attr(not(target_os = "linux"), allow(unused_variables))]
        max_packet_size: usize,
        #[cfg_attr(not(target_os = "linux"), allow(unused_variables))]
        use_paced: bool,
        announce: bool,
    ) -> Self {
        #[cfg(target_os = "linux")]
        {
            if use_paced {
                if announce {
                    eprintln!("  Pacing: per-packet (dedicated thread)");
                }
                return PacketSender::Paced(PacedSender::new(socket, remote, 1024));
            }
        }

        // Defer backend selection (GSO vs sendmmsg vs USO vs parallel-sendmsg)
        // to ahp-platform-net's create_best_sender. The capacity is capped at
        // (65535 / segment_size) so a single GSO/USO submission stays under
        // the IP-fragmentation limit on backends that use segmentation offload.
        let cap = (65535 / segment_size).min(batch_capacity);
        let inner = create_best_sender(raw_socket_handle(socket), remote, cap, segment_size);
        if announce {
            eprintln!("  Backend: {} (capacity={}, segment_size={})", inner.name(), cap, segment_size);
        }
        // The scratch buffer is sized for the largest packet we may encode.
        // On non-Linux this constant is the same; suppress the unused warning.
        #[cfg(target_os = "linux")]
        let scratch = vec![0u8; max_packet_size];
        #[cfg(not(target_os = "linux"))]
        let scratch = vec![0u8; MAX_PACKET];
        PacketSender::Platform(inner, scratch)
    }

    fn stage_data(
        &mut self,
        conn_id: u64,
        packet_number: u64,
        stream_id: u32,
        file_id: u64,
        chunk_index: u64,
        chunk_offset: u32,
        ts: u64,
        data: &[u8],
        transforms: HeaderTransforms<'_>,
    ) -> usize {
        match self {
            PacketSender::Platform(s, scratch) => {
                // Encode the AHP packet into the scratch buffer, then hand it
                // off to the platform backend (which will copy it into its own
                // contiguous buffer for batched submission).
                let n = encode_data_packet_into(
                    scratch, conn_id, packet_number, ts, stream_id, file_id, chunk_index, chunk_offset, data,
                );
                // Backends without post-stage mutation (macOS parallel
                // sendmsg) cannot be fixed up after staging, so header
                // protection and per-packet flags are applied to the encoded
                // bytes here — the payload is already encrypted, so the HP
                // ciphertext sample is in place and the result is identical
                // to the post-stage path.
                if !s.supports_post_stage_mutation() {
                    transforms.apply(&mut scratch[..n]);
                }
                let _ = s.stage(&scratch[..n]).expect("platform sender stage failed");
                n
            }
            #[cfg(target_os = "linux")]
            PacketSender::Paced(s) => s.stage_and_send(conn_id, packet_number, stream_id, file_id, chunk_index, chunk_offset, ts, data, transforms),
            #[cfg(target_os = "linux")]
            PacketSender::ZeroCopy(s) => s.stage_data_zerocopy(conn_id, packet_number, stream_id, file_id, chunk_index, chunk_offset, ts, data.as_ptr(), data.len()),
            #[cfg(target_os = "linux")]
            #[cfg(all(target_os = "linux", any(target_arch = "x86_64", target_arch = "aarch64")))]
            PacketSender::IoUring(s) => s.stage_data(conn_id, packet_number, stream_id, file_id, chunk_index, chunk_offset, ts, data),
            #[cfg(target_os = "linux")]
            PacketSender::Xdp(s) => s.stage_data(conn_id, packet_number, stream_id, file_id, chunk_index, chunk_offset, ts, data),
        }
    }

    /// Apply header protection (mask connection_id + packet_number) to the
    /// last staged packet. Must be called AFTER staging and encryption.
    fn protect_last_packet_header(&mut self, hp: &HeaderProtector) {
        match self {
            PacketSender::Platform(s, _) => {
                // Delegate the in-place mutation to the trait — backends that
                // buffer contiguously (Linux GSO/sendmmsg, Windows USO) hand
                // back a slice into their internal buffer; async backends
                // (macOS parallel sendmsg) return false here, in which case
                // `stage_data` has already applied the transform pre-stage.
                s.modify_last_packet(&mut |pkt: &mut [u8]| {
                    HeaderTransforms { hp: Some(hp), flags: 0 }.apply(pkt);
                });
            }
            #[cfg(target_os = "linux")]
            PacketSender::Paced(_) => {
                // Paced: header protection is applied inside `stage_and_send`
                // before the slot is published to the pacer thread — mutating
                // the ring here would race with an in-flight sendmsg.
            }
            #[cfg(target_os = "linux")]
            PacketSender::ZeroCopy(_) => {} // Zero-copy mode is unencrypted — no header protection.
            #[cfg(target_os = "linux")]
            #[cfg(all(target_os = "linux", any(target_arch = "x86_64", target_arch = "aarch64")))]
            PacketSender::IoUring(s) => {
                if s.count > 0 {
                    let off = (s.count - 1) * s.max_packet_size;
                    let len = s.lengths[s.count - 1];
                    if len >= HEADER_SIZE {
                        hp.protect(&mut s.buf[off..off + len], HEADER_SIZE);
                    }
                }
            }
            #[cfg(target_os = "linux")]
            PacketSender::Xdp(_) => {} // XDP mode is unencrypted.
        }
    }

    /// OR a flag into the last staged packet's header flags field.
    /// Used to set COMPRESSED per-packet after staging. The header CRC is
    /// refreshed so it covers the mutated flags (see `HeaderTransforms`).
    fn set_last_packet_flag(&mut self, flag: u16) {
        match self {
            PacketSender::Platform(s, _) => {
                // Async backends (macOS parallel sendmsg) return false here,
                // in which case `stage_data` has already applied the flag
                // pre-stage.
                s.modify_last_packet(&mut |pkt: &mut [u8]| {
                    HeaderTransforms { hp: None, flags: flag }.apply(pkt);
                });
            }
            #[cfg(target_os = "linux")]
            PacketSender::Paced(_) => {
                // Paced: flags are applied inside `stage_and_send` before the
                // slot is published to the pacer thread — mutating the ring
                // here would race with an in-flight sendmsg.
            }
            #[cfg(target_os = "linux")]
            PacketSender::ZeroCopy(s) => {
                // Zero-copy is only selected for uncompressed transfers, so
                // this arm is unreachable in practice — keep it correct anyway.
                if s.count > 0 {
                    let base = (s.count - 1) * WIRE_OVERHEAD;
                    let off = base + 2;
                    let cur = u16::from_be_bytes([s.headers[off], s.headers[off + 1]]);
                    s.headers[off..off + 2].copy_from_slice(&(cur | flag).to_be_bytes());
                    update_crc(&mut s.headers[base..base + HEADER_SIZE]);
                }
            }
            #[cfg(target_os = "linux")]
            #[cfg(all(target_os = "linux", any(target_arch = "x86_64", target_arch = "aarch64")))]
            PacketSender::IoUring(s) => {
                if s.count > 0 {
                    let base = (s.count - 1) * s.max_packet_size;
                    let off = base + 2;
                    let cur = u16::from_be_bytes([s.buf[off], s.buf[off + 1]]);
                    s.buf[off..off + 2].copy_from_slice(&(cur | flag).to_be_bytes());
                    update_crc(&mut s.buf[base..base + HEADER_SIZE]);
                }
            }
            #[cfg(target_os = "linux")]
            PacketSender::Xdp(_) => {} // XDP: flags already in headers.
        }
    }

    fn flush(&mut self) -> std::io::Result<usize> {
        match self {
            PacketSender::Platform(s, _) => s.flush().map_err(|e| match e {
                ahp_platform_net::SendError::Io(io) => io,
                other => std::io::Error::new(std::io::ErrorKind::Other, other.to_string()),
            }),
            #[cfg(target_os = "linux")]
            PacketSender::Paced(_) => Ok(0),
            #[cfg(target_os = "linux")]
            PacketSender::ZeroCopy(s) => s.flush(),
            #[cfg(target_os = "linux")]
            #[cfg(all(target_os = "linux", any(target_arch = "x86_64", target_arch = "aarch64")))]
            PacketSender::IoUring(s) => s.flush(),
            #[cfg(target_os = "linux")]
            PacketSender::Xdp(s) => s.flush(),
        }
    }

    fn is_full(&self) -> bool {
        match self {
            PacketSender::Platform(s, _) => s.is_full(),
            #[cfg(target_os = "linux")]
            PacketSender::Paced(s) => s.is_full(),
            #[cfg(target_os = "linux")]
            PacketSender::ZeroCopy(s) => s.is_full(),
            #[cfg(target_os = "linux")]
            #[cfg(all(target_os = "linux", any(target_arch = "x86_64", target_arch = "aarch64")))]
            PacketSender::IoUring(s) => s.is_full(),
            #[cfg(target_os = "linux")]
            PacketSender::Xdp(s) => s.is_full(),
        }
    }

    fn pending(&self) -> usize {
        match self {
            PacketSender::Platform(s, _) => s.pending(),
            #[cfg(target_os = "linux")]
            PacketSender::Paced(_) => 0,
            #[cfg(target_os = "linux")]
            PacketSender::ZeroCopy(s) => s.pending(),
            #[cfg(target_os = "linux")]
            #[cfg(all(target_os = "linux", any(target_arch = "x86_64", target_arch = "aarch64")))]
            PacketSender::IoUring(s) => s.pending(),
            #[cfg(target_os = "linux")]
            PacketSender::Xdp(s) => s.pending(),
        }
    }

    #[cfg_attr(not(target_os = "linux"), allow(unused_variables))]
    fn set_pacing_interval(&self, interval: Duration) {
        #[cfg(target_os = "linux")]
        if let PacketSender::Paced(s) = self {
            s.set_pacing_interval(interval);
        }
    }

    fn is_paced(&self) -> bool {
        #[cfg(target_os = "linux")]
        { matches!(self, PacketSender::Paced(_)) }
        #[cfg(not(target_os = "linux"))]
        { false }
    }
}

/// Send a file over UDP using the AHP protocol with congestion control.
///
/// When `adaptive` is provided, the policy engine suggests (and occasionally
/// explores) transfer parameters *after* probing the network path.  The
/// actually-used [`PolicyParams`] are returned in [`TransferStats::policy_params`]
/// so the caller can record the outcome.
/// Cached session ticket from a previous transfer to a daemon, keyed by address.
/// Enables 0-RTT reconnection without a full DH handshake.
static SESSION_TICKET_CACHE: std::sync::LazyLock<
    std::sync::Mutex<std::collections::HashMap<SocketAddr, Vec<u8>>>
> = std::sync::LazyLock::new(|| std::sync::Mutex::new(std::collections::HashMap::new()));

/// Extract the resume_secret from a cached ticket entry (layout:
/// [encoded_ticket] [32-byte resume_secret]). The ticket itself is encrypted
/// under the daemon's ticket key — only the daemon can read the secret out of
/// it — so the client must keep its own copy to derive the same resumed keys.
fn extract_resume_secret(ticket_data: &[u8]) -> Option<[u8; 32]> {
    let ticket = decode_ticket(ticket_data)?;
    let secret_offset = ahp_crypto::session_ticket::encode_ticket(&ticket).len();
    let secret_bytes = ticket_data.get(secret_offset..secret_offset + 32)?;
    let mut secret = [0u8; 32];
    secret.copy_from_slice(secret_bytes);
    Some(secret)
}

/// Compare the crypto mode this client planned with the mode the daemon
/// selected in HELLO_ACK. Any mismatch is fatal: proceeding would stream
/// ciphertext the daemon parses as plaintext (or vice versa) — silent file
/// corruption on one side, universal AEAD failure on the other.
fn check_negotiated_mode(planned: HelloAckMode, replied: HelloAckMode) -> Result<(), String> {
    if planned == replied {
        Ok(())
    } else {
        Err(format!(
            "crypto mode mismatch: client planned {planned:?}, daemon selected {replied:?}"
        ))
    }
}

/// Verify the daemon's Ed25519 identity presented in HELLO_ACK against an
/// optional pin (S5, RFC §12.2/§12.4).
///
/// With a pin, the daemon MUST present auth material whose identity key
/// matches the pin and whose signature covers the handshake transcript (both
/// DH public keys + both nonces) — any failure aborts the transfer. Without
/// a pin the handshake stays anonymous DH (pre-S5 behavior) and a warning is
/// logged.
fn verify_server_identity(
    pinned: Option<&[u8; 32]>,
    ack: &HelloAckPayload,
    client_public: &[u8; 32],
    client_nonce: &[u8; 16],
) -> Result<(), String> {
    let Some(pinned) = pinned else {
        tracing::warn!(
            "connection is UNAUTHENTICATED (anonymous DH) — \
             pass --server-key to pin the daemon's identity"
        );
        return Ok(());
    };
    let (identity_pub, signature) = ack.auth_material.ok_or(
        "daemon presented no identity but --server-key was given — \
         start the daemon with --identity or drop the pin",
    )?;
    if &identity_pub != pinned {
        return Err(format!(
            "daemon identity mismatch: presented {}…, pinned {}… — aborting (possible MitM)",
            ahp_crypto::signatures::hex_encode(&identity_pub[..4]),
            ahp_crypto::signatures::hex_encode(&pinned[..4]),
        ));
    }
    let (server_public, server_nonce) = ack.dh_material
        .ok_or("HELLO_ACK missing key material")?;
    let vk = ahp_crypto::signatures::VerifyingKeyRef::from_bytes(&identity_pub)
        .map_err(|e| format!("invalid daemon identity key: {e}"))?;
    // From the client's perspective the daemon is the peer: its ephemeral
    // pubkey and nonce are the "local" values it signed with.
    vk.verify_handshake(&server_public, client_public, &server_nonce, client_nonce, &signature)
        .map_err(|e| format!("daemon handshake signature invalid ({e}) — aborting (possible MitM)"))
}

/// Parse a `--server-key` pin: either a 64-char hex Ed25519 public key, or a
/// path to a file containing that hex string (as printed by
/// `favonius-daemon keygen`).
pub fn parse_server_key_pin(s: &str) -> Result<[u8; 32], String> {
    let trimmed = s.trim();
    let hex_str = if trimmed.len() == 64 && trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
        trimmed.to_string()
    } else {
        let path = std::path::Path::new(trimmed);
        let contents = std::fs::read_to_string(path).map_err(|e| {
            format!("--server-key is neither a 64-char hex key nor a readable file ({trimmed}): {e}")
        })?;
        // Accept a bare hex line, or the pubkey line of `keygen` output
        // (last non-empty line is the hex key in both cases).
        contents
            .lines()
            .filter(|l| !l.trim().is_empty())
            .next_back()
            .unwrap_or("")
            .trim()
            .to_string()
    };
    let bytes = ahp_crypto::signatures::hex_decode(&hex_str)
        .filter(|b| b.len() == 32)
        .ok_or_else(|| format!("invalid daemon public key: expected 64 hex chars, got {hex_str:?}"))?;
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    Ok(key)
}

/// Clamp policy-loaded parameters to sane ranges before use.
///
/// policy.json is hand-editable and loaded without validation; an absurd
/// `payload_size` would overflow the wire MTU (panicking the packet
/// encoder) or push the GSO segment size past 65535 (collapsing batch
/// capacity to 0), and a huge `num_streams` or `batch_size` blows up
/// allocations. Clamping here keeps a bad config degrading to slow-but-sane
/// behavior instead of crashing.
fn sanitize_policy_params(p: &mut PolicyParams) {
    // Payload must fit in one datagram: fixed header + data header + GCM tag.
    let max_payload = MAX_PACKET - WIRE_OVERHEAD - 16;
    p.payload_size = p.payload_size.clamp(1, max_payload);
    // Match the daemon's negotiated stream cap (MAX_NUM_STREAMS = 64).
    p.num_streams = p.num_streams.clamp(1, 64);
    p.batch_size = p.batch_size.clamp(1, 1024);
    p.socket_buf_kb = p.socket_buf_kb.clamp(16, 64 * 1024);
    p.min_cwnd_kb = p.min_cwnd_kb.clamp(1, 64 * 1024);
    p.retx_timeout_ms = p.retx_timeout_ms.clamp(10, 60_000);
    p.progress_ack_interval_ms = p.progress_ack_interval_ms.clamp(1, 10_000);
}

pub async fn send_file(
    remote: SocketAddr,
    source: &Path,
    dest_path: &str,
    // `None` is `--congestion auto`: the profile is chosen below, once the
    // path probe has classified the link.
    cc_profile: Option<CongestionProfile>,
    ack_mode: AckMode,
    num_streams: u32,
    pacing_mode: &str,
    encrypt: bool,
    compression: CompressionProfile,
    resume: bool,
    adaptive: Option<&AdaptivePolicy>,
    header_protect: bool,
    pinned_server_key: Option<[u8; 32]>,
) -> Result<TransferStats, Box<dyn std::error::Error + Send + Sync>> {
    // Validate the source path before any network I/O: paths like "/" or
    // ending in ".." have no final component to name the transfer after.
    let file_name: String = source
        .file_name()
        .ok_or("cannot determine file name from source path")?
        .to_string_lossy()
        .into_owned();

    // ── Socket setup ─────────────────────────────────────────────────────
    //
    // The socket family must match the destination's. This was hardcoded to
    // IPv4 with a `0.0.0.0:0` bind, so an IPv6 destination failed at
    // `connect` with EAFNOSUPPORT ("Address family not supported by
    // protocol") *after* parsing and starting the transfer — the code
    // compiled and the address resolved, and it still could not send.
    let (domain, bind_any) = if remote.is_ipv6() {
        (Domain::IPV6, SocketAddr::from((std::net::Ipv6Addr::UNSPECIFIED, 0)))
    } else {
        (Domain::IPV4, SocketAddr::from((std::net::Ipv4Addr::UNSPECIFIED, 0)))
    };
    let sock2 = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    sock2.set_send_buffer_size(4 * 1024 * 1024)?;
    sock2.set_recv_buffer_size(4 * 1024 * 1024)?;
    sock2.set_nonblocking(true)?;
    sock2.bind(&bind_any.into())?;
    let socket = UdpSocket::from_std(sock2.into())?;

    let conn_id: u64 = rand::random();
    let mut seq: u64 = 0;
    let mut recv_buf = vec![0u8; MAX_PACKET];

    // ── Handshake (with key exchange when encrypted) ───────────────────
    // HELLO payload formats:
    //   0x00: plaintext
    //   0x01: full DH — [32-byte public key] [16-byte nonce]
    //   0x02: 0-RTT resume — [4-byte ticket_len BE] [ticket_data] [16-byte nonce]
    // HELLO_ACK payload: [1-byte mode] [mode material (DH material for full
    //   handshake, server nonce for resume)] [2-byte data port BE] — the mode
    //   byte names the negotiated crypto mode (see ahp_proto::hello).
    let local_kp = if encrypt { Some(generate_keypair()) } else { None };
    let local_nonce: [u8; 16] = rand::random();

    // Try 0-RTT resume if we have a cached ticket for this daemon.
    let cached_ticket = if encrypt {
        SESSION_TICKET_CACHE.lock().unwrap().get(&remote).cloned()
    } else {
        None
    };
    let using_ticket = cached_ticket.is_some();

    // The resume_secret is cached alongside the ticket (layout:
    // [encoded_ticket] [32-byte resume_secret]). Without it we cannot derive
    // resumed keys, so the ticket alone does not let us plan on encryption.
    let cached_resume_secret = cached_ticket.as_deref().and_then(extract_resume_secret);
    if using_ticket && cached_resume_secret.is_none() {
        tracing::warn!("cached ticket missing resume_secret, falling back to no encryption");
        SESSION_TICKET_CACHE.lock().unwrap().remove(&remote);
    }

    // The crypto mode we intend to use; checked against the daemon's HELLO_ACK
    // mode byte before any data flows.
    let planned_mode = if using_ticket && cached_resume_secret.is_some() {
        HelloAckMode::Resumed
    } else if using_ticket {
        HelloAckMode::Plaintext
    } else if encrypt {
        HelloAckMode::FullHandshake
    } else {
        HelloAckMode::Plaintext
    };

    let hello_payload = if let Some(ref ticket_data) = cached_ticket {
        // 0-RTT resume: [0x02] [4-byte ticket_len BE] [ticket_data] [16-byte nonce]
        let mut buf = Vec::with_capacity(1 + 4 + ticket_data.len() + 16);
        buf.push(0x02);
        buf.extend_from_slice(&(ticket_data.len() as u32).to_be_bytes());
        buf.extend_from_slice(ticket_data);
        buf.extend_from_slice(&local_nonce);
        buf
    } else if let Some(ref kp) = local_kp {
        let mut buf = Vec::with_capacity(1 + 32 + 16);
        buf.push(0x01); // flags: encrypted
        buf.extend_from_slice(&kp.public);
        buf.extend_from_slice(&local_nonce);
        buf
    } else {
        vec![0x00] // flags: plaintext
    };

    // A HELLO_ACK carrying no data port is the daemon saying it is busy: it
    // serves one transfer at a time (the main loop awaits `handle_transfer`
    // inline), and its data thread answers a second sender with a bare mode
    // byte before queueing it.
    //
    // Treating that as a normal ack is what made concurrent transfers fail.
    // The sender fell back to the control port, streamed a whole file at a
    // daemon that was not listening for it, received not one ACK, and
    // aborted after 30 s — while the daemon logged the peer as dead. Both
    // ends blamed the other and the real answer, "wait your turn", was
    // already on the wire and being discarded. Measured 2026-08-12: 1 of 2
    // and 2 of 4 concurrent transfers completed. Measured; see the congestion-control notes.
    //
    // Waiting is correct rather than merely nicer: the daemon *will* serve
    // this transfer once the current one finishes, so the only thing needed
    // was to not give up first.
    const HELLO_ATTEMPTS: u32 = 15;
    const BUSY_WAIT_MAX: Duration = Duration::from_secs(300);
    // Backoff for a daemon that answered "busy", not a fixed poll.
    //
    // This was a flat 1 s, and it was the single largest fixed cost in a
    // concurrent transfer. The daemon must advertise its port-run length in
    // HELLO_ACK before it knows `num_streams` (that arrives in the
    // MANIFEST), so it reserves up to `per_transfer_cap` ports optimistically
    // and hands the unused tail straight back once the MANIFEST arrives —
    // milliseconds later. A sender declined in the meantime then slept a
    // full second before asking again, long after the sockets it wanted were
    // free. Measured on loopback with a 10-port pool: two of four senders
    // finished in 0.40 s and the other two in 2.32 s. With a 40-port pool,
    // where nobody is declined, all four finish in 0.43-0.57 s.
    //
    // Starting short and doubling keeps that window tight without turning a
    // genuinely busy daemon — one serving a multi-GB transfer for minutes —
    // into a retry storm: the interval reaches the old 1 s after six
    // attempts and stays there.
    const BUSY_POLL_MIN: Duration = Duration::from_millis(25);
    const BUSY_POLL_MAX: Duration = Duration::from_secs(1);
    let hello_ack_pkt: Packet;
    let mut attempt: u32 = 0;
    let mut announced_busy = false;
    let mut busy_poll = BUSY_POLL_MIN;
    let busy_deadline = Instant::now() + BUSY_WAIT_MAX;
    loop {
        send_ctrl(&socket, remote, PacketType::Hello, conn_id, seq, &hello_payload).await?;
        match recv_ctrl_typed(&socket, &mut recv_buf, PacketType::HelloAck, Duration::from_secs(2)).await {
            Ok(pkt) => {
                let busy = decode_hello_ack_payload(&pkt.payload)
                    .map(|a| a.data_port.is_none())
                    .unwrap_or(false);
                if busy {
                    if Instant::now() >= busy_deadline {
                        return Err(format!(
                            "daemon busy with another transfer for {}s — it serves one at \
a time; retry when it is free",
                            BUSY_WAIT_MAX.as_secs()
                        ).into());
                    }
                    if !announced_busy {
                        eprintln!("Daemon is busy with another transfer — waiting for a slot...");
                        announced_busy = true;
                    }
                    tracing::debug!(
                        backoff_ms = busy_poll.as_millis() as u64,
                        "HELLO_ACK carried no data port: daemon busy, waiting"
                    );
                    tokio::time::sleep(busy_poll).await;
                    busy_poll = (busy_poll * 2).min(BUSY_POLL_MAX);
                    continue;
                }
                hello_ack_pkt = pkt;
                break;
            }
            Err(_) if attempt + 1 < HELLO_ATTEMPTS => {
                attempt += 1;
                tracing::debug!(attempt, "HELLO timeout, retrying");
            }
            Err(_) => {
                return Err(format!("handshake failed after {HELLO_ATTEMPTS} attempts").into())
            }
        }
    }
    seq += 1;

    // Parse HELLO_ACK: [1-byte mode] [mode material (DH material for full
    // handshake, server nonce for resume)] [2-byte data port BE]. A bare
    // "busy" ack carries only the mode byte; fall back to the control port
    // then, as before.
    let ack_payload = &hello_ack_pkt.payload[..];
    let hello_ack = decode_hello_ack_payload(ack_payload)
        .ok_or("HELLO_ACK missing or invalid mode byte")?;
    let data_port = hello_ack.data_port.unwrap_or_else(|| remote.port());
    let data_remote = SocketAddr::new(remote.ip(), data_port);
    tracing::info!(control = %remote, data = %data_remote, "daemon ports");

    // How many contiguous data ports the daemon reserved for this transfer,
    // counting `data_port`. 1 unless it advertised a run — which it can only
    // do when started with `--data-port-range`, so nothing changes for a
    // default daemon or one that predates the capability.
    //
    // A count rather than a list of ports, because the daemon has to publish
    // this in HELLO_ACK, before our MANIFEST tells it how many streams there
    // will be. Taking the minimum of the two is our side of that bargain.
    let advertised_data_ports = ahp_proto::data_port_count(hello_ack.capabilities);
    // `FAVONIUS_PER_STREAM_PORTS=0` declines the run: same binary, same
    // daemon, one socket — which is the control arm this is measured
    // against, and the way to get the old behaviour back if it misbehaves.
    let per_stream_ports_enabled = std::env::var("FAVONIUS_PER_STREAM_PORTS")
        .map(|v| v != "0")
        .unwrap_or(true);

    // Never proceed in a crypto mode different from the one we planned: if the
    // daemon rejected the resume ticket (e.g. after a restart) it expects
    // plaintext while we hold resumed keys — streaming anyway writes garbage
    // into the destination file. The reverse mismatch fails every AEAD check.
    // Abort instead; the evicted ticket makes the next attempt a full DH
    // handshake.
    if let Err(e) = check_negotiated_mode(planned_mode, hello_ack.mode) {
        if using_ticket {
            SESSION_TICKET_CACHE.lock().unwrap().remove(&remote);
        }
        return Err(e.into());
    }

    // Derive session keys according to the negotiated mode.
    let session_keys: Option<SessionKeys> = match hello_ack.mode {
        HelloAckMode::Resumed => {
            // planned_mode == Resumed implies the cached secret is present.
            // S5 note: a resumed session inherits authentication from the
            // ticket-issuing (full, optionally verified) handshake — the
            // daemon identity is not re-verified here. Fails safe across
            // daemon restarts: the per-instance ticket key is gone, the
            // ticket is rejected, and the mode check above aborts.
            let resume_secret = cached_resume_secret.as_ref()
                .ok_or("daemon resumed the session but the client has no resume_secret")?;
            // The daemon's fresh server nonce is mixed into the derivation
            // (S4 replay protection): without it the keys are not the ones
            // the daemon derived, so abort rather than stream garbage.
            let server_nonce = hello_ack.resume_server_nonce
                .ok_or("HELLO_ACK missing resume server nonce")?;
            let keys = derive_resumed_keys(resume_secret, &local_nonce, &server_nonce)
                .map_err(|e| format!("resume key derivation failed: {e}"))?;
            tracing::info!("encryption: 0-RTT session resumed from ticket");
            Some(keys)
        }
        HelloAckMode::FullHandshake => {
            let kp = local_kp.as_ref()
                .ok_or("daemon requested full handshake but the client has no keypair")?;
            // S5 (RFC §12.4): authenticate the daemon BEFORE deriving keys —
            // a pinned client aborts on identity mismatch or a bad signature.
            verify_server_identity(pinned_server_key.as_ref(), &hello_ack, &kp.public, &local_nonce)
                .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.into() })?;
            let (peer_public, peer_nonce) = hello_ack.dh_material
                .ok_or("HELLO_ACK missing key material")?;
            let shared_secret = diffie_hellman(&kp.private, &peer_public)
                .map_err(|e| format!("key exchange failed: {e}"))?;
            let keys = derive_session_keys(&shared_secret, &local_nonce, &peer_nonce)
                .map_err(|e| format!("key derivation failed: {e}"))?;
            if pinned_server_key.is_some() {
                tracing::info!("encryption: X25519 + AES-256-GCM established (daemon identity verified)");
            } else {
                tracing::info!("encryption: X25519 + AES-256-GCM established");
            }
            Some(keys)
        }
        HelloAckMode::Plaintext => None,
    };

    // Create a separate socket for DATA packets, pointed at the data port.
    // Same family as the destination; see the control socket above.
    let data_socket = UdpSocket::bind(bind_any).await?;
    data_socket.connect(data_remote).await?;

    // ── Path probing (on control socket) ─────────────────────────────────
    let profile = net_probe::probe_path(&socket, remote, conn_id, &mut seq).await;

    // ── `--congestion auto` ──────────────────────────────────────────────
    //
    // Take the profile `ahp-policy` already carries for this link type.
    // That table has existed all along and never won an argument, because
    // `--congestion` defaulted to a hard `classic` that overrode it — and
    // `classic` is the worst profile on every path measured to date: on a
    // real 5 GHz radio it managed 27.3 MB/s at cv 47.6% against `model`'s
    // 34.2 at 7.4% and `cycle`'s 35.5 at 2.7%, with one run collapsing to
    // 8.8 MB/s and 3498 retransmits.
    //
    // Deliberately NOT a best-measured-per-cell selector. Which profile is
    // right depends on whether loss is congestion-induced or random, and
    // measurement established that the probe cannot tell those apart;
    // a selector keyed on measured loss would pick a loss-ignoring profile
    // on a congested path, which is precisely the bad-citizenship failure
    // that justified `classic` as the default in the first place. The
    // link-type table only makes claims where the classification is
    // unambiguous, and answers `classic` everywhere else.
    let cc_profile = match cc_profile {
        Some(explicit) => explicit,
        None => {
            let name = ahp_policy::defaults_for_link_type(profile.link_type).cc_profile;
            let chosen = CongestionProfile::from_name(&name).unwrap_or_else(|| {
                // The table is ours and this cannot fire today; if it ever
                // does, say so rather than silently running a third thing.
                tracing::warn!(
                    unknown = %name, link_type = %profile.link_type,
                    "auto: policy default names an unknown profile; using classic"
                );
                CongestionProfile::Classic
            });
            tracing::info!(
                link_type = %profile.link_type, profile = %chosen,
                "congestion: auto"
            );
            eprintln!("  Congestion: {chosen} (auto, {} link)", profile.link_type);
            chosen
        }
    };

    // ── Policy-driven parameters ────────────────────────────────────────
    // If an adaptive policy is provided, build a NetworkContext from the
    // probe results and let the policy suggest (or explore) parameters.
    // This must happen BEFORE the manifest and CC controller are created
    // because the policy may override ack_mode, cc_profile, and payload_size.
    let policy_params: Option<PolicyParams> = adaptive.map(|ap| {
        let ctx = NetworkContext {
            link_type: profile.link_type.to_string(),
            base_rtt_us: profile.base_rtt.as_micros() as u64,
            jitter_us: profile.rtt_jitter.as_micros() as u64,
            loss_rate: profile.probe_loss_rate,
        };
        let suggested = ap.suggest_params(&ctx);
        // Explore 20% of the time to discover better parameter combinations.
        let mut params = if rand::random::<f64>() < 0.2 {
            ap.explore_params(&suggested)
        } else {
            suggested
        };
        sanitize_policy_params(&mut params);
        params
    });
    let policy = policy_params.as_ref();

    // Resolve effective values: policy overrides CLI args when adaptive.
    let effective_cc = policy.map_or(cc_profile, |p| {
        CongestionProfile::from_name(&p.cc_profile).unwrap_or_else(|| {
            // A policy file naming a profile that does not exist used to
            // select Classic silently. The CLI rejects an unknown
            // `--congestion` outright, but this is a file read at transfer
            // time rather than an argument, so it warns and keeps the
            // profile already resolved rather than substituting a third
            // one.
            tracing::warn!(
                unknown = %p.cc_profile,
                falling_back_to = %cc_profile,
                "policy: unknown cc_profile; expected one of {}",
                CongestionProfile::NAMES
            );
            cc_profile
        })
    });
    let effective_ack = policy.map_or(ack_mode, |p| match p.ack_mode.as_str() {
        "nack" => AckMode::Nack,
        _ => AckMode::Bitmap,
    });
    let payload_size: usize = policy.map_or(DEFAULT_PAYLOAD, |p| p.payload_size);

    // Resize socket buffers if the policy specifies a different size.
    if let Some(p) = policy {
        let buf_bytes = p.socket_buf_kb * 1024;
        let sock_ref = SockRef::from(&socket);
        let _ = sock_ref.set_send_buffer_size(buf_bytes);
        let _ = sock_ref.set_recv_buffer_size(buf_bytes);
    }

    let num_streams: u32 = policy.map_or(num_streams, |p| p.num_streams);

    if let Some(p) = policy {
        eprintln!(
            "  adaptive: cc={}, ack={}, payload={}, sock={}KB, cwnd_floor={}KB, batch={}, retx={}ms, ack_int={}ms, streams={}",
            p.cc_profile, p.ack_mode, p.payload_size, p.socket_buf_kb,
            p.min_cwnd_kb, p.batch_size, p.retx_timeout_ms, p.progress_ack_interval_ms,
            p.num_streams,
        );
    }

    // ── Map the source file ──────────────────────────────────────────────
    // The file is memory-mapped read-only instead of being read into a heap
    // buffer: a 100 GB source costs page-table entries, not 100 GB of RAM.
    // Chunk payloads are slices of the mapping; the compression/encryption
    // stages already copy into owned scratch (zstd output, crypt_buf), and
    // the zero-copy sender points its iovecs into the mapping directly.
    //
    // Zero-copy: when no encryption/compression, use ZeroCopyBatchSender
    // which points iovecs directly at the file data (avoids batch buffer copy).
    let zero_copy = session_keys.is_none() && compression == CompressionProfile::None && !header_protect;
    let src_file = std::fs::File::open(source)?;
    let file_size = src_file.metadata()?.len();
    // Invariant: the source file must not shrink while mapped — reading a
    // page beyond the truncated end raises SIGBUS (the daemon's destination
    // mmap carries the same exposure; a SIGBUS handler is out of scope).
    // The length is snapshot here, the manifest publishes it, and the
    // receiver rejects inconsistent geometry, so growth is merely ignored.
    // An empty file cannot be mapped; it needs no mapping (zero chunks).
    let file_map = if file_size > 0 {
        let map = unsafe { memmap2::Mmap::map(&src_file)? };
        #[cfg(target_os = "linux")]
        let _ = map.advise(memmap2::Advice::Sequential);
        Some(map)
    } else {
        None
    };
    let file_data: &[u8] = file_map.as_deref().unwrap_or(&[]);
    // Zero-copy eligibility message printed later when sender is selected.
    let total_chunks = file_size.div_ceil(payload_size as u64);

    // Linux: page-cache prefetch thread. Reading the source lazily through
    // the mapping makes a cache-cold file trickle in through synchronous
    // major faults (MADV_WILLNEED readahead is capped too small to help),
    // throttling the whole transfer to a fraction of disk speed. A
    // dedicated thread issuing big buffered reads populates the page cache
    // at full sequential speed; consumers of the mapping then only ever
    // fault hot pages. It starts paced to the setup-phase hashing frontier
    // below (warming ahead of it so cold-disk hashing stays inside the
    // daemon's MANIFEST wait), then the send loop republishes the slowest
    // stream's send position and it paces itself PREFETCH_AHEAD past that,
    // so prefetch + drop keep the resident window bounded on huge files.
    // Stopped and joined on every exit path via the guard.
    #[cfg(target_os = "linux")]
    const PREFETCH_AHEAD: u64 = 256 * 1024 * 1024;
    #[cfg(target_os = "linux")]
    let (prefetch_stop, prefetch_pos, prefetch_join) = {
        let stop = Arc::new(AtomicBool::new(false));
        // Consumer position (setup hashing frontier, then the slowest
        // stream's send position), published by the phases below; the
        // prefetcher stays at most PREFETCH_AHEAD past it.
        let pos = Arc::new(AtomicU64::new(0));
        let join = if file_size > 0 {
            let pf_file = std::fs::File::open(source)?;
            let (stop2, pos2) = (stop.clone(), pos.clone());
            Some(std::thread::spawn(move || {
                use std::os::unix::fs::FileExt;
                let mut buf = vec![0u8; 1024 * 1024];
                let mut off = 0u64;
                while off < file_size && !stop2.load(Ordering::Relaxed) {
                    if off >= pos2.load(Ordering::Relaxed).saturating_add(PREFETCH_AHEAD) {
                        std::thread::sleep(Duration::from_millis(2));
                        continue;
                    }
                    match pf_file.read_at(&mut buf, off) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => off += n as u64,
                    }
                }
            }))
        } else {
            None
        };
        (stop, pos, join)
    };
    #[cfg(target_os = "linux")]
    let _prefetch_guard = PrefetchGuard { stop: &prefetch_stop, join: prefetch_join };

    // Compute file hash and optionally Merkle tree for resume modes. Both
    // hashers are fed through a bounded window instead of one call over the
    // whole mapping, and mapping pages are dropped behind the read frontier
    // as we go, so setup on a huge file keeps a constant resident set rather
    // than faulting the entire mapping in. The frontier is also published
    // to the prefetch thread, bounding its warmup to PREFETCH_AHEAD ahead
    // of the hashing reader (still enough to keep cold-disk hashing inside
    // the daemon's MANIFEST wait) instead of letting it race through the
    // whole file. Results are byte-identical to the whole-slice hashes:
    // BLAKE3 output does not depend on update() chunking, and the Merkle
    // leaves are hashed per payload chunk exactly as in build_file_merkle.
    let resume_mode_str = if resume { "merkle" } else { "none" };
    let (file_hash, merkle_tree) = if resume {
        const SETUP_WINDOW: usize = 32 * 1024 * 1024;
        let mut hasher = blake3::Hasher::new();
        // Zero payload size mirrors build_file_merkle: an empty tree.
        let mut builder = ahp_sync::merkle::FileMerkleBuilder::new(payload_size).ok();
        let mut offset = 0usize;
        while offset < file_data.len() {
            let end = (offset + SETUP_WINDOW).min(file_data.len());
            let window = &file_data[offset..end];
            hasher.update(window);
            if let Some(ref mut b) = builder {
                b.update(window);
            }
            #[cfg(target_os = "linux")]
            {
                prefetch_pos.store(end as u64, Ordering::Relaxed);
                if let Some(ref map) = file_map {
                    drop_mapping_pages(map, offset, end - offset);
                }
            }
            offset = end;
        }
        let tree = match builder {
            Some(b) => b.finish(),
            None => ahp_sync::merkle::MerkleTree::from_leaves(&[]),
        };
        (Some(hasher.finalize().to_hex().to_string()), Some(tree))
    } else {
        (None, None)
    };
    let merkle_root = merkle_tree.as_ref().map(|t| {
        t.root().iter().map(|b| format!("{:02x}", b)).collect::<String>()
    });

    // ── Manifest ─────────────────────────────────────────────────────────
    // Clamp num_streams: at most total_chunks streams, at least 1. An empty
    // file has total_chunks == 0: keep one (empty) stream so the transfer
    // loop is skipped cleanly and completion is signaled by FINISH alone —
    // the daemon creates the empty destination file from the manifest.
    let num_streams = num_streams.max(1).min(total_chunks.max(1) as u32);

    // ── Per-stream data ports ────────────────────────────────────────────
    // Stream *i* goes to `data_port + min(i, n_dest - 1)`: streams past the
    // end of the run share the last port rather than vanishing, so the two
    // sides never have to agree on a number.
    //
    // Only the batched backends split. `perpacket` owns a pacer thread per
    // sender, `iouring` a ring, and `xdp` a UMEM bound to one 4-tuple —
    // multiplying those is a different piece of work, and none of them is
    // the default this is being measured for.
    let split_capable = !matches!(pacing_mode, "perpacket" | "iouring" | "xdp");
    let n_dest: usize = if per_stream_ports_enabled && split_capable {
        advertised_data_ports.min(num_streams as usize).max(1)
    } else {
        1
    };
    let data_remotes: Vec<SocketAddr> = (0..n_dest)
        .map(|i| SocketAddr::new(remote.ip(), data_port.saturating_add(i as u16)))
        .collect();
    if n_dest > 1 {
        eprintln!(
            "  Data ports: {}-{} ({} sockets, {} streams)",
            data_port, data_port + n_dest as u16 - 1, n_dest, num_streams
        );
    } else if advertised_data_ports > 1 {
        tracing::info!(
            advertised = advertised_data_ports, num_streams, split_capable,
            per_stream_ports_enabled,
            "daemon offered a data port run; using one port"
        );
    }

    let manifest = serde_json::to_vec(&FileManifest {
        file_name,
        file_size,
        dest_path: dest_path.into(),
        payload_size,
        total_chunks,
        ack_mode: effective_ack,
        num_streams,
        encrypted: session_keys.is_some(),
        compressed: compression != CompressionProfile::None,
        header_protected: header_protect && session_keys.is_some(),
        resume_mode: resume_mode_str.into(),
        file_hash,
        merkle_root,
        // What we actually took up of what was offered. Diagnostic only —
        // the daemon polls every socket it holds regardless — but "offered"
        // and "used" are the two arms of this measurement and a log that
        // cannot tell them apart is no use. A tag that changes the wire
        // needs a matching HELLO_ACK capability bit; this one does not,
        // because the capability it answers is already negotiated.
        features: if n_dest > 1 {
            vec!["per-stream-ports".to_string()]
        } else {
            Vec::new()
        },
    })?;
    // Send MANIFEST with retries. Accept AckBitmap (normal) or ResumeAck (resume).
    let mut manifest_acked = false;
    let mut resume_bitmap: Option<Vec<u8>> = None;
    // Set when the bitmap was computed sender-side from a Merkle diff and
    // must be reported back to the daemon (it cannot derive which chunks we
    // skip from the root hash alone).
    let mut report_resume_bitmap = false;
    for attempt in 0..10 {
        send_ctrl(&socket, remote, PacketType::Manifest, conn_id, seq, &manifest).await?;
        match recv_ctrl(&socket, &mut recv_buf, Duration::from_secs(2)).await {
            Ok(pkt) => match pkt.header.packet_type {
                PacketType::AckBitmap => { manifest_acked = true; break; }
                PacketType::ResumeAck => {
                    if pkt.payload.len() > 1 {
                        let prefix = pkt.payload[0];
                        let data = &pkt.payload[1..];
                        match prefix {
                            0x01 => {
                                // Bitmap: decompress directly.
                                let decompressed = zstd::decode_all(data)
                                    .unwrap_or_else(|_| data.to_vec());
                                resume_bitmap = Some(decompressed);
                            }
                            0x02 => {
                                // Merkle diff: daemon sent level hashes from its
                                // cached tree. Compare against our tree to find diffs.
                                if let Some(ref tree) = merkle_tree {
                                    let decompressed = zstd::decode_all(data)
                                        .unwrap_or_else(|_| data.to_vec());
                                    if decompressed.len() >= 5 {
                                        let level = decompressed[0] as usize;
                                        let _daemon_leaf_count = u32::from_le_bytes([
                                            decompressed[1], decompressed[2],
                                            decompressed[3], decompressed[4],
                                        ]) as usize;
                                        let hash_data = &decompressed[5..];
                                        let daemon_hashes: Vec<[u8; 32]> = hash_data
                                            .chunks_exact(32)
                                            .map(|c| { let mut h = [0u8; 32]; h.copy_from_slice(c); h })
                                            .collect();

                                        // Compare daemon's hashes at this level against ours.
                                        let our_level = tree.level(level);
                                        let mut diff_nodes = Vec::new();
                                        let max_len = our_level.len().max(daemon_hashes.len());
                                        for i in 0..max_len {
                                            let ours = our_level.get(i);
                                            let theirs = daemon_hashes.get(i);
                                            if ours != theirs {
                                                diff_nodes.push(i);
                                            }
                                        }

                                        // Expand differing nodes down to leaf indices.
                                        let diff_leaves = tree.expand_diffs_to_leaves(level, &diff_nodes);
                                        let matching_count = total_chunks as usize - diff_leaves.len();

                                        // Build bitmap: set bits for MATCHING chunks (skip them).
                                        let bitmap_bytes = (total_chunks as usize + 7) / 8;
                                        let mut bm = vec![0xFFu8; bitmap_bytes]; // start all set
                                        // Clear trailing bits.
                                        let trailing = total_chunks as usize % 8;
                                        if trailing != 0 {
                                            bm[bitmap_bytes - 1] = (1u8 << trailing) - 1;
                                        }
                                        // Clear bits for differing leaves (need to send).
                                        for &li in &diff_leaves {
                                            if li / 8 < bm.len() {
                                                bm[li / 8] &= !(1 << (li % 8));
                                            }
                                        }

                                        tracing::info!(
                                            level, diff_nodes = diff_nodes.len(),
                                            diff_leaves = diff_leaves.len(),
                                            matching = matching_count,
                                            "merkle diff: {}/{} chunks match, {} to send",
                                            matching_count, total_chunks, diff_leaves.len()
                                        );
                                        resume_bitmap = Some(bm);
                                        report_resume_bitmap = true;
                                    }
                                }
                                // The diff could not be decoded — report an
                                // all-zeros bitmap (nothing matches → full
                                // transfer) so the daemon's accounting stays
                                // in lockstep with what we actually send.
                                if resume_bitmap.is_none() {
                                    resume_bitmap =
                                        Some(vec![0u8; (total_chunks as usize).div_ceil(8)]);
                                    report_resume_bitmap = true;
                                }
                            }
                            _ => {}
                        }
                    }
                    manifest_acked = true;
                    break;
                }
                _ => continue,
            },
            Err(_) if attempt < 9 => {
                tracing::debug!(attempt = attempt + 1, "MANIFEST ACK timeout, retrying");
            }
            Err(e) => return Err(e),
        }
    }
    if !manifest_acked {
        return Err("manifest exchange failed after 10 attempts".into());
    }
    seq += 1;

    // Merkle-diff resume: the daemon sent level hashes and WE computed the
    // skip bitmap — report it back (RESUME_REQ, zstd-compressed like the
    // bitmap-mode exchange) so the daemon can pre-populate its received
    // state for the chunks we will skip. Without this the daemon's received
    // count can never reach total_chunks and the transfer fails at
    // finalization.
    if report_resume_bitmap {
        let bm = resume_bitmap.as_ref().ok_or("missing sender resume bitmap")?;
        let compressed = zstd::encode_all(bm.as_slice(), 1).unwrap_or_else(|_| bm.clone());
        let mut report_acked = false;
        for attempt in 0..10 {
            send_ctrl(&socket, remote, PacketType::ResumeReq, conn_id, seq, &compressed).await?;
            match recv_ctrl_typed(&socket, &mut recv_buf, PacketType::AckBitmap, Duration::from_secs(2)).await {
                Ok(_) => { report_acked = true; break; }
                Err(_) if attempt < 9 => {
                    tracing::debug!(attempt = attempt + 1, "RESUME_REQ ack timeout, retrying");
                }
                Err(e) => return Err(e),
            }
        }
        if !report_acked {
            return Err("resume bitmap report failed after 10 attempts".into());
        }
        seq += 1;
    }

    let _data_seq_base = seq;

    // ── Congestion controller ───────────────────────────────────────────
    let mut cc = create_controller(effective_cc);

    // Feed initial RTT from probing so the CC doesn't start blind.
    if !profile.base_rtt.is_zero() {
        cc.on_rtt_update(profile.base_rtt);
    }

    let min_cwnd_floor = if let Some(p) = policy {
        p.min_cwnd_kb * 1024
    } else {
        profile.min_cwnd
    };

    // No bandwidth seed. `min_cwnd_floor / base_rtt` used to be handed to
    // the controller as a bottleneck estimate, but the floor is a minimum
    // *window*, not a measurement, and net_probe.rs measures no bandwidth
    // at all -- it returns RTT, jitter, loss and that floor. For a WAN
    // profile the floor is 16 KB, so over a 25 ms base RTT the "estimate"
    // was 5.2 Mbit on a 100 Mbit link.
    //
    // Every rate-based controller set its *pacing rate* from it and armed
    // its startup plateau detector against it, so delivery could not
    // exceed the fabricated number, the detector saw no growth, startup
    // exited after three flat rounds, and the controller settled on the
    // figure it had been handed. Measured in the path simulator, Model on
    // a 100 Mbit link: 87.5% of capacity without the seed, 52.8% with it,
    // and 0.3% on a longer-RTT variant.
    //
    // This was inert while the pacer could not enforce a rate -- cwnd drove
    // the send, delivery came in far above the seed and the estimate
    // escaped. Once pacing became real the seed became a ceiling. Startup
    // discovers the bottleneck in ~10 round trips; being pinned for the
    // whole transfer is the more expensive of the two.

    let batch_size: usize = policy.map_or(256, |p| p.batch_size);
    // In NACK mode the receiver tells us what's missing, so use a much longer
    // timeout fallback (only fires if NACKs themselves are lost).
    let default_retx_ms = if effective_ack == AckMode::Nack { 500 } else { 100 };
    let configured_retx = Duration::from_millis(policy.map_or(default_retx_ms, |p| p.retx_timeout_ms));

    // Never arm the retransmit timer below what the path can physically
    // answer. The configured value is a *floor* on fast links (preserving
    // LAN recovery latency), but on a long path the probed base RTT
    // dominates: a timer shorter than the RTT declares every packet lost
    // before its ACK can possibly arrive, and the resulting retransmit
    // storm is self-sustaining. 2x base RTT is the same margin RFC 6298's
    // `srtt + 4*rttvar` converges to once samples exist.
    let retx_floor = configured_retx.max(profile.base_rtt * 2);
    // Sender-side RTT estimator, kept independently of the CC so the
    // retransmit timer adapts under every congestion controller (UDT, RL
    // and Model expose no RTT state of their own).
    let mut rtt_est = RttEstimator::new();
    if !profile.base_rtt.is_zero() {
        rtt_est.update(profile.base_rtt);
    }

    // ── Transfer state ───────────────────────────────────────────────────
    let mut in_flight: usize = 0;
    let mut streams = build_streams(total_chunks, num_streams);
    let mut packets_sent: u64 = 0;
    let mut retransmits: u64 = 0;
    let mut current_stream: usize = 0; // round-robin index

    // Pre-populate acked state from resume bitmap.
    let mut chunks_skipped: u64 = 0;
    if let Some(ref bitmap) = resume_bitmap {
        for stream in streams.iter_mut() {
            for local_ci in 0..stream.acked.len() {
                let global_ci = stream.to_global(local_ci as u64) as usize;
                let byte_idx = global_ci / 8;
                let bit_idx = global_ci % 8;
                if byte_idx < bitmap.len()
                    && (bitmap[byte_idx] & (1 << bit_idx)) != 0
                    && stream.mark_acked(local_ci)
                {
                    chunks_skipped += 1;
                }
            }
        }
        tracing::info!(
            skipped = chunks_skipped, total = total_chunks,
            "resume: skipping {}/{} chunks", chunks_skipped, total_chunks
        );
    }

    let start = Instant::now();
    let compressor = create_compressor(compression);
    // Reusable zstd context for the per-chunk compress path: `encode_all`
    // would build a fresh compression context (workspace allocation +
    // parameter setup) for every chunk.
    let mut compress_ctx = compressor
        .as_ref()
        .map(|c| c.bulk_compressor())
        .transpose()
        .map_err(|e| std::io::Error::other(format!("{e}")))?;

    // Wrap session keys in a KeyEpoch for automatic key rotation.
    let mut key_epoch: Option<KeyEpoch> = session_keys.map(KeyEpoch::new);

    // Per-epoch crypto objects, built once and rebuilt only on key rotation
    // (mirrors the daemon's receive path). `Aes256GcmProtector::new` runs a
    // full AES-256 key schedule and `HeaderProtector::new` an AES-128 one —
    // constructing them per packet dominated the encrypted send path's CPU.
    let mut data_protector = key_epoch.as_ref().map(|ke| {
        Aes256GcmProtector::new(&ke.keys.data_key)
    });
    let mut data_nonce_gen = key_epoch.as_ref().map(|ke| {
        NonceGenerator::new(ke.keys.data_iv)
    });
    let mut header_protector = if header_protect {
        key_epoch.as_ref().map(|ke| {
            HeaderProtector::new(&ke.keys.header_protection_key)
        })
    } else {
        None
    };
    // Reusable scratch for AEAD plaintext + 16-byte tag (per-packet alloc
    // otherwise). Capacity grows to the largest chunk once, then is reused.
    let mut crypt_buf: Vec<u8> = Vec::new();

    // Overhead per packet: crypto adds 16 bytes (GCM tag).
    // Compression can produce smaller data, but we skip compression if output
    // is larger than input, so worst case is still payload_size.
    let crypto_overhead = if key_epoch.is_some() { 16 } else { 0 };
    let wire_size = payload_size + crypto_overhead + WIRE_OVERHEAD;

    // Real-time metrics tracker.
    let mut metrics = TransferMetrics::new();
    let mut delivery_tracker = DeliveryTracker::new();

    // Linux: how far into each stream's source range we have already
    // dropped pages (MADV_DONTNEED) — the send loop drops pages behind
    // each stream's own send position in PAGE_DROP_GRANULARITY steps so
    // peak RSS stays near-constant regardless of file size. Per-stream
    // because streams own disjoint contiguous ranges and send in lockstep:
    // a single global contiguous-prefix frontier would cover only the
    // first stream's range until the very end of the transfer.
    #[cfg(target_os = "linux")]
    let mut pages_dropped_upto: Vec<usize> = streams
        .iter()
        .map(|s| (s.chunk_base as usize).saturating_mul(payload_size))
        .collect();
    #[cfg(target_os = "linux")]
    const PAGE_DROP_GRANULARITY: usize = 16 * 1024 * 1024;

    // The delivery tracker is likewise not pre-loaded. It carried the same
    // fabricated figure, and a delivery *estimator* holding a number that
    // nothing delivered is the same defect one layer down: the controllers
    // read it as measured throughput. It reports zero until the first
    // interval has actually been measured, which is the honest answer.

    // Batched sender selection. Linux gets the full set of specialized
    // backends (paced, zero-copy sendmmsg, io_uring, AF_XDP); other targets
    // always use the cross-platform `Platform` variant, which is backed by
    // ahp-platform-net's best available backend (Windows USO, macOS parallel
    // sendmsg, etc.).
    //
    // One sender per destination port. `PacketSender` binds a single
    // destination, and with a per-stream port run there are several — so the
    // staging loop indexes by stream and the flush loop walks the ones with
    // pending packets. With a single port this is a one-element vector and
    // every path below is the historical one.
    #[cfg(target_os = "linux")]
    let mut senders: Vec<PacketSender> = {
        let use_paced = match pacing_mode {
            "perpacket" => true,
            "batch" | "iouring" | "xdp" => false,
            _ => false, // auto: batch (GSO) is faster on all link types
        };
        let use_iouring = pacing_mode == "iouring";
        let use_xdp = pacing_mode == "xdp";

        // DATA packets go to the data port; control stays on the control socket.
        let gso_available = !use_paced && !use_iouring && !use_xdp
            && ahp_platform_net::linux::probe_gso(data_socket.as_raw_fd());
        let use_zero_copy = zero_copy && !use_paced && !use_iouring && !use_xdp && !gso_available;

        if use_xdp {
            // AF_XDP requires: root, unencrypted, XDP-capable interface.
            // Find the outgoing interface for the destination.
            let ifname = std::env::var("FAVONIUS_XDP_IFACE").unwrap_or_else(|_| "lo".into());
            let src_ip = match data_socket.local_addr() {
                Ok(SocketAddr::V4(a)) => *a.ip(),
                _ => std::net::Ipv4Addr::new(127, 0, 0, 1),
            };
            let dst_ip = match data_remote {
                SocketAddr::V4(a) => *a.ip(),
                _ => std::net::Ipv4Addr::new(127, 0, 0, 1),
            };
            let src_port = data_socket.local_addr().map(|a| a.port()).unwrap_or(0);
            let dst_port = data_remote.port();

            if !zero_copy {
                eprintln!("  AF_XDP: requires --compression none and no encryption, falling back to GSO");
                vec![PacketSender::new(&data_socket, data_remote, batch_size, wire_size, MAX_PACKET, false)]
            } else {
                match XdpBatchSender::new(&ifname, src_ip, dst_ip, src_port, dst_port, batch_size) {
                    Ok(s) => {
                        eprintln!("  AF_XDP: enabled (iface={}, src={}:{}, dst={}:{}) [EXPERIMENTAL]",
                            ifname, src_ip, src_port, dst_ip, dst_port);
                        eprintln!("  WARNING: AF_XDP integration is experimental. Known issues:");
                        eprintln!("    - Ring backpressure not fed to CC (may overflow TX ring)");
                        eprintln!("    - Frame reuse timing not strict (possible in-flight corruption)");
                        eprintln!("    - Loopback interface does not route XDP TX back to RX");
                        eprintln!("    - Works best with veth pairs or physical NICs with native XDP");
                        vec![PacketSender::Xdp(s)]
                    }
                    Err(e) => {
                        eprintln!("  AF_XDP: unavailable ({}), falling back to GSO/sendmmsg", e);
                        vec![PacketSender::new(&data_socket, data_remote, batch_size, wire_size, MAX_PACKET, false)]
                    }
                }
            }
        } else if use_iouring {
            #[cfg(not(all(target_os = "linux", any(target_arch = "x86_64", target_arch = "aarch64"))))]
            {
                // io-uring's prebuilt bindings do not cover this target.
                eprintln!("  io_uring: unavailable on this architecture, using GSO/sendmmsg");
                vec![PacketSender::new(&data_socket, data_remote, batch_size, wire_size, MAX_PACKET, false)]
            }
            #[cfg(all(target_os = "linux", any(target_arch = "x86_64", target_arch = "aarch64")))]
            match IoUringBatchSender::new(&data_socket, data_remote, batch_size, MAX_PACKET) {
                Ok(s) => {
                    eprintln!("  io_uring: enabled (sendmsg SQEs, batch_capacity={}) [SLOWER THAN GSO — debug only]", batch_size);
                    eprintln!("  WARNING: io_uring blocks on submit_and_wait under loss, degrading 60-82% on lossy links");
                    #[cfg(all(target_os = "linux", any(target_arch = "x86_64", target_arch = "aarch64")))]
                    vec![PacketSender::IoUring(s)]
                }
                Err(e) => {
                    eprintln!("  io_uring: unavailable ({}), falling back to GSO/sendmmsg", e);
                    vec![PacketSender::new(&data_socket, data_remote, batch_size, wire_size, MAX_PACKET, false)]
                }
            }
        } else if use_zero_copy {
            eprintln!("  Zero-copy: enabled (2-iovec sendmmsg, no payload copy)");
            data_remotes
                .iter()
                .map(|&r| PacketSender::ZeroCopy(ZeroCopyBatchSender::new(&data_socket, r, batch_size)))
                .collect()
        } else {
            data_remotes
                .iter()
                .enumerate()
                // Only the first announces its backend: they all resolve the
                // same one, and N identical lines read as N different things.
                .map(|(i, &r)| {
                    PacketSender::new_inner(
                        &data_socket, r, batch_size, wire_size, MAX_PACKET, use_paced, i == 0,
                    )
                })
                .collect()
        }
    };

    #[cfg(not(target_os = "linux"))]
    let mut senders: Vec<PacketSender> = {
        // Suppress unused-warning for the Linux-only `zero_copy` flag.
        let _ = zero_copy;
        match pacing_mode {
            "perpacket" | "iouring" | "xdp" => {
                eprintln!(
                    "  warning: --pacing {} is Linux-only; falling back to the cross-platform batched sender",
                    pacing_mode
                );
            }
            _ => {}
        }
        data_remotes
            .iter()
            .enumerate()
            .map(|(i, &r)| {
                PacketSender::new_inner(
                    &data_socket, r, batch_size, wire_size, MAX_PACKET, false, i == 0,
                )
            })
            .collect()
    };

    // ── Stall detector ────────────────────────────────────────────────────
    // If no progress (no new ACKs) for STALL_TIMEOUT seconds, abort the
    // transfer instead of hanging until the daemon's overall timeout.
    const STALL_TIMEOUT: Duration = Duration::from_secs(30);
    let mut last_progress_time = Instant::now();
    let mut last_acked_total: u64 = 0;

    // ── Multi-stream stall diagnostics (FAVONIUS_TRACE_STALL=1) ───────────
    // A rate-limited link with >=3 streams throttles to ~1% of the
    // expected rate while cwnd and RTT both look healthy. These counters
    // separate the candidate causes: whether the staging loop stops
    // because the window is full or because no stream has work, and
    // whether the sender's `in_flight` matches the outstanding count
    // derived from per-stream counters.
    let trace_stall = std::env::var("FAVONIUS_TRACE_STALL").is_ok_and(|v| v == "1");
    // Pacing diagnostics (FAVONIUS_PACE_DEBUG=1). Cheap enough to keep
    // unconditional: two adds per flush.
    let pace_debug = std::env::var("FAVONIUS_PACE_DEBUG").is_ok_and(|v| v == "1");
    let cc_debug = std::env::var("FAVONIUS_CC_DEBUG").is_ok_and(|v| v == "1");
    let mut cc_dbg_at = Instant::now();
    let mut pace_want_us: u64 = 0;   // pacing debt incurred
    let mut pace_got_us: u64 = 0;    // time actually spent paying it
    let mut pace_flushes: u64 = 0;
    let mut pace_pkts: u64 = 0;
    let mut pace_dbg_at = Instant::now();
    let mut pace_dbg_pkts: u64 = 0;
    let mut pace_dbg_want: u64 = 0;
    let mut pace_dbg_got: u64 = 0;
    let mut pace_dbg_flushes: u64 = 0;

    // Carried pacing debt, microseconds, signed. Positive means the sender
    // owes the link idle time; negative is credit — it is behind the paced
    // schedule and may send without waiting until it has caught up.
    //
    // Without the carry the deadline is `t_stage + owed` recomputed from
    // each pass's own start, so a pass that overruns its budget discards
    // the overrun while a pass that finishes early still sleeps its full
    // residual. Overruns never bank; residuals always spend. Measured on
    // the LAN rig 2026-08-11 that made the sender sleep 2.7x more than its
    // own debt model justifies — 28.3% of loop wall clock against 10.5% —
    // while the commanded rate was already 1.8x what the path delivered.
    // Measured.
    //
    // **Off by default, but a live candidate rather than a rejected one.**
    // `FAVONIUS_PACE_DEBT=1` enables it. n=10 pairs on the LAN rig, order
    // counterbalanced ABBA, one binary (measured; see the congestion-control notes):
    //
    //                      per-pass   carried    delta   paired t
    //   throughput MB/s       33.50     35.81    +6.9%      +1.15
    //   pacer wait %          30.49     21.55   -29.3%      -2.83
    //   window blocked %      19.01     18.32    -3.6%      -0.13
    //
    // It removes 29% of the pacing sleep (t=-2.83) at no measured cost:
    // window-blocked time does not move. Throughput is +6.9% and NOT
    // significant -- MDE at n=10 is 18.9% and the CI is -6.7% to +20.5%, so
    // an effect this size is simply invisible on this rig. It does not ship
    // on that. Resolving it needs ~75 pairs here, or many fewer on a wired
    // path: the paired sd is 6.38 MB/s and almost all of it is the radio.
    //
    // An earlier 50 ms credit bound measured the opposite -- throughput
    // -2.4%, blocked +72% -- and that result is superseded, not merely
    // improved on. At these rates 50 ms is ~3.9 MB, six times the cwnd, so
    // it saturated every pass and the arm was "pacing off" rather than
    // "debt carried". The bound is now `pacing_burst()`, the control's own
    // burst envelope, so the two arms burst equally hard.
    //
    // The blocked-time rise seen then was also mis-explained here as loss
    // shrinking cwnd. Measured, the carried arm's cwnd was *larger*
    // (725.9 KB against 643.0). An unspaced sender fills the same window
    // sooner and waits on ACKs; no cwnd step is involved.
    //
    // Kept behind the flag rather than deleted for one reason: the
    // mechanism that defeats it is specific to a shared radio. On a wired
    // path, where loss is not airtime contention, the trade may go the
    // other way -- and that is the same loss-origin question as
    // the engineering log. Do not enable it without measuring on
    // the path in question; on wifi it is strictly worse.
    // The absolute instant at which the next flush is permitted to begin.
    // Advancing it by `owed` per flush is a leaky bucket, and it carries the
    // debt without any explicit accounting: an overrunning pass leaves the
    // schedule in the past and the next pass sends at once, an early pass
    // leaves it ahead and the next pass waits. Nothing is charged or
    // forgiven, so the wait loop's sub-50us early break cannot accumulate
    // into drift — the failure that made a first attempt sleep *more*.
    let mut pace_next_send: Option<Instant> = None;
    let carry_pace_debt = std::env::var("FAVONIUS_PACE_DEBT")
        .map(|v| v == "1")
        .unwrap_or(false);
    let mut pace_credit_clamps: u64 = 0;
    let mut pace_skipped_sleeps: u64 = 0;
    // Overrun the per-pass reset throws away, summed per pass. Entry 54
    // estimated this as `max(0, sum(owed) - sum(work))`, an end-of-run
    // aggregate that ignores temporal order and therefore bounds nothing:
    // a pass that must sleep 100us before a later pass's work exists is
    // invisible to it. This is the quantity that estimate was reaching for,
    // measured where it actually occurs.
    let mut pace_overrun_discarded_us: u64 = 0;
    // Credit the carried path declines to bank because it hit the bound.
    let mut pace_credit_discarded_us: u64 = 0;
    // Chunks staged from one stream before moving to the next. 1 restores
    // the historical strict per-packet round-robin, for A/B from one binary.
    let stream_run: u32 = std::env::var("FAVONIUS_STREAM_RUN")
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|k: &u32| *k >= 1 && *k <= 4096)
        // Default 1 on one socket = the historical per-packet round-robin. A
        // run of 128 measured +13% and -36% drops at 4 streams, but only
        // t=1.80 at n=3, and it is not the dominant term there anyway (the
        // ACK rate is). Not significant, so not the default.
        //
        // Per-stream sockets change that from an optimisation into a
        // requirement, and this coupling is the least obvious thing in the
        // design. Each destination now has its own staging buffer, so strict
        // per-packet round-robin hands every sender exactly one packet per
        // rotation and every GSO batch collapses to a single datagram — the
        // send path would lose more than the receive path gains. A run of 32
        // keeps each batch worth a syscall while still turning over all four
        // streams inside a window.
        .unwrap_or(if n_dest > 1 { 32 } else { 1 });
    let mut stream_run_pos: u32 = 0;
    let mut brk_burst: u64 = 0;    // stopped: pacing burst quantum reached
    // Where the wall clock goes between two flushes.
    //
    // Six parameter sweeps failed to move Model's ~330 Mbit attractor, and
    // what survives is that the commanded rate and the wire rate differ by
    // a fifth *invariantly*. That is a question about the pass, not about a
    // constant: `bw_next = gain x ratio x bw` cannot climb while
    // `gain x ratio` is 1. See the CC dynamics notes.
    let mut prof_stage_us: u64 = 0;   // compress + encrypt + stage
    let mut prof_flush_us: u64 = 0;   // the sendmmsg/GSO syscall itself
    // Of that, the part actually on-CPU. wall - cpu is time the thread spent
    // blocked inside the syscall, i.e. backpressure rather than work.
    let mut prof_flush_cpu_us: u64 = 0;
    let mut prof_wait_us: u64 = 0;    // the pacing wait, feedback included
    let mut prof_fb_us: u64 = 0;      // process_feedback inside that wait
    let mut prof_drain_us: u64 = 0;   // post-flush feedback drain
    let mut prof_passes: u64 = 0;
    // Feedback volume, to separate "more datagrams" from "each costs more".
    // Model spends 285us/pass in `drain` against Classic's 1.2us for the
    // same chunk count, and which of those two it is decides the fix.
    let mut prof_fb_dgrams: u64 = 0;
    let mut brk_window: u64 = 0;   // stopped: in_flight >= effective_cwnd
    let mut brk_nowork: u64 = 0;   // stopped: no stream had work
    let mut brk_batch: u64 = 0;    // stopped: batch buffer full
    let mut staged_total: u64 = 0; // packets staged across all passes
    // Passes that never entered the staging block at all. Every `brk_*`
    // counter above is reachable only from inside that block, so a pass that
    // arrives already window-blocked stages nothing and increments nothing --
    // and `prof_passes` likewise counts only passes that staged. Both
    // instruments were therefore blind to the same branch: on the 2026-08-11
    // LAN measurement GATE_SUMMARY reported `window=7.6%` for a transfer that
    // spent 29% of its wall clock window-blocked, which sent the TCP-gap
    // investigation looking at the send path for an hour. The send path was
    // moving 45.2 MiB/s against TCP's 46.0 the whole time.
    let mut blocked_window: u64 = 0;  // pass skipped: window full on entry
    let mut blocked_nowork: u64 = 0;  // pass skipped: no stream had work
    let mut prof_blocked_us: u64 = 0; // wall clock spent in that wait
    let mut last_trace = Instant::now();
    // Cadence of the retransmit timeout scan, independent of feedback.
    const RETX_SCAN_INTERVAL: Duration = Duration::from_millis(20);
    let mut last_retx_scan = Instant::now();

    // Post-transfer control packets observed while draining feedback (see
    // `process_feedback`): the daemon's FINISH reply and, for encrypted
    // transfers, its session-ticket Checkpoint. Consumed by the post-FINISH
    // wait below.
    let mut finish_seen = false;
    let mut checkpoint_payload: Option<Bytes> = None;

    // KEY_UPDATE retransmission state: (epoch, remaining resends, sealing
    // keys). The update is fire-and-forget UDP, so re-send it a bounded
    // number of times across subsequent send-loop iterations. The daemon
    // applies it only once (epoch-guarded), so duplicates are harmless.
    // The sealing keys are the OUTGOING epoch's session keys (see the
    // rotation site below), reused verbatim for every resend.
    const KEY_UPDATE_RESENDS: u8 = 3;
    let mut pending_key_update: Option<(u64, u8, Option<SessionKeys>)> = None;

    // ── Data transfer loop ───────────────────────────────────────────────
    while streams.iter().map(|s| s.n_acked).sum::<u64>() < total_chunks {
        // Straggler accounting: when did each stream finish? Cheap (a
        // handful of streams) and it is the only way to see the tail
        // serialisation that static partitioning creates.
        for s in streams.iter_mut() {
            if s.done_at.is_none() && s.n_acked >= s.chunk_count {
                s.done_at = Some(start.elapsed().as_secs_f64());
            }
        }
        let has_work = streams.iter().any(|s| s.has_work());

        // Effective window: CC window floored by the link-type minimum.
        let effective_cwnd = cc.congestion_window().max(min_cwnd_floor);

        // How many packets this pass may flush as one burst. See
        // `PACING_BURST`: the cap is a pacing debt, not a packet count, so
        // it tracks whatever rate the controller is currently commanding.
        let burst_quantum = {
            let p = cc.pacing_interval(wire_size);
            if p.is_zero() {
                batch_size
            } else {
                ((pacing_burst().as_secs_f64() / p.as_secs_f64()) as usize)
                    .clamp(1, batch_size)
            }
        };
        let mut staged_this_pass: usize = 0;

        if has_work && in_flight < effective_cwnd {
            // One timestamp per batch — avoids per-packet vDSO call.
            let batch_ts = timestamp_us();
            let t_stage = Instant::now();

            // Stage packets into the batch buffer, round-robin across streams.
            loop {
                if in_flight >= effective_cwnd { brk_window += 1; break; }
                // Any full sender ends the pass: the flush below empties
                // every one that has packets, so stopping at the first full
                // buffer keeps all the destinations on one cadence.
                if senders.iter().any(|s| s.is_full()) { brk_batch += 1; break; }
                if staged_this_pass >= burst_quantum { brk_burst += 1; break; }
                // Find next stream with work, starting from current_stream.
                let mut found = false;
                for _ in 0..streams.len() {
                    if streams[current_stream].has_work() {
                        found = true;
                        break;
                    }
                    current_stream = (current_stream + 1) % streams.len();
                }
                if !found {
                    brk_nowork += 1;
                    break;
                }

                let n_streams = streams.len();
                // Which destination port this stream's packets go to.
                // Streams past the end of the daemon's port run share the
                // last one — the daemon has to publish the run before it
                // knows how many streams there are, so the two counts need
                // not match and the extras must land somewhere real.
                let dest = current_stream.min(senders.len() - 1);
                let stream = &mut streams[current_stream];

                // Pop retx entries, skipping any that were acked while queued.
                let local_ci = loop {
                    if let Some(retx) = stream.retx_queue.pop_front() {
                        // No longer queued — a later timeout may legitimately
                        // re-queue it if this transmission is also lost.
                        stream.flags[retx as usize] &= !CHUNK_IN_RETX;
                        if !stream.acked[retx as usize] {
                            retransmits += 1;
                            break retx;
                        }
                        continue;
                    } else if stream.next_local < stream.chunk_count {
                        let c = stream.next_local;
                        stream.next_local += 1;
                        if stream.acked[c as usize] {
                            continue; // skip already-acked chunk (resume)
                        }
                        break c;
                    } else {
                        current_stream = (current_stream + 1) % n_streams;
                        break u64::MAX;
                    }
                };
                if local_ci == u64::MAX {
                    continue;
                }

                let global_ci = stream.to_global(local_ci);
                let offset = (global_ci as usize) * payload_size;
                let end = (offset + payload_size).min(file_data.len());
                let chunk_data = &file_data[offset..end];

                // Pipeline: compress (optional) → encrypt (optional) → stage.
                // Per-chunk: skip compression if output >= input (incompressible).
                // The COMPRESSED flag is set per-packet so the receiver knows.
                let compressed_data;
                let chunk_compressed;
                let data_after_compress: &[u8] = if let (Some(ref comp), Some(ref mut ctx)) = (&compressor, &mut compress_ctx) {
                    compressed_data = comp.compress_with(ctx, chunk_data)
                        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("{e}")))?;
                    if compressed_data.len() < chunk_data.len() {
                        chunk_compressed = true;
                        &compressed_data
                    } else {
                        chunk_compressed = false;
                        chunk_data
                    }
                } else {
                    chunk_compressed = false;
                    chunk_data
                };

                // Per-packet COMPRESSED flag, passed to `stage_data` so
                // backends without post-stage mutation (macOS) can apply it
                // pre-stage; post-stage backends get it via
                // `set_last_packet_flag` below.
                let compressed_flag = if chunk_compressed { 0x0010 } else { 0 };

                let _pkt_size = if let Some(ref mut epoch) = key_epoch {
                    // The protectors are built alongside `key_epoch` above and
                    // rebuilt on every rotation below, so they are always
                    // present when `key_epoch` is.
                    let protector = data_protector.as_ref().expect("data protector matches key epoch");
                    let nonce_gen = data_nonce_gen.as_ref().expect("nonce generator matches key epoch");
                    let nonce = nonce_gen.nonce_for(seq);
                    let pt_len = data_after_compress.len();
                    crypt_buf.clear();
                    crypt_buf.reserve(pt_len + 16);
                    crypt_buf.extend_from_slice(data_after_compress);
                    crypt_buf.resize(pt_len + 16, 0); // space for the GCM tag
                    // AEAD associated data: the logical fixed header,
                    // including the COMPRESSED flag (see `data_header_aad`).
                    let aad = data_header_aad(
                        conn_id, seq, stream.id, batch_ts,
                        DATA_PAYLOAD_HEADER_SIZE + crypt_buf.len(), compressed_flag,
                    );
                    let enc_len = protector.encrypt_in_place(&nonce, &aad, &mut crypt_buf, pt_len)
                        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("{e}")))?;
                    let sz = senders[dest].stage_data(
                        conn_id, seq, stream.id, 0, global_ci, 0, batch_ts, &crypt_buf[..enc_len],
                        HeaderTransforms {
                            hp: header_protector.as_ref(),
                            flags: compressed_flag,
                        },
                    );

                    // Set the per-packet COMPRESSED flag BEFORE header
                    // protection: the CRC refresh must cover the unprotected
                    // header, and HP does not touch the flags or CRC bytes.
                    if chunk_compressed {
                        senders[dest].set_last_packet_flag(0x0010);
                    }

                    // Apply header protection if enabled.
                    if let Some(ref hp) = header_protector {
                        senders[dest].protect_last_packet_header(hp);
                    }

                    // Track packet count for key rotation.
                    if epoch.on_packet_encrypted() {
                        epoch.rotate()
                            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("{e}")))?;
                        // Rebuild the per-epoch crypto objects from the new keys.
                        data_protector = Some(Aes256GcmProtector::new(&epoch.keys.data_key));
                        data_nonce_gen = Some(NonceGenerator::new(epoch.keys.data_iv));
                        if header_protect {
                            header_protector = Some(HeaderProtector::new(&epoch.keys.header_protection_key));
                        }
                        tracing::info!(epoch = epoch.epoch, "sender key rotation");
                        // Send KEY_UPDATE to the daemon's DATA port — during a
                        // transfer the daemon only reads its data socket, where
                        // the KeyUpdate handler rotates its keys. It is
                        // fire-and-forget UDP, so it is also retransmitted a
                        // bounded number of times across subsequent loop
                        // iterations (see below).
                        //
                        // S3: the update is AEAD-sealed with the OUTGOING
                        // epoch's control keys — the daemon still holds them
                        // (it rotates on receipt), so the first delivery
                        // authenticates under its current keys and
                        // retransmissions arriving after its rotation
                        // authenticate via its previous-epoch grace window.
                        // A forged KEY_UPDATE can no longer force a
                        // premature rotation.
                        let ku_epoch = epoch.epoch;
                        let ku_seal_keys = epoch.previous_keys().cloned();
                        let ku_payload = encode_key_update(ku_epoch);
                        send_ctrl_sealed(&data_socket, data_remote, PacketType::KeyUpdate, conn_id, seq, &ku_payload, ku_seal_keys.as_ref()).await?;
                        pending_key_update = Some((ku_epoch, KEY_UPDATE_RESENDS, ku_seal_keys));
                    }

                    sz
                } else {
                    let sz = senders[dest].stage_data(
                        conn_id, seq, stream.id, 0, global_ci, 0, batch_ts, data_after_compress,
                        HeaderTransforms { hp: None, flags: compressed_flag },
                    );
                    // Set per-packet COMPRESSED flag in the staged header if
                    // this chunk was actually compressed. Flags at header
                    // bytes [2..4]; the header CRC is refreshed to cover them.
                    if chunk_compressed {
                        senders[dest].set_last_packet_flag(0x0010);
                    }
                    sz
                };

                let now = Instant::now();
                stream.sent_us[local_ci as usize] = elapsed_us(start);
                // CC packet numbers are global chunk indices (not the wire
                // sequence `seq`, which retransmits inflate) so that sent /
                // ack / loss / epoch tracking all live in one sequence space.
                cc.on_packet_sent(global_ci, wire_size, now);
                staged_total += 1;
                staged_this_pass += 1;
                in_flight += wire_size;
                seq += 1;
                packets_sent += 1;

                // Advance to the next stream only after a *run* of chunks,
                // not after every packet.
                //
                // Strict per-packet round-robin is maximal scatter: with 4
                // streams, consecutive datagrams carry chunks from four
                // regions of the file a quarter of a file apart, and the
                // receiver writes each one into its mmap at that offset. So
                // the receive path touches four distant pages per four
                // packets instead of one page per three, its drain slows,
                // and the 4 MB socket buffer -- which cannot be enlarged,
                // being already at `net.core.rmem_max` -- overflows. Loopback,
                // where there is no network to lose anything: 1 stream drops
                // 0 packets at 469 MB/s, 4 streams drop 4239 and manage 303.
                // Every drop is a retransmit.
                //
                // A run restores locality on the wire without changing the
                // stream abstraction: ranges, retx queues and ACK bitmaps are
                // all still per-stream. Measured; see the congestion-control notes.
                stream_run_pos += 1;
                if stream_run_pos >= stream_run {
                    stream_run_pos = 0;
                    current_stream = (current_stream + 1) % streams.len();
                }
            }

            prof_stage_us += t_stage.elapsed().as_micros() as u64;
            prof_passes += 1;

            if senders[0].is_paced() {
                // Paced mode: packets are already sent by the pacer thread.
                // Update the pacing interval from the CC, then drain ACKs.
                let pace = {
                    let cc_pace = cc.pacing_interval(wire_size);
                    if effective_cwnd > cc.congestion_window() && !cc_pace.is_zero() {
                        let ratio = cc.congestion_window() as f64 / effective_cwnd as f64;
                        Duration::from_secs_f64(cc_pace.as_secs_f64() * ratio)
                    } else {
                        cc_pace
                    }
                };
                for s in senders.iter_mut() {
                    s.set_pacing_interval(pace);
                }
            } else {
                // Batch mode: flush then pace.
                let total_pending: usize = senders.iter().map(|s| s.pending()).sum();
                if total_pending > 0 {
                    let n_flushed = total_pending;
                    let t_flush = Instant::now();
                    let cpu_flush = thread_cpu_us();
                    // Only the senders holding packets: an empty flush is a
                    // syscall that sends nothing.
                    for s in senders.iter_mut() {
                        if s.pending() > 0 {
                            s.flush()?;
                        }
                    }
                    prof_flush_us += t_flush.elapsed().as_micros() as u64;
                    prof_flush_cpu_us += thread_cpu_us().saturating_sub(cpu_flush);

                    let pace = {
                        let cc_pace = cc.pacing_interval(wire_size);
                        if effective_cwnd > cc.congestion_window() && !cc_pace.is_zero() {
                            let ratio = cc.congestion_window() as f64 / effective_cwnd as f64;
                            Duration::from_secs_f64(cc_pace.as_secs_f64() * ratio)
                        } else {
                            cc_pace
                        }
                    };
                    if !pace.is_zero() {
                        // Record the debt the send *incurred*, before the
                        // cap. Accumulating the capped value instead makes
                        // want and got agree by construction, which is the
                        // same self-referential mistake this whole line of
                        // instrumentation exists to detect -- and it did
                        // exactly that until a negative test caught it.
                        let owed = pace.saturating_mul(n_flushed as u32);
                        let batch_pace = owed.min(PACING_SLEEP_MAX);
                        pace_want_us += owed.as_micros() as u64;
                        pace_flushes += 1;
                        pace_pkts += n_flushed as u64;
                        let pace_started = Instant::now();
                        // The deadline runs from the start of the *pass*,
                        // not from the end of the flush.
                        //
                        // The pacing debt describes how long the packets
                        // just sent should occupy the link. Sleeping that
                        // long *after* doing the work adds the work to the
                        // interval instead of fitting it inside, so the
                        // achieved rate is `wait / (wait + overhead)` of the
                        // commanded rate — systematically, on every pass.
                        //
                        // Profiled at 1 Gbit, cross-country (PROFILE_SUMMARY):
                        //
                        //   model    wait 995.4us  overhead 216.6us -> 0.821
                        //   classic  wait 448.3us  overhead  80.3us -> 0.848
                        //
                        // against measured `wire/ach` of 0.800 and 0.815.
                        //
                        // For a window-driven controller that is a 15-18%
                        // throughput tax. For a rate-paced one it is worse
                        // than a tax, because the controller derives its next
                        // rate from the delivery it measures: the loop is
                        // `bw <- gain x ratio x bw`, which cannot climb while
                        // `gain x ratio` is 1, and 1.25 x 0.8 is exactly 1.
                        // That is the ~330 Mbit attractor in
                        // the CC dynamics notes, and it is why six
                        // parameter sweeps could not move it: doubling
                        // PACING_BURST doubles the debt *and* the per-pass
                        // work, so the ratio is scale-invariant.
                        // Measured on, against off, one binary and one
                        // batch, 1 Gbit, n=3 (`dupA` / `dupB`):
                        //
                        //   wifi     +38.6% cross-country, +41.9% satellite
                        //   rl       +10.4% / +1.5%
                        //   encrypt   +1.0% / +5.5%
                        //   classic   +1.9% / +3.7%
                        //   udt       +2.9% / -11.1%
                        //   fair       +0.5% / timeout in both arms
                        //
                        // Five of seven improve and `fair`'s satellite
                        // timeout is pre-existing rather than caused here —
                        // an earlier reading that blamed this change was a
                        // cross-batch comparison.
                        //
                        // It composes with `PROBE_BW_GAINS[0]` rather than
                        // duplicating it. A 2x2 at probe 2.0 suggested the
                        // two were substitutes; at 1.75, Model reads 80.3
                        // MB/s cross-country with both against 75.1 for the
                        // gain alone and 61.1 for this alone. 2.0 is past
                        // Model's optimum, which is why the pairing there
                        // looked redundant.
                        // Two formulations of the same intent. The legacy one
                        // measures from this pass's start, which silently
                        // discards any overrun; the carried one keeps a
                        // signed running balance, so time the pass spent
                        // over budget offsets the next pass's sleep instead
                        // of evaporating.
                        let deadline = if carry_pace_debt {
                            let now = pace_started;
                            // How far behind schedule the sender may be.
                            let floor = now
                                .checked_sub(pacing_credit_max())
                                .unwrap_or(now);
                            let base = match pace_next_send {
                                Some(t) if t >= floor => t,
                                Some(t) => {
                                    pace_credit_discarded_us +=
                                        floor.saturating_duration_since(t).as_micros() as u64;
                                    pace_credit_clamps += 1;
                                    floor
                                }
                                None => now,
                            };
                            let next = base + owed;
                            pace_next_send = Some(next);
                            if next <= now {
                                pace_skipped_sleeps += 1;
                            }
                            // Absolute, so an early break leaves the debt on
                            // the schedule rather than needing to be charged.
                            next.min(now + PACING_SLEEP_MAX)
                        } else {
                            // What the per-pass reset discards: this pass's
                            // work beyond its own budget, which the next
                            // pass will not inherit.
                            let work = t_stage.elapsed();
                            if work > batch_pace {
                                pace_overrun_discarded_us +=
                                    (work - batch_pace).as_micros() as u64;
                            }
                            t_stage + batch_pace
                        };
                        while Instant::now() < deadline {
                            if let Ok((len, _)) = socket.try_recv_from(&mut recv_buf) {
                                prof_fb_dgrams += 1;
                                let t_fb = Instant::now();
                                process_feedback(
                                    &recv_buf[..len],
                                    &mut streams, &mut in_flight,
                                    wire_size,
                                    &mut *cc, &mut delivery_tracker, &mut metrics, start,
                                    &mut finish_seen, &mut checkpoint_payload, &mut rtt_est,
                                );
                                prof_fb_us += t_fb.elapsed().as_micros() as u64;
                            } else {
                                let remaining = deadline.saturating_duration_since(Instant::now());
                                if remaining > Duration::from_micros(50) {
                                    std::thread::sleep(Duration::from_micros(50));
                                } else {
                                    break;
                                }
                            }
                        }
                        // Actual, for the instrumentation only — the debt was
                        // already charged its planned amount above, so
                        // `want` and `got` stay independently measured and
                        // can still disagree, which is the point of them.
                        let slept_us = pace_started.elapsed().as_micros() as u64;
                        pace_got_us += slept_us;
                        prof_wait_us += slept_us;
                    }
                }
            }

            // Drain any remaining ACKs / NACKs.
            let t_drain = Instant::now();
            while let Ok((len, _)) = socket.try_recv_from(&mut recv_buf) {
                prof_fb_dgrams += 1;
                process_feedback(
                    &recv_buf[..len],
                    &mut streams, &mut in_flight,
                    wire_size,
                    &mut *cc, &mut delivery_tracker, &mut metrics, start,
                    &mut finish_seen, &mut checkpoint_payload, &mut rtt_est,
                );
            }
            prof_drain_us += t_drain.elapsed().as_micros() as u64;
        } else {
            // Attributed before the wait, not after: with work pending, a
            // full window is what stopped this pass. With no work the window
            // is not what stopped it -- everything is already out and this is
            // tail drain -- so the two are not interchangeable and the order
            // of these tests is the attribution.
            if has_work {
                blocked_window += 1;
            } else {
                blocked_nowork += 1;
            }
            let t_blocked = Instant::now();
            // Window full or nothing to send — wait for feedback on the
            // CONTROL socket. The daemon sends ACK bitmaps, NACK ranges and
            // the FINISH reply to the address the HELLO/MANIFEST came from
            // (this socket), never to our data port — waiting on
            // `data_socket` here would always burn the full 20ms timeout
            // while real ACKs sit unread, causing spurious retransmissions
            // exactly when the window is full. (Non-feedback packets that
            // can arrive here, e.g. a Checkpoint session ticket, are decoded
            // and ignored by `process_feedback`, and the post-FINISH wait
            // below re-reads this same socket.)
            match tokio::time::timeout(
                Duration::from_millis(20),
                socket.recv_from(&mut recv_buf),
            )
            .await
            {
                Ok(Ok((len, _))) => {
                    process_feedback(
                        &recv_buf[..len],
                        &mut streams, &mut in_flight,
                        wire_size,
                        &mut *cc, &mut delivery_tracker, &mut metrics, start,
                        &mut finish_seen, &mut checkpoint_payload, &mut rtt_est,
                    );
                    // Drain all remaining available ACKs before looping back
                    // to send — avoids re-entering the 20ms timeout when
                    // multiple ACKs arrived while we were blocked.
                    while let Ok((len, _)) = socket.try_recv_from(&mut recv_buf) {
                        process_feedback(
                            &recv_buf[..len],
                            &mut streams, &mut in_flight,
                            wire_size,
                            &mut *cc, &mut delivery_tracker, &mut metrics, start,
                            &mut finish_seen, &mut checkpoint_payload, &mut rtt_est,
                        );
                    }
                }
                _ => {}
            }
            prof_blocked_us += t_blocked.elapsed().as_micros() as u64;
        }

        // ── Retransmit timeout scan ──────────────────────────────────────
        // Runs on its own clock, not as the fallthrough of the feedback
        // `select`. It used to live only in that select's timeout arm, so
        // it ran only when *no* packet arrived for 20 ms — and the daemon
        // ACKs every stream on a 15 ms timer, so at four streams an ACK
        // always landed inside the window and the scan never ran at all.
        // Loss was therefore never detected, dropped chunks were never
        // retransmitted, and the window silently filled with chunks that
        // could never be acked: 4 streams over a rate-limited link crawled
        // at ~2% of capacity with `retx` frozen and `in_flight` pinned at
        // the window. Perversely, more streams meant more ACKs meant less
        // loss recovery.
        if last_retx_scan.elapsed() >= RETX_SCAN_INTERVAL {
            last_retx_scan = Instant::now();

                // Timeout — recalculate in_flight and queue stale chunks.
                let total_retx_pending: usize = streams.iter().map(|s| s.retx_queue.len()).sum();
                let total_sent: u64 = streams.iter().map(|s| s.next_local.min(s.chunk_count)).sum();
                let total_acked_now: u64 = streams.iter().map(|s| s.n_acked).sum();
                // `saturating_sub`, not `-`. These two counters are
                // accumulated from different places -- `next_local` advances
                // in the send loop, `n_acked` in feedback processing -- and
                // nothing structurally guarantees the second cannot briefly
                // exceed the first (a duplicate ACK counted once too often
                // is enough). A raw u64 subtraction wraps to ~1.8e19 there,
                // `in_flight` becomes enormous, and `can_send` is false for
                // the rest of the transfer. That is precisely the symptom
                // described in the comment above this block, and it is the
                // leading candidate for the multi-stream stall recorded in
                // the CC dynamics notes.
                //
                // Whether it is *the* cause is unproven -- a wrap would stop
                // progress dead and the stall creeps forward at ~1% -- but a
                // counter subtraction that can wrap has no defensible
                // version, and in a debug build this line is a panic.
                let outstanding = total_sent.saturating_sub(total_acked_now) as usize;
                in_flight = outstanding.saturating_sub(total_retx_pending)
                    * wire_size;

                // Re-derive the timer from the live RTT estimate: the
                // path may be nothing like the probe (route change,
                // queue build-up), and a stale timer is exactly what
                // turns one late ACK into a retransmit storm.
                let retx_timeout = rtt_est.rto_with_min(retx_floor).min(RETX_TIMEOUT_MAX);

                let now_us = elapsed_us(start);
                let retx_timeout_us = retx_timeout.as_micros() as u32;
                let now = Instant::now();
                let mut lost_packets: Vec<u64> = Vec::new();
                for stream in &mut streams {
                    let lost = stream.queue_timed_out(now_us, retx_timeout_us);
                    in_flight = in_flight.saturating_sub(wire_size * lost.len());
                    lost_packets.extend(lost);
                }
                if !lost_packets.is_empty() {
                    metrics.record_loss(lost_packets.len() as u64);
                    // Only signal timeout losses to CC if it wants
                    // them. The rate-based CCs (UDT, Model, RL) opt
                    // out and respond only to receiver-detected loss
                    // (NACK ranges, see process_nack). Now that the
                    // timer above is RTT-derived rather than a fixed
                    // 100 ms, a timeout is real evidence of a drop, so
                    // window-based Classic opts in.
                    if cc.wants_timeout_loss() {
                        cc.on_packet_lost(&lost_packets, now);
                    }
                }
                    }

        // Retransmit a pending KEY_UPDATE across subsequent iterations,
        // sealed with the same outgoing-epoch control keys as the first send.
        if let Some((ku_epoch, ref mut resends_left, ref ku_keys)) = pending_key_update {
            if *resends_left > 0 {
                let ku_payload = encode_key_update(ku_epoch);
                let _ = send_ctrl_sealed(&data_socket, data_remote, PacketType::KeyUpdate, conn_id, seq, &ku_payload, ku_keys.as_ref()).await;
                *resends_left -= 1;
            }
        }

        // Periodic real-time metrics report.
        let n_acked_now: u64 = streams.iter().map(|s| s.n_acked).sum();
        metrics.maybe_report(n_acked_now, total_chunks, cc.congestion_window(), retransmits, payload_size as u64);

        // FAVONIUS_CC_DEBUG=1: one line of controller-internal state per
        // sample interval. `congestion_window()` alone cannot explain a
        // transition, and every failure worth chasing here is a transition:
        // a measured collapse could previously only be described as
        // "cwnd=101KB, then cwnd=18KB", with no way to say which state the
        // controller was in or whether its bandwidth filter had emptied.
        if cc_debug && cc_dbg_at.elapsed() >= CC_DEBUG_INTERVAL {
            if let Some(line) = cc.diag_line() {
                eprintln!("  CC t={:.2}s {}", start.elapsed().as_secs_f64(), line);
            }
            cc_dbg_at = Instant::now();
        }

        // FAVONIUS_PACE_DEBUG=1: commanded vs achieved send rate.
        //
        // A rate-based controller can only be judged against what actually
        // left the host. `cmd` is what the CC asked for, `ach` is what the
        // wire saw over the last window, and `slp` compares the pacing debt
        // incurred with the time actually spent paying it -- if those
        // diverge the pacer is the thing under test, not the controller.
        if pace_debug && pace_dbg_at.elapsed() >= Duration::from_secs(1) {
            let secs = pace_dbg_at.elapsed().as_secs_f64();
            let sent_delta = packets_sent - pace_dbg_pkts;
            let ach_mbit = sent_delta as f64 * wire_size as f64 * 8.0 / secs / 1e6;
            let p = cc.pacing_interval(wire_size);
            let cmd_mbit = if p.is_zero() {
                f64::INFINITY
            } else {
                wire_size as f64 * 8.0 / p.as_secs_f64() / 1e6
            };
            eprintln!(
                "  PACE cmd={:.1}Mbit ach={:.1}Mbit ratio={:.2} quantum={} \
slp_want={:.0}ms slp_got={:.0}ms flushes={} inflight={}KB cwnd={}KB",
                cmd_mbit, ach_mbit,
                if cmd_mbit.is_finite() && cmd_mbit > 0.0 { ach_mbit / cmd_mbit } else { 0.0 },
                burst_quantum,
                (pace_want_us - pace_dbg_want) as f64 / 1000.0,
                (pace_got_us - pace_dbg_got) as f64 / 1000.0,
                pace_flushes - pace_dbg_flushes,
                in_flight / 1024,
                cc.congestion_window() / 1024,
            );
            pace_dbg_at = Instant::now();
            pace_dbg_pkts = packets_sent;
            pace_dbg_want = pace_want_us;
            pace_dbg_got = pace_got_us;
            pace_dbg_flushes = pace_flushes;
        }

        // Linux: publish the slowest stream's send position for the
        // prefetch thread, and drop source pages behind each stream's own
        // position. A retransmit into a dropped range simply re-faults the
        // page from the page cache with identical contents.
        #[cfg(target_os = "linux")]
        if let Some(ref map) = file_map {
            let mut slowest = usize::MAX;
            for (si, s) in streams.iter().enumerate() {
                let sent_bytes = ((s.chunk_base + s.next_local.min(s.chunk_count)) as usize)
                    .saturating_mul(payload_size)
                    .min(file_data.len());
                slowest = slowest.min(sent_bytes);
                if sent_bytes >= pages_dropped_upto[si] + PAGE_DROP_GRANULARITY {
                    drop_mapping_pages(map, pages_dropped_upto[si], sent_bytes - pages_dropped_upto[si]);
                    pages_dropped_upto[si] = sent_bytes;
                }
            }
            if slowest != usize::MAX {
                prefetch_pos.store(slowest as u64, Ordering::Relaxed);
            }
        }

        if trace_stall && last_trace.elapsed() >= Duration::from_secs(1) {
            last_trace = Instant::now();
            let sent: u64 = streams.iter().map(|s| s.next_local.min(s.chunk_count)).sum();
            let acked: u64 = streams.iter().map(|s| s.n_acked).sum();
            let retxq: usize = streams.iter().map(|s| s.retx_queue.len()).sum();
            // What in_flight *should* be, from authoritative counters.
            let derived = sent.saturating_sub(acked) as usize * wire_size;
            let per_stream: Vec<String> = streams.iter().map(|s| {
                format!("{}:{}/{}/{}", s.id, s.next_local, s.n_acked, s.retx_queue.len())
            }).collect();
            eprintln!(
                "STALL in_flight={} derived={} delta={} cwnd={} eff_cwnd={} pace_us={} \
staged={} brk[win={} nowork={} batch={} burst={}] blocked[win={} nowork={}] \
retxq={} streams[id:next/ackd/retx]={}",
                in_flight, derived,
                in_flight as i64 - derived as i64,
                cc.congestion_window(), effective_cwnd,
                cc.pacing_interval(wire_size).as_micros(),
                staged_total, brk_window, brk_nowork, brk_batch, brk_burst,
                blocked_window, blocked_nowork, retxq,
                per_stream.join(" "),
            );
        }

        // Stall detector: abort if no new ACKs for STALL_TIMEOUT.
        if n_acked_now > last_acked_total {
            last_acked_total = n_acked_now;
            last_progress_time = Instant::now();
        } else if last_progress_time.elapsed() > STALL_TIMEOUT {
            // Never having received a single ACK is a different failure from
            // stalling partway, and it has a different cause. The peer is
            // reachable — the handshake completed or we would not be here —
            // so silence on the data path means it is discarding what we
            // send: an unknown packet type, a feature it does not implement,
            // a protocol version mismatch. All of those are dropped without
            // comment (`process_feedback` returns on any decode error), so
            // the only symptom is this timeout.
            //
            // Saying "stalled at 0.0%" names the wrong thing and sends the
            // reader looking at the network. There is no capability
            // negotiation to consult yet, so the diagnosis cannot be
            // precise — but it can point at the right half of the system.
            // See the per-stream data ports section of the README.
            if n_acked_now == 0 {
                // State the symptom, list the causes, assert none of them.
                // The first version of this message said a version or
                // capability mismatch was the usual cause. The first time it
                // fired in anger the cause was something else entirely — a
                // second concurrent transfer to the same daemon, which never
                // receives ACKs — and the message sent the reader looking at
                // versions. A diagnostic that names one cause confidently is
                // only an improvement while it is right.
                eprintln!(
                    "No feedback received from peer in {}s: the handshake succeeded but \
not one ACK arrived, so the peer is receiving nothing it will answer. Known causes, \
in rough order of likelihood: another transfer is already running against that daemon \
(concurrent transfers to one daemon are not currently supported); a protocol version \
or capability mismatch, so the peer is silently discarding packets it cannot parse; \
or the data port ({}) is filtered in one direction while the control port is not.",
                    STALL_TIMEOUT.as_secs(),
                    data_remote.port(),
                );
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    format!(
                        "no feedback from peer after {}s (0 of {} chunks acked) — \
likely a version or capability mismatch",
                        STALL_TIMEOUT.as_secs(), total_chunks
                    ),
                ).into());
            }
            eprintln!("Transfer stalled: no progress for {}s, aborting", STALL_TIMEOUT.as_secs());
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!("transfer stalled at {:.1}% ({}/{} chunks)",
                    n_acked_now as f64 / total_chunks as f64 * 100.0, n_acked_now, total_chunks),
            ).into());
        }
    }

    let elapsed = start.elapsed();

    // ── Finish ───────────────────────────────────────────────────────────
    // FINISH goes to the daemon's DATA port: during a transfer the daemon
    // only reads its data socket, where the Finish handler finalizes the
    // receive loop. Its reply (final ACKs + Finish) is sent back to this
    // sender's control address, so the wait below stays on the control socket.
    //
    // S3: when encryption was negotiated, FINISH is AEAD-sealed with the
    // current epoch's control key — it finalizes/truncates the transfer, so
    // a forged cleartext FINISH must not be acted on. Plaintext transfers
    // keep the cleartext FINISH.
    send_ctrl_sealed(
        &data_socket, data_remote, PacketType::Finish, conn_id, seq, &[],
        key_epoch.as_ref().map(|ke| &ke.keys),
    ).await?;
    // Wait for the FINISH response, then (encrypted only) for the session
    // ticket (Checkpoint). Both may already have been recorded while
    // draining feedback above (see `process_feedback`). The 2 s deadline is
    // only a safety net: the daemon replies from its post-transfer path as
    // soon as its receive loop ends, so the wait normally completes on the
    // first check/datagram instead of expiring.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    loop {
        if let Some(payload) = checkpoint_payload.take() {
            // Session ticket from daemon — cache for 0-RTT reconnection.
            // Store as: [encoded_ticket] + [32-byte resume_secret]
            if let Some(ref epoch) = key_epoch {
                let mut cache_data = payload.to_vec();
                cache_data.extend_from_slice(&epoch.keys.resume_secret);
                SESSION_TICKET_CACHE.lock().unwrap().insert(remote, cache_data);
                tracing::info!("cached session ticket for 0-RTT reconnection");
            }
            break;
        }
        // FINISH acknowledged. Encrypted transfers still wait for the
        // session ticket (Checkpoint) issued by the daemon's post-transfer
        // path, so only a plaintext transfer breaks here.
        if finish_seen && key_epoch.is_none() { break; }
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() { break; }
        match tokio::time::timeout(remaining, socket.recv_from(&mut recv_buf)).await {
            Ok(Ok((len, _))) => {
                if let Ok(pkt) = decode_packet(&recv_buf[..len]) {
                    match pkt.header.packet_type {
                        PacketType::Checkpoint if !pkt.payload.is_empty() => {
                            checkpoint_payload = Some(pkt.payload);
                        }
                        PacketType::Finish => finish_seen = true,
                        _ => {}
                    }
                }
            }
            _ => break,
        }
    }

    // Ground truth for the benchmark rig, always on: one line, two adds
    // per flush. `benchmarks/scripts/rig_check.sh` asserts on these and
    // fails the run rather than letting a CSV be written from a
    // measurement of the harness.
    //
    // `debt_ratio` is the number that matters. It compares the pacing debt
    // the sender *incurred* against the time it actually spent paying it,
    // so it measures whether the pacer is the thing setting the send rate.
    // It read ~15 for as long as batch mode capped a 30 ms debt at 2 ms,
    // and every congestion-control result recorded in that period was a
    // measurement of the actuator. Nothing in the tree would have caught
    // it; this line is the check that would have.
    let debt_ratio = if pace_got_us > 0 {
        pace_want_us as f64 / pace_got_us as f64
    } else {
        1.0
    };
    let paced_secs = pace_got_us as f64 / 1e6;
    let mbit = |pkts: u64, secs: f64| {
        if secs > 0.0 {
            pkts as f64 * wire_size as f64 * 8.0 / secs / 1e6
        } else {
            0.0
        }
    };
    eprintln!(
        "PACE_SUMMARY pacing={} carry_debt={} debt_ratio={:.3} want_ms={:.0} got_ms={:.0} \
flushes={} paced_pkts={} ach_mbit={:.1} wire_mbit={:.1} \
skipped_sleeps={} credit_clamps={} overrun_discarded_ms={} credit_discarded_ms={}",
        pacing_mode,
        carry_pace_debt,
        debt_ratio,
        pace_want_us as f64 / 1000.0,
        pace_got_us as f64 / 1000.0,
        pace_flushes,
        pace_pkts,
        mbit(pace_pkts, paced_secs),
        mbit(packets_sent, elapsed.as_secs_f64()),
        pace_skipped_sleeps,
        pace_credit_clamps,
        pace_overrun_discarded_us / 1000,
        pace_credit_discarded_us / 1000,
    );

    // Where the wall clock actually went, per pass and in total. The
    // question this answers: the commanded rate exceeds the wire rate by
    // about a fifth, invariantly under every parameter swept, and
    // `bw_next = gain x ratio x bw` cannot climb while `gain x ratio` is 1.
    //
    // This comment used to end "if the missing fifth is not in one of these
    // four buckets it is not in this loop at all", and there was a fifth
    // bucket: `blocked`, the wait taken by a pass that never staged. It is
    // the largest term on a LAN path (29% measured) and it was outside the
    // denominator, so every percentage printed here was a share of the
    // wrong total. Five buckets now, and `total` is the whole loop.
    {
        let total = (prof_stage_us + prof_flush_us + prof_wait_us + prof_drain_us
            + prof_blocked_us).max(1);
        eprintln!(
            "PROFILE_SUMMARY passes={} total_ms={} \
stage={}us ({:.1}%) flush={}us ({:.1}%) wait={}us ({:.1}%) drain={}us ({:.1}%) \
blocked={}us ({:.1}%) flush_cpu={}us ({:.1}% of flush, rest is off-CPU) \
feedback_in_wait={}us ({:.1}% of wait) \
per_pass[stage={:.1}us flush={:.1}us wait={:.1}us drain={:.1}us] \
fb_dgrams={} per_pass={:.1} us_per_dgram={:.2}",
            prof_passes, total / 1000,
            prof_stage_us, 100.0 * prof_stage_us as f64 / total as f64,
            prof_flush_us, 100.0 * prof_flush_us as f64 / total as f64,
            prof_wait_us,  100.0 * prof_wait_us  as f64 / total as f64,
            prof_drain_us, 100.0 * prof_drain_us as f64 / total as f64,
            prof_blocked_us, 100.0 * prof_blocked_us as f64 / total as f64,
            prof_flush_cpu_us,
            if prof_flush_us > 0 { 100.0 * prof_flush_cpu_us as f64 / prof_flush_us as f64 } else { 0.0 },
            prof_fb_us,
            if prof_wait_us > 0 { 100.0 * prof_fb_us as f64 / prof_wait_us as f64 } else { 0.0 },
            prof_stage_us as f64 / prof_passes.max(1) as f64,
            prof_flush_us as f64 / prof_passes.max(1) as f64,
            prof_wait_us  as f64 / prof_passes.max(1) as f64,
            prof_drain_us as f64 / prof_passes.max(1) as f64,
            prof_fb_dgrams,
            prof_fb_dgrams as f64 / prof_passes.max(1) as f64,
            (prof_drain_us + prof_fb_us) as f64 / prof_fb_dgrams.max(1) as f64,
        );
    }
    // What actually stopped the send loop, per pass.
    //
    // Read the second line first. The `brk_*` shares on line one are shares
    // of *staging* passes only -- they say what ended a pass that got to send
    // something, which is a different question from what the loop spent its
    // time doing. A pass that arrives already window-blocked never reaches
    // any of them. On the 2026-08-11 LAN measurement line one read
    // `window=7.6%` while 29% of the wall clock was window-blocked, and the
    // gap between those two numbers is entirely the pass-level line below.
    //
    // Line one: the staging loop breaks for exactly four reasons, mutually
    // exclusive per pass, so their shares say which resource a controller is
    // short of once it is sending: `window` means it hit cwnd mid-pass,
    // `burst` means the pacing rate it commanded is the limit, `nowork`
    // means no stream had a chunk ready, `batch` means the send buffer
    // filled first.
    //
    // Line two: what fraction of passes sent nothing at all, and where the
    // wall clock went. `blocked_window` is the one to watch -- it is work
    // pending against a closed window, i.e. the controller's own limit, and
    // it is the term that separates "asked for too little" from "was not
    // allowed to send what it asked for". `blocked_nowork` is tail drain and
    // is expected to be non-zero at the end of any transfer.
    //
    // Line one was added to compare Model against Classic at 1 Gbit, where
    // Classic reaches 78% of the link and Model 28% with the pacer faithful
    // in both. Line two was added after it answered that question and then
    // gave a wrong answer to a different one.
    let brk_total = (brk_window + brk_burst + brk_nowork + brk_batch).max(1);
    eprintln!(
        "GATE_SUMMARY window={} ({:.1}%) burst={} ({:.1}%) nowork={} ({:.1}%) batch={} ({:.1}%) staged={}",
        brk_window, 100.0 * brk_window as f64 / brk_total as f64,
        brk_burst,  100.0 * brk_burst  as f64 / brk_total as f64,
        brk_nowork, 100.0 * brk_nowork as f64 / brk_total as f64,
        brk_batch,  100.0 * brk_batch  as f64 / brk_total as f64,
        staged_total,
    );
    let all_passes = (prof_passes + blocked_window + blocked_nowork).max(1);
    eprintln!(
        "PASS_SUMMARY total={} staged={} ({:.1}%) blocked_window={} ({:.1}%) \
blocked_nowork={} ({:.1}%) blocked_ms={} ({:.1}% of loop)",
        all_passes,
        prof_passes,     100.0 * prof_passes     as f64 / all_passes as f64,
        blocked_window,  100.0 * blocked_window  as f64 / all_passes as f64,
        blocked_nowork,  100.0 * blocked_nowork  as f64 / all_passes as f64,
        prof_blocked_us / 1000,
        100.0 * prof_blocked_us as f64
            / (prof_stage_us + prof_flush_us + prof_wait_us + prof_drain_us
                + prof_blocked_us).max(1) as f64,
    );
    {
        // Per-stream finish times. `spread` is the straggler cost: the
        // transfer cannot end before the slowest stream does, so any gap
        // between first and last is capacity that finished early and then
        // sat idle.
        let el = elapsed.as_secs_f64();
        // Streams still unstamped completed on the final pass — the loop
        // exits before the next iteration can observe them. They are by
        // definition the last to finish, which is exactly the straggler
        // this measures, so stamping them with the transfer end is correct
        // rather than a fudge.
        for s in streams.iter_mut() {
            if s.done_at.is_none() && s.n_acked >= s.chunk_count {
                s.done_at = Some(el);
            }
        }
        let dones: Vec<f64> = streams.iter().filter_map(|s| s.done_at).collect();
        let first = dones.iter().cloned().fold(f64::INFINITY, f64::min);
        let last = dones.iter().cloned().fold(0.0_f64, f64::max);
        let per: Vec<String> = streams
            .iter()
            .map(|s| {
                format!(
                    "{}:{}/{}chunks@{}",
                    s.id,
                    s.n_acked,
                    s.chunk_count,
                    s.done_at.map(|d| format!("{d:.2}s")).unwrap_or_else(|| "-".into())
                )
            })
            .collect();
        eprintln!(
            "STREAM_SUMMARY n={} elapsed={:.2}s first_done={:.2}s last_done={:.2}s \
spread={:.2}s ({:.1}% of transfer) [{}]",
            streams.len(),
            el,
            if first.is_finite() { first } else { 0.0 },
            last,
            if first.is_finite() { last - first } else { 0.0 },
            if first.is_finite() && el > 0.0 { 100.0 * (last - first) / el } else { 0.0 },
            per.join(" "),
        );
    }
    eprintln!(
        "CC_SUMMARY controller={} streams={} base_rtt_ms={:.2} packets={} retx={}",
        effective_cc,
        streams.len(),
        profile.base_rtt.as_secs_f64() * 1000.0,
        packets_sent,
        retransmits,
    );
    if let Some(advice) = loss_advice(retransmits, packets_sent, effective_cc) {
        eprintln!("  {advice}");
    }

    Ok(TransferStats {
        bytes_sent: file_size,
        elapsed,
        packets_sent,
        retransmits,
        profile,
        policy_params,
        data_ports: n_dest,
    })
}

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Sender-side delivery rate tracker (approximates UDT's receiver-side
/// packet arrival rate measurement).
struct DeliveryTracker {
    /// Total bytes acked so far.
    total_acked: u64,
    /// Bytes acked at last measurement point.
    prev_acked: u64,
    /// Timestamp of last measurement.
    prev_time: Option<Instant>,
    /// Current delivery rate estimate (bytes/sec), EWMA-smoothed.
    rate: u64,
}

impl DeliveryTracker {
    fn new() -> Self {
        Self {
            total_acked: 0,
            prev_acked: 0,
            prev_time: None,
            rate: 0,
        }
    }

    /// Record newly acked bytes and update the delivery rate estimate.
    fn on_ack(&mut self, bytes: u64, now: Instant) {
        self.total_acked += bytes;

        let prev = match self.prev_time {
            Some(t) => t,
            None => {
                self.prev_time = Some(now);
                self.prev_acked = self.total_acked;
                return;
            }
        };

        let elapsed = now.duration_since(prev);
        // Update rate every ~5ms to avoid noisy per-ACK measurements.
        if elapsed >= Duration::from_millis(5) {
            let delta_bytes = self.total_acked - self.prev_acked;
            let sample = (delta_bytes as f64 / elapsed.as_secs_f64()) as u64;
            if sample > 0 {
                if self.rate == 0 {
                    self.rate = sample;
                } else {
                    // EWMA: 7/8 old + 1/8 new (same as UDT).
                    self.rate = (self.rate * 7 + sample) / 8;
                }
            }
            self.prev_acked = self.total_acked;
            self.prev_time = Some(now);
        }
    }

    fn delivery_rate(&self) -> u64 {
        self.rate
    }
}

/// Feed newly-acked chunks into the congestion controller and metrics tracker.
///
/// Uses the **minimum** RTT from the batch for the CC's RTT estimator to avoid
/// inflating srtt with sender-side queuing or ACK batching delays. Each per-
/// packet RTT is still recorded in metrics for observability.
///
/// `newly_acked` contains `(pseudo_pn, rtt)` pairs — the RTT measured from
/// the chunk's last send time at ACK-processing time.
fn feed_cc(
    cc: &mut dyn CongestionController,
    newly_acked: &[(u64, Option<Duration>)],
    wire_size: usize,
    delivery_tracker: &mut DeliveryTracker,
    metrics: &mut TransferMetrics,
    rtt_est: &mut RttEstimator,
) {
    if newly_acked.is_empty() {
        return;
    }
    let now = Instant::now();

    // Two samples per batch, because the controller needs two different
    // things from them.
    //
    // The minimum is the least-queued sample available and is what a
    // baseline should be built from; retransmitted chunks contribute no
    // sample at all (Karn), which makes the minimum safe rather than
    // merely tidy, since it actively selects for the shortest and so the
    // most corrupted sample in a batch.
    //
    // The mean is what a packet actually experienced, and it is what any
    // delay-based congestion signal has to see. Only the minimum used to
    // be fed, to both quantities, on the reasoning that it kept
    // sender-side queueing and ACK batching out of the estimate. It also
    // kept the bottleneck queue out: a controller's srtt read 25.7 ms
    // while this transfer's mean RTT was 56.2 ms. Classic's `queueing`
    // congestion evidence could therefore never fire, and its pacing
    // rate -- `cwnd / srtt` -- divided by less than half the real RTT,
    // commanding ~235 Mbit and achieving 127 Mbit into a 100 Mbit link.
    // Every delay-based signal in the tree was inert for the same reason.
    let rtts: Vec<Duration> = newly_acked.iter().filter_map(|&(_, rtt)| rtt).collect();
    let min_rtt = rtts.iter().copied().min();
    let mean_rtt = if rtts.is_empty() {
        None
    } else {
        Some(rtts.iter().sum::<Duration>() / rtts.len() as u32)
    };

    // Update delivery rate from actual acked bytes over time.
    let batch_bytes = newly_acked.len() as u64 * wire_size as u64;
    delivery_tracker.on_ack(batch_bytes, now);

    // Use the delivery tracker's rate (tracks actual goodput over time).
    // On loopback, the tracker may underestimate because of measurement
    // artifacts, but on WiFi it correctly avoids in_flight/RTT inflation.
    let delivery_rate = delivery_tracker.delivery_rate();

    // Feed the CC with the min RTT once (not per-packet, to avoid noise).
    // A batch of purely retransmitted chunks carries no timing information,
    // so the estimators simply keep their previous value.
    if let (Some(min_rtt), Some(mean_rtt)) = (min_rtt, mean_rtt) {
        cc.on_rtt_batch(mean_rtt, min_rtt);
        rtt_est.update_batch(mean_rtt, min_rtt);
    }

    for &(pn, rtt) in newly_acked.iter() {
        cc.on_ack_received(
            &CcAckInfo {
                packet_number: pn,
                ack_delay: Duration::ZERO,
                delivered_bytes: wire_size as u64,
                delivery_rate,
            },
            now,
        );
        if let Some(rtt) = rtt {
            metrics.record_rtt(rtt);
        }
    }
}

async fn send_ctrl(
    socket: &UdpSocket,
    to: SocketAddr,
    ptype: PacketType,
    conn_id: u64,
    seq: u64,
    payload: &[u8],
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut pkt = Packet {
        header: make_header(ptype, conn_id, seq, payload.len() as u32),
        extensions: vec![],
        payload: Bytes::copy_from_slice(payload),
    };
    let buf = encode_packet_auto(&mut pkt);
    socket.send_to(&buf, to).await?;
    Ok(())
}

/// Send a control packet, AEAD-sealing its payload with the session control
/// key when `seal_keys` is provided (i.e. encryption was negotiated for the
/// transfer). Plaintext transfers pass `None` and stay cleartext — sealed
/// vs. cleartext is implicit in the negotiated mode, no wire flag is needed.
async fn send_ctrl_sealed(
    socket: &UdpSocket,
    to: SocketAddr,
    ptype: PacketType,
    conn_id: u64,
    seq: u64,
    payload: &[u8],
    seal_keys: Option<&SessionKeys>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    match seal_keys {
        Some(keys) => {
            let buf = encode_sealed_ctrl_packet(ptype, conn_id, seq, keys, payload);
            socket.send_to(&buf, to).await?;
            Ok(())
        }
        None => send_ctrl(socket, to, ptype, conn_id, seq, payload).await,
    }
}

/// Encode a control packet with an AEAD-sealed payload: the 42-byte fixed
/// header with `payload_length` covering ciphertext + tag, then the sealed
/// payload. The seal mirrors the data plane (S2): nonce = control_iv XOR the
/// packet sequence number, AAD = the header bytes exactly as they go on the
/// wire (RFC §14.4).
fn encode_sealed_ctrl_packet(
    ptype: PacketType,
    conn_id: u64,
    seq: u64,
    keys: &SessionKeys,
    payload: &[u8],
) -> Vec<u8> {
    let sealed_len = payload.len() + CONTROL_TAG_LEN;
    let hdr = make_header(ptype, conn_id, seq, sealed_len as u32);
    let mut buf = vec![0u8; HEADER_SIZE + sealed_len];
    hdr.encode_into(&mut buf[..HEADER_SIZE]);
    let sealed = seal_control(keys, seq, &buf[..HEADER_SIZE], payload)
        .expect("AES-256-GCM seal of a control payload cannot fail");
    buf[HEADER_SIZE..].copy_from_slice(&sealed);
    buf
}

/// Receive a control packet, filtering by expected type. Ignores packets
/// that don't match (stale data, PathProbes, etc.) and keeps waiting.
async fn recv_ctrl(
    socket: &UdpSocket,
    buf: &mut [u8],
    timeout: Duration,
) -> Result<Packet, Box<dyn std::error::Error + Send + Sync>> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return Err("deadline has elapsed".into());
        }
        let (len, _) = tokio::time::timeout(remaining, socket.recv_from(buf)).await??;
        match decode_packet(&buf[..len]) {
            Ok(pkt) => return Ok(pkt),
            Err(_) => continue, // malformed packet, keep waiting
        }
    }
}

/// Receive a specific packet type, ignoring all others until timeout.
async fn recv_ctrl_typed(
    socket: &UdpSocket,
    buf: &mut [u8],
    expected: PacketType,
    timeout: Duration,
) -> Result<Packet, Box<dyn std::error::Error + Send + Sync>> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return Err(format!("timeout waiting for {:?}", expected).into());
        }
        let (len, _) = tokio::time::timeout(remaining, socket.recv_from(buf)).await??;
        if let Ok(pkt) = decode_packet(&buf[..len]) {
            if pkt.header.packet_type == expected {
                return Ok(pkt);
            }
            // Ignore non-matching packets (stale data, probes, etc.)
        }
    }
}


/// Dispatch an incoming feedback packet (AckBitmap or NackRange).
///
/// Routes feedback to the correct stream based on the stream_id in the payload.
/// `t0` is the transfer start instant, the epoch of the per-chunk `sent_us`
/// timestamps.
///
/// The daemon's post-transfer FINISH reply and session-ticket Checkpoint can
/// arrive while the send loop is still draining its last ACKs (the daemon
/// sends them as soon as its receive thread exits — its completion is
/// exactly what our final ACKs report). They are not feedback, so they are
/// recorded into `finish_seen` / `checkpoint_payload` for the post-FINISH
/// wait below instead of being silently dropped.
fn process_feedback(
    data: &[u8],
    streams: &mut [StreamState],
    in_flight: &mut usize,
    wire_size: usize,
    cc: &mut dyn CongestionController,
    delivery_tracker: &mut DeliveryTracker,
    metrics: &mut TransferMetrics,
    t0: Instant,
    finish_seen: &mut bool,
    checkpoint_payload: &mut Option<Bytes>,
    rtt_est: &mut RttEstimator,
) {
    let pkt = match decode_packet(data) {
        Ok(p) => p,
        Err(_) => return,
    };

    match pkt.header.packet_type {
        PacketType::AckBitmap => {
            let newly_acked = process_ack_bitmap(
                &pkt, streams, in_flight, wire_size, t0,
            );
            feed_cc(cc, &newly_acked, wire_size, delivery_tracker, metrics, rtt_est);
        }
        PacketType::NackRange => {
            process_nack(
                &pkt, streams,
                in_flight, wire_size, cc, t0,
            );
        }
        PacketType::Finish => *finish_seen = true,
        PacketType::Checkpoint if !pkt.payload.is_empty() => {
            *checkpoint_payload = Some(pkt.payload);
        }
        _ => {} // Ignore other packet types
    }
}

/// Process an ACK bitmap packet. Returns `(pseudo_pn, rtt)` pairs for each
/// newly acknowledged chunk (for CC feedback), where `rtt` is measured from
/// the chunk's last send time. `t0` is the transfer start instant.
fn process_ack_bitmap(
    pkt: &Packet,
    streams: &mut [StreamState],
    in_flight: &mut usize,
    wire_size: usize,
    t0: Instant,
) -> Vec<(u64, Option<Duration>)> {
    let mut newly_acked = Vec::new();
    let now_us = elapsed_us(t0);

    let ack = match AckBitmap::decode(&mut &pkt.payload[..]) {
        Ok(a) => a,
        Err(_) => return newly_acked,
    };

    let sid = ack.stream_id as usize;
    if sid >= streams.len() {
        return newly_acked;
    }
    let stream = &mut streams[sid];

    // The ACK's base_packet_number is the stream's chunk_base.
    // Convert packet numbers to local chunk indices.
    // Clamp the wire-derived range to this stream's chunk space
    // [chunk_base, chunk_base + chunk_count): a spoofed or corrupt ACK with
    // highest_contiguous = u64::MAX would otherwise livelock the loop below.
    // This also rejects the receiver's legitimate "nothing contiguous yet"
    // sentinel (hc = chunk_base - 1, wrapping to u64::MAX for stream 0), which
    // the old `hc >= base` guard mishandled when chunk_base == 0.
    //
    // The contiguous prefix is monotonic per stream, so iteration resumes at
    // `hc_applied` instead of the stream base: per-ACK work stays
    // proportional to newly acked chunks, not O(chunk_count).
    let stream_end = stream.chunk_base + stream.chunk_count; // exclusive
    if ack.highest_contiguous >= ack.base_packet_number
        && ack.highest_contiguous < stream_end
    {
        let lo = ack
            .base_packet_number
            .max(stream.chunk_base)
            .max(stream.chunk_base + stream.hc_applied);
        if lo <= ack.highest_contiguous {
            for pn in lo..=ack.highest_contiguous {
                let local_ci = pn.wrapping_sub(stream.chunk_base) as usize;
                if local_ci < stream.acked.len() && !stream.acked[local_ci] {
                    let rtt = stream.rtt_sample(local_ci, now_us);
                    stream.mark_acked(local_ci);
                    *in_flight = in_flight.saturating_sub(wire_size);
                    newly_acked.push((pn, rtt));
                }
            }
            stream.hc_applied = ack.highest_contiguous - stream.chunk_base + 1;
        }
    }

    // Bitmap (LSB-first). The local-index check filters bits outside this
    // stream's chunk space; wrapping arithmetic keeps a highest_contiguous
    // near u64::MAX from overflowing the packet-number computation.
    let bitmap_base = ack.highest_contiguous.wrapping_add(1);
    for (bi, &byte) in ack.bitmap.iter().enumerate() {
        if byte == 0 {
            continue;
        }
        for bit in 0..8u64 {
            if byte & (1 << bit) != 0 {
                let pn = bitmap_base.wrapping_add(bi as u64 * 8 + bit);
                let local_ci = pn.wrapping_sub(stream.chunk_base) as usize;
                if local_ci < stream.acked.len() && !stream.acked[local_ci] {
                    let rtt = stream.rtt_sample(local_ci, now_us);
                    stream.mark_acked(local_ci);
                    *in_flight = in_flight.saturating_sub(wire_size);
                    newly_acked.push((pn, rtt));
                }
            }
        }
    }

    newly_acked
}

/// Process a NackRange packet — queue missing chunks for priority retransmit
/// and notify the congestion controller of the receiver-detected loss.
///
/// NACKs are the CC's primary loss signal: the rate-based CCs (Model, UDT,
/// RL) ignore sender-side retransmit timeouts (`wants_timeout_loss()` is
/// false) and only react to receiver-detected loss, delivered here. A
/// chunk is reported as lost only when it is newly queued for retransmit —
/// duplicate NACKs for a chunk already in the retx queue, and stale NACKs
/// for a just-resent chunk, are not reported again (the controllers also
/// suppress duplicate reactions within a congestion epoch). Retransmit
/// counting is done by the main send loop when the chunk is actually re-sent.
fn process_nack(
    pkt: &Packet,
    streams: &mut [StreamState],
    _in_flight: &mut usize,
    _wire_size: usize,
    cc: &mut dyn CongestionController,
    t0: Instant,
) {
    let nack = match NackRange::decode(&mut &pkt.payload[..]) {
        Ok(n) => n,
        Err(_) => return,
    };

    let sid = nack.stream_id as usize;
    if sid >= streams.len() {
        return;
    }
    let stream = &mut streams[sid];
    let now_us = elapsed_us(t0);

    let mut lost: Vec<u64> = Vec::new();
    let stream_end = stream.chunk_base + stream.chunk_count; // exclusive
    for (start_pn, end_pn) in &nack.ranges {
        // Clamp the wire-derived range to this stream's chunk space
        // [chunk_base, chunk_base + chunk_count): a spoofed NACK spanning
        // 0..=u64::MAX would otherwise livelock the sender. Chunks outside
        // the stream cannot be retransmitted anyway.
        let lo = (*start_pn).max(stream.chunk_base);
        let hi = (*end_pn).min(stream_end.saturating_sub(1));
        if lo > hi {
            continue;
        }
        for pn in lo..=hi {
            let local_ci = pn.wrapping_sub(stream.chunk_base) as usize;
            if local_ci < stream.acked.len() && !stream.acked[local_ci] {
                let lci = local_ci as u64;
                // Only queue if not already in the retx queue (O(1) via the
                // per-chunk flag rather than a scan of the whole queue).
                // Also check sent_us to avoid re-queuing chunks that were
                // just sent (the NACK was for an older transmission).
                if stream.flags[local_ci] & CHUNK_IN_RETX == 0 {
                    let recently_sent = if local_ci < stream.sent_us.len() {
                        now_us.wrapping_sub(stream.sent_us[local_ci]) < 50_000
                    } else {
                        false
                    };
                    if !recently_sent {
                        stream.retx_queue.push_front(lci);
                        stream.flags[local_ci] |= CHUNK_IN_RETX | CHUNK_RETRANSMITTED;
                        // Newly-detected loss: report to the CC (global chunk
                        // index space, same as the timeout path).
                        lost.push(pn);
                    }
                    // Do NOT subtract from in_flight: the chunk is still
                    // outstanding until acked.
                }
            }
        }
    }

    if !lost.is_empty() {
        cc.on_packet_lost(&lost, Instant::now());
    }
}


#[cfg(test)]
mod tests {
    use super::parse_remote_dest_detailed as pd;

    /// A hostname must work. It did not, and the error message said it
    /// should — the one combination that misleads rather than merely
    /// failing.
    #[test]
    fn hostnames_resolve() {
        let (addr, path) = pd("localhost:7801:/tmp/f").expect("localhost must resolve");
        assert!(addr.is_ipv4(), "must prefer IPv4, got {addr}");
        assert_eq!(addr.port(), 7801);
        assert_eq!(path, "/tmp/f");
    }

    #[test]
    fn ipv4_literals_still_work() {
        let (addr, path) = pd("192.168.1.5:7801:/tmp/f").unwrap();
        assert_eq!(addr.to_string(), "192.168.1.5:7801");
        assert_eq!(path, "/tmp/f");
    }

    /// IPv6 must be *refused with a reason*, not passed through to a
    /// backend that panics on SocketAddr::V6.
    /// IPv6 is accepted where the send path implements it (Linux) and
    /// refused *with a reason* where it does not — never passed through to
    /// a backend that would panic on `SocketAddr::V6`.
    #[test]
    fn ipv6_is_handled_per_platform() {
        let r = pd("[::1]:7801:/tmp/f");
        if cfg!(target_os = "linux") {
            let (addr, path) = r.expect("Linux must accept IPv6");
            assert!(addr.is_ipv6(), "expected an IPv6 address, got {addr}");
            assert_eq!(addr.port(), 7801);
            assert_eq!(path, "/tmp/f");
        } else {
            assert!(r.unwrap_err().contains("IPv6"));
        }
    }

    #[test]
    fn errors_say_what_is_wrong() {
        assert!(pd("192.168.1.5:7801:relative/path").unwrap_err().contains("absolute"));
        assert!(pd("192.168.1.5:notaport:/tmp/f").unwrap_err().contains("port"));
        assert!(pd("nodots").unwrap_err().contains("host:port:/path"));
        assert!(pd("no-such-host.invalid:7801:/tmp/f").unwrap_err().contains("resolve"));
    }
    use super::{check_negotiated_mode, data_header_aad, extract_resume_secret, sanitize_policy_params};
    use super::{
        elapsed_us, make_header, process_ack_bitmap, process_nack, AckBitmap, CcAckInfo,
        CongestionController, NackRange, Packet, PacketType, StreamState,
        CHUNK_IN_RETX, CHUNK_RETRANSMITTED,
    };
    use super::{DATA_PAYLOAD_HEADER_SIZE};
    use super::{encode_sealed_ctrl_packet, encode_key_update, decode_packet, SessionKeys, CONTROL_TAG_LEN};
    use ahp_crypto::session_ticket::{encode_ticket, TicketKey, DEFAULT_TICKET_TTL};
    use ahp_policy::PolicyParams;
    use ahp_proto::{decode_hello_ack_payload, encode_hello_ack_payload, HelloAckMode};
    use std::time::{Duration, Instant};

    #[test]
    fn negotiated_mode_must_match() {
        let modes = [
            HelloAckMode::Plaintext,
            HelloAckMode::FullHandshake,
            HelloAckMode::Resumed,
        ];
        for planned in modes {
            for replied in modes {
                let result = check_negotiated_mode(planned, replied);
                if planned == replied {
                    assert!(result.is_ok(), "{planned:?} vs {replied:?} must proceed");
                } else {
                    assert!(result.is_err(), "{planned:?} vs {replied:?} must abort");
                }
            }
        }
    }

    // Every daemon HELLO_ACK path, encoded daemon-side and interpreted
    // client-side: a matching plan proceeds, any other plan aborts.

    #[test]
    fn resume_success_ack_matches_resumed_plan() {
        let ack = encode_hello_ack_payload(HelloAckMode::Resumed, Some(7801), None, None, ahp_proto::CAP_NONE);
        let decoded = decode_hello_ack_payload(&ack).unwrap();
        assert!(check_negotiated_mode(HelloAckMode::Resumed, decoded.mode).is_ok());
        // The F5 mismatch: client planned resume, daemon fell back to
        // plaintext (or vice versa) — must abort, never stream.
        let fallback = encode_hello_ack_payload(HelloAckMode::Plaintext, Some(7801), None, None, ahp_proto::CAP_NONE);
        let decoded_fallback = decode_hello_ack_payload(&fallback).unwrap();
        assert!(check_negotiated_mode(HelloAckMode::Resumed, decoded_fallback.mode).is_err());
        assert!(check_negotiated_mode(HelloAckMode::Plaintext, decoded.mode).is_err());
    }

    #[test]
    fn full_handshake_ack_carries_material_and_matches() {
        let public = [0xA5; 32];
        let nonce = [0x5A; 16];
        let ack = encode_hello_ack_payload(
            HelloAckMode::FullHandshake,
            Some(7801),
            Some((&public, &nonce)),
            None,
            ahp_proto::CAP_NONE,
        );
        let decoded = decode_hello_ack_payload(&ack).unwrap();
        assert!(check_negotiated_mode(HelloAckMode::FullHandshake, decoded.mode).is_ok());
        assert_eq!(decoded.dh_material, Some((public, nonce)));
        assert_eq!(decoded.data_port, Some(7801));
        // A plaintext-planning client must abort on an encrypted daemon.
        assert!(check_negotiated_mode(HelloAckMode::Plaintext, decoded.mode).is_err());
    }

    #[test]
    fn busy_ack_without_port_is_plaintext() {
        let ack = encode_hello_ack_payload(HelloAckMode::Plaintext, None, None, None, ahp_proto::CAP_NONE);
        let decoded = decode_hello_ack_payload(&ack).unwrap();
        assert_eq!(decoded.data_port, None);
        assert!(check_negotiated_mode(HelloAckMode::Plaintext, decoded.mode).is_ok());
        // An encrypting client must abort on a busy (plaintext) ack.
        assert!(check_negotiated_mode(HelloAckMode::FullHandshake, decoded.mode).is_err());
        assert!(check_negotiated_mode(HelloAckMode::Resumed, decoded.mode).is_err());
    }

    // ── S5: Ed25519-authenticated handshake (RFC §12.2/§12.4) ────────────

    use super::{parse_server_key_pin, verify_server_identity};
    use ahp_crypto::signatures::SigningIdentity;
    use ahp_proto::HelloAckPayload;

    /// Build the HELLO_ACK the daemon sends for a full handshake with an
    /// identity, mirroring net_receiver's signing exactly.
    fn authed_ack(
        identity: &SigningIdentity,
        server_public: &[u8; 32],
        server_nonce: &[u8; 16],
        client_public: &[u8; 32],
        client_nonce: &[u8; 16],
    ) -> HelloAckPayload {
        let signature =
            identity.sign_handshake(server_public, client_public, server_nonce, client_nonce);
        let encoded = encode_hello_ack_payload(
            HelloAckMode::FullHandshake,
            Some(7801),
            Some((server_public, server_nonce)),
            Some((&identity.public_bytes(), &signature)),
            ahp_proto::CAP_NONE,
        );
        decode_hello_ack_payload(&encoded).unwrap()
    }

    const CLIENT_PUB: [u8; 32] = [0xC1; 32];
    const CLIENT_NONCE: [u8; 16] = [0xC2; 16];
    const SERVER_PUB: [u8; 32] = [0xD1; 32];
    const SERVER_NONCE: [u8; 16] = [0xD2; 16];

    #[test]
    fn pinned_client_verifies_identity_daemon() {
        let identity = SigningIdentity::generate();
        let ack = authed_ack(&identity, &SERVER_PUB, &SERVER_NONCE, &CLIENT_PUB, &CLIENT_NONCE);
        assert!(
            verify_server_identity(Some(&identity.public_bytes()), &ack, &CLIENT_PUB, &CLIENT_NONCE).is_ok(),
            "correct pin + valid signature must verify"
        );
    }

    #[test]
    fn wrong_pinned_key_aborts() {
        let identity = SigningIdentity::generate();
        let other = SigningIdentity::generate();
        let ack = authed_ack(&identity, &SERVER_PUB, &SERVER_NONCE, &CLIENT_PUB, &CLIENT_NONCE);
        let err = verify_server_identity(Some(&other.public_bytes()), &ack, &CLIENT_PUB, &CLIENT_NONCE)
            .expect_err("wrong pin must abort");
        assert!(err.contains("identity mismatch"), "unexpected error: {err}");
    }

    #[test]
    fn tampered_signature_aborts() {
        let identity = SigningIdentity::generate();
        let mut ack = authed_ack(&identity, &SERVER_PUB, &SERVER_NONCE, &CLIENT_PUB, &CLIENT_NONCE);
        let (pk, mut sig) = ack.auth_material.unwrap();
        sig[0] ^= 0xFF;
        ack.auth_material = Some((pk, sig));
        let err = verify_server_identity(Some(&identity.public_bytes()), &ack, &CLIENT_PUB, &CLIENT_NONCE)
            .expect_err("tampered signature must abort");
        assert!(err.contains("signature invalid"), "unexpected error: {err}");
    }

    #[test]
    fn pinned_client_without_daemon_identity_aborts() {
        // Anonymous daemon: FullHandshake with DH material but no auth material.
        let encoded = encode_hello_ack_payload(
            HelloAckMode::FullHandshake,
            Some(7801),
            Some((&SERVER_PUB, &SERVER_NONCE)),
            None,
            ahp_proto::CAP_NONE,
        );
        let ack = decode_hello_ack_payload(&encoded).unwrap();
        let pin = SigningIdentity::generate().public_bytes();
        let err = verify_server_identity(Some(&pin), &ack, &CLIENT_PUB, &CLIENT_NONCE)
            .expect_err("pin against identity-less daemon must abort");
        assert!(err.contains("no identity"), "unexpected error: {err}");
    }

    #[test]
    fn anonymous_mode_proceeds_without_pin() {
        let encoded = encode_hello_ack_payload(
            HelloAckMode::FullHandshake,
            Some(7801),
            Some((&SERVER_PUB, &SERVER_NONCE)),
            None,
            ahp_proto::CAP_NONE,
        );
        let ack = decode_hello_ack_payload(&encoded).unwrap();
        assert!(verify_server_identity(None, &ack, &CLIENT_PUB, &CLIENT_NONCE).is_ok());
    }

    #[test]
    fn parse_server_key_pin_accepts_hex_and_file() {
        let identity = SigningIdentity::generate();
        let hex = ahp_crypto::signatures::hex_encode(&identity.public_bytes());
        assert_eq!(parse_server_key_pin(&hex).unwrap(), identity.public_bytes());

        // File form: bare hex line, or full `keygen` output (hex is last line).
        let dir = std::env::temp_dir().join(format!("favonius-pin-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let bare = dir.join("key.hex");
        std::fs::write(&bare, format!("{hex}\n")).unwrap();
        assert_eq!(parse_server_key_pin(bare.to_str().unwrap()).unwrap(), identity.public_bytes());
        let keygen_out = dir.join("keygen.txt");
        std::fs::write(&keygen_out, format!("identity written to x\npublic key:\n{hex}\n")).unwrap();
        assert_eq!(parse_server_key_pin(keygen_out.to_str().unwrap()).unwrap(), identity.public_bytes());
        std::fs::remove_dir_all(&dir).ok();

        assert!(parse_server_key_pin("not-a-key").is_err());
        assert!(parse_server_key_pin("00ff").is_err());
    }

    #[test]
    fn extract_resume_secret_from_cached_ticket() {
        let mut ticket_key = TicketKey::generate();
        let secret = [0x42; 32];
        let ticket = ticket_key.issue(&secret, DEFAULT_TICKET_TTL).unwrap();
        // Cache layout: [encoded_ticket] [32-byte resume_secret]
        let mut cached = encode_ticket(&ticket);
        cached.extend_from_slice(&secret);
        assert_eq!(extract_resume_secret(&cached), Some(secret));

        // Missing or truncated secret → None (client plans plaintext).
        assert_eq!(extract_resume_secret(&encode_ticket(&ticket)), None);
        let mut truncated = cached.clone();
        truncated.truncate(truncated.len() - 1);
        assert_eq!(extract_resume_secret(&truncated), None);
        assert_eq!(extract_resume_secret(&[0xDE, 0xAD]), None);
    }

    // ── NACK → congestion controller loss delivery (F3) ─────────────────

    /// Records every `on_packet_lost` call; no-op otherwise.
    #[derive(Debug, Default)]
    struct MockCc {
        lost_events: Vec<Vec<u64>>,
    }

    impl CongestionController for MockCc {
        fn on_packet_sent(&mut self, _packet_number: u64, _bytes: usize, _now: Instant) {}
        fn on_ack_received(&mut self, _acked: &CcAckInfo, _now: Instant) {}
        fn on_packet_lost(&mut self, lost: &[u64], _now: Instant) {
            self.lost_events.push(lost.to_vec());
        }
        fn congestion_window(&self) -> usize { 1 << 20 }
        fn send_rate(&self) -> Option<u64> { None }
        fn can_send(&self, _bytes_in_flight: usize) -> bool { true }
        fn on_rtt_update(&mut self, _rtt: Duration) {}
        fn pacing_interval(&self, _packet_size: usize) -> Duration { Duration::ZERO }
    }

    fn nack_packet(stream_id: u32, ranges: Vec<(u64, u64)>) -> Packet {
        let nack = NackRange { stream_id, ranges };
        let mut buf = bytes::BytesMut::new();
        nack.encode(&mut buf);
        Packet {
            header: make_header(PacketType::NackRange, 1, 0, buf.len() as u32),
            extensions: vec![],
            payload: buf.freeze(),
        }
    }

    /// Build streams whose chunks all look sent long ago (send stamps are
    /// `sent_us` relative to the transfer start; with `t0_aged()` as the
    /// start, a stamp of 0 reads as ~1s old, so process_nack does not
    /// filter them as "recently sent").
    fn aged_streams(specs: &[(u32, u64, u64)]) -> Vec<StreamState> {
        specs
            .iter()
            .map(|&(id, base, count)| StreamState::new(id, base, count))
            .collect()
    }

    /// Transfer-start instant ~1s in the past, matching `aged_streams`.
    fn t0_aged() -> Instant {
        Instant::now() - Duration::from_secs(1)
    }

    #[test]
    fn nack_reports_new_losses_to_cc_once() {
        let mut streams = aged_streams(&[(0, 0, 10)]);
        let mut cc = MockCc::default();
        let mut in_flight = 0usize;

        let pkt = nack_packet(0, vec![(2, 4)]);
        process_nack(&pkt, &mut streams, &mut in_flight, 1200, &mut cc, t0_aged());
        assert_eq!(cc.lost_events, vec![vec![2, 3, 4]]);
        assert_eq!(streams[0].retx_queue.len(), 3);

        // Duplicate NACK for the same chunks: no re-queue, no second report.
        let pkt = nack_packet(0, vec![(2, 4)]);
        process_nack(&pkt, &mut streams, &mut in_flight, 1200, &mut cc, t0_aged());
        assert_eq!(cc.lost_events.len(), 1);
        assert_eq!(streams[0].retx_queue.len(), 3);
    }

    #[test]
    fn nack_skips_acked_and_recently_sent_chunks() {
        let mut streams = aged_streams(&[(0, 0, 10)]);
        streams[0].acked[3] = true;
        streams[0].n_acked = 1;
        // Chunk 4 was just (re-)sent — this NACK is stale for it.
        streams[0].sent_us[4] = 1_000_000; // ~now, given t0_aged() is 1s in the past

        let mut cc = MockCc::default();
        let mut in_flight = 0usize;
        let pkt = nack_packet(0, vec![(2, 4)]);
        process_nack(&pkt, &mut streams, &mut in_flight, 1200, &mut cc, t0_aged());

        assert_eq!(cc.lost_events, vec![vec![2]]);
        assert_eq!(streams[0].retx_queue.len(), 1);
    }

    #[test]
    fn nack_loss_reported_in_global_chunk_index_space() {
        // Two streams; stream 1 owns global chunk indices 5..10.
        let mut streams = aged_streams(&[(0, 0, 5), (1, 5, 5)]);
        let mut cc = MockCc::default();
        let mut in_flight = 0usize;

        // NACK stream 1's local chunks 0..=1 → global indices 5, 6.
        let pkt = nack_packet(1, vec![(5, 6)]);
        process_nack(&pkt, &mut streams, &mut in_flight, 1200, &mut cc, t0_aged());
        assert_eq!(cc.lost_events, vec![vec![5, 6]]);
        assert_eq!(streams[1].retx_queue.len(), 2);
        assert!(streams[0].retx_queue.is_empty());
    }

    // ── Spoofed ACK/NACK ranges must not livelock the sender (P2) ────────

    fn ack_packet(stream_id: u32, base: u64, highest_contiguous: u64, bitmap: &[u8]) -> Packet {
        let ack = AckBitmap {
            stream_id,
            base_packet_number: base,
            highest_contiguous,
            ack_delay_micros: 0,
            bitmap: bytes::Bytes::copy_from_slice(bitmap),
        };
        let mut buf = bytes::BytesMut::new();
        ack.encode(&mut buf);
        Packet {
            header: make_header(PacketType::AckBitmap, 1, 0, buf.len() as u32),
            extensions: vec![],
            payload: buf.freeze(),
        }
    }

    #[test]
    fn ack_bitmap_legitimate_contiguous_range_still_works() {
        let mut streams = aged_streams(&[(0, 0, 10)]);
        let mut in_flight = 5 * 1200usize;

        let pkt = ack_packet(0, 0, 4, &[]);
        let newly = process_ack_bitmap(&pkt, &mut streams, &mut in_flight, 1200, t0_aged());
        assert_eq!(newly.len(), 5);
        assert_eq!(streams[0].n_acked, 5);
        assert_eq!(in_flight, 0);

        // Duplicate ACK: nothing newly acked.
        let pkt = ack_packet(0, 0, 4, &[]);
        let newly = process_ack_bitmap(&pkt, &mut streams, &mut in_flight, 1200, t0_aged());
        assert!(newly.is_empty());
        assert_eq!(streams[0].n_acked, 5);
    }

    // ── Karn's algorithm & retransmit-queue hygiene ─────────────────────

    #[test]
    fn retransmitted_chunk_yields_no_rtt_sample() {
        // A chunk that has been queued for retransmit exists in two copies
        // on the wire, so `sent_us` no longer identifies which one an ACK
        // answers. Measuring anyway produces a sample bounded by the retx
        // interval rather than the path — the bug that collapsed the RTT
        // estimate to sub-millisecond values on a 150 ms link.
        let mut streams = aged_streams(&[(0, 0, 10)]);
        let mut in_flight = 4 * 1200usize;
        streams[0].next_local = 4;

        // Time out chunks 0..4, which marks them retransmitted.
        let lost = streams[0].queue_timed_out(elapsed_us(t0_aged()), 1_000);
        assert_eq!(lost, vec![0, 1, 2, 3]);

        // Chunk 2 is re-sent (stamp refreshed) and then acked along with
        // the rest: no chunk in this batch may produce an RTT sample.
        streams[0].flags[2] &= !CHUNK_IN_RETX;
        streams[0].sent_us[2] = elapsed_us(t0_aged());

        let pkt = ack_packet(0, 0, 3, &[]);
        let newly = process_ack_bitmap(&pkt, &mut streams, &mut in_flight, 1200, t0_aged());
        assert_eq!(newly.len(), 4);
        assert!(
            newly.iter().all(|&(_, rtt)| rtt.is_none()),
            "retransmitted chunks must not be timed: {newly:?}"
        );
    }

    #[test]
    fn untouched_chunk_still_yields_an_rtt_sample() {
        // Karn suppression must be limited to ambiguous chunks — a chunk
        // sent exactly once is still the estimator's only input.
        let mut streams = aged_streams(&[(0, 0, 10)]);
        let mut in_flight = 2 * 1200usize;
        streams[0].next_local = 2;

        let pkt = ack_packet(0, 0, 1, &[]);
        let newly = process_ack_bitmap(&pkt, &mut streams, &mut in_flight, 1200, t0_aged());
        assert_eq!(newly.len(), 2);
        assert!(
            newly.iter().all(|&(_, rtt)| rtt.is_some_and(|r| r >= Duration::from_millis(900))),
            "unambiguous chunks must be timed against their send stamp: {newly:?}"
        );
    }

    #[test]
    fn timeout_scan_does_not_requeue_a_waiting_chunk() {
        // A chunk can sit in `retx_queue` for longer than a whole timeout
        // interval when the window is full. Re-queueing it there pushes a
        // second copy that the send loop dutifully transmits again, and
        // inflates the `retx_queue.len()` correction the caller subtracts
        // from `in_flight`.
        let mut streams = aged_streams(&[(0, 0, 10)]);
        streams[0].next_local = 3;
        let now_us = elapsed_us(t0_aged());

        let first = streams[0].queue_timed_out(now_us, 1_000);
        assert_eq!(first, vec![0, 1, 2]);
        assert_eq!(streams[0].retx_queue.len(), 3);

        // A later scan, still well past the timeout, must find nothing:
        // these chunks are already queued.
        let second = streams[0].queue_timed_out(now_us.wrapping_add(500_000), 1_000);
        assert!(second.is_empty(), "re-queued chunks already awaiting resend: {second:?}");
        assert_eq!(streams[0].retx_queue.len(), 3);

        // Once popped for resend the chunk is eligible again, so a genuine
        // second loss is still recovered.
        let popped = streams[0].retx_queue.pop_front().unwrap();
        streams[0].flags[popped as usize] &= !CHUNK_IN_RETX;
        let third = streams[0].queue_timed_out(now_us.wrapping_add(600_000), 1_000);
        assert_eq!(third, vec![0]);
    }

    #[test]
    fn nack_does_not_requeue_a_waiting_chunk() {
        let mut streams = aged_streams(&[(0, 0, 10)]);
        let mut cc = MockCc::default();
        let mut in_flight = 0usize;
        streams[0].next_local = 4;

        let pkt = nack_packet(0, vec![(0, 2)]);
        process_nack(&pkt, &mut streams, &mut in_flight, 1200, &mut cc, t0_aged());
        assert_eq!(streams[0].retx_queue.len(), 3);
        assert_eq!(cc.lost_events, vec![vec![0, 1, 2]]);

        // A duplicate NACK for the same range adds nothing and reports no
        // new loss.
        let pkt = nack_packet(0, vec![(0, 2)]);
        process_nack(&pkt, &mut streams, &mut in_flight, 1200, &mut cc, t0_aged());
        assert_eq!(streams[0].retx_queue.len(), 3);
        assert_eq!(cc.lost_events.len(), 1, "duplicate NACK re-reported loss");
    }

    #[test]
    fn ack_bitmap_extreme_highest_contiguous_is_bounded() {
        let mut streams = aged_streams(&[(0, 0, 10)]);
        let mut in_flight = 0usize;

        // Stream 0 "nothing contiguous yet" sentinel: hc = chunk_base - 1
        // wraps to u64::MAX. Must not iterate to u64::MAX and must not mark
        // the contiguous range acked. (Returns immediately — a livelock
        // would hang the test runner.)
        let pkt = ack_packet(0, 0, u64::MAX, &[]);
        let newly = process_ack_bitmap(&pkt, &mut streams, &mut in_flight, 1200, t0_aged());
        assert!(newly.is_empty());
        assert_eq!(streams[0].n_acked, 0);

        // Contiguous range fully above the stream's chunk space: skipped,
        // and bitmap bits (relative to hc + 1) land out of range too.
        let pkt = ack_packet(0, 100, 200, &[0xFF; 8]);
        let newly = process_ack_bitmap(&pkt, &mut streams, &mut in_flight, 1200, t0_aged());
        assert!(newly.is_empty());
        assert_eq!(streams[0].n_acked, 0);

        // hc near u64::MAX with a full bitmap: wrapping packet-number math
        // must not overflow-panic; work stays bounded by the bitmap length.
        let pkt = ack_packet(0, 0, u64::MAX - 1, &[0xFF; 8]);
        let newly = process_ack_bitmap(&pkt, &mut streams, &mut in_flight, 1200, t0_aged());
        assert!(newly.len() <= 10);
    }

    #[test]
    fn ack_bitmap_wrapped_sentinel_with_bitmap_acks_reordered_chunks() {
        // Legitimate stream-0 initial reordering: nothing contiguous yet
        // (hc wrapped to u64::MAX), but the bitmap reports chunks received
        // out of order. bitmap_base = hc + 1 wraps back to chunk_base = 0.
        let mut streams = aged_streams(&[(0, 0, 10)]);
        let mut in_flight = 2 * 1200usize;

        let pkt = ack_packet(0, 0, u64::MAX, &[0b0000_0101]);
        let newly = process_ack_bitmap(&pkt, &mut streams, &mut in_flight, 1200, t0_aged());
        assert_eq!(newly.len(), 2);
        assert!(streams[0].acked[0]);
        assert!(streams[0].acked[2]);
        assert_eq!(streams[0].n_acked, 2);
    }

    #[test]
    fn ack_bitmap_clamps_to_stream_chunk_space() {
        // Stream 1 owns global chunk indices 5..10. An ACK with base below
        // chunk_base and hc inside the stream acks only the owned chunks.
        let mut streams = aged_streams(&[(0, 0, 5), (1, 5, 5)]);
        let mut in_flight = 10 * 1200usize;

        let pkt = ack_packet(1, 0, 7, &[]);
        let newly = process_ack_bitmap(&pkt, &mut streams, &mut in_flight, 1200, t0_aged());
        assert_eq!(newly.len(), 3); // global 5, 6, 7
        assert_eq!(streams[1].n_acked, 3);
        assert_eq!(streams[0].n_acked, 0);
    }

    #[test]
    fn nack_extreme_range_is_clamped_to_chunk_space() {
        let mut streams = aged_streams(&[(0, 0, 10)]);
        let mut cc = MockCc::default();
        let mut in_flight = 0usize;

        // A spoofed 0..=u64::MAX range clamps to the stream's 10 chunks
        // instead of iterating u64::MAX times.
        let pkt = nack_packet(0, vec![(0, u64::MAX)]);
        process_nack(&pkt, &mut streams, &mut in_flight, 1200, &mut cc, t0_aged());
        assert_eq!(streams[0].retx_queue.len(), 10);
        assert_eq!(cc.lost_events.len(), 1);
        assert_eq!(cc.lost_events[0].len(), 10);
    }

    #[test]
    fn nack_range_outside_stream_is_ignored() {
        let mut streams = aged_streams(&[(0, 0, 10), (1, 10, 5)]);
        let mut cc = MockCc::default();
        let mut in_flight = 0usize;

        // Entirely above this stream's chunk space: no work, no CC report.
        let pkt = nack_packet(0, vec![(u64::MAX - 5, u64::MAX)]);
        process_nack(&pkt, &mut streams, &mut in_flight, 1200, &mut cc, t0_aged());
        assert!(streams[0].retx_queue.is_empty());
        assert!(cc.lost_events.is_empty());

        // Straddling range: only the owned tail (global 8, 9) is queued.
        let pkt = nack_packet(0, vec![(8, u64::MAX)]);
        process_nack(&pkt, &mut streams, &mut in_flight, 1200, &mut cc, t0_aged());
        assert_eq!(streams[0].retx_queue.len(), 2);
        assert_eq!(cc.lost_events, vec![vec![8, 9]]);
        assert!(streams[1].retx_queue.is_empty());
    }

    // ── Cursor-based retransmit scan & compact send timestamps ──────────

    /// Reference implementation of the O(chunk_count) timeout sweep,
    /// expressed in `sent_us` terms. `queue_timed_out` must find exactly
    /// the same timeouts while scanning only the unacked tail.
    ///
    /// Mirrors the real contract: a chunk already queued for retransmit is
    /// skipped, and send stamps are left alone (they are rewritten when
    /// the chunk is actually re-sent, not when it is queued).
    fn reference_timeout_sweep(stream: &mut StreamState, now_us: u32, retx_us: u32) -> Vec<u64> {
        let sent_count = stream.next_local.min(stream.chunk_count);
        let mut lost = Vec::new();
        for li in 0..sent_count as usize {
            if stream.acked[li] || stream.flags[li] & CHUNK_IN_RETX != 0 {
                continue;
            }
            if now_us.wrapping_sub(stream.sent_us[li]) > retx_us {
                stream.retx_queue.push_back(li as u64);
                stream.flags[li] |= CHUNK_IN_RETX | CHUNK_RETRANSMITTED;
                lost.push(stream.to_global(li as u64));
            }
        }
        lost
    }

    #[test]
    fn retx_scan_cursor_matches_full_sweep() {
        // xorshift64 — deterministic.
        let mut x = 0x9E37_79B9_7F4A_7C15u64;
        let mut next = || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };

        for case in 0..100 {
            let count = 1 + next() % 200;
            let base = (next() % 3) * 1000; // exercise a non-zero chunk_base
            // `a` is driven through mark_acked (maintains scan_cursor);
            // `b` gets raw bit sets (what the reference sweep needs). Both
            // end up with identical acked/sent_us/next_local/retx_queue.
            let mut a = StreamState::new(0, base, count);
            let mut b = StreamState::new(0, base, count);
            let sent = next() % (count + 1);
            a.next_local = sent;
            b.next_local = sent;
            for i in 0..count as usize {
                let t = (next() % 100_000) as u32;
                a.sent_us[i] = t;
                b.sent_us[i] = t;
                if next() % 3 == 0 {
                    a.mark_acked(i);
                    b.acked[i] = true;
                    b.n_acked += 1;
                }
            }

            // Several timeout passes: between them, more chunks get sent
            // and more acks arrive (advancing the cursor).
            for pass in 0..3 {
                let now_us = (next() % 200_000) as u32;
                let retx_us = [0u32, 1, 100, 65_535][(next() % 4) as usize];
                let la = a.queue_timed_out(now_us, retx_us);
                let lb = reference_timeout_sweep(&mut b, now_us, retx_us);
                assert_eq!(la, lb, "case {case} pass {pass}: lost sets differ");
                assert_eq!(a.retx_queue, b.retx_queue, "case {case} pass {pass}: queues differ");
                assert_eq!(a.sent_us, b.sent_us, "case {case} pass {pass}: stamps differ");

                // Inter-pass churn: send more, ack more.
                let more_sent = next() % (count + 1);
                a.next_local = a.next_local.max(more_sent);
                b.next_local = b.next_local.max(more_sent);
                for i in 0..count as usize {
                    if next() % 4 == 0 {
                        a.mark_acked(i);
                        if !b.acked[i] {
                            b.acked[i] = true;
                            b.n_acked += 1;
                        }
                    }
                }
            }

            // Cursor invariant: everything below it is acked.
            assert!(a.acked[..a.scan_cursor as usize].iter().all(|&v| v));
        }
    }

    #[test]
    fn queue_timed_out_resets_stamps_and_scans_only_sent_tail() {
        let mut s = StreamState::new(0, 0, 10);
        s.next_local = 5; // chunks 5..10 unsent
        // Ages at now = 1250: [250, 350, 450, 150, 50] µs.
        s.sent_us[..5].copy_from_slice(&[1000, 900, 800, 1100, 1200]);
        let lost = s.queue_timed_out(1250, 200);
        // Chunks 0, 1, 2 are stale (> 200 µs); 3, 4 are not; 5+ unsent.
        assert_eq!(lost, vec![0, 1, 2]);
        assert_eq!(s.retx_queue.len(), 3);
        // Stamps of queued chunks were reset: an immediate second pass at
        // the same instant queues nothing.
        assert!(s.queue_timed_out(1250, 200).is_empty());
        // At now = 1450 the reset stamps sit exactly at the timeout
        // boundary (age 200, strict `>` → not stale), while chunks 3 and 4
        // have aged out.
        let lost = s.queue_timed_out(1450, 200);
        assert_eq!(lost, vec![3, 4]);
    }

    #[test]
    fn sent_us_wrapping_and_boundary_math() {
        // Boundary: strict `>` — an age exactly equal to the timeout is not
        // stale; acked chunks are never queued.
        let mut s = StreamState::new(0, 0, 3);
        s.next_local = 3;
        s.sent_us[0] = 1000; // age exactly 100 at now = 1100
        s.sent_us[1] = 999; // age 101
        s.mark_acked(2);
        let lost = s.queue_timed_out(1100, 100);
        assert_eq!(lost, vec![1]);

        // Wrap: a chunk sent at u32::MAX - 5 is 16 µs old at now = 10.
        let mut s = StreamState::new(0, 0, 2);
        s.next_local = 2;
        s.sent_us[0] = u32::MAX - 5;
        s.sent_us[1] = u32::MAX - 5;
        assert!(s.queue_timed_out(10, 100).is_empty()); // 16 µs < 100 µs
        assert_eq!(s.queue_timed_out(10, 10), vec![0, 1]); // 16 µs > 10 µs
    }

    #[test]
    fn hc_applied_makes_sequential_acks_incremental() {
        let mut streams = aged_streams(&[(0, 0, 10)]);
        let mut in_flight = 10 * 1200usize;

        // First ACK: contiguous prefix 0..=1, chunk 4 via bitmap.
        let pkt = ack_packet(0, 0, 1, &[0b0000_0100]); // bit 2 → hc+1+2 = 4
        let newly = process_ack_bitmap(&pkt, &mut streams, &mut in_flight, 1200, t0_aged());
        assert_eq!(newly.len(), 3); // 0, 1, 4
        assert_eq!(streams[0].hc_applied, 2);

        // Second ACK: prefix advanced to 4 — only 2, 3 are newly applied;
        // the already-applied range (and bitmap-acked 4) is not revisited.
        let pkt = ack_packet(0, 0, 4, &[]);
        let newly = process_ack_bitmap(&pkt, &mut streams, &mut in_flight, 1200, t0_aged());
        let pns: Vec<u64> = newly.iter().map(|&(pn, _)| pn).collect();
        assert_eq!(pns, vec![2, 3]);
        assert_eq!(streams[0].n_acked, 5);
        assert_eq!(in_flight, 5 * 1200);

        // A stale ACK with a regressed prefix reports nothing.
        let pkt = ack_packet(0, 0, 2, &[]);
        let newly = process_ack_bitmap(&pkt, &mut streams, &mut in_flight, 1200, t0_aged());
        assert!(newly.is_empty());
        assert_eq!(streams[0].n_acked, 5);
    }

    // ── Empty-file transfer must not divide by zero (P7) ─────────────────

    #[test]
    fn build_streams_with_zero_chunks_does_not_panic() {
        // Empty file: total_chunks == 0 clamps num_streams to 0 at the call
        // site — build_streams must still not divide by zero.
        let streams = super::build_streams(0, 0);
        assert!(streams.iter().map(|s| s.n_acked).sum::<u64>() == 0);

        // The clamped call-site path: one empty stream, no work, so the
        // transfer loop is skipped and FINISH alone completes the transfer.
        let streams = super::build_streams(0, 1);
        assert_eq!(streams.len(), 1);
        assert_eq!(streams[0].chunk_count, 0);
        assert!(!streams[0].has_work());

        // Normal splitting is unchanged.
        let streams = super::build_streams(10, 4);
        let counts: Vec<u64> = streams.iter().map(|s| s.chunk_count).collect();
        assert_eq!(counts, vec![3, 3, 2, 2]);
        assert_eq!(streams[1].chunk_base, 3);
    }

    // ── Nameless source path must error, not panic (P8) ──────────────────

    #[tokio::test]
    async fn send_with_nameless_source_path_returns_err() {
        for source in [std::path::Path::new("/"), std::path::Path::new("..")] {
            let result = super::send_file(
                "127.0.0.1:1".parse().unwrap(),
                source,
                "/tmp/out",
                Some(super::CongestionProfile::Classic),
                super::AckMode::Bitmap,
                4,
                "auto",
                false,
                super::CompressionProfile::None,
                false,
                None,
                false,
                None,
            )
            .await;
            let err = match result {
                Ok(_) => panic!("nameless source path must fail"),
                Err(e) => e,
            };
            assert!(
                err.to_string().contains("file name"),
                "unexpected error for {source:?}: {err}"
            );
        }
    }

    // ── Pre-stage header transforms for no-mutation backends (F4) ────────

    use super::{HeaderTransforms, PacketSender, HEADER_SIZE, MAX_PACKET, WIRE_OVERHEAD};
    use ahp_crypto::header_protection::HeaderProtector;
    use ahp_platform_net::{Capabilities, PacketBatchSender, SendError};
    use ahp_proto::{encode_data_packet_into, update_crc};
    use std::sync::{Arc, Mutex};

    const TEST_CONN_ID: u64 = 0x1122_3344_5566_7788;
    const TEST_PKT_NUM: u64 = 42;
    const COMPRESSED: u16 = 0x0010;

    /// macOS-like mock: copies each staged packet and cannot mutate it
    /// afterwards (default `modify_last_packet` returns false, default
    /// `supports_post_stage_mutation` is false).
    struct MockNoMutateSender {
        staged: Arc<Mutex<Vec<Vec<u8>>>>,
    }

    impl PacketBatchSender for MockNoMutateSender {
        fn stage(&mut self, packet: &[u8]) -> Result<usize, SendError> {
            self.staged.lock().unwrap().push(packet.to_vec());
            Ok(packet.len())
        }
        fn flush(&mut self) -> Result<usize, SendError> { Ok(0) }
        fn is_full(&self) -> bool { false }
        fn pending(&self) -> usize { self.staged.lock().unwrap().len() }
        fn capabilities(&self) -> Capabilities {
            Capabilities {
                max_batch_size: 64,
                supports_segmentation_offload: false,
                supports_zero_copy: false,
                typical_throughput_mbps: 550,
            }
        }
        fn name(&self) -> &'static str { "mock/no-mutate" }
    }

    /// Linux-GSO-like mock: hands back a slice of the last staged packet.
    struct MockMutateSender {
        staged: Arc<Mutex<Vec<Vec<u8>>>>,
    }

    impl PacketBatchSender for MockMutateSender {
        fn stage(&mut self, packet: &[u8]) -> Result<usize, SendError> {
            self.staged.lock().unwrap().push(packet.to_vec());
            Ok(packet.len())
        }
        fn flush(&mut self) -> Result<usize, SendError> { Ok(0) }
        fn is_full(&self) -> bool { false }
        fn pending(&self) -> usize { self.staged.lock().unwrap().len() }
        fn modify_last_packet(&mut self, f: &mut dyn FnMut(&mut [u8])) -> bool {
            match self.staged.lock().unwrap().last_mut() {
                Some(pkt) => {
                    f(pkt);
                    true
                }
                None => false,
            }
        }
        fn supports_post_stage_mutation(&self) -> bool { true }
        fn capabilities(&self) -> Capabilities {
            Capabilities {
                max_batch_size: 64,
                supports_segmentation_offload: true,
                supports_zero_copy: false,
                typical_throughput_mbps: 900,
            }
        }
        fn name(&self) -> &'static str { "mock/mutate" }
    }

    /// Mirror of the transfer loop's staging sequence for one packet:
    /// stage with the transforms, then run the post-stage fix-ups (which
    /// no-op on backends that already applied them pre-stage) in wire order:
    /// flag mutation first, then header protection.
    fn stage_one(sender: &mut PacketSender, hp: Option<&HeaderProtector>, compressed: bool, data: &[u8]) {
        sender.stage_data(
            TEST_CONN_ID, TEST_PKT_NUM, 1, 0, 7, 0, 123_456_789, data,
            HeaderTransforms { hp, flags: if compressed { COMPRESSED } else { 0 } },
        );
        if compressed {
            sender.set_last_packet_flag(COMPRESSED);
        }
        if let Some(hp) = hp {
            sender.protect_last_packet_header(hp);
        }
    }

    #[test]
    fn pre_stage_transforms_reach_the_wire_on_no_mutation_backends() {
        let staged: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));
        let mock = MockNoMutateSender { staged: staged.clone() };
        let mut sender = PacketSender::Platform(Box::new(mock), vec![0u8; MAX_PACKET]);

        let hp_key = [0xAB; 16];
        let hp = HeaderProtector::new(&hp_key);
        let data = [0x5Au8; 256];
        stage_one(&mut sender, Some(&hp), true, &data);

        let pkts = staged.lock().unwrap();
        assert_eq!(pkts.len(), 1);
        let pkt = &pkts[0];
        assert_eq!(pkt.len(), WIRE_OVERHEAD + data.len());

        // The COMPRESSED flag reached the wire (F4: silently dropped on macOS).
        let flags = u16::from_be_bytes([pkt[2], pkt[3]]);
        assert_ne!(flags & COMPRESSED, 0);

        // Header protection reached the wire: conn_id + packet_number masked.
        assert_ne!(&pkt[6..14], &TEST_CONN_ID.to_be_bytes());
        assert_ne!(&pkt[18..26], &TEST_PKT_NUM.to_be_bytes());

        // ... and the protected header unprotects correctly with the key.
        let mut unprotected = pkt.clone();
        HeaderProtector::new(&hp_key).unprotect(&mut unprotected, HEADER_SIZE);
        assert_eq!(&unprotected[6..14], &TEST_CONN_ID.to_be_bytes());
        assert_eq!(&unprotected[18..26], &TEST_PKT_NUM.to_be_bytes());
        assert_eq!(&unprotected[WIRE_OVERHEAD..], &data);
    }

    #[test]
    fn pre_stage_compressed_flag_without_header_protection() {
        // Unencrypted but compressed transfer on a no-mutation backend.
        let staged: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));
        let mock = MockNoMutateSender { staged: staged.clone() };
        let mut sender = PacketSender::Platform(Box::new(mock), vec![0u8; MAX_PACKET]);

        let data = [0x11u8; 128];
        stage_one(&mut sender, None, true, &data);

        let pkts = staged.lock().unwrap();
        let pkt = &pkts[0];
        let flags = u16::from_be_bytes([pkt[2], pkt[3]]);
        assert_ne!(flags & COMPRESSED, 0);
        // No header protection: conn_id and packet_number in the clear.
        assert_eq!(&pkt[6..14], &TEST_CONN_ID.to_be_bytes());
        assert_eq!(&pkt[18..26], &TEST_PKT_NUM.to_be_bytes());
    }

    #[test]
    fn pre_stage_and_post_stage_paths_are_wire_identical() {
        let hp_key = [0xCD; 16];
        let hp = HeaderProtector::new(&hp_key);
        let data: Vec<u8> = (0..=255u8).collect();

        let pre_staged: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));
        let mut pre = PacketSender::Platform(
            Box::new(MockNoMutateSender { staged: pre_staged.clone() }),
            vec![0u8; MAX_PACKET],
        );
        stage_one(&mut pre, Some(&hp), true, &data);

        let post_staged: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));
        let mut post = PacketSender::Platform(
            Box::new(MockMutateSender { staged: post_staged.clone() }),
            vec![0u8; MAX_PACKET],
        );
        stage_one(&mut post, Some(&hp), true, &data);

        // The receiver must not be able to tell which path produced the packet.
        assert_eq!(*pre_staged.lock().unwrap(), *post_staged.lock().unwrap());
    }

    #[test]
    fn flag_mutated_data_header_passes_crc_validation() {
        // The COMPRESSED flag is OR-ed in post-encode; the header CRC must
        // cover the final flag bits so a CRC-validating receiver accepts the
        // packet — on pre-stage and post-stage paths, with and without
        // header protection.
        let hp_key = [0x7Eu8; 16];
        let hp = HeaderProtector::new(&hp_key);
        let data = [0x33u8; 200];

        for hp in [None, Some(&hp)] {
            for mutate in [false, true] {
                let staged: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));
                let mut sender = if mutate {
                    PacketSender::Platform(
                        Box::new(MockMutateSender { staged: staged.clone() }),
                        vec![0u8; MAX_PACKET],
                    )
                } else {
                    PacketSender::Platform(
                        Box::new(MockNoMutateSender { staged: staged.clone() }),
                        vec![0u8; MAX_PACKET],
                    )
                };
                stage_one(&mut sender, hp, true, &data);

                let mut pkt = staged.lock().unwrap()[0].clone();
                if let Some(hp) = hp {
                    hp.unprotect(&mut pkt, HEADER_SIZE);
                }
                // Full decode — validates the CRC32C over the first 38 bytes.
                let mut slice: &[u8] = &pkt;
                let decoded = ahp_proto::PacketHeader::decode(&mut slice)
                    .unwrap_or_else(|e| panic!("CRC must cover mutated flags (hp={hp:?}, mutate={mutate}): {e}"));
                assert_ne!(decoded.flags.bits() & COMPRESSED, 0);
            }
        }
    }

    // ── S2: data-plane AEAD authenticates the fixed header ──────────────

    /// Mirror of the sender's encrypt + stage sequence for one DATA packet:
    /// AAD from the logical header, encrypt, encode, HP, flag mutation.
    /// Returns the wire packet and the sender-side AAD.
    fn encrypted_wire_packet(
        data_key: &[u8; 32],
        data_iv: &[u8; 12],
        hp_key: Option<&[u8; 16]>,
        compressed: bool,
        plaintext: &[u8],
    ) -> (Vec<u8>, [u8; HEADER_SIZE], [u8; 12]) {
        use ahp_crypto::packet_protection::Aes256GcmProtector;
        use ahp_crypto::NonceGenerator;

        let conn_id = TEST_CONN_ID;
        let seq = TEST_PKT_NUM;
        let stream_id = 3u32;
        let ts = 123_456_789u64;
        let flags = if compressed { COMPRESSED } else { 0 };

        let nonce = NonceGenerator::new(*data_iv).nonce_for(seq);
        let prot = Aes256GcmProtector::new(data_key);
        let mut crypt_buf = vec![0u8; plaintext.len() + 16];
        crypt_buf[..plaintext.len()].copy_from_slice(plaintext);
        let aad = data_header_aad(
            conn_id, seq, stream_id, ts,
            DATA_PAYLOAD_HEADER_SIZE + crypt_buf.len(), flags,
        );
        let enc_len = prot
            .encrypt_in_place(&nonce, &aad, &mut crypt_buf, plaintext.len())
            .unwrap();

        // Encode as stage_data does, then apply the post-encode transforms
        // in wire order: flag mutation (with a CRC refresh), then header
        // protection.
        let mut pkt = vec![0u8; MAX_PACKET];
        let n = encode_data_packet_into(
            &mut pkt, conn_id, seq, ts, stream_id, 0, 7, 0, &crypt_buf[..enc_len],
        );
        pkt.truncate(n);
        if compressed {
            let cur = u16::from_be_bytes([pkt[2], pkt[3]]);
            pkt[2..4].copy_from_slice(&(cur | COMPRESSED).to_be_bytes());
            update_crc(&mut pkt[..HEADER_SIZE]);
        }
        if let Some(key) = hp_key {
            HeaderProtector::new(key).protect(&mut pkt, HEADER_SIZE);
        }
        (pkt, aad, nonce)
    }

    #[test]
    fn data_aad_matches_receiver_view_and_decrypts() {
        use ahp_crypto::packet_protection::Aes256GcmProtector;

        let data_key = [0x42; 32];
        let data_iv = [0x11; 12];
        let hp_key = [0x24; 16];
        let plaintext = b"chunk payload bytes for aad round-trip";

        for hp in [None, Some(&hp_key)] {
            for compressed in [false, true] {
                let (mut pkt, aad, nonce) =
                    encrypted_wire_packet(&data_key, &data_iv, hp, compressed, plaintext);

                // Receiver: unprotect, then the wire header IS the AAD.
                if let Some(key) = hp {
                    HeaderProtector::new(key).unprotect(&mut pkt, HEADER_SIZE);
                }
                assert_eq!(
                    &pkt[..HEADER_SIZE], &aad[..],
                    "sender AAD must equal receiver AAD (hp={hp:?}, compressed={compressed})"
                );
                let flags = u16::from_be_bytes([pkt[2], pkt[3]]);
                assert_eq!((flags & COMPRESSED) != 0, compressed);

                // Decrypt with the header AAD recovers the plaintext.
                let prot = Aes256GcmProtector::new(&data_key);
                let mut dec = pkt[WIRE_OVERHEAD..].to_vec();
                let clen = dec.len();
                let dec_len = prot
                    .decrypt_in_place(&nonce, &pkt[..HEADER_SIZE], &mut dec, clen)
                    .unwrap();
                assert_eq!(&dec[..dec_len], &plaintext[..]);
            }
        }
    }

    #[test]
    fn tampered_header_fails_authentication() {
        use ahp_crypto::packet_protection::Aes256GcmProtector;

        let data_key = [0x42; 32];
        let data_iv = [0x11; 12];
        let hp_key = [0x24; 16];
        let plaintext = b"sensitive chunk data";

        for hp in [None, Some(&hp_key)] {
            let (mut pkt, _aad, nonce) =
                encrypted_wire_packet(&data_key, &data_iv, hp, true, plaintext);
            if let Some(key) = hp {
                HeaderProtector::new(key).unprotect(&mut pkt, HEADER_SIZE);
            }
            let prot = Aes256GcmProtector::new(&data_key);

            // Flip the stream_id (byte 14) — previously this silently routed
            // decrypted data into the wrong stream.
            let mut tampered = pkt.clone();
            tampered[14] ^= 0x01;
            let mut dec = tampered[WIRE_OVERHEAD..].to_vec();
            let clen = dec.len();
            assert!(
                prot.decrypt_in_place(&nonce, &tampered[..HEADER_SIZE], &mut dec, clen).is_err(),
                "flipped stream_id must fail authentication (hp={hp:?})"
            );

            // Flip the COMPRESSED flag — must fail, not change parse semantics.
            let mut tampered = pkt.clone();
            tampered[3] ^= COMPRESSED as u8; // flags are BE at bytes [2..4]; 0x0010 is in byte 3
            let mut dec = tampered[WIRE_OVERHEAD..].to_vec();
            let clen = dec.len();
            assert!(
                prot.decrypt_in_place(&nonce, &tampered[..HEADER_SIZE], &mut dec, clen).is_err(),
                "flipped COMPRESSED flag must fail authentication (hp={hp:?})"
            );
        }
    }

    // ── S4: resumed HELLO_ACK carries the server nonce ──────────────────

    #[test]
    fn resumed_ack_feeds_client_key_derivation() {
        use ahp_crypto::session_ticket::derive_resumed_keys;

        // Daemon side encodes; client side decodes and derives. Both must
        // arrive at identical keys from (resume_secret, client, server).
        let server_nonce = [0x77; 16];
        let ack = ahp_proto::encode_hello_ack_resumed(Some(7801), &server_nonce, ahp_proto::CAP_NONE);
        let decoded = decode_hello_ack_payload(&ack).unwrap();
        assert_eq!(decoded.mode, HelloAckMode::Resumed);
        let client_nonce = [0x07; 16];
        let secret = [0x42; 32];
        let keys = derive_resumed_keys(
            &secret,
            &client_nonce,
            &decoded.resume_server_nonce.expect("server nonce required"),
        )
        .unwrap();
        let expected = derive_resumed_keys(&secret, &client_nonce, &server_nonce).unwrap();
        assert_eq!(keys.data_key, expected.data_key);
    }

    // ── S10: policy.json values are clamped ─────────────────────────────

    #[test]
    fn policy_params_are_clamped() {
        fn params(payload_size: usize, num_streams: u32, batch_size: usize) -> PolicyParams {
            PolicyParams {
                retx_timeout_ms: 100,
                min_cwnd_kb: 512,
                batch_size,
                progress_ack_interval_ms: 75,
                cc_profile: "classic".into(),
                ack_mode: "bitmap".into(),
                socket_buf_kb: 208,
                payload_size,
                num_streams,
            }
        }

        // Absurd hand-edited values (policy.json is unvalidated on load).
        let mut p = params(1_000_000, 0, 0);
        p.retx_timeout_ms = 0;
        p.progress_ack_interval_ms = u64::MAX;
        p.socket_buf_kb = usize::MAX;
        p.min_cwnd_kb = usize::MAX;
        sanitize_policy_params(&mut p);
        let max_payload = MAX_PACKET - WIRE_OVERHEAD - 16;
        assert_eq!(p.payload_size, max_payload);
        assert_eq!(p.num_streams, 1);
        assert_eq!(p.batch_size, 1);
        assert_eq!(p.socket_buf_kb, 64 * 1024);
        assert_eq!(p.retx_timeout_ms, 10);
        assert_eq!(p.progress_ack_interval_ms, 10_000);

        // Zero payload size (would divide-by-zero in chunk geometry) → 1;
        // stream/batch counts above the caps are pulled down.
        let mut p2 = params(0, 10_000, usize::MAX);
        sanitize_policy_params(&mut p2);
        assert_eq!(p2.payload_size, 1);
        assert_eq!(p2.num_streams, 64);
        assert_eq!(p2.batch_size, 1024);

        // In-range values pass through untouched.
        let mut p3 = params(1350, 4, 32);
        sanitize_policy_params(&mut p3);
        assert_eq!(p3.payload_size, 1350);
        assert_eq!(p3.num_streams, 4);
        assert_eq!(p3.batch_size, 32);
    }

    // ── S3: control plane is AEAD-sealed when encryption is negotiated ──

    fn test_session_keys() -> SessionKeys {
        let mut keys = SessionKeys::zeroed();
        keys.control_key = [0x42; 32];
        keys.control_iv = [0x11; 12];
        keys
    }

    #[test]
    fn sealed_finish_wire_round_trip() {
        use ahp_crypto::control::unseal_control;

        let keys = test_session_keys();
        let buf = encode_sealed_ctrl_packet(PacketType::Finish, 0xABCD, 11, &keys, &[]);

        // The wire packet decodes like any other; the payload is tag-only.
        let pkt = decode_packet(&buf).unwrap();
        assert_eq!(pkt.header.packet_type, PacketType::Finish);
        assert_eq!(pkt.header.payload_length as usize, CONTROL_TAG_LEN);

        // ... and unseals under the control key with the wire header as AAD.
        let opened = unseal_control(
            &keys, None, pkt.header.packet_number, &buf[..HEADER_SIZE], &pkt.payload,
        )
        .expect("authentic FINISH must unseal");
        assert!(opened.is_empty());

        // A forged FINISH (flipped tag byte) fails authentication.
        let mut forged = buf.clone();
        let last = forged.len() - 1;
        forged[last] ^= 0xFF;
        let forged_pkt = decode_packet(&forged).unwrap();
        assert!(unseal_control(
            &keys, None, forged_pkt.header.packet_number, &forged[..HEADER_SIZE], &forged_pkt.payload,
        ).is_none());

        // A cleartext FINISH (empty payload) is not accepted either.
        assert!(unseal_control(&keys, None, 11, &buf[..HEADER_SIZE], &[]).is_none());
    }

    #[test]
    fn sealed_key_update_carries_epoch() {
        use ahp_crypto::control::unseal_control;
        use ahp_crypto::key_update::decode_key_update;

        let keys = test_session_keys();
        let buf = encode_sealed_ctrl_packet(
            PacketType::KeyUpdate, 7, 21, &keys, &encode_key_update(1),
        );
        let pkt = decode_packet(&buf).unwrap();
        assert_eq!(pkt.header.packet_type, PacketType::KeyUpdate);
        let opened = unseal_control(&keys, None, 21, &buf[..HEADER_SIZE], &pkt.payload)
            .expect("authentic KEY_UPDATE must unseal");
        assert_eq!(decode_key_update(&opened), Some(1));
    }

    // ── B5: PacedSender ring slots are never rewritten mid-send ──────────

    /// Payload whose every byte is derived from a counter (byte i is
    /// `counter.to_le_bytes()[i % 8]`), with the counter itself in the first
    /// 8 bytes: any torn read mixing two write generations of the same ring
    /// slot fails the coherence check.
    #[cfg(target_os = "linux")]
    fn patterned_payload(counter: u64, len: usize) -> Vec<u8> {
        let le = counter.to_le_bytes();
        (0..len).map(|i| le[i % 8]).collect()
    }

    /// Returns the counter if the payload is a coherent `patterned_payload`.
    #[cfg(target_os = "linux")]
    fn payload_counter(payload: &[u8]) -> Option<u64> {
        if payload.len() < 8 {
            return None;
        }
        let counter = u64::from_le_bytes(payload[..8].try_into().unwrap());
        let le = counter.to_le_bytes();
        if payload.iter().enumerate().all(|(i, &b)| b == le[i % 8]) {
            Some(counter)
        } else {
            None
        }
    }

    /// Drive the paced sender with a tiny ring so the producer laps the
    /// pacer thread every few packets, and verify on a real loopback socket
    /// that every packet reaching the wire is coherent. Before B5 the
    /// producer could rewrite a slot while the consumer's sendmsg was still
    /// reading it; that race shows up here as a torn payload (or a lost /
    /// double-applied header transform). Dropped packets are fine — UDP
    /// backpressure drops are by design; only torn wire bytes fail the test.
    #[cfg(target_os = "linux")]
    #[test]
    fn paced_sender_ring_slots_are_never_torn() {
        use std::net::UdpSocket as StdUdpSocket;

        // Receiver: plain blocking std socket with a read timeout.
        let receiver = StdUdpSocket::bind("127.0.0.1:0").unwrap();
        receiver
            .set_read_timeout(Some(Duration::from_millis(500)))
            .unwrap();
        let recv_addr = receiver.local_addr().unwrap();

        // PacedSender takes a tokio socket only for its raw fd; build one on
        // a throwaway runtime (the pacer thread uses the fd directly).
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let sender_sock =
            rt.block_on(async { tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap() });

        // Tiny ring: the producer laps the consumer constantly.
        const SLOTS: usize = 8;
        let paced = super::PacedSender::new(&sender_sock, recv_addr, SLOTS);
        paced.set_pacing_interval(Duration::ZERO);
        let mut sender = PacketSender::Paced(paced);

        let recv_handle = std::thread::spawn(move || {
            let mut buf = vec![0u8; MAX_PACKET];
            let mut received = 0u64;
            loop {
                match receiver.recv_from(&mut buf) {
                    Ok((len, _)) => {
                        let pkt = &buf[..len];
                        // Header transforms must have reached the wire BEFORE
                        // the pacer thread read the slot: COMPRESSED flag in
                        // the clear, conn_id masked by header protection.
                        let flags = u16::from_be_bytes([pkt[2], pkt[3]]);
                        assert_ne!(flags & COMPRESSED, 0, "COMPRESSED flag lost on the wire");
                        assert_ne!(
                            &pkt[6..14],
                            &TEST_CONN_ID.to_be_bytes(),
                            "header protection lost on the wire"
                        );
                        assert!(
                            payload_counter(&pkt[WIRE_OVERHEAD..]).is_some(),
                            "torn packet on the wire: payload mixes two slot generations"
                        );
                        received += 1;
                    }
                    // Read timeout: producer finished, drain complete.
                    Err(e)
                        if e.kind() == std::io::ErrorKind::WouldBlock
                            || e.kind() == std::io::ErrorKind::TimedOut =>
                    {
                        break;
                    }
                    Err(e) => panic!("recv error: {e}"),
                }
            }
            received
        });

        let hp_key = [0x5A; 16];
        let hp = HeaderProtector::new(&hp_key);
        const N: u64 = 30_000;
        const PAYLOAD_LEN: usize = 512;
        for counter in 0..N {
            let payload = patterned_payload(counter, PAYLOAD_LEN);
            // The exact staging sequence of the send loop: stage with
            // transforms, then the post-stage fix-ups (no-ops for Paced).
            stage_one(&mut sender, Some(&hp), true, &payload);
            if counter % 64 == 0 {
                std::thread::yield_now();
            }
        }

        let received = recv_handle.join().unwrap();
        // Backpressure drops are expected with 8 slots; in release mode the
        // producer outruns the loopback receive buffer by a wide margin, so
        // the floor only needs to be large enough for the coherence checks
        // above to mean anything (a torn slot fails those assertions, not
        // this count).
        assert!(received > 500, "too few packets received: {received}/{N}");
    }

    /// The forward-compatibility claim for the manifest channel: a peer that
    /// has never heard of `features` must still parse a manifest carrying
    /// them, and a peer that expects them must parse one without.
    /// The advice fires only when it is both true and actionable: enough
    /// loss to matter, and a controller that treats loss as congestion.
    #[test]
    fn loss_advice_is_offered_only_when_it_would_help() {
        use ahp_congestion::CongestionProfile as P;
        // Lossy path on a loss-based controller: say something.
        let a = super::loss_advice(2_000, 100_000, P::Classic).expect("2% on classic");
        assert!(a.contains("2.0%"), "the measured rate must appear: {a}");
        assert!(a.contains("cycle"), "the alternative must be named: {a}");
        // ...and it must NOT read as an instruction, because which profile
        // is right depends on where the loss came from (measured).
        assert!(a.contains("congestion"), "the counter-case must be stated: {a}");

        // `udt` is loss-based too and collapsed to 5.3 MB/s in the same cell.
        assert!(super::loss_advice(2_000, 100_000, P::Udt).is_some());

        // Already on a loss-tolerant profile: nothing useful to add.
        for p in [P::Model, P::Rl, P::Wifi] {
            assert!(super::loss_advice(2_000, 100_000, p).is_none(), "{p} needs no advice");
        }

        // Clean path: silence. A WAN at 0.0-0.5% retx must not nag.
        assert!(super::loss_advice(500, 100_000, P::Classic).is_none());
        assert!(super::loss_advice(0, 100_000, P::Classic).is_none());
        // Degenerate input must not divide by zero.
        assert!(super::loss_advice(0, 0, P::Classic).is_none());
    }

    #[test]
    fn manifest_features_are_forward_and_backward_compatible() {
        // Old sender -> new daemon: no `features` key at all.
        let old_json = r#"{"file_name":"f","file_size":1,"dest_path":"/d",
            "payload_size":1350,"total_chunks":1}"#;
        let m: crate::net_sender::FileManifest = serde_json::from_str(old_json).expect("must parse without features");
        assert!(m.features.is_empty(), "absent means no features selected");

        // New sender -> old daemon: unknown keys alongside features must not
        // break parsing, which is what `deny_unknown_fields` would have done.
        let new_json = r#"{"file_name":"f","file_size":1,"dest_path":"/d",
            "payload_size":1350,"total_chunks":1,
            "features":["multi-socket","some-future-thing"],
            "a_field_from_the_future":42}"#;
        let m: crate::net_sender::FileManifest = serde_json::from_str(new_json).expect("unknown keys must be ignored");
        assert_eq!(m.features, vec!["multi-socket", "some-future-thing"]);
    }

    /// An empty list must not appear on the wire at all, so a transfer
    /// between two current peers is byte-identical to one before this field
    /// existed.
    #[test]
    fn empty_features_are_not_serialized() {
        let m = crate::net_sender::FileManifest {
            file_name: "f".into(),
            file_size: 1,
            dest_path: "/d".into(),
            payload_size: 1350,
            total_chunks: 1,
            ack_mode: crate::net_sender::default_ack_mode(),
            num_streams: crate::net_sender::default_num_streams(),
            encrypted: false,
            compressed: false,
            header_protected: false,
            resume_mode: crate::net_sender::default_resume_mode(),
            file_hash: None,
            merkle_root: None,
            features: Vec::new(),
        };
        let json = serde_json::to_string(&m).unwrap();
        assert!(!json.contains("features"), "empty features must be omitted: {json}");
    }
}
