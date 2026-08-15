// Favonius — high-performance file transfer over UDP
// Copyright (c) 2025-2026 Vantino SàRL
// SPDX-License-Identifier: Apache-2.0

//! AHP protocol listener — receives files over UDP.
//!
//! Binds to the daemon's protocol port and handles incoming AHP transfers.
//! Each transfer: HELLO → HELLO_ACK → MANIFEST → DATA* → FINISH.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::{Bytes, BytesMut};
use memmap2::MmapMut;
use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;

use ahp_proto::*;

/// Maximum wire packet size.
const MAX_PACKET: usize = 1500;
/// Datagrams pulled per batched receive syscall (Linux recvmmsg). Sized so a
/// burst is drained in a few syscalls without adding latency when idle — an
/// empty socket still returns immediately with WouldBlock.
const RECV_BATCH: usize = 32;
/// Send an ACK bitmap every N data packets per stream.
/// At 4 streams and ~13k packets/sec/stream, 128 packets ≈ one ACK per 10ms
/// per stream — still 2.5× per RTT on a 4ms WiFi link.
const ACK_EVERY: u64 = 128;

/// Capabilities every transfer advertises regardless of what it was given.
///
/// Still empty: the only capability this daemon has to offer is per-stream
/// data ports, and that one is *per transfer* — it depends on the run the
/// pool could spare at HELLO time, so it is OR-ed in by `handle_transfer`
/// rather than being a constant. See
/// the per-stream data ports section of the README.
const DAEMON_CAPABILITIES: u32 = ahp_proto::CAP_NONE;

/// Feature tags this daemon understands in a manifest's `features` list.
/// An unknown tag is informational, never fatal.
const KNOWN_FEATURES: &[&str] = &[FEATURE_PER_STREAM_PORTS];

/// The sender reports back, in the MANIFEST, that it actually took up the
/// per-stream port run this daemon advertised. Purely diagnostic — the
/// daemon polls every socket it holds either way — but without it a log
/// shows only that the run was *offered*, and the two are the whole
/// difference between the A and B arms of this measurement.
const FEATURE_PER_STREAM_PORTS: &str = "per-stream-ports";

/// Maximum parallel streams accepted from a manifest. The sender side
/// negotiates at most 16 (policy clamp), so 64 leaves generous headroom
/// while bounding the per-stream allocation a crafted manifest can force.
const MAX_NUM_STREAMS: u32 = 64;
/// Hard cap on chunks per transfer. The per-stream `received` bitmaps cost
/// 1 byte per chunk, so 2^26 chunks ≈ 64 MiB of bitmaps; with the largest
/// payload (1500 B) that still covers ~96 GB files.
const MAX_TOTAL_CHUNKS: u64 = 1 << 26;

/// Data-plane inactivity limit for the active transfer's peer. Once the
/// DATA phase starts the sender's pacer emits continuously, so a full
/// silence of this length means a dead peer (SIGKILL, partition), not a
/// slow one. 15 s is half the sender's 30 s HELLO retry budget (15 × 2 s
/// in ahp-cli/src/net_sender.rs): a dead transfer is torn down while an
/// immediately retried sender is still retransmitting HELLOs, so the retry
/// is answered instead of timing out — without this the daemon waits out
/// the 300 s transfer timeout while the retry's HELLOs sit unread in the
/// control socket. The clock arms only when the recv thread starts — after
/// the MANIFEST and any resume exchange — so quiet setup phases
/// (pre-MANIFEST hashing, Merkle diff) can never trip it, and it refreshes
/// only on packets bearing THIS transfer's connection id, so stale or
/// spoofed traffic on the shared data port cannot keep a dead transfer
/// alive.
const PEER_INACTIVITY_TIMEOUT: Duration = Duration::from_secs(15);

/// Tail-of-transfer grace period. Once the completion check passes, the
/// recv thread stays on the data port this long as a "tail responder":
/// the final ACK bitmap(s) may have been lost in flight, and the sender —
/// not knowing the transfer is complete — keeps retransmitting the
/// "unacked" tail chunks. Without a listener those retransmissions land
/// on a deaf port, no ACK ever comes back, and the sender's 30 s stall
/// detector aborts a transfer the daemon already has in full. The grace
/// is bounded so a dead sender cannot hold the port, it ends immediately
/// on the peer's FINISH (the normal case) or a queued HELLO from the next
/// transfer, and it is far shorter than the stall timeout it protects
/// against.
const TAIL_GRACE: Duration = Duration::from_secs(3);

/// File manifest received from sender.
#[derive(serde::Deserialize)]
struct FileManifest {
    file_name: String,
    file_size: u64,
    dest_path: String,
    payload_size: usize,
    total_chunks: u64,
    /// Acknowledgement mode: bitmap (default) or nack.
    #[serde(default = "default_ack_mode")]
    ack_mode: ahp_proto::data::AckMode,
    /// Number of parallel streams (default 1 for backward compatibility).
    #[serde(default = "default_num_streams")]
    num_streams: u32,
    /// Whether DATA payloads are compressed.
    #[serde(default)]
    compressed: bool,
    /// Whether packet headers are protected (connection_id + packet_number masked).
    #[serde(default)]
    header_protected: bool,
    /// Resume mode: "none", "bitmap", "merkle".
    #[serde(default = "default_resume_mode")]
    resume_mode: String,
    /// BLAKE3 hash of the entire source file (hex).
    #[serde(default)]
    file_hash: Option<String>,
    /// Merkle tree root hash (hex, 64 chars). Present when resume_mode = "merkle".
    #[serde(default)]
    merkle_root: Option<String>,
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
    #[serde(default)]
    features: Vec<String>,
}

fn default_ack_mode() -> ahp_proto::data::AckMode {
    ahp_proto::data::AckMode::Bitmap
}

fn default_num_streams() -> u32 {
    1
}

fn default_resume_mode() -> String {
    "none".into()
}

/// Per-stream receive state for multi-stream multiplexing.
struct StreamRecvState {
    /// First global chunk index owned by this stream.
    chunk_base: u64,
    /// Total number of chunks in this stream.
    chunk_count: u64,
    /// Per local chunk: has this chunk been received?
    received: Vec<bool>,
    /// Number of received chunks in this stream.
    n_received: u64,
    /// Number of contiguously received local chunks from index 0 — i.e.
    /// highest_contiguous + 1. Tracked incrementally at mark time so
    /// `build_stream_ack_bitmap` (runs per emitted ACK) is O(bitmap cap)
    /// instead of O(chunk_count).
    contig_prefix: u64,
    /// Bitmap mode: packets since last ACK for this stream.
    since_ack: u64,
    /// Nack mode: high-water mark for gap detection (local chunk index).
    expected_next_local: u64,
    /// Nack mode: packets received since last gap was first seen. Used to
    /// delay NACKs until reordering has had a chance to resolve.
    gap_counter: u32,
    /// Nack mode: local chunk index where the current gap starts (if any).
    gap_start_local: Option<u64>,
    /// Nack mode: timestamp when the current gap was first detected.
    gap_first_seen: Option<Instant>,
    /// Nack mode: set of global chunk ranges already NACKed in this cooldown.
    nacked_ranges: std::collections::HashSet<u64>,
}

impl StreamRecvState {
    fn new(chunk_base: u64, chunk_count: u64) -> Self {
        Self {
            chunk_base,
            chunk_count,
            received: vec![false; chunk_count as usize],
            n_received: 0,
            contig_prefix: 0,
            since_ack: 0,
            expected_next_local: 0,
            gap_counter: 0,
            gap_start_local: None,
            gap_first_seen: None,
            nacked_ranges: std::collections::HashSet::new(),
        }
    }

    /// Mark a local chunk received and advance the contiguous prefix over
    /// any run that this completes. The advance is amortized O(1): each
    /// index is stepped over at most once per transfer.
    fn mark_received(&mut self, local_ci: usize) {
        self.received[local_ci] = true;
        self.n_received += 1;
        while (self.contig_prefix as usize) < self.received.len()
            && self.received[self.contig_prefix as usize]
        {
            self.contig_prefix += 1;
        }
    }
}

/// Build per-stream receive states by splitting total_chunks into num_streams ranges.
fn build_recv_streams(total_chunks: u64, num_streams: u32) -> Vec<StreamRecvState> {
    let ns = num_streams as u64;
    let chunks_per_stream = total_chunks / ns;
    let remainder = total_chunks % ns;
    let mut streams = Vec::with_capacity(num_streams as usize);
    let mut base: u64 = 0;
    for i in 0..num_streams {
        let count = chunks_per_stream + if (i as u64) < remainder { 1 } else { 0 };
        streams.push(StreamRecvState::new(base, count));
        base += count;
    }
    streams
}

/// Pre-populate per-stream received state from a resume bitmap: every chunk
/// whose bit is set is marked received so the receive loop only waits for
/// the chunks the sender will actually transmit. Returns chunks skipped.
fn apply_resume_bitmap(streams: &mut [StreamRecvState], bitmap: &[u8]) -> u64 {
    let mut total_skipped = 0u64;
    for stream in streams.iter_mut() {
        for local_ci in 0..stream.received.len() {
            let global_ci = (stream.chunk_base + local_ci as u64) as usize;
            let byte_idx = global_ci / 8;
            let bit_idx = global_ci % 8;
            if byte_idx < bitmap.len() && (bitmap[byte_idx] & (1 << bit_idx)) != 0 {
                stream.received[local_ci] = true;
                stream.n_received += 1;
                total_skipped += 1;
            }
        }
        // Rebuild the contiguous prefix over the pre-populated bits (one
        // pass per stream; afterwards it advances incrementally).
        while (stream.contig_prefix as usize) < stream.received.len()
            && stream.received[stream.contig_prefix as usize]
        {
            stream.contig_prefix += 1;
        }
    }
    total_skipped
}

/// Decode and validate a sender-reported resume bitmap (RESUME_REQ payload,
/// zstd-compressed like the daemon's own ResumeAck bitmap exchange). The
/// bitmap must cover exactly `total_chunks` bits: a wrong-sized bitmap would
/// either fail the transfer at finalization or silently skip chunks that
/// were never verified, so it is rejected outright. Note a well-sized but
/// dishonest bitmap is still caught by the whole-file BLAKE3 check in
/// `finalize_transfer` — this check only guards the accounting geometry.
fn decode_resume_bitmap(payload: &[u8], total_chunks: u64) -> Result<Vec<u8>, String> {
    let bitmap = zstd::decode_all(payload).unwrap_or_else(|_| payload.to_vec());
    let expected = (total_chunks as usize).div_ceil(8);
    if bitmap.len() != expected {
        return Err(format!(
            "invalid resume bitmap: {} bytes, expected {expected} for {total_chunks} chunks",
            bitmap.len()
        ));
    }
    Ok(bitmap)
}

/// Cross-validate manifest geometry before it drives any allocation,
/// `set_len`, or mmap slicing.
///
/// All of these fields arrive over the wire: `num_streams` and
/// `total_chunks` size allocations, `file_size` sizes the output file, and
/// the (file_size, payload_size, total_chunks) triple must agree or the
/// per-chunk offset math in the receive loop can slice out of bounds.
fn validate_manifest(m: &FileManifest, max_file_size: Option<u64>) -> Result<(), String> {
    if let Some(max_size) = max_file_size {
        if m.file_size > max_size {
            return Err(format!(
                "file size {} exceeds limit {} MB",
                m.file_size,
                max_size / (1024 * 1024)
            ));
        }
    }
    if m.payload_size == 0 || m.payload_size > MAX_PACKET {
        return Err(format!("invalid payload_size {}", m.payload_size));
    }
    if m.num_streams > MAX_NUM_STREAMS {
        return Err(format!(
            "num_streams {} exceeds limit {MAX_NUM_STREAMS}",
            m.num_streams
        ));
    }
    if m.total_chunks > MAX_TOTAL_CHUNKS {
        return Err(format!(
            "total_chunks {} exceeds limit {MAX_TOTAL_CHUNKS}",
            m.total_chunks
        ));
    }
    let expected_chunks = m.file_size.div_ceil(m.payload_size as u64);
    if m.total_chunks != expected_chunks {
        return Err(format!(
            "inconsistent manifest: total_chunks {} != ceil(file_size {} / payload_size {}) = {}",
            m.total_chunks, m.file_size, m.payload_size, expected_chunks
        ));
    }
    Ok(())
}

/// Map a wire chunk index to a stream-local index.
///
/// Returns `None` when `ci` is outside the stream's
/// `[chunk_base, chunk_base + chunk_count)` range — a crafted or stray
/// packet that must be skipped with no bookkeeping side effects. A plain
/// subtraction would underflow (panic in debug, wrap to ~u64::MAX in
/// release), poisoning `expected_next_local` and the NACK gap scan below
/// into a ~2^64-iteration hang.
fn local_chunk_index(stream: &StreamRecvState, ci: u64) -> Option<u64> {
    match ci.checked_sub(stream.chunk_base) {
        Some(l) if l < stream.chunk_count => Some(l),
        _ => None,
    }
}

/// Write `data` into the mapped file at `offset`, clamped to the mapped
/// region. A fully out-of-bounds region is skipped entirely —
/// defense-in-depth against packets/manifests that disagree on geometry
/// (the manifest is validated at ingest, so this should never trigger).
fn write_chunk(mmap: &mut [u8], offset: usize, data: &[u8]) {
    if offset >= mmap.len() {
        return;
    }
    let end = offset.saturating_add(data.len()).min(mmap.len());
    mmap[offset..end].copy_from_slice(&data[..end - offset]);
}

/// Linux: granularity of the periodic page drop behind each stream's
/// receive frontier. Per-stream because streams own disjoint contiguous
/// ranges: a single global contiguous-prefix frontier would cover only the
/// first stream's range until the very end of the transfer. 16 MiB × 4
/// default streams bounds the receive-phase mmap RSS at ~64 MiB regardless
/// of file size (same value as the sender's PAGE_DROP_GRANULARITY).
#[cfg(target_os = "linux")]
const PAGE_DROP_GRANULARITY: usize = 16 * 1024 * 1024;

/// Drop the mapping's page-table entries over `[offset, offset+len)` so the
/// pages stop counting toward this process's RSS. The range is aligned
/// inward to whole pages (madvise requires a page-aligned address).
///
/// Unlike the sender's read-only `drop_mapping_pages`, these pages are
/// DIRTY (received chunks are written through this MAP_SHARED mapping), so
/// the ordering question is "must they be written back first?" — no:
/// MADV_DONTNEED only unmaps the process's PTEs. Dirty page-cache pages
/// stay in the kernel's page cache and are written back by the flusher
/// threads and by the final detached msync+fsync; a re-fault (the
/// finalization hash re-read) finds the contents intact. Verified
/// empirically on Linux 7.0: contents survive DONTNEED with no flush at
/// all, observed through both the mapping and pread(2).
///
/// Why no sync_file_range/msync here anyway: submitting writeback inline
/// from the receive loop makes dirty+writeback pages cross the kernel's
/// dirty throttle ~2 GiB earlier than the baseline accumulate-then-fsync
/// behavior, pacing the whole transfer to disk speed (measured: 2 GiB
/// loopback 8.4 s → 16 s). Baseline lets the dirty pages sit (they were
/// the RSS), so the drop must leave writeback pacing to the kernel too.
///
/// Note on accounting: these pages are the process's only large RSS
/// consumer — the daemon mmaps the destination, so every received chunk
/// and every verification re-read faults file pages into the mapping, and
/// without the drop they accumulate to the full file size (measured:
/// peak RSS ≈ file size at 1/2/4 GiB). The pages are reclaimable page
/// cache, not leaked heap — harmless under memory pressure but
/// indistinguishable from a leak in RSS monitors, hence the bound.
#[cfg(target_os = "linux")]
fn drop_mapping_pages(map: &MmapMut, offset: usize, len: usize) {
    const PAGE: usize = 4096;
    let start = offset.next_multiple_of(PAGE);
    let end = offset.saturating_add(len).min(map.len()) & !(PAGE - 1);
    if end > start {
        let _ = unsafe {
            map.unchecked_advise_range(memmap2::UncheckedAdvice::DontNeed, start, end - start)
        };
    }
}

/// Handle the writeback pacer needs, where it exists.
///
/// `sync_file_range(2)` is a Linux syscall with no portable equivalent —
/// `fsync` is not the same thing, because the whole point is to start (or
/// wait on) writeback for *one range* without forcing the entire file. So
/// the pacer is Linux-only, and on every other target this degrades to a
/// unit: the option is still threaded through the receive loop so the
/// signature does not fork, and the code that would read it is compiled
/// out alongside the syscalls.
#[cfg(target_os = "linux")]
pub(crate) type WritebackFd = std::os::unix::io::RawFd;

/// See the Linux variant. Non-Linux targets have no range-writeback
/// facility, so this carries nothing.
#[cfg(not(target_os = "linux"))]
pub(crate) type WritebackFd = ();

/// Linux: how much received-but-not-yet-durable data we tolerate before the
/// receive loop starts waiting for the disk.
///
/// Why this exists. The receive path deliberately does not sync inline: it
/// writes through a MAP_SHARED mapping and lets the kernel's flusher handle
/// writeback, because submitting writeback from the receive loop paces the
/// whole transfer to disk speed (measured: 2 GiB loopback 8.4 s -> 16 s).
/// That is right when the disk is faster than the link.
///
/// When it is slower, the same design fails hard rather than degrading.
/// Dirty pages accumulate until the kernel's dirty throttle blocks the
/// writing thread outright; the receive loop stops draining the socket,
/// packets are dropped, the sender retransmits into a receiver that cannot
/// listen, and the transfer dies. Measured on a Raspberry Pi 4 whose SD
/// card writes at 17.3 MB/s over a 46 MB/s link: 9.6% retransmits and
/// **5 of 24 transfers failed outright**. The same runs to tmpfs: 0.4%
/// retransmits, 0 of 15 failed.
///
/// So: start writeback early and asynchronously (nearly free, and it stops
/// the backlog forming), and only if the backlog still grows past this
/// bound — proof the disk cannot keep up — wait for the oldest window.
/// Waiting slows the receive loop, which slows ACKs, which closes the
/// sender's window through the congestion control that already exists. The
/// transfer then runs at disk speed instead of failing, which is the
/// outcome a user wants and the one they did not get.
#[cfg(target_os = "linux")]
const WRITEBACK_BACKLOG_LIMIT: usize = 96 * 1024 * 1024;

/// Linux: ask the kernel to begin writing `[offset, len)` back, without
/// waiting. `SYNC_FILE_RANGE_WRITE` alone queues the I/O and returns.
#[cfg(target_os = "linux")]
fn start_writeback(fd: std::os::unix::io::RawFd, offset: usize, len: usize) {
    if len == 0 {
        return;
    }
    unsafe {
        nix::libc::sync_file_range(
            fd, offset as nix::libc::off64_t, len as nix::libc::off64_t,
            nix::libc::SYNC_FILE_RANGE_WRITE,
        );
    }
}

/// Linux: block until `[offset, len)` has actually reached the device.
/// Only called when the backlog shows the disk is behind.
#[cfg(target_os = "linux")]
fn await_writeback(fd: std::os::unix::io::RawFd, offset: usize, len: usize) {
    if len == 0 {
        return;
    }
    unsafe {
        nix::libc::sync_file_range(
            fd, offset as nix::libc::off64_t, len as nix::libc::off64_t,
            nix::libc::SYNC_FILE_RANGE_WAIT_BEFORE
                | nix::libc::SYNC_FILE_RANGE_WRITE
                | nix::libc::SYNC_FILE_RANGE_WAIT_AFTER,
        );
    }
}

/// Linux: whole-file BLAKE3 over the mapping in PAGE_DROP_GRANULARITY
/// windows, dropping each window behind the read frontier. Without the
/// chase the verification re-read would fault the entire file back into
/// the mapping, un-doing the receive-phase RSS bound at the last step.
/// Contents hashed are identical to `blake3::hash(&map[..len])`.
#[cfg(target_os = "linux")]
fn blake3_with_drop_chase(map: &MmapMut, len: usize) -> String {
    let mut hasher = blake3::Hasher::new();
    let mut offset = 0;
    while offset < len {
        let end = offset.saturating_add(PAGE_DROP_GRANULARITY).min(len);
        hasher.update(&map[offset..end]);
        drop_mapping_pages(map, offset, end - offset);
        offset = end;
    }
    hasher.finalize().to_hex().to_string()
}

/// Linux: whole-file Merkle build over the mapping in PAGE_DROP_GRANULARITY
/// windows, dropping each window behind the read frontier — the merkle-mode
/// counterpart of `blake3_with_drop_chase`. Without the chase the
/// finalization tree build would re-fault the entire file into RSS at the
/// last step, un-doing the receive-phase RSS bound. The streaming
/// `FileMerkleBuilder` tolerates arbitrary window splits (it buffers a
/// partial payload chunk across windows), so the resulting tree is
/// byte-identical to `build_file_merkle(&map[..len], payload_size)`
/// regardless of how the 16 MiB windows cut across payload boundaries —
/// the property `streaming_builder_matches_slice_path` tests in ahp-sync.
#[cfg(target_os = "linux")]
fn merkle_with_drop_chase(
    map: &MmapMut,
    len: usize,
    payload_size: usize,
) -> ahp_sync::merkle::MerkleTree {
    // Mirror build_file_merkle's zero-payload fallback (the manifest
    // validator already rejects payload_size == 0, so this is unreachable
    // on the transfer path).
    let mut builder = match ahp_sync::merkle::FileMerkleBuilder::new(payload_size) {
        Ok(b) => b,
        Err(_) => return ahp_sync::merkle::MerkleTree::from_leaves(&[]),
    };
    let mut offset = 0;
    while offset < len {
        let end = offset.saturating_add(PAGE_DROP_GRANULARITY).min(len);
        builder.update(&map[offset..end]);
        drop_mapping_pages(map, offset, end - offset);
        offset = end;
    }
    builder.finish()
}

/// Maximum ACK bitmap payload in bytes: bits for this many×8 chunks beyond
/// the contiguous prefix. The wire field is u16 and the sender's decoder
/// accepts any length, so raising the old 32-byte (256-chunk) cap is not a
/// wire-format change — larger bitmaps simply stop silently dropping
/// reordering reports on high-BDP links (256 chunks ≈ 345 KB at 1350 B
/// payloads; 8192 ≈ 11 MB). 42 B header + 26 B ACK header + 1024 B bitmap
/// = 1092 B, still under a 1500 B MTU.
const MAX_ACK_BITMAP_BYTES: usize = 1024;

/// Build ACK bitmap for a single stream.
///
/// Returns (highest_contiguous_pn, bitmap_bytes). Packet numbers are in the
/// stream's global chunk-index space (base = stream.chunk_base). The
/// contiguous prefix is the incrementally tracked `contig_prefix`, so this
/// is O(MAX_ACK_BITMAP_BYTES) per call, not O(chunk_count).
fn build_stream_ack_bitmap(stream: &StreamRecvState) -> (u64, Vec<u8>) {
    // Highest contiguous local chunk index (or "none" when the prefix is
    // empty): the receiver's sentinel is chunk_base - 1, which wraps to
    // u64::MAX for stream 0 — the sender's clamp handles it.
    let hc_pn = if stream.contig_prefix > 0 {
        stream.chunk_base + stream.contig_prefix - 1
    } else {
        stream.chunk_base.wrapping_sub(1)
    };

    // Build bitmap for chunks after highest_contiguous.
    let start = stream.contig_prefix as usize;
    let remaining = if start < stream.received.len() {
        &stream.received[start..]
    } else {
        &[]
    };

    let bitmap_len = remaining.len().div_ceil(8).min(MAX_ACK_BITMAP_BYTES);
    let mut bitmap = vec![0u8; bitmap_len];
    for (i, &r) in remaining.iter().enumerate() {
        if i >= MAX_ACK_BITMAP_BYTES * 8 {
            break;
        }
        if r {
            bitmap[i / 8] |= 1 << (i % 8); // LSB-first
        }
    }

    (hc_pn, bitmap)
}

fn make_header(ptype: PacketType, conn_id: u64, seq: u64, plen: u32) -> PacketHeader {
    PacketHeader {
        version: PROTOCOL_VERSION,
        packet_type: ptype,
        flags: PacketFlags::empty(),
        header_length: HEADER_SIZE as u16,
        connection_id: conn_id,
        stream_id: 0,
        packet_number: seq,
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_micros() as u64,
        payload_length: plen,
        header_crc: 0,
    }
}

/// Lexically normalize a path: resolve `.` and `..` components without
/// touching the filesystem (symlinks are NOT resolved). A `..` that would
/// climb above the root component is dropped.
fn lexical_normalize(path: &std::path::Path) -> std::path::PathBuf {
    let mut out = std::path::PathBuf::new();
    for comp in path.components() {
        match comp {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                out.pop();
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

/// Confine a sender-controlled destination path under `root` (S1).
///
/// `root` must already be canonicalized (done once at startup). The joined
/// path is lexically normalized and must stay under the root: absolute
/// destinations outside the root and `..` escapes are rejected.
fn confine_dest_path(root: &std::path::Path, dest: &str) -> Result<std::path::PathBuf, String> {
    let joined = lexical_normalize(&root.join(dest));
    if !joined.starts_with(root) {
        return Err(format!(
            "destination path {dest} escapes the configured --dest-root {}",
            root.display()
        ));
    }
    Ok(joined)
}

/// Control-plane datagrams routed to one transfer, by `connection_id`.
///
/// `handle_transfer` used to read MANIFEST and FINISH straight off the
/// shared control socket. That is safe only while exactly one transfer
/// exists: two would steal each other's control packets, the same failure
/// as two receive threads on one data socket. A single pump task now owns
/// the socket and routes each datagram to the transfer it belongs to, which
/// is what allows transfers to run concurrently at all.
type CtrlRx = tokio::sync::mpsc::Receiver<(Vec<u8>, SocketAddr)>;
type CtrlTx = tokio::sync::mpsc::Sender<(Vec<u8>, SocketAddr)>;

/// Longest run of contiguous data ports one transfer may reserve.
///
/// 8 is more than the 4-stream default needs, and the sender maps streams
/// beyond the run onto the last port, so a larger `--streams` degrades to
/// sharing rather than failing.
const MAX_PER_STREAM_PORTS: usize = 8;

/// How many sockets one transfer may hold, given the size of the whole
/// pool: half of it, at least one, never more than [`MAX_PER_STREAM_PORTS`].
///
/// A *fairness* cap, and the distinction from what this used to be matters.
/// The old rule held back one socket for every transfer that might still be
/// admitted, because a transfer that found the pool empty fell back to the
/// daemon's shared data socket and would have stolen DATA from whoever was
/// already on it — a correctness reserve, and a pessimistic one: a pool no
/// larger than the configured concurrency could never spare a run at all.
///
/// Admission now takes the socket first (see the accept loop), so a
/// transfer with nowhere to land is simply not admitted and its sender
/// retries — the same queueing `--max-concurrent` has always described.
/// With the correctness argument gone, all that is left is not letting one
/// transfer lock out every other, and half the pool is the simplest rule
/// that keeps two transfers running.
fn per_transfer_cap(pool_size: usize) -> usize {
    (pool_size / 2).clamp(1, MAX_PER_STREAM_PORTS)
}

/// Take this transfer's data sockets: the longest contiguous run up to
/// `max_run`, or a single socket, or `None` when the pool is empty.
///
/// `None` is now a "wait your turn", not a "carry on anyway". The caller
/// declines the transfer, and the sender — which already retries HELLO
/// every 2 s for up to 5 minutes against a busy daemon — comes back when a
/// socket has been returned.
async fn take_transfer_sockets(
    pool: &std::sync::Arc<tokio::sync::Mutex<Vec<std::sync::Arc<UdpSocket>>>>,
    max_run: usize,
) -> Option<Vec<std::sync::Arc<UdpSocket>>> {
    let mut pool = pool.lock().await;
    for n in (2..=max_run.min(pool.len())).rev() {
        if let Some(run) = take_contiguous_ports(&mut pool, n) {
            return Some(run);
        }
    }
    pool.pop().map(|s| vec![s])
}

/// Returns a transfer's data sockets to the pool, once, as soon as nothing
/// will read them again.
///
/// The natural place to do that looks like the end of the transfer, and it
/// is too late: the receive thread answers FINISH itself, so the sender is
/// gone while `handle_transfer` is still hashing the file and waiting for
/// writeback. Everything after the thread joins runs on the *control*
/// socket. A transfer starting in that window found the pool short and was
/// given a single socket — measured on loopback, where a 4 MiB file's
/// finalize is milliseconds; on a multi-GB file the whole-file BLAKE3 makes
/// the window seconds long.
///
/// `release` is idempotent because it is called twice on purpose: once
/// where it belongs, and once on the way out of `run_transfer_slot`, which
/// is what returns the sockets when the transfer failed, timed out, or
/// never reached the receive loop at all.
struct SocketReturn {
    pool: std::sync::Arc<tokio::sync::Mutex<Vec<std::sync::Arc<UdpSocket>>>>,
    socks: tokio::sync::Mutex<Option<Vec<std::sync::Arc<UdpSocket>>>>,
}

impl SocketReturn {
    fn new(
        pool: std::sync::Arc<tokio::sync::Mutex<Vec<std::sync::Arc<UdpSocket>>>>,
        socks: Vec<std::sync::Arc<UdpSocket>>,
    ) -> Self {
        Self { pool, socks: tokio::sync::Mutex::new(Some(socks)) }
    }

    /// Give back everything beyond the first `keep` sockets, now that the
    /// MANIFEST has said how many streams there will be.
    ///
    /// The run is reserved at HELLO time, before `num_streams` is known —
    /// that is why the capability advertises a count — so it is routinely
    /// longer than the transfer needs, and a **single-stream transfer was
    /// holding a run of five**. With a pool of ten that is two concurrent
    /// transfers instead of ten, for sockets that can never receive a
    /// packet: the sender maps stream *i* to `base + min(i, count-1)`, so
    /// nothing above `num_streams - 1` is addressable.
    ///
    /// Cheap and worth doing early: this runs before any DATA arrives.
    async fn release_tail(&self, keep: usize) {
        let mut held = self.socks.lock().await;
        let Some(socks) = held.as_mut() else { return };
        if keep == 0 || socks.len() <= keep {
            return;
        }
        let extra = socks.split_off(keep);
        drop(held);
        self.pool.lock().await.extend(extra);
    }

    async fn release(&self) {
        let Some(socks) = self.socks.lock().await.take() else {
            return; // already returned
        };
        // Drain first. The sender may still be retransmitting into these
        // ports (its FINISH reply can be lost), and the next transfer to
        // take one would spend real receive slots on datagrams it is only
        // going to drop by connection_id. Bounded by what is already
        // queued: nothing here waits for more.
        let mut buf = vec![0u8; MAX_PACKET];
        let mut drained = 0u64;
        for s in &socks {
            while s.try_recv_from(&mut buf).is_ok() {
                drained += 1;
            }
        }
        if drained > 0 {
            tracing::debug!(drained, "drained stale packets before returning data sockets");
        }
        // The whole run goes back, not just the base: a run returned short
        // leaks the rest of the pool one transfer at a time.
        self.pool.lock().await.extend(socks);
    }
}

/// Take `n` sockets on *consecutive* ports from the free pool.
///
/// Per-stream sockets need contiguity, not just count: the wire carries one
/// data port (HELLO_ACK's existing field) and the sender derives stream
/// *i*'s destination as `base + i`. That is what lets the split ship with
/// no new packet type and no new field — but it means the allocator has to
/// hand back a run, and the pool is a `Vec` that transfers pop from and
/// push back in arbitrary order, so runs fragment as transfers come and go.
///
/// Returns the sockets in ascending port order, or `None` if no run of `n`
/// exists — in which case the caller falls back to a single socket for the
/// whole transfer, which is correct, just slower.
fn take_contiguous_ports(
    pool: &mut Vec<std::sync::Arc<UdpSocket>>,
    n: usize,
) -> Option<Vec<std::sync::Arc<UdpSocket>>> {
    if n == 0 || pool.len() < n {
        return None;
    }
    // Index by port so the search is over ports, not pool order.
    let mut by_port: Vec<(u16, usize)> = pool
        .iter()
        .enumerate()
        .filter_map(|(i, s)| s.local_addr().ok().map(|a| (a.port(), i)))
        .collect();
    by_port.sort_unstable();

    let mut run_start = 0usize;
    for k in 1..=by_port.len() {
        let broken = k == by_port.len() || by_port[k].0 != by_port[k - 1].0 + 1;
        if k - run_start >= n {
            // Take the first run long enough; removing by descending index
            // keeps the remaining indices valid.
            let mut idxs: Vec<usize> =
                by_port[run_start..run_start + n].iter().map(|(_, i)| *i).collect();
            let mut taken: Vec<(u16, std::sync::Arc<UdpSocket>)> = Vec::with_capacity(n);
            idxs.sort_unstable_by(|a, b| b.cmp(a));
            for i in idxs {
                let sock = pool.remove(i);
                let port = sock.local_addr().map(|a| a.port()).unwrap_or(0);
                taken.push((port, sock));
            }
            taken.sort_by_key(|(p, _)| *p);
            return Some(taken.into_iter().map(|(_, s)| s).collect());
        }
        if broken {
            run_start = k;
        }
    }
    None
}

/// Bind one data socket at `data_addr`.
///
/// The premise of per-transfer (and later per-stream) sockets is that the
/// wire already supports it: `handle_transfer` takes the data port as a
/// parameter, HELLO_ACK carries it, and the sender honours whatever it is
/// told (`data_port.unwrap_or(control port)`). Nothing needs to be
/// negotiated. This function is the proof of that, and the building block
/// for real concurrency — each transfer owning its socket is what lets two
/// run at once without stealing each other's DATA.
///
/// Off by default. Ephemeral ports multiply the inbound firewall surface,
/// and UDP reachability is already this project's most common support
/// issue, so an operator has to opt in with `FAVONIUS_EPHEMERAL_DATA_PORT=1`
/// until there is a bounded `--data-port-range` to point a rule at.
fn bind_transfer_data_socket(
    data_addr: SocketAddr,
    rcvbuf_mb: usize,
) -> std::io::Result<UdpSocket> {
    let domain = if data_addr.is_ipv6() { Domain::IPV6 } else { Domain::IPV4 };
    let sock = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    sock.set_recv_buffer_size(rcvbuf_mb * 1024 * 1024)?;
    sock.set_send_buffer_size(2 * 1024 * 1024)?;
    sock.set_nonblocking(true)?;
    sock.bind(&data_addr.into())?;
    UdpSocket::from_std(sock.into())
}

/// Run the AHP protocol listener with separate control and data ports.
///
/// The **control socket** (e.g., 7801) handles HELLO, MANIFEST, FINISH and
/// stays in the async tokio main loop — always responsive to new connections.
///
/// The **data socket** (e.g., 7802) handles DATA + ACK packets and is handed
/// to the bitmap recv thread during transfers. This prevents the bitmap thread
/// from consuming HELLOs intended for the control port.
///
/// `dest_root`, when set, confines every transfer destination under that
/// directory (S1); when unset the daemon honors arbitrary sender-controlled
/// destination paths (a loud warning is logged at startup).
///
/// `identity`, when set, makes the daemon sign every full handshake with its
/// Ed25519 identity key and carry the signature in HELLO_ACK (S5, RFC §12.2)
/// so pinning clients can authenticate it.
pub async fn run_protocol_listener(
    control_addr: SocketAddr,
    data_addr: SocketAddr,
    max_concurrent: usize,
    // Inclusive range of extra data ports for parallel transfers. `None`
    // keeps the daemon serial on the single `data_addr` port.
    data_port_range: Option<(u16, u16)>,
    max_file_size: Option<u64>,
    dest_root: Option<std::path::PathBuf>,
    identity: Option<ahp_crypto::signatures::SigningIdentity>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Canonicalize the confinement root once: it must exist, and the
    // canonical form is what lexical `starts_with` checks compare against.
    let dest_root = match dest_root {
        Some(root) => {
            let canon = root.canonicalize().map_err(|e| {
                format!("--dest-root {} cannot be canonicalized: {e}", root.display())
            })?;
            tracing::info!(dest_root = %canon.display(), "destination confinement enabled");
            Some(canon)
        }
        None => {
            tracing::warn!(
                "no --dest-root configured: the daemon accepts ARBITRARY \
                 destination paths from any peer that can reach the control \
                 port — set --dest-root to confine incoming transfers"
            );
            None
        }
    };
    // Socket family follows the bind address. These were hardcoded to
    // `Domain::IPV4`, so `--protocol-listen [::]:7801` created a v4 socket
    // and every IPv6 HELLO was dropped without a log line — the sender saw
    // only "deadline has elapsed".
    let ctrl_domain = if control_addr.is_ipv6() { Domain::IPV6 } else { Domain::IPV4 };
    let data_domain = if data_addr.is_ipv6() { Domain::IPV6 } else { Domain::IPV4 };

    // Control socket: async, always in tokio.
    let ctrl_sock = Socket::new(ctrl_domain, Type::DGRAM, Some(Protocol::UDP))?;
    ctrl_sock.set_recv_buffer_size(1 * 1024 * 1024)?;
    ctrl_sock.set_send_buffer_size(1 * 1024 * 1024)?;
    ctrl_sock.set_nonblocking(true)?;
    ctrl_sock.bind(&control_addr.into())?;
    let socket = UdpSocket::from_std(ctrl_sock.into())?;

    // Data socket: given to bitmap recv thread during transfers.
    let data_sock = Socket::new(data_domain, Type::DGRAM, Some(Protocol::UDP))?;
    // 4 MB by default. `FAVONIUS_RCVBUF_MB` overrides it — a measurement
    // instrument, not a tuning knob: on loopback the receive buffer
    // overflows 230x more at 4 streams than at 1 (17 drops against 3939),
    // and every drop becomes a retransmit. Whether that is arrival
    // burstiness or a slower drain is what varying this separates.
    let rcvbuf_mb: usize = std::env::var("FAVONIUS_RCVBUF_MB")
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|m: &usize| *m >= 1 && *m <= 512)
        .unwrap_or(4);
    data_sock.set_recv_buffer_size(rcvbuf_mb * 1024 * 1024)?;
    data_sock.set_send_buffer_size(2 * 1024 * 1024)?;
    data_sock.set_nonblocking(true)?;
    data_sock.bind(&data_addr.into())?;
    let data_socket = std::sync::Arc::new(UdpSocket::from_std(data_sock.into())?);

    // Pre-bind the whole range now. Binding per transfer would surface a
    // port conflict as a mid-flight failure on someone else's transfer;
    // failing at startup means the operator learns immediately and the
    // firewall rule they opened is exactly what the daemon holds.
    let mut data_pool: Vec<std::sync::Arc<UdpSocket>> = Vec::new();
    if let Some((lo, hi)) = data_port_range {
        for port in lo..=hi {
            let addr = SocketAddr::new(data_addr.ip(), port);
            match bind_transfer_data_socket(addr, rcvbuf_mb) {
                Ok(s) => data_pool.push(std::sync::Arc::new(s)),
                Err(e) => {
                    return Err(format!(
                        "--data-port-range {lo}-{hi}: cannot bind {addr}: {e}"
                    )
                    .into())
                }
            }
        }
        tracing::info!(
            low = lo, high = hi, sockets = data_pool.len(),
            "data port range bound — open UDP {}-{} inbound for parallel transfers", lo, hi
        );
    }
    let pool_size = data_pool.len();
    let parallel_capable = pool_size > 0;
    // Sockets currently free. A transfer takes one and returns it on exit.
    let free_data_socks = std::sync::Arc::new(tokio::sync::Mutex::new(data_pool));

    // `--max-concurrent` is a queue depth unless per-transfer data sockets
    // are enabled, and saying so is the point.
    //
    // The daemon serves one transfer at a time: the accept loop below
    // `await`s `handle_transfer` inline, and `handle_transfer` receives
    // MANIFEST and FINISH on the *shared* control socket. Two transfers in
    // flight would steal each other's control packets, which is the same
    // class of bug as two receive threads sharing one data socket.
    //
    // Accepting `--max-concurrent 8` and then serialising was measured on
    // 2026-08-12: with the pre-fix sender, 1 of 2 and 2 of 4 concurrent
    // transfers failed outright; with the fixed sender they all succeed but
    // aggregate throughput is 854-866 Mbit against 895 for a single
    // transfer, i.e. no parallelism at all. Advertising a capability the
    // architecture does not have is worse than not offering it, so the
    // semaphore is pinned at 1 and the flag now only bounds how many
    // senders may queue.
    //
    // Real parallelism needs a per-transfer data socket (already expressible
    // on the wire — HELLO_ACK carries the data port and the sender honours
    // it) plus control-plane demultiplexing by connection_id, so each
    // transfer reads its own MANIFEST/FINISH from a channel instead of
    // racing on one socket. See the per-stream data ports section of
    // the README.
    let queue_depth = if max_concurrent > 0 { max_concurrent } else { 1024 };
    if queue_depth > 1 && !parallel_capable {
        tracing::warn!(
            requested = queue_depth,
            "--max-concurrent {} accepted as QUEUE DEPTH, not parallelism: parallel \
transfers need a data socket each, so pass --data-port-range LOW-HIGH to enable them. \
Additional senders currently wait for a slot",
            queue_depth
        );
    }
    // Parallelism is gated on per-transfer data sockets, because that is
    // what makes it safe: two transfers sharing one data socket would steal
    // each other's DATA, the same bug the control-plane router removed one
    // layer up. With the opt-in on, `--max-concurrent` finally means what
    // it says; without it the daemon is serial and the flag is queue depth.
    //
    // The permit no longer has to be clamped to the pool size. **The socket
    // is the admission token**: the accept loop takes one before it starts
    // anything, and a HELLO that cannot be given one is declined so the
    // sender retries — which is what `--max-concurrent` has always claimed
    // to do. That inversion is what makes a greedy port run safe. Under the
    // old order a permit could be granted with no socket left to back it,
    // and the transfer fell through to the shared socket; the allocator had
    // to hold a socket in reserve for every admission that might still
    // happen, which meant a pool no larger than the concurrency could never
    // spare a run at all.
    let permits = if parallel_capable { queue_depth } else { 1 };
    // What one transfer may hold, so a single big transfer cannot lock out
    // every other. Purely fairness now — see `per_transfer_cap`.
    let run_cap = per_transfer_cap(pool_size);
    let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(permits));
    let active_transfers = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));

    // Per-daemon-instance ticket key for 0-RTT session resumption.
    // Shared across concurrent transfers. `std::sync::Mutex` rather than
    // tokio's: every critical section here is a single synchronous call
    // (`decrypt`, `check_and_record`, `issue`) and no lock is held across an
    // `.await`, which is the only thing that would require the async lock.
    let ticket_key = std::sync::Arc::new(std::sync::Mutex::new(
        ahp_crypto::session_ticket::TicketKey::generate(),
    ));
    // Used-ticket registry: a ticket already presented to a previous
    // transfer is rejected (0-RTT replay protection, S4).
    //
    // `UsedTicketCache::check_and_record` is deliberately one call: it tests
    // and inserts under a single lock acquisition. Splitting it into a
    // `contains` then an `insert` would be a TOCTOU race the moment two
    // handshakes run at once, and would reopen the 0-RTT replay hole (S4)
    // that the server-nonce work closed. See the concurrent-replay test.
    let used_tickets = std::sync::Arc::new(std::sync::Mutex::new(
        ahp_crypto::session_ticket::UsedTicketCache::new(),
    ));

    tracing::info!(
        control = %control_addr, data = %data_addr,
        concurrency = permits,
        queue_depth,
        max_file_size_mb = max_file_size.map(|s| s / (1024 * 1024)).unwrap_or(0),
        identity = ?identity.as_ref().map(ahp_crypto::signatures::SigningIdentity::public_bytes),
        "AHP protocol listener ready (split control/data ports)"
    );
    // A pool of fewer than 4 cannot produce a run at all: one transfer may
    // hold at most half of it. Worth saying out loud, because the daemon
    // otherwise works exactly as before and says nothing — the operator
    // opened a firewall range and got no per-stream ports out of it. (An
    // end-to-end test configured that way silently tested nothing, which is
    // how the old version of this warning came to exist.)
    if parallel_capable && run_cap < 2 {
        tracing::warn!(
            ports = pool_size,
            "--data-port-range has {} port(s): one transfer may hold at most half the pool, so \
NO per-stream port run can be handed out. Give the range at least 4 ports — and for the full \
split, about (concurrent transfers) x (streams per transfer)",
            pool_size
        );
    } else if parallel_capable {
        tracing::info!(
            ports = pool_size, run_cap,
            "per-stream data ports available: up to {} contiguous ports per transfer", run_cap
        );
    }
    if identity.is_none() {
        tracing::warn!(
            "no --identity configured: handshakes are anonymous X25519 — \
             clients cannot authenticate this daemon (S5)"
        );
    }

    // ── Control-plane router ────────────────────────────────────────────
    // One task owns reading the control socket and dispatches each datagram
    // by `connection_id`: to the transfer that owns it, or — for a HELLO
    // from an unknown connection — to the accept loop below.
    //
    // Before this, `handle_transfer` read MANIFEST and FINISH directly off
    // the shared socket, which is correct only while exactly one transfer
    // exists. It also meant the accept loop could not read while a transfer
    // ran, so a HELLO arriving mid-transfer had to be recovered afterwards
    // by draining the socket — the block further down that this replaces.
    // Routing removes both problems and is the prerequisite for running
    // transfers concurrently.
    let socket = std::sync::Arc::new(socket);
    let routes: std::sync::Arc<tokio::sync::Mutex<std::collections::HashMap<u64, CtrlTx>>> =
        std::sync::Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new()));
    let (new_tx, mut new_rx) =
        tokio::sync::mpsc::channel::<(u64, SocketAddr, Vec<u8>)>(64);
    // Connections already queued for admission.
    //
    // A sender retries HELLO every 2 s, up to 15 times, until it is served.
    // Without this set the router enqueues *every* retry, so one waiting
    // sender can deposit fifteen copies of itself — and the accept loop
    // then starts a transfer for each, every one of which waits the full
    // 10 s MANIFEST timeout because that sender has long since been served
    // or given up. Three waiting senders was enough to wedge the daemon for
    // minutes (2026-08-12). The pre-router accept loop never saw this: it
    // read the socket directly, so a HELLO arriving mid-transfer was simply
    // dropped and the next retry was served cleanly.
    let pending: std::sync::Arc<tokio::sync::Mutex<std::collections::HashSet<u64>>> =
        std::sync::Arc::new(tokio::sync::Mutex::new(std::collections::HashSet::new()));
    // The accept loop keeps its own handle so a transfer can requeue a
    // HELLO its receive thread saw mid-flight.
    let new_tx_accept = new_tx.clone();
    // Shared, read-only, for the life of the daemon.
    let dest_root = dest_root.map(std::sync::Arc::new);
    let identity = std::sync::Arc::new(identity);
    {
        let socket = socket.clone();
        let routes = routes.clone();
        let pending = pending.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; MAX_PACKET];
            loop {
                let (len, from) = match socket.recv_from(&mut buf).await {
                    Ok(v) => v,
                    Err(e) => {
                        tracing::warn!("control socket read failed: {e}");
                        continue;
                    }
                };
                let pkt = match decode_packet(&buf[..len]) {
                    Ok(p) => p,
                    Err(e) => {
                        tracing::warn!("bad packet: {}", e);
                        continue;
                    }
                };
                if pkt.header.packet_type == PacketType::PathProbe {
                    let _ = echo_probe(&socket, from, &pkt).await;
                    continue;
                }
                let cid = pkt.header.connection_id;
                let route = routes.lock().await.get(&cid).cloned();
                if let Some(tx) = route {
                    // Full queue means that transfer is not draining its
                    // control packets; dropping is correct, the sender
                    // retransmits MANIFEST and FINISH.
                    let _ = tx.try_send((buf[..len].to_vec(), from));
                    continue;
                }
                if pkt.header.packet_type == PacketType::Hello {
                    // First HELLO for this connection only; retries while it
                    // waits are dropped, exactly as they were before the
                    // router existed.
                    if !pending.lock().await.insert(cid) {
                        continue;
                    }
                    if new_tx.send((cid, from, pkt.payload.to_vec())).await.is_err() {
                        break; // accept loop is gone; so is the daemon
                    }
                }
            }
        });
    }

    loop {
        // A HELLO from a connection no transfer owns.
        let Some((conn_id, sender, hello_payload)) = new_rx.recv().await else {
            return Ok(());
        };
        // Admitted: a later HELLO for this connection is a retry the
        // transfer itself should see, not a new admission.
        pending.lock().await.remove(&conn_id);

        // Concurrency requires a per-transfer data socket: two transfers on
        // one data socket would steal each other's DATA, which is the same
        // bug the control-plane router just removed one layer up. So the
        // port-range opt-in is what enables parallelism, and without it the
        // daemon stays strictly serial.
        let active = active_transfers.load(std::sync::atomic::Ordering::Relaxed);
        let permit = match semaphore.clone().try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                tracing::warn!(
                    conn_id, active,
                    "rejecting transfer: {} already running (queue depth {queue_depth})", active
                );
                decline_busy(&socket, sender, conn_id).await;
                continue;
            }
        };

        // ── The socket is the admission token ────────────────────────────
        //
        // Taken before anything else is started, and a HELLO that cannot be
        // given one is declined here — the sender retries every 2 s for up
        // to 5 minutes, which is exactly the queueing `--max-concurrent`
        // has always described. Nothing falls back to the daemon's shared
        // data socket while a pool exists, because that fallback is how two
        // transfers end up stealing each other's DATA.
        //
        // Doing it in this order is what lets the run be greedy: the old
        // code granted the permit first and had to keep a socket in reserve
        // for every admission that might still happen, so a pool no larger
        // than the concurrency never produced a run at all.
        let per_transfer_socks = if parallel_capable {
            match take_transfer_sockets(&free_data_socks, run_cap).await {
                Some(socks) => Some(socks),
                None => {
                    // Every socket is out with a running transfer. Drop the
                    // permit and say nothing louder than debug: this is the
                    // normal, designed back-pressure, not an error.
                    drop(permit);
                    tracing::debug!(
                        conn_id, active,
                        "no data socket free; declining so the sender retries"
                    );
                    decline_busy(&socket, sender, conn_id).await;
                    continue;
                }
            }
        } else {
            // No `--data-port-range`: the daemon is serial on its one
            // shared data socket, and `permits` is 1 to match.
            None
        };
        active_transfers.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        ahp_observability::global().active_transfers.inc();
        tracing::info!(conn_id, peer = %sender, active = active + 1, "incoming transfer");

        let owns_data_sock = per_transfer_socks.is_some();
        let xfer_data_socks =
            per_transfer_socks.unwrap_or_else(|| vec![data_socket.clone()]);
        let xfer_data_port = xfer_data_socks[0]
            .local_addr()
            .map(|a| a.port())
            .unwrap_or(data_addr.port());
        if owns_data_sock {
            tracing::info!(
                conn_id, port = xfer_data_port, ports = xfer_data_socks.len(),
                "per-transfer data socket"
            );
        }

        // Registered before the handshake reply goes out, so the sender's
        // MANIFEST cannot arrive before there is somewhere to put it.
        let (ctrl_tx, ctrl_rx) = tokio::sync::mpsc::channel::<(Vec<u8>, SocketAddr)>(256);
        routes.lock().await.insert(conn_id, ctrl_tx);

        let slot = run_transfer_slot(
            socket.clone(),
            xfer_data_socks,
            xfer_data_port,
            owns_data_sock,
            sender,
            conn_id,
            hello_payload,
            ctrl_rx,
            routes.clone(),
            new_tx_accept.clone(),
            max_file_size,
            ticket_key.clone(),
            used_tickets.clone(),
            dest_root.clone(),
            identity.clone(),
            free_data_socks.clone(),
        );
        let active_transfers = active_transfers.clone();
        let finish = async move {
            slot.await;
            active_transfers.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
            ahp_observability::global().active_transfers.dec();
            drop(permit);
        };

        if owns_data_sock {
            // Parallel: the accept loop returns to `new_rx` immediately.
            tokio::spawn(finish);
        } else {
            // Serial: one shared data socket, so one transfer at a time.
            finish.await;
        }
    }
}

/// Everything that happens for one accepted HELLO, from permit to teardown.
///
/// Extracted so the serial and concurrent paths are the *same* code — the
/// only difference is whether the caller `await`s it or `tokio::spawn`s it.
/// Two copies of this would drift, and the bugs that hid in the old
/// single-transfer assumptions were exactly the kind that drift produces.
#[allow(clippy::too_many_arguments)]
async fn run_transfer_slot(
    socket: std::sync::Arc<UdpSocket>,
    // This transfer's data sockets, in ascending port order. Length 1 is the
    // ordinary case; a contiguous run means the sender may spread its
    // streams across them (`CAP_PER_STREAM_PORTS`).
    data_socks: Vec<std::sync::Arc<UdpSocket>>,
    data_port: u16,
    owns_data_sock: bool,
    peer: SocketAddr,
    conn_id: u64,
    hello_payload: Vec<u8>,
    mut ctrl_rx: CtrlRx,
    routes: std::sync::Arc<tokio::sync::Mutex<std::collections::HashMap<u64, CtrlTx>>>,
    new_tx: tokio::sync::mpsc::Sender<(u64, SocketAddr, Vec<u8>)>,
    max_file_size: Option<u64>,
    ticket_key: std::sync::Arc<std::sync::Mutex<ahp_crypto::session_ticket::TicketKey>>,
    used_tickets: std::sync::Arc<std::sync::Mutex<ahp_crypto::session_ticket::UsedTicketCache>>,
    dest_root: Option<std::sync::Arc<std::path::PathBuf>>,
    identity: std::sync::Arc<Option<ahp_crypto::signatures::SigningIdentity>>,
    // Where to return the data socket. Returning it is what bounds the
    // daemon to its configured range; without it the pool drains and later
    // transfers fall back to the shared socket, silently reintroducing the
    // cross-talk the range exists to prevent.
    free_data_socks: std::sync::Arc<tokio::sync::Mutex<Vec<std::sync::Arc<UdpSocket>>>>,
) {
    // Only a per-transfer run goes back to the pool; the daemon's shared
    // data socket is not the pool's to hand out.
    let releaser = owns_data_sock
        .then(|| SocketReturn::new(free_data_socks.clone(), data_socks.clone()));

    // Adaptive transfer timeout: max(5 min, 10 min per GB estimated).
    let transfer_timeout = Duration::from_secs(300).max(Duration::from_secs(600));
    let transfer_result = tokio::time::timeout(
        transfer_timeout,
        handle_transfer(
            &socket,
            &mut ctrl_rx,
            &data_socks,
            releaser.as_ref(),
            data_port,
            peer,
            conn_id,
            &hello_payload,
            max_file_size,
            &ticket_key,
            &used_tickets,
            dest_root.as_deref().map(|p| p.as_path()),
            identity.as_ref().as_ref(),
        ),
    )
    .await;

    routes.lock().await.remove(&conn_id);

    let mut next_hello: Option<(u64, SocketAddr)> = None;
    match transfer_result {
        Ok(Ok(pending)) => {
            tracing::info!(conn_id, "transfer complete");
            next_hello = pending;
        }
        Ok(Err(e)) => tracing::error!(conn_id, "transfer failed: {}", e),
        Err(_) => tracing::error!(conn_id, "transfer timed out (300s)"),
    }

    // Restore non-blocking on the control socket. The bitmap recv thread
    // can change socket flags and an error path may leave them anywhere.
    // `set_nonblocking` is the portable spelling of the fcntl pair — on
    // Windows the equivalent is `ioctlsocket(FIONBIO)`, which socket2 picks.
    let _ = socket2::SockRef::from(&*socket).set_nonblocking(true);

    // A shared data socket outlives this transfer, so stale DATA left on it
    // would be read by the next transfer's receive thread; drain it. A
    // per-transfer socket is dropped with this function and cannot leak
    // anything into anyone else, which is one of the reasons to prefer it.
    if !owns_data_sock {
        let mut buf = vec![0u8; MAX_PACKET];
        let mut drained = 0u64;
        while data_socks[0].try_recv_from(&mut buf).is_ok() {
            drained += 1;
        }
        if drained > 0 {
            tracing::debug!(drained, "drained stale packets between transfers");
        }
    }

    // A HELLO the bitmap thread saw mid-transfer goes back to the router's
    // queue rather than being dispatched here. One admission path means one
    // place that acquires a permit, registers a route and binds a socket —
    // the old inline dispatch duplicated all three and skipped the permit.
    // Normally a no-op: the receive path released these the moment its
    // thread joined. This is the path for a transfer that failed, timed
    // out, or never got as far as receiving.
    if let Some(r) = &releaser {
        r.release().await;
    }

    if let Some((next_conn_id, next_peer)) = next_hello {
        tracing::info!(conn_id = next_conn_id, peer = %next_peer, "requeueing transfer seen mid-flight");
        let _ = new_tx.send((next_conn_id, next_peer, Vec::new())).await;
    }
}

/// Returns Ok(pending_hello) — if a new HELLO was received during data transfer,
/// returns (conn_id, peer) so the caller can dispatch it immediately.
/// Build a bitmap of chunks already present in the destination file.
///
/// Zero-check heuristic: any non-zero chunk is assumed to be valid (written
/// by a previous interrupted transfer of the same file). Known limits (B12):
/// non-zero *garbage* also passes — after a same-name, same-size replacement
/// of the destination, differing chunks are wrongly marked present and the
/// sender skips them. The bitmap exchange carries only have/need bits (no
/// per-chunk hashes), so there is no cheap way to strengthen this; integrity
/// instead relies on the final whole-file BLAKE3 check in
/// `finalize_transfer`, which fails the transfer honestly on corruption
/// rather than blessing it. Prefer `resume_mode = "merkle"` where the
/// integrity of the resume diff itself matters.
fn build_resume_bitmap(manifest: &FileManifest) -> Option<Vec<u8>> {
    let path = std::path::Path::new(&manifest.dest_path);
    let metadata = std::fs::metadata(path).ok()?;
    if metadata.len() != manifest.file_size {
        tracing::info!(
            existing = metadata.len(), expected = manifest.file_size,
            "resume: file size mismatch, full transfer"
        );
        return None;
    }

    let file = std::fs::File::open(path).ok()?;
    let existing = unsafe { memmap2::Mmap::map(&file).ok()? };

    let total = manifest.total_chunks as usize;
    let ps = manifest.payload_size;
    let bitmap_bytes = (total + 7) / 8;
    let mut bitmap = vec![0u8; bitmap_bytes];
    let mut have = 0usize;

    for ci in 0..total {
        let offset = ci * ps;
        let end = (offset + ps).min(existing.len());
        let chunk = &existing[offset..end];
        // Non-zero chunk → assume already received.
        if chunk.iter().any(|&b| b != 0) {
            bitmap[ci / 8] |= 1 << (ci % 8);
            have += 1;
        }
    }

    tracing::info!(have, total, "resume: found {}/{} chunks", have, total);
    if have == 0 {
        return None; // no chunks to resume, do full transfer
    }
    Some(bitmap)
}

/// Merkle resume result: either a precomputed bitmap (roots match or no cache)
/// or a "merkle_diff" payload with cached tree level hashes for the sender to diff.
enum MerkleResumeResult {
    /// Ready bitmap (all-ones if roots match, or per-chunk from hashing).
    Bitmap(Vec<u8>),
    /// Cached tree level hashes for sender-side diff.
    /// Format: [1-byte level] [hashes at that level, 32 bytes each], zstd-compressed.
    MerkleDiff(Vec<u8>),
}

/// Path of the Merkle cache file for a destination:
/// `<dest_dir>/.favonius-merkle/<file_name>.merkle`.
fn merkle_cache_path(dest_path: &str) -> std::path::PathBuf {
    let path = std::path::Path::new(dest_path);
    path.parent()
        .unwrap_or(std::path::Path::new("/tmp"))
        .join(".favonius-merkle")
        .join(format!("{}.merkle", path.file_name().unwrap_or_default().to_string_lossy()))
}

/// Merkle cache envelope magic + version (B12). Pre-B12 cache files hold the
/// bare tree bytes and fail this check → clean cache miss.
const MERKLE_CACHE_MAGIC: &[u8; 4] = b"HMC1";
/// Bytes hashed from the head and the tail of the file for the cache
/// content fingerprint.
const CACHE_FINGERPRINT_WINDOW: usize = 4096;

/// Cheap O(1) content fingerprint: BLAKE3 over the first and last
/// [`CACHE_FINGERPRINT_WINDOW`] bytes of `data` (overlapping for small
/// files). Catches the B12 threat — an innocent same-name, same-size
/// replacement of the destination — even when the replacement preserves the
/// original mtime, without paying for a full-file rehash per resume.
fn content_fingerprint(data: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(&data[..data.len().min(CACHE_FINGERPRINT_WINDOW)]);
    h.update(&data[data.len().saturating_sub(CACHE_FINGERPRINT_WINDOW)..]);
    *h.finalize().as_bytes()
}

/// Serialize a cache entry:
/// magic(4) | file_size(8 LE) | mtime_sec(8 LE, -1 = unknown) |
/// mtime_nsec(4 LE) | fingerprint(32) | tree_len(4 LE) | tree bytes.
fn encode_merkle_cache(
    tree: &ahp_sync::merkle::MerkleTree,
    file_size: u64,
    mtime: Option<std::time::SystemTime>,
    fingerprint: &[u8; 32],
) -> Vec<u8> {
    let tree_bytes = tree.to_bytes();
    let (sec, nsec) = match mtime.and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok()) {
        Some(d) => (d.as_secs() as i64, d.subsec_nanos()),
        None => (-1, 0),
    };
    let mut out = Vec::with_capacity(60 + tree_bytes.len());
    out.extend_from_slice(MERKLE_CACHE_MAGIC);
    out.extend_from_slice(&file_size.to_le_bytes());
    out.extend_from_slice(&sec.to_le_bytes());
    out.extend_from_slice(&nsec.to_le_bytes());
    out.extend_from_slice(fingerprint);
    out.extend_from_slice(&(tree_bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(&tree_bytes);
    out
}

/// Persist a Merkle cache entry for `dest_path`, stamped with the file's
/// current size/mtime and a fingerprint of `data` — the exact content the
/// tree was built from (B12). Best-effort: cache writes never fail a
/// transfer.
fn write_merkle_cache(dest_path: &str, tree: &ahp_sync::merkle::MerkleTree, data: &[u8]) {
    let cache_path = merkle_cache_path(dest_path);
    if let Some(cache_dir) = cache_path.parent() {
        let _ = std::fs::create_dir_all(cache_dir);
    }
    let mtime = std::fs::metadata(dest_path).and_then(|md| md.modified()).ok();
    let blob = encode_merkle_cache(tree, data.len() as u64, mtime, &content_fingerprint(data));
    let _ = std::fs::write(&cache_path, blob);
}

/// Load and validate the Merkle cache for `dest_path` (B12).
///
/// The cache is trusted only when it provably describes the CURRENT local
/// file: the entry's size and mtime must match the file metadata, and the
/// stored head/tail fingerprint must match a fresh fingerprint of the file
/// content. Filename (+size) alone is not enough — a same-name, same-size
/// replacement must miss, otherwise the sender is told to skip chunks that
/// actually differ and the destination is silently corrupted. Old-format
/// entries (bare tree bytes, pre-B12), truncated or malformed blobs are all
/// a clean miss, never a panic. Cost of a hit: one stat + a mmap + ~8 KiB of
/// hashing, vs. O(file) for the strongest option (whole-file hash) — the
/// cache is local and the threat is innocent replacement, not an attacker.
fn read_merkle_cache(
    cache_path: &std::path::Path,
    dest_path: &std::path::Path,
) -> Option<ahp_sync::merkle::MerkleTree> {
    let raw = std::fs::read(cache_path).ok()?;
    if raw.len() < 60 || raw[..4] != MERKLE_CACHE_MAGIC[..] {
        return None; // old format or garbage
    }
    let stored_size = u64::from_le_bytes(raw[4..12].try_into().ok()?);
    let mtime_sec = i64::from_le_bytes(raw[12..20].try_into().ok()?);
    let mtime_nsec = u32::from_le_bytes(raw[20..24].try_into().ok()?);
    let stored_fp: &[u8; 32] = raw[24..56].try_into().ok()?;
    let tree_len = u32::from_le_bytes(raw[56..60].try_into().ok()?) as usize;
    let tree_bytes = raw.get(60..60 + tree_len)?;

    let md = std::fs::metadata(dest_path).ok()?;
    if md.len() != stored_size {
        return None;
    }
    // mtime pre-check (skipped when the writer could not stat the file).
    if mtime_sec >= 0 {
        let actual = md.modified().ok()?.duration_since(std::time::UNIX_EPOCH).ok()?;
        if actual.as_secs() as i64 != mtime_sec || actual.subsec_nanos() != mtime_nsec {
            return None;
        }
    }
    // Fingerprint check: even with a preserved mtime, changed head/tail
    // content must miss.
    let file = std::fs::File::open(dest_path).ok()?;
    let existing = unsafe { memmap2::Mmap::map(&file).ok()? };
    if &content_fingerprint(&existing) != stored_fp {
        return None;
    }
    ahp_sync::merkle::MerkleTree::from_bytes(tree_bytes)
}

/// Build resume data using Merkle tree.
/// Returns a bitmap if roots match (instant skip) or level hashes if a cached
/// tree exists (sender does the diff). Falls back to per-chunk hashing if no cache.
fn build_merkle_resume(manifest: &FileManifest) -> Option<MerkleResumeResult> {
    let path = std::path::Path::new(&manifest.dest_path);
    let metadata = std::fs::metadata(path).ok()?;
    if metadata.len() != manifest.file_size {
        tracing::info!("merkle resume: file size mismatch, full transfer");
        return None;
    }

    let sender_root_hex = manifest.merkle_root.as_deref()?;
    if sender_root_hex.len() != 64 { return None; }
    let mut sender_root = [0u8; 32];
    for i in 0..32 {
        sender_root[i] = u8::from_str_radix(&sender_root_hex[i*2..i*2+2], 16).ok()?;
    }

    // Try loading a cached Merkle tree first (O(1) — no full-file hashing).
    // B12: the entry is trusted only if its size+mtime+fingerprint match the
    // current local file; a same-name, same-size replacement is a cache miss.
    let cache_path = merkle_cache_path(&manifest.dest_path);
    let cached_tree = read_merkle_cache(&cache_path, path);

    if let Some(ref tree) = cached_tree {
        // Roots match → instant skip (all chunks present).
        if tree.root() == sender_root {
            tracing::info!("merkle resume: roots match (from cache), no transfer needed");
            let total = manifest.total_chunks as usize;
            let n = (total + 7) / 8;
            let mut bm = vec![0xFFu8; n];
            let trailing = total % 8;
            if trailing != 0 { bm[n - 1] = (1u8 << trailing) - 1; }
            return Some(MerkleResumeResult::Bitmap(bm));
        }

        // Roots differ — send cached tree's strategic level hashes for
        // sender-side diff. The sender compares these against its own tree
        // and computes which subtrees differ → which leaves need retransmit.
        // This avoids O(N) hashing on the daemon!
        let (level, count) = tree.strategic_level();
        let level_hashes = tree.level(level);
        tracing::info!(
            level, count, local_root = %hex::encode(tree.root()),
            sender_root = %sender_root_hex,
            "merkle resume: sending level {} hashes for sender-side diff", level
        );

        // Encode: [1-byte level] [4-byte leaf_count] [count × 32-byte hashes]
        let mut payload = Vec::with_capacity(5 + count * 32);
        payload.push(level as u8);
        payload.extend_from_slice(&(tree.leaf_count() as u32).to_le_bytes());
        for h in level_hashes {
            payload.extend_from_slice(h);
        }
        let compressed = zstd::encode_all(payload.as_slice(), 1).unwrap_or(payload);
        return Some(MerkleResumeResult::MerkleDiff(compressed));
    }

    // No cached tree — fall back to building one from the file (O(N) hashing).
    // This only happens on the first resume of a given file.
    tracing::info!("merkle resume: no cache, building tree from file (first time)");
    let file = std::fs::File::open(path).ok()?;
    let existing = unsafe { memmap2::Mmap::map(&file).ok()? };
    let local_tree = ahp_sync::merkle::build_file_merkle(&existing, manifest.payload_size);

    // Cache it for next time, stamped with size+mtime+fingerprint of the
    // content the tree was built from (B12).
    write_merkle_cache(&manifest.dest_path, &local_tree, &existing);

    if local_tree.root() == sender_root {
        tracing::info!("merkle resume: roots match, no transfer needed");
        let total = manifest.total_chunks as usize;
        let n = (total + 7) / 8;
        let mut bm = vec![0xFFu8; n];
        let trailing = total % 8;
        if trailing != 0 { bm[n - 1] = (1u8 << trailing) - 1; }
        return Some(MerkleResumeResult::Bitmap(bm));
    }

    // We need the SENDER's tree to diff, but we only have the root.
    // Fall back to per-chunk zero-check for the first time.
    let total = manifest.total_chunks as usize;
    let n = (total + 7) / 8;
    let mut bm = vec![0u8; n];
    let mut have = 0;
    for ci in 0..total {
        let offset = ci * manifest.payload_size;
        let end = (offset + manifest.payload_size).min(existing.len());
        if existing[offset..end].iter().any(|&b| b != 0) {
            bm[ci / 8] |= 1 << (ci % 8);
            have += 1;
        }
    }
    tracing::info!(have, total, "merkle resume: first-time fallback, {}/{} chunks", have, total);
    if have == 0 { return None; }
    Some(MerkleResumeResult::Bitmap(bm))
}

/// Hex-encode helper (no external dep).
mod hex {
    pub fn encode(bytes: impl AsRef<[u8]>) -> String {
        bytes.as_ref().iter().map(|b| format!("{:02x}", b)).collect()
    }
}

/// Wait for the MANIFEST packet on the control socket.
///
/// PathProbes are echoed and duplicate HELLOs re-acked; malformed or
/// unexpected datagrams are logged and ignored — a single spoofed garbage
/// datagram must not abort the transfer (same policy as the main loop).
/// Still bounded by a 10 s idle timeout — idle meaning no word from THE
/// TRANSFER'S PEER: the sender's pre-MANIFEST hash/Merkle phase is quiet,
/// so peer traffic (duplicate HELLOs, probes) extends the wait, but
/// datagrams from anyone else do not. A retried sender's HELLOs can
/// therefore neither keep a dead peer's MANIFEST wait alive nor trigger a
/// HELLO_ACK addressed to that dead peer; once the dead peer's clock runs
/// out, the main loop resumes and answers the retry itself.
async fn recv_manifest_packet(
    ctrl_socket: &UdpSocket,
    ctrl_rx: &mut CtrlRx,
    peer: SocketAddr,
    conn_id: u64,
    seq: u64,
    hello_ack_payload: &[u8],
) -> Result<Packet, Box<dyn std::error::Error + Send + Sync>> {
    let mut deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err("timeout waiting for MANIFEST".into());
        }
        let (bytes, probe_sender) = tokio::time::timeout(remaining, ctrl_rx.recv())
            .await?
            .ok_or("control router closed while awaiting MANIFEST")?;
        let pkt = match decode_packet(&bytes) {
            Ok(p) => p,
            Err(e) => {
                tracing::debug!("ignoring malformed datagram while awaiting MANIFEST: {}", e);
                continue;
            }
        };
        // The peer is still alive — extend the idle deadline.
        if probe_sender == peer {
            deadline = Instant::now() + Duration::from_secs(10);
        }
        match pkt.header.packet_type {
            PacketType::PathProbe => {
                // Only echo probes from the transfer's own peer while a
                // transfer is being set up — anything else gets no reply.
                if probe_sender == peer {
                    let _ = echo_probe(ctrl_socket, probe_sender, &pkt).await;
                }
            }
            PacketType::Hello if probe_sender == peer => {
                tracing::debug!("duplicate HELLO, re-sending HELLO_ACK");
                // Re-send the exact original ack so the mode byte (and any DH
                // key material) survives retransmission.
                send_ctrl_with_payload(ctrl_socket, peer, PacketType::HelloAck, conn_id, seq, hello_ack_payload).await?;
            }
            PacketType::Manifest => return Ok(pkt),
            other => {
                tracing::debug!(?other, "ignoring unexpected packet while waiting for MANIFEST");
            }
        }
    }
}

/// Wait for the sender's RESUME_REQ carrying the skip bitmap it computed
/// from our Merkle diff. The sender retransmits the report until acked; a
/// duplicate MANIFEST means our ResumeAck was lost, so it is re-sent
/// verbatim. Stale reports from previous connections are filtered by
/// connection id. Gives up after 30s — without the bitmap the daemon cannot
/// account for the chunks the sender skips, so failing the transfer is the
/// only honest option.
async fn recv_sender_resume_bitmap(
    ctrl_socket: &UdpSocket,
    ctrl_rx: &mut CtrlRx,
    peer: SocketAddr,
    conn_id: u64,
    seq: u64,
    resume_ack_payload: &[u8],
    total_chunks: u64,
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err("timeout waiting for sender resume bitmap".into());
        }
        let (bytes, _) = match tokio::time::timeout(remaining, ctrl_rx.recv()).await {
            Ok(Some(r)) => r,
            Ok(None) => return Err("control router closed awaiting resume bitmap".into()),
            Err(_) => return Err("timeout waiting for sender resume bitmap".into()),
        };
        let pkt = match decode_packet(&bytes) {
            Ok(p) => p,
            Err(_) => continue, // malformed packet, keep waiting
        };
        match pkt.header.packet_type {
            PacketType::Manifest => {
                // Sender never saw our ResumeAck — re-send it verbatim.
                send_ctrl_with_payload(
                    ctrl_socket, peer, PacketType::ResumeAck, conn_id, seq, resume_ack_payload,
                ).await?;
            }
            PacketType::ResumeReq if pkt.header.connection_id == conn_id => {
                return decode_resume_bitmap(&pkt.payload, total_chunks).map_err(Into::into);
            }
            other => {
                tracing::debug!(?other, "ignoring unexpected packet while waiting for RESUME_REQ");
            }
        }
    }
}

/// What the daemon answered the MANIFEST with. Remembered so a duplicate
/// MANIFEST from the same peer/connection can be re-answered verbatim while
/// the recv thread runs: the sender retransmits MANIFEST every 2 s until
/// acked, and before this watch existed a single lost reply cost the sender
/// its whole 10-attempt retry budget while the recv thread — seeing no
/// DATA — died on the dead-peer inactivity clock.
enum ManifestReply {
    /// Normal post-MANIFEST ACK (empty bitmap over stream 0), also the
    /// terminal reply of the merkle-resume exchange.
    AckBitmap { ack_seq: u64, data_seq_base: u64 },
    /// ResumeAck carrying the prefixed (bitmap / merkle-diff) payload.
    ResumeAck { ack_seq: u64, payload: Vec<u8> },
}

/// Join the recv thread while keeping the CONTROL socket responsive for the
/// duration of the data phase:
///
/// - a duplicate MANIFEST from this transfer's peer/connection means our
///   MANIFEST reply was lost — re-send it verbatim (the same policy
///   `recv_sender_resume_bitmap` already applies during the resume
///   exchange). One copy per duplicate: a retransmission rate-limited
///   1:1 reply, no amplification.
/// - PathProbes are echoed (same policy as the main loop).
/// - a HELLO from a NEW connection gets the same bare-ACK + queue treatment
///   the recv thread applies on the data port, so a back-to-back sender is
///   not stalled until the post-transfer drain.
///
/// Anything else is ignored — before this watch those datagrams sat unread
/// until the post-transfer drain discarded them, so ignoring is no
/// regression. All re-sends are best-effort (`let _ =`): a failed redundant
/// reply must not abort a healthy receive.
async fn join_recv_thread(
    handle: std::thread::JoinHandle<Result<ThreadedRecvResult, String>>,
    ctrl_socket: &UdpSocket,
    ctrl_rx: &mut CtrlRx,
    peer: SocketAddr,
    conn_id: u64,
    manifest_reply: &ManifestReply,
) -> Result<(ThreadedRecvResult, Option<(u64, SocketAddr)>), Box<dyn std::error::Error + Send + Sync>> {
    let mut join = tokio::task::spawn_blocking(move || handle.join());
    let mut queued_hello: Option<(u64, SocketAddr)> = None;
    let result = loop {
        tokio::select! {
            r = &mut join => break r,
            recv = ctrl_rx.recv() => {
                let Some((bytes, from)) = recv else { continue };
                let pkt = match decode_packet(&bytes) {
                    Ok(p) => p,
                    Err(_) => continue,
                };
                match pkt.header.packet_type {
                    // Scoped to this transfer's peer AND connection id —
                    // a MANIFEST from anyone else is stale or spoofed and
                    // gets no reply.
                    PacketType::Manifest if from == peer && pkt.header.connection_id == conn_id => {
                        tracing::debug!("duplicate MANIFEST mid-transfer, re-sending MANIFEST reply");
                        match manifest_reply {
                            ManifestReply::AckBitmap { ack_seq, data_seq_base } => {
                                let _ = send_ack_bitmap(
                                    ctrl_socket, peer, conn_id, *ack_seq, 0,
                                    *data_seq_base, data_seq_base.wrapping_sub(1), &[],
                                ).await;
                            }
                            ManifestReply::ResumeAck { ack_seq, payload } => {
                                let _ = send_ctrl_with_payload(
                                    ctrl_socket, peer, PacketType::ResumeAck,
                                    conn_id, *ack_seq, payload,
                                ).await;
                            }
                        }
                    }
                    PacketType::PathProbe => {
                        let _ = echo_probe(ctrl_socket, from, &pkt).await;
                    }
                    PacketType::Hello if queued_hello.is_none() => {
                        // Queue for the main loop, answering with a bare
                        // HELLO_ACK whose mode byte says Plaintext — the
                        // queued handling re-runs the handshake with an
                        // empty HELLO payload, so an encrypting sender must
                        // abort rather than stream in a mode we will not
                        // expect (same contract as the recv thread's HELLO).
                        let new_conn = pkt.header.connection_id;
                        let _ = send_ctrl_with_payload(
                            ctrl_socket, from, PacketType::HelloAck,
                            new_conn, 0, &[HelloAckMode::Plaintext.to_byte()],
                        ).await;
                        queued_hello = Some((new_conn, from));
                    }
                    _ => {}
                }
            }
        }
    };
    let result = result
        .map_err(|e| format!("join recv thread: {e}"))?
        .map_err(|_| "recv thread panicked")?
        .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.into() })?;
    Ok((result, queued_hello))
}

async fn handle_transfer(
    ctrl_socket: &UdpSocket,
    ctrl_rx: &mut CtrlRx,
    // This transfer's data sockets in ascending port order; `data_port` is
    // the first. More than one means the streams may be split across them.
    data_socks: &[std::sync::Arc<UdpSocket>],
    // Returns those sockets to the pool as soon as the receive thread
    // joins. `None` when they are not the pool's to return (the daemon's
    // shared data socket).
    releaser: Option<&SocketReturn>,
    data_port: u16,
    peer: SocketAddr,
    conn_id: u64,
    hello_payload: &[u8],
    max_file_size: Option<u64>,
    ticket_key: &std::sync::Arc<std::sync::Mutex<ahp_crypto::session_ticket::TicketKey>>,
    used_tickets: &std::sync::Arc<std::sync::Mutex<ahp_crypto::session_ticket::UsedTicketCache>>,
    dest_root: Option<&std::path::Path>,
    identity: Option<&ahp_crypto::signatures::SigningIdentity>,
) -> Result<Option<(u64, SocketAddr)>, Box<dyn std::error::Error + Send + Sync>> {
    let mut seq: u64 = 0;

    // What this transfer can offer, as opposed to what the daemon can do in
    // general: the port run is whatever the pool could spare when this HELLO
    // was admitted, and it has to be published now — `num_streams` does not
    // arrive until the MANIFEST, which is read below. Advertising a *count*
    // from the port already in the ack is what lets the sender take the
    // minimum without a new field or a new packet type.
    let capabilities = DAEMON_CAPABILITIES | ahp_proto::per_stream_ports(data_socks.len());

    // ── Key exchange + HELLO_ACK ─────────────────────────────────────────
    let hello_flag = if !hello_payload.is_empty() { hello_payload[0] } else { 0x00 };
    // HELLO_ACK payload: [1-byte mode] [mode material (DH material for full
    // handshake, server nonce for resume)] [2-byte data port BE]. The mode
    // byte tells the sender which crypto mode was negotiated so it can abort
    // on mismatch instead of streaming data in a mode the daemon does not
    // expect (silent corruption / AEAD failures).
    let (session_keys, hello_ack_payload): (Option<ahp_crypto::SessionKeys>, Vec<u8>) =
        if hello_flag == 0x01 && hello_payload.len() >= 1 + 32 + 16 {
        // Full DH handshake.
        let mut peer_public = [0u8; 32];
        peer_public.copy_from_slice(&hello_payload[1..33]);
        let mut peer_nonce = [0u8; 16];
        peer_nonce.copy_from_slice(&hello_payload[33..49]);

        let local_kp = ahp_crypto::key_exchange::generate_keypair();
        let local_nonce: [u8; 16] = rand::random();

        let shared_secret = ahp_crypto::key_exchange::diffie_hellman(&local_kp.private, &peer_public)
            .map_err(|e| format!("key exchange failed: {e}"))?;
        let keys = ahp_crypto::key_schedule::derive_session_keys(&shared_secret, &peer_nonce, &local_nonce)
            .map_err(|e| format!("key derivation failed: {e}"))?;

        // S5 (RFC §12.2): with an Ed25519 identity, sign the handshake
        // transcript — the daemon's ephemeral DH pubkey and nonce are
        // "local", the client's are "remote" — and carry
        // [identity pubkey][signature] after the DH material so a pinning
        // client can authenticate the daemon before deriving keys.
        let auth_material = identity.map(|id| {
            let signature = id.sign_handshake(&local_kp.public, &peer_public, &local_nonce, &peer_nonce);
            (id.public_bytes(), signature)
        });
        let ack_payload = encode_hello_ack_payload(
            HelloAckMode::FullHandshake,
            Some(data_port),
            Some((&local_kp.public, &local_nonce)),
            auth_material.as_ref().map(|(pk, sig)| (pk, sig)),
            capabilities,
        );
        send_ctrl_with_payload(ctrl_socket, peer, PacketType::HelloAck, conn_id, seq, &ack_payload).await?;
        if auth_material.is_some() {
            tracing::info!("encryption: X25519 + AES-256-GCM established (Ed25519-authenticated)");
        } else {
            tracing::info!("encryption: X25519 + AES-256-GCM established (anonymous — no daemon identity)");
        }
        (Some(keys), ack_payload)
    } else if hello_flag == 0x02 {
        // 0-RTT resume with session ticket. A successful resume carries the
        // fresh server nonce in the ack; the client mixes it into its key
        // derivation (S4 replay protection). The stored ack payload is
        // re-sent verbatim on duplicate HELLOs, so retransmissions reuse the
        // original server nonce and derive identical keys.
        // S5 limitation: a resumed session inherits its authentication from
        // the ticket — the daemon's Ed25519 identity is NOT re-verified on
        // resume (the ticket is bound to the per-instance ticket key, and
        // binding the long-lived identity into tickets would require a
        // ticket-format change). This fails safe: after a daemon restart the
        // ticket key is gone, the ticket is rejected, and the client aborts
        // on the plaintext fallback (mode mismatch), forcing a full
        // handshake in which the identity IS verified.
        let (mode, keys, server_nonce) = {
            // Both locks span exactly the ticket decrypt + check_and_record.
            let tk = ticket_key.lock().expect("ticket key mutex poisoned");
            let mut ut = used_tickets.lock().expect("used-ticket mutex poisoned");
            resume_from_ticket(&tk, &mut ut, hello_payload)
        };
        let ack_payload = match server_nonce {
            Some(nonce) => {
                encode_hello_ack_resumed(Some(data_port), &nonce, capabilities)
            }
            None => {
                encode_hello_ack_payload(mode, Some(data_port), None, None, capabilities)
            }
        };
        send_ctrl_with_payload(ctrl_socket, peer, PacketType::HelloAck, conn_id, seq, &ack_payload).await?;
        (keys, ack_payload)
    } else {
        // Plaintext.
        let ack_payload = encode_hello_ack_payload(
            HelloAckMode::Plaintext,
            Some(data_port),
            None,
            None,
            capabilities,
        );
        send_ctrl_with_payload(ctrl_socket, peer, PacketType::HelloAck, conn_id, seq, &ack_payload).await?;
        (None, ack_payload)
    };
    seq += 1;

    // ── Receive MANIFEST on control socket ─────────────────────────────
    let mpkt = recv_manifest_packet(ctrl_socket, ctrl_rx, peer, conn_id, seq, &hello_ack_payload).await?;
    let mut manifest: FileManifest = serde_json::from_slice(&mpkt.payload)?;
    // Reject inconsistent or oversized manifests before they can drive
    // allocations, set_len, or the mmap slicing in the receive loop.
    if let Err(e) = validate_manifest(&manifest, max_file_size) {
        tracing::warn!(error = %e, "rejecting transfer: invalid manifest");
        return Err(e.into());
    }
    // S1: confine the sender-controlled destination under --dest-root.
    // Without this the manifest makes the daemon create/truncate/write any
    // path it can reach. The rewritten (absolute, confined) path is used by
    // every consumer below — resume probes, merkle cache, output file.
    if let Some(root) = dest_root {
        match confine_dest_path(root, &manifest.dest_path) {
            Ok(confined) => manifest.dest_path = confined.to_string_lossy().into_owned(),
            Err(e) => {
                tracing::warn!(error = %e, "rejecting transfer: destination escapes dest-root");
                return Err(e.into());
            }
        }
    }
    tracing::info!(
        file = %manifest.file_name,
        size = manifest.file_size,
        chunks = manifest.total_chunks,
        dest = %manifest.dest_path,
        "manifest received"
    );

    // Data packets use sequential packet numbers starting after MANIFEST.
    let data_seq_base = mpkt.header.packet_number + 1;

    // ── Resume check ─────────────────────────────────────────────────────
    let resume_result = match manifest.resume_mode.as_str() {
        "bitmap" => build_resume_bitmap(&manifest).map(MerkleResumeResult::Bitmap),
        "merkle" => build_merkle_resume(&manifest),
        _ => None,
    };

    // Send resume response: bitmap, merkle diff, or normal ACK. The reply
    // is remembered in `manifest_reply`: a duplicate MANIFEST arriving
    // mid-transfer means the reply was lost (the sender retransmits
    // MANIFEST every 2 s until acked), and join_recv_thread re-sends it
    // verbatim from the control-socket watch while the recv thread runs.
    let resume_bitmap: Option<Vec<u8>>;
    let manifest_reply: ManifestReply;
    match resume_result {
        Some(MerkleResumeResult::Bitmap(bm)) => {
            let compressed = zstd::encode_all(bm.as_slice(), 1).unwrap_or_else(|_| bm.clone());
            // Prefix 0x01 = bitmap (sender can decompress and use directly).
            let mut payload = Vec::with_capacity(1 + compressed.len());
            payload.push(0x01);
            payload.extend_from_slice(&compressed);
            send_ctrl_with_payload(
                ctrl_socket, peer, PacketType::ResumeAck, conn_id, seq, &payload,
            ).await?;
            tracing::info!(raw = bm.len(), compressed = compressed.len(), "sent ResumeAck (bitmap)");
            manifest_reply = ManifestReply::ResumeAck { ack_seq: seq, payload };
            resume_bitmap = Some(bm);
        }
        Some(MerkleResumeResult::MerkleDiff(diff_payload)) => {
            // Prefix 0x02 = merkle diff (sender compares level hashes and builds bitmap).
            let mut payload = Vec::with_capacity(1 + diff_payload.len());
            payload.push(0x02);
            payload.extend_from_slice(&diff_payload);
            send_ctrl_with_payload(
                ctrl_socket, peer, PacketType::ResumeAck, conn_id, seq, &payload,
            ).await?;
            tracing::info!(bytes = diff_payload.len(), "sent ResumeAck (merkle diff)");
            // The skip bitmap is computed by the SENDER from the diff — it
            // reports it back (RESUME_REQ) so we can pre-populate received
            // state for exactly the chunks it will skip. Without it our
            // received count could never reach total_chunks and the transfer
            // would fail at finalization.
            let bm = recv_sender_resume_bitmap(
                ctrl_socket,
                ctrl_rx, peer, conn_id, seq, &payload, manifest.total_chunks,
            ).await?;
            // ACK the report (3 copies: a lost ack would leave the sender
            // retransmitting RESUME_REQ while we wait for data; harmless
            // duplicates are filtered by connection id on both sides).
            for _ in 0..3 {
                send_ack_bitmap(
                    ctrl_socket, peer, conn_id, seq, 0,
                    data_seq_base, data_seq_base.wrapping_sub(1), &[],
                ).await?;
            }
            tracing::info!(bytes = bm.len(), "received sender resume bitmap");
            // A conforming sender is past MANIFEST retransmission once it
            // sent RESUME_REQ (it retransmits RESUME_REQ, not MANIFEST), so
            // this is only a safety net: answer like the normal ACK below.
            manifest_reply = ManifestReply::AckBitmap { ack_seq: seq, data_seq_base };
            resume_bitmap = Some(bm);
        }
        None => {
            // 3 copies, 1 ms apart (same idiom as the FINISH reply and the
            // resume-bitmap ACK above): this ACK is fire-and-forget, and a
            // single lost datagram would cost the sender a full 2 s MANIFEST
            // retry. Duplicates still arriving afterwards are re-answered by
            // join_recv_thread's control-socket watch during the data phase.
            for copy in 0..3 {
                send_ack_bitmap(
                    ctrl_socket, peer, conn_id, seq, 0,
                    data_seq_base, data_seq_base.wrapping_sub(1), &[],
                ).await?;
                if copy < 2 {
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
            }
            manifest_reply = ManifestReply::AckBitmap { ack_seq: seq, data_seq_base };
            resume_bitmap = None;
        }
    }
    seq += 1;

    // ── Memory-mapped output file ──────────────────────────────────────
    if let Some(parent) = std::path::Path::new(&manifest.dest_path).parent() {
        tokio::fs::create_dir_all(parent).await.ok();
    }
    let dest_file = if resume_bitmap.is_some() {
        // Resume: open existing file without truncating.
        std::fs::OpenOptions::new()
            .read(true).write(true)
            .open(&manifest.dest_path)?
    } else {
        // Fresh transfer: create/truncate.
        let f = std::fs::OpenOptions::new()
            .read(true).write(true).create(true).truncate(true)
            .open(&manifest.dest_path)?;
        f.set_len(manifest.file_size)?;
        f
    };

    // Kept for writeback pacing in the receive loop; the mapping alone does
    // not expose the file behind it. Only Linux has range writeback, so
    // elsewhere this is a unit and the pacer compiles out — see
    // [`WritebackFd`].
    #[cfg(target_os = "linux")]
    let dest_fd_raw: WritebackFd = {
        use std::os::unix::io::AsRawFd;
        dest_file.as_raw_fd()
    };
    #[cfg(not(target_os = "linux"))]
    let dest_fd_raw: WritebackFd = ();

    let mut mmap = if manifest.file_size > 0 {
        // SAFETY: We are the sole writer.
        unsafe { MmapMut::map_mut(&dest_file)? }
    } else {
        // Zero-length file: mmap(2) rejects a zero-length mapping (EINVAL).
        // A 1-byte anonymous placeholder carries no content — no DATA
        // packets ever arrive for an empty file, and every consumer below
        // slices the map to `file_size` (0 bytes) — while the empty output
        // file itself was already created/truncated above.
        MmapMut::map_anon(1)?
    };

    let num_streams = manifest.num_streams.max(1);
    // Feature tags the sender selected. Unrecognised tags are logged and
    // ignored, never fatal: the manifest is the forward-compatible channel
    // precisely so an old daemon keeps working against a newer sender.
    // Anything that actually changes the wire is gated on a HELLO_ACK
    // capability bit this daemon advertised, so a tag alone can never make
    // the stream unparseable.
    if !manifest.features.is_empty() {
        let unknown: Vec<&str> = manifest
            .features
            .iter()
            .map(|f| f.as_str())
            .filter(|f| !KNOWN_FEATURES.contains(f))
            .collect();
        tracing::info!(features = ?manifest.features, ?unknown, "sender selected features");
    }
    let mut streams = build_recv_streams(manifest.total_chunks, num_streams);

    // Pre-populate received state from resume bitmap.
    if let Some(ref bitmap) = resume_bitmap {
        let total_skipped = apply_resume_bitmap(&mut streams, bitmap);
        tracing::info!(skipped = total_skipped, "pre-populated received bitmap from resume");
    }

    // Poll only the ports this transfer can actually receive on.
    //
    // The run was reserved at HELLO time, before `num_streams` was known —
    // that is the whole reason the capability advertises a count — so it is
    // routinely longer than the transfer needs. The sender maps stream *i*
    // to `base + min(i, count-1)`, so nothing can ever arrive above
    // `num_streams - 1`, and polling those sockets is a rotation slot that
    // is guaranteed to come back empty. Measured on loopback: a run of 5
    // against 4 streams spent one poll in five on a socket no packet could
    // reach.
    //
    // A sender that ignores the capability puts everything on the base
    // port, which is `data_fds[0]` either way. One that violates the
    // mapping strands a stream and trips the sender's 30 s stall detector —
    // loud, and not a correctness risk, because the run is our own contract.
    let used_ports = (num_streams as usize).min(data_socks.len());
    // Hand the rest of the run back now, not at teardown: it was reserved
    // before `num_streams` was known and nothing above `used_ports` is
    // addressable by the sender's `base + min(i, count-1)` mapping. A
    // single-stream transfer was holding a run of five, which is two
    // concurrent transfers out of a ten-port pool instead of ten.
    if let Some(r) = releaser {
        r.release_tail(used_ports).await;
    }
    // This transfer's data sockets, in ascending port order. The receive
    // loop needs the sockets themselves, not just their handles: it answers
    // on whichever one a stream arrived at, and `send_to` needs an owner.
    let data_socks_used: Vec<Arc<UdpSocket>> =
        data_socks.iter().take(used_ports).cloned().collect();
    let took_run = manifest.features.iter().any(|f| f == FEATURE_PER_STREAM_PORTS);
    if data_socks.len() > 1 {
        tracing::info!(
            reserved = data_socks.len(), polling = data_socks_used.len(),
            base = data_port, num_streams, took_run,
            "per-stream data port run"
        );
    }

    // ── Branch on ACK mode ───────────────────────────────────────────────
    tracing::info!(ack_mode = ?manifest.ack_mode, num_streams, "using ack mode");
    let (n_received, pending_hello, finish_replied) = match manifest.ack_mode {
        ahp_proto::data::AckMode::Bitmap => {
            // Use dedicated I/O thread on the DATA socket(s) — the control
            // socket stays in the async main loop, always responsive.
            let socks = data_socks_used.clone();
            // `SocketAddr` holds either family; this used to refuse v6
            // outright, which is why an IPv6 handshake succeeded and then
            // stalled at 0 chunks with "transfer failed: IPv6 not supported".
            let peer_sin = peer;

            // Socket stays non-blocking — the thread uses spin-wait recv.

            let ps = manifest.payload_size;
            let tc = manifest.total_chunks;
            let sk = session_keys.clone();
            let is_compressed = manifest.compressed;
            let is_hp = manifest.header_protected;
            let handle = std::thread::Builder::new()
                .name("favonius-recv".into())
                .spawn(move || {
                    threaded_bitmap_recv(socks, Some(dest_fd_raw), peer_sin, conn_id, seq, mmap, streams, ps, tc, sk, is_compressed, false, is_hp)
                })
                .map_err(|e| format!("spawn recv thread: {e}"))?;

            let (result, watch_hello) = join_recv_thread(
                handle, ctrl_socket, ctrl_rx, peer, conn_id, &manifest_reply,
            ).await?;

            // Socket flags are restored in the outer loop (post-transfer
            // recovery) regardless of success/failure — no need to do it here.

            // The thread is joined, so nothing will read these sockets
            // again — everything below runs on the control socket. Hand
            // them back now rather than after the file is hashed and
            // flushed, which can take seconds on a large transfer.
            if let Some(r) = releaser {
                r.release().await;
            }

            // Take ownership back from the thread.
            let next_hello = result.pending_hello.or(watch_hello);
            let finish_replied = result.finish_replied;
            mmap = result.mmap;
            seq = result.seq;
            (result.n_received, next_hello, finish_replied)
        }
        ahp_proto::data::AckMode::Nack => {
            // NACK mode also uses the threaded receiver for performance.
            // The thread sends both ACK bitmaps AND NACKs for detected gaps.
            let socks = data_socks_used.clone();
            // `SocketAddr` holds either family; this used to refuse v6
            // outright, which is why an IPv6 handshake succeeded and then
            // stalled at 0 chunks with "transfer failed: IPv6 not supported".
            let peer_sin = peer;
            let ps = manifest.payload_size;
            let tc = manifest.total_chunks;
            let sk = session_keys.clone();
            let is_compressed = manifest.compressed;
            let is_hp = manifest.header_protected;
            let handle = std::thread::Builder::new()
                .name("favonius-recv-nack".into())
                .spawn(move || {
                    threaded_bitmap_recv(socks, Some(dest_fd_raw), peer_sin, conn_id, seq, mmap, streams, ps, tc, sk, is_compressed, true, is_hp)
                })
                .map_err(|e| format!("spawn recv thread: {e}"))?;

            let (result, watch_hello) = join_recv_thread(
                handle, ctrl_socket, ctrl_rx, peer, conn_id, &manifest_reply,
            ).await?;

            if let Some(r) = releaser {
                r.release().await;
            }

            let next_hello = result.pending_hello.or(watch_hello);
            let finish_replied = result.finish_replied;
            mmap = result.mmap;
            seq = result.seq;
            (result.n_received, next_hello, finish_replied)
        }
    };

    // ── FINISH reply ──────────────────────────────────────────────────────
    // The receive thread replies to the sender's FINISH when it sees one —
    // the normal case since the tail responder (TAIL_GRACE) keeps it on the
    // data port after the completion check passes. It still exits through
    // the grace clock when the FINISH itself was lost, and then the reply
    // must go out from here or the sender burns its whole post-transfer
    // wait deadline. A duplicate Finish (the thread already replied) is
    // harmless: the sender acts on the first, and a second copy arriving at
    // an already-exited sender is just a dropped datagram.
    //
    // Sent 3×: the reply is fire-and-forget and the sender's post-FINISH
    // wait has no retransmission of its own, so a single lost datagram
    // would burn its whole 2 s safety-net deadline (same 3-copy idiom as
    // the resume-bitmap ACK above). The sender acts on the first copy.
    if !finish_replied {
        for copy in 0..3 {
            let _ = send_ctrl_with_payload(
                ctrl_socket, peer, PacketType::Finish, conn_id, seq, &[],
            ).await;
            if copy < 2 {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        }
        seq += 1;
    }

    // Issue session ticket for 0-RTT reconnection (only if encrypted).
    // This gates only on complete reception — not on the flush/fsync below —
    // so it goes out BEFORE finalization: an encrypted sender ends its
    // post-transfer wait on this Checkpoint, and holding it behind the
    // writeback would leave the sender blocked for the whole fsync.
    // Feed the process-wide registry that /metrics exports. Recorded here
    // rather than at the accept loop because this is where the byte and
    // chunk totals actually exist.
    {
        let m = ahp_observability::global();
        m.bytes_transferred.inc_by(manifest.file_size);
        m.packets_sent.inc_by(n_received);
    }

    if session_keys.is_some() && n_received >= manifest.total_chunks {
        if let Some(ref keys) = session_keys {
            let issued = ticket_key
                .lock()
                .expect("ticket key mutex poisoned")
                .issue(&keys.resume_secret, ahp_crypto::session_ticket::DEFAULT_TICKET_TTL);
            match issued {
                Ok(ticket) => {
                    let ticket_payload = ahp_crypto::session_ticket::encode_ticket(&ticket);
                    // Send ticket as a Checkpoint packet after the transfer.
                    // 3 copies, as for the FINISH reply above: an encrypted
                    // sender's post-transfer wait ends ONLY on this packet
                    // (or the 2 s deadline), so losing the single copy
                    // stalls an otherwise-complete transfer for 2 s.
                    for copy in 0..3 {
                        let _ = send_ctrl_with_payload(
                            ctrl_socket, peer, PacketType::Checkpoint, conn_id, seq, &ticket_payload,
                        ).await;
                        if copy < 2 {
                            tokio::time::sleep(Duration::from_millis(1)).await;
                        }
                    }
                    tracing::info!("issued session ticket for 0-RTT reconnection");
                }
                Err(e) => tracing::warn!("failed to issue session ticket: {e}"),
            }
        }
    }

    // B7: verification and completeness are FATAL at finalization — a
    // corrupt or incomplete transfer returns Err (the caller logs it as
    // "transfer failed") and must never seed the Merkle resume cache.
    // Slice to the declared file size: for a zero-length file the mmap is a
    // 1-byte placeholder (see above) and the received content is empty.
    //
    // Linux: the whole-file hash is computed with a page-drop chase behind
    // the read frontier (blake3_with_drop_chase) so the verification
    // re-read does not fault the whole file back into RSS; the checks and
    // their fatal-on-failure semantics are identical. Merkle mode gets the
    // same treatment (merkle_with_drop_chase): the resume-cache tree is
    // built windowed with a drop chase instead of re-reading the mapping
    // whole inside finalize_transfer_hashed.
    #[cfg(target_os = "linux")]
    {
        let precomputed = manifest.file_hash.as_ref().map(|_| {
            blake3_with_drop_chase(&mmap, manifest.file_size as usize)
        });
        let precomputed_tree = (manifest.resume_mode == "merkle").then(|| {
            merkle_with_drop_chase(&mmap, manifest.file_size as usize, manifest.payload_size)
        });
        finalize_transfer_hashed(
            &manifest, &mmap[..manifest.file_size as usize], n_received, precomputed,
            precomputed_tree,
        )?;
    }
    #[cfg(not(target_os = "linux"))]
    finalize_transfer(&manifest, &mmap[..manifest.file_size as usize], n_received)?;

    // Writeback (msync + fsync) runs detached. It can take ~1 s per GiB on a
    // busy disk; running it inline blocks the main loop, so a back-to-back
    // sender's next HELLO sat unanswered for the remainder of the previous
    // file's fsync (recovered by the drain above only after the wait).
    // Nothing gates on durability: verification already ran inline, and the
    // 0-RTT ticket was issued on complete reception. The old mapping and fd
    // stay valid inside the task; a same-path next transfer writes through
    // the same page cache, which the late flush only helps.
    let dest = manifest.dest_path.clone();
    let size = manifest.file_size;
    tokio::task::spawn_blocking(move || {
        let result = mmap.flush().and_then(|()| dest_file.sync_all());
        drop(mmap);
        match result {
            Ok(()) => tracing::info!(dest = %dest, size, chunks = n_received, "file written"),
            Err(e) => tracing::error!(dest = %dest, error = %e, "file writeback failed"),
        }
    });

    Ok(pending_hello)
}

/// Finalize a received transfer: check completeness and (when the manifest
/// carries one) the whole-file BLAKE3 hash, then maintain the Merkle resume
/// cache. `data` is the received file contents (the mmap before flushing).
///
/// B7: any failure is fatal. An incomplete transfer or a hash mismatch
/// returns Err so the transfer is reported as failed, and a file that
/// failed verification is never cached as the resume source. A pre-existing
/// cache entry is removed on failure: the file on disk may have been
/// partially overwritten, so the old tree no longer reflects it and would
/// corrupt future merkle-resume diffs.
///
/// On Linux the transfer path calls `finalize_transfer_hashed` directly
/// with a hash computed under the page-drop chase; this wrapper remains for
/// tests and non-Linux platforms.
#[cfg_attr(all(target_os = "linux", not(test)), allow(dead_code))]
fn finalize_transfer(manifest: &FileManifest, data: &[u8], n_received: u64) -> Result<(), String> {
    let precomputed = manifest
        .file_hash
        .as_ref()
        .map(|_| blake3::hash(data).to_hex().to_string());
    finalize_transfer_hashed(manifest, data, n_received, precomputed, None)
}

/// `finalize_transfer` with the BLAKE3 of `data` supplied by the caller
/// (`Some` iff the manifest carries a hash) and, optionally, a precomputed
/// Merkle tree over `data`. Split out so the Linux transfer path can
/// compute both incrementally with a page-drop chase behind the read
/// frontier (bounding RSS) while the checks and failure semantics stay
/// identical. A `None` tree falls back to the slice-based build over
/// `data`; a supplied tree MUST be byte-identical to
/// `build_file_merkle(data, manifest.payload_size)` — the resume cache and
/// future diff computations depend on the exact tree bytes.
fn finalize_transfer_hashed(
    manifest: &FileManifest,
    data: &[u8],
    n_received: u64,
    actual_hash: Option<String>,
    precomputed_tree: Option<ahp_sync::merkle::MerkleTree>,
) -> Result<(), String> {
    if n_received < manifest.total_chunks {
        let _ = std::fs::remove_file(merkle_cache_path(&manifest.dest_path));
        return Err(format!(
            "incomplete transfer: received {n_received} of {} chunks",
            manifest.total_chunks
        ));
    }

    if let Some(ref expected) = manifest.file_hash {
        let actual = actual_hash.unwrap_or_else(|| blake3::hash(data).to_hex().to_string());
        if actual != *expected {
            let _ = std::fs::remove_file(merkle_cache_path(&manifest.dest_path));
            tracing::error!(expected = %expected, actual = %actual, "file hash MISMATCH after transfer");
            return Err(format!(
                "integrity check failed: BLAKE3 mismatch (expected {expected}, got {actual})"
            ));
        }
        tracing::info!(hash = %actual, "file hash verified");
    }

    // Cache Merkle tree for future instant re-sync — only reached after
    // successful verification, so the cache always reflects a known-good
    // file. The entry is stamped with size+mtime+fingerprint of the verified
    // content so a later same-name replacement misses (B12).
    // On Linux the tree comes in precomputed from the transfer path, built
    // windowed under the page-drop chase (merkle_with_drop_chase) so the
    // build does not re-fault the whole file into RSS; the slice-based
    // fallback here remains for tests and non-Linux platforms.
    if manifest.resume_mode == "merkle" {
        let tree = precomputed_tree
            .unwrap_or_else(|| ahp_sync::merkle::build_file_merkle(data, manifest.payload_size));
        write_merkle_cache(&manifest.dest_path, &tree, data);
        let cache_path = merkle_cache_path(&manifest.dest_path);
        tracing::info!(path = %cache_path.display(), root = %hex::encode(tree.root()), "cached Merkle tree");
    }

    Ok(())
}

/// Bitmap ACK mode data receive loop with multi-stream support.
///
// ── Threaded receiver (dedicated I/O thread, no tokio overhead) ──────────

/// Result from the threaded receiver, carrying back ownership of buffers.
struct ThreadedRecvResult {
    n_received: u64,
    mmap: MmapMut,
    seq: u64,
    /// If a HELLO packet from a new connection arrived during data reception,
    /// store it here so the main loop can handle it immediately.
    pending_hello: Option<(u64, std::net::SocketAddr)>,
    /// Whether the loop exited through the FINISH handler (which already
    /// sent the FINISH reply). False when it exited through the completion
    /// check — the post-transfer path must then send the reply itself.
    finish_replied: bool,
}

/// Send raw bytes to a destination (no tokio, no allocation).
///
/// Borrows the socket's native handle and issues a plain `sendto` on it.
/// The sockets are non-blocking, so this has the semantics the receive loop
/// needs — a full transmit queue returns `WouldBlock` rather than parking
/// the thread — without going through the async runtime, which matters
/// because every caller is on a dedicated OS thread outside it.
///
/// Failures other than `WouldBlock` are dropped: an ACK is soft state and
/// the next one carries the same information.
fn send_raw(buf: &[u8], sock: &UdpSocket, dest: SocketAddr) {
    let sock = socket2::SockRef::from(sock);
    let dest: socket2::SockAddr = dest.into();
    loop {
        match sock.send_to(buf, &dest) {
            Ok(_) => break,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::hint::spin_loop();
                continue;
            }
            Err(_) => break,
        }
    }
}

/// Send a header and its payload as one datagram, without joining them.
///
/// `sendmsg` with two iovecs did this natively. `send_to` takes one buffer,
/// so the two are staged into a caller-provided scratch buffer instead —
/// still one datagram on the wire, still no heap allocation per send.
fn send_raw_vectored(hdr: &[u8], payload: &[u8], scratch: &mut Vec<u8>, sock: &UdpSocket, dest: SocketAddr) {
    scratch.clear();
    scratch.extend_from_slice(hdr);
    scratch.extend_from_slice(payload);
    send_raw(scratch, sock, dest);
}

/// Where a finished ACK datagram goes: straight out of the receive loop, or
/// onto a queue drained by a dedicated transmit thread.
///
/// The receive thread's job is to keep `recvmmsg` drained; a 4 MB socket
/// buffer at 300 MB/s is ~13 ms deep and cannot be enlarged (it is already
/// at `net.core.rmem_max`). Today that thread also *sends* every ACK
/// inline, one `sendmsg` per stream per feedback event, so four streams
/// take four syscalls out of the drain loop. Offloading them changes
/// neither the wire format nor the cadence, which is exactly what makes it
/// the clean test: if drops and goodput move, ACK work in the receive loop
/// was causal; if only drops move, the cost was real but not the
/// bottleneck; if nothing moves, the earlier `ack_every` result was
/// throttling the sender rather than relieving the receiver.
/// Measured.
enum AckSink {
    /// Historical behaviour: `sendmsg` inline, on the receive thread.
    Inline,
    /// Hand off to the transmit thread. Send failures are dropped, exactly
    /// as `send_raw` drops them — an ACK is soft state and the next one
    /// carries the same information. The socket travels with the datagram:
    /// with a per-stream port run there is no single "the" fd any more, and
    /// a queue that assumed one would answer every stream from the base
    /// port.
    Queued(std::sync::mpsc::Sender<(Arc<UdpSocket>, Vec<u8>)>),
}

impl AckSink {
    #[inline]
    fn send(&self, buf: &[u8], sock: &Arc<UdpSocket>, dest: SocketAddr) {
        match self {
            AckSink::Inline => send_raw(buf, sock, dest),
            AckSink::Queued(tx) => {
                let _ = tx.send((Arc::clone(sock), buf.to_vec()));
            }
        }
    }
}

/// Tight blocking receive loop on a dedicated OS thread.
///
/// Eliminates tokio::select overhead (~500ns/packet) by using blocking
/// `recvfrom` and inline timer checks. Mirrors UDT's receiver architecture.
///
/// `fds` is this transfer's data sockets in ascending port order. One is the
/// historical case. Several means the sender was told it could split its
/// streams across a contiguous port run, and this loop polls them
/// round-robin so N kernel receive queues are drained instead of one — a
/// single 4 MB buffer at `net.core.rmem_max` overflowing is what an earlier
/// run measured as the 4-stream cost, and N queues is the cheapest way to test
/// whether the queue or this thread is the limit. Everything else — the
/// mmap, `seq`, teardown, FINISH, the tail responder — is per *transfer*,
/// not per socket, and is unchanged.
///
/// Nothing routes by socket: a DATA packet is placed by its `stream_id`
/// wherever it arrives, so a sender that ignores the run, one that uses it,
/// and a retransmission that crosses ports are all handled by the same code.
fn threaded_bitmap_recv(
    socks: Vec<Arc<UdpSocket>>,
    // Destination file descriptor, for writeback pacing. `None` disables it
    // (tests, and any path without a real file behind the mapping). Writeback
    // pacing is a Linux facility; see [`WritebackFd`]. Off Linux the pacer
    // compiles out and nothing reads this, but it stays in the signature so
    // the call sites do not have to fork.
    #[cfg_attr(not(target_os = "linux"), allow(unused_variables))]
    dest_fd: Option<WritebackFd>,
    peer_addr: SocketAddr,
    conn_id: u64,
    mut seq: u64,
    mut mmap: MmapMut,
    mut streams: Vec<StreamRecvState>,
    payload_size: usize,
    total_chunks: u64,
    session_keys: Option<ahp_crypto::SessionKeys>,
    compressed: bool,
    nack_enabled: bool,
    header_protected: bool,
) -> Result<ThreadedRecvResult, String> {
    // Batched receive through the platform abstraction. On Linux this is
    // recvmmsg(2): up to RECV_BATCH datagrams per syscall instead of one per
    // recvfrom. The receiver owns its buffers, so each packet is still
    // processed in place (header unprotect + in-place decrypt) with no extra
    // copy — identical per-packet work, fewer syscalls.
    // ACK transmit offload. Default off: shipped behaviour is unchanged
    // until this is measured. `FAVONIUS_ACK_THREAD=1` enables it.
    let ack_thread = std::env::var("FAVONIUS_ACK_THREAD").map(|v| v == "1").unwrap_or(false);
    let (ack_sink, ack_join) = if ack_thread {
        let (tx, rx) = std::sync::mpsc::channel::<(Arc<UdpSocket>, Vec<u8>)>();
        let dest = peer_addr;
        let join = std::thread::Builder::new()
            .name("ahp-ack-tx".into())
            .spawn(move || {
                // Drain whatever else is already queued before syscalling, so
                // a feedback event covering N streams costs one wakeup.
                while let Ok((sock, first)) = rx.recv() {
                    send_raw(&first, &sock, dest);
                    while let Ok((sock, next)) = rx.try_recv() {
                        send_raw(&next, &sock, dest);
                    }
                }
            })
            .map_err(|e| format!("spawn ack-tx thread: {e}"))?;
        (AckSink::Queued(tx), Some(join))
    } else {
        (AckSink::Inline, None)
    };
    if socks.is_empty() {
        return Err("threaded_bitmap_recv: no data sockets".into());
    }
    // One receiver per socket. Each carries its own RECV_BATCH x MAX_PACKET
    // staging buffer (48 KB), so a full run costs under 400 KB.
    let mut receivers: Vec<Box<dyn ahp_platform_net::PacketBatchReceiver>> = socks
        .iter()
        .map(|s| {
            ahp_platform_net::create_best_receiver(
                ahp_platform_net::raw_socket(&**s),
                RECV_BATCH,
                MAX_PACKET,
            )
        })
        .collect();
    // Where the round-robin resumes. Kept across iterations so a socket that
    // is always polled last does not starve behind a busy one.
    let mut rr: usize = 0;
    // The socket a given stream's feedback goes out on. Streams beyond the
    // run share the last port — the same mapping the sender uses to pick a
    // destination, so an ACK leaves by the port its DATA arrived on.
    let sock_for = |stream_id: usize| &socks[stream_id.min(socks.len() - 1)];
    let mut ack_buf = [0u8; 1152]; // >= 42 hdr + 26 ACK hdr + MAX_ACK_BITMAP_BYTES
    // Scratch for the one send that carries a header plus a separate payload
    // (NackRange). Reused so the NACK path stays allocation-free.
    let mut nack_tx_buf: Vec<u8> = Vec::with_capacity(512);
    let mut decrypt_buf = [0u8; MAX_PACKET]; // scratch for in-place decryption
    let mut last_ack = Instant::now();
    let mut pending_hello: Option<(u64, std::net::SocketAddr)> = None;

    // Key epoch for tracking rotation (mirrors sender-side KeyEpoch).
    let mut key_epoch = session_keys.map(ahp_crypto::key_update::KeyEpoch::new);

    // Longest DATA payload this transfer can legitimately carry: one chunk,
    // plus the AEAD tag when encrypted. Anything longer is rejected before
    // it is touched.
    //
    // This check used to be done for us by the receive buffer. Each slot was
    // `MAX_PACKET` bytes, so the kernel truncated anything larger and
    // `decode_data_inline`'s `buf.len() < data_end` test rejected a header
    // claiming more than had arrived. Enabling UDP_GRO raised the slot to
    // 64 KiB, and that implicit bound went with it: `data_len` is an
    // attacker-controlled u16, so a single datagram could then deliver up to
    // 65535 bytes of "chunk".
    //
    // Two things went wrong at once, and one check fixes both. The
    // plaintext path handed the whole thing to `write_chunk`, which clamps
    // to the mapping but happily spans chunk boundaries — 45x more of the
    // destination file per forged packet than before. The encrypted path
    // copied it into `decrypt_buf` (a fixed MAX_PACKET array) *before*
    // verifying the AEAD tag, so unauthenticated input could panic the
    // receive thread.
    //
    // The `min` matters: `validate_manifest` allows `payload_size` up to
    // MAX_PACKET, so `payload_size + tag` can exceed the scratch buffer, and
    // the copy below must never be given more than it can hold.
    const AEAD_TAG_LEN: usize = 16;
    let max_data_len = if key_epoch.is_some() {
        payload_size.saturating_add(AEAD_TAG_LEN).min(decrypt_buf.len())
    } else {
        payload_size
    };

    // Set up decryption from current key epoch.
    let mut data_protector = key_epoch.as_ref().map(|ke| {
        ahp_crypto::packet_protection::Aes256GcmProtector::new(&ke.keys.data_key)
    });
    let mut data_nonce_gen = key_epoch.as_ref().map(|ke| {
        ahp_crypto::NonceGenerator::new(ke.keys.data_iv)
    });

    // Header protector for unmasking connection_id + packet_number.
    let mut header_protector = if header_protected {
        key_epoch.as_ref().map(|ke| {
            ahp_crypto::header_protection::HeaderProtector::new(&ke.keys.header_protection_key)
        })
    } else {
        None
    };

    // Set up decompressor (used per-packet based on COMPRESSED flag).
    let decompressor = if compressed {
        ahp_compression::zstd_impl::create_compressor(ahp_compression::CompressionProfile::ZstdBalanced)
    } else {
        None
    };
    // Reusable zstd context for the per-chunk decompress path: a fresh
    // context per packet (decode_all) would re-allocate its workspace
    // ~1M times per GB transferred.
    let mut decomp_ctx = decompressor
        .as_ref()
        .map(|d| d.bulk_decompressor())
        .transpose()
        .map_err(|e| e.to_string())?;
    const COMPRESSED_FLAG: u16 = 0x0010;
    let ack_interval = Duration::from_millis(15);

    // Keep socket non-blocking: use try_recvfrom in a tight loop with
    // brief spin-waits when no data is available. This matches UDT's
    // approach and avoids the 1ms SO_RCVTIMEO granularity.

    // Dead-peer detection: armed now (thread start = DATA phase begin, after
    // MANIFEST/resume setup) and refreshed per accepted peer packet below.
    let mut last_peer_activity = Instant::now();

    // Set when the loop exits through the FINISH handler (which replies);
    // the completion-check exit leaves the reply to the post-transfer path.
    let mut finish_replied = false;

    // Tail-responder clock: `Some` once every chunk has been received (the
    // completion check below arms it). While armed, the loop keeps
    // answering the peer's tail retransmissions until the FINISH handler
    // runs, a new HELLO is queued, or the grace expires.
    let mut tail_start: Option<Instant> = None;

    // Linux: how far into each stream's file range pages have already been
    // dropped (MADV_DONTNEED). The timer block below drops pages behind
    // each stream's contiguous-receive frontier in PAGE_DROP_GRANULARITY
    // steps so peak RSS stays near-constant regardless of file size (see
    // drop_mapping_pages).
    // ACK_EVERY is a PER-STREAM packet count, but a window turn is divided
    // among the streams — so the trigger's reachability depends on how many
    // there are, and nobody scaled it.
    //
    // With the shipped 4 streams and the 512 KB LanWifi window floor, a
    // window turn is 512 KiB / 1414 B = 371 packets, i.e. ~93 per stream:
    // permanently short of 128, so the count trigger could never fire and
    // every window turn waited out the 15 ms timer instead. That sets the
    // sender's clock, not the path: 512 KiB / 15.78 ms = 31.7 MB/s against
    // 33.1 measured on a real radio whose send path was doing 45.2 while it
    // was actually sending.
    //
    // It also explains why `--streams 1` measured 41.5 MB/s on the same
    // path: one stream puts all 371 packets on one counter, so the trigger
    // fires and feedback arrives on data rather than on a timer.
    //
    // Scaling by stream count restores the aggregate cadence the constant
    // was chosen for — 128 packets between ACKs across the transfer, not
    // 128 per stream — with a floor so a large --streams cannot turn every
    // packet into an ACK.
    // `FAVONIUS_ACK_EVERY` overrides the per-stream count. Instrument, not a
    // knob: scaling by stream count means 4 streams emit 4x the ACK packets
    // for the same data, and every ACK is time the receive thread spends in
    // sendto() rather than draining its socket. Varying this separates
    // "multi-stream costs ACK bandwidth" from "multi-stream costs write
    // locality" as causes of the 4-stream receive-buffer overflow.
    let ack_every: u64 = match std::env::var("FAVONIUS_ACK_EVERY")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|n| *n >= 1 && *n <= 8192)
    {
        Some(n) => n,
        None => (ACK_EVERY / streams.len().max(1) as u64).max(16),
    };

    #[cfg(target_os = "linux")]
    let mut writeback_waited_upto: usize = 0;
    #[cfg(target_os = "linux")]
    let mut pages_dropped_upto: Vec<usize> = streams
        .iter()
        .map(|s| (s.chunk_base as usize).saturating_mul(payload_size))
        .collect();

    // ── Drain instrumentation (FAVONIUS_RECV_DEBUG=1) ─────────────────────
    //
    // Is this thread keeping up? Its CPU time cannot answer that: the loop
    // spin-waits with `yield_now()` on an empty socket, so it burns a full
    // core at 470 MB/s and at 2 MB/s alike — measured both, 2026-08-12, and
    // the first reading of "100%, therefore saturated" was wrong.
    //
    // What answers it is how full `recv_batch` comes back. A thread that is
    // behind the arrival rate always finds a backlog and returns RECV_BATCH
    // datagrams every time; one that is keeping up returns one or two and
    // then finds the socket empty. So mean fullness against RECV_BATCH, and
    // the share of polls that found nothing, bound how much headroom is
    // left — which is the question step (b) (N sockets, N threads) turns on.
    //
    // Per-socket counts come with it: they are what shows the port run is
    // actually spreading traffic rather than the sender putting everything
    // on the base port.
    let recv_debug = std::env::var("FAVONIUS_RECV_DEBUG").is_ok_and(|v| v == "1");
    let mut dbg_batches: u64 = 0;
    let mut dbg_datagrams: u64 = 0;
    let mut dbg_empty_polls: u64 = 0;
    let mut dbg_full_batches: u64 = 0;
    let mut dbg_per_fd: Vec<u64> = vec![0; socks.len()];
    let dbg_start = Instant::now();

    'recv: loop {
        // Once complete, only the grace clock governs the exit — the peer
        // going silent here is the normal case (sender done, its FINISH
        // lost), not a dead peer, and every chunk is already received.
        if let Some(t) = tail_start {
            if t.elapsed() >= TAIL_GRACE {
                break 'recv;
            }
        } else if last_peer_activity.elapsed() >= PEER_INACTIVITY_TIMEOUT {
            return Err(format!(
                "peer silent for {}s mid-transfer (dead peer?), aborting",
                PEER_INACTIVITY_TIMEOUT.as_secs()
            ));
        }
        // Poll the sockets round-robin, resuming where the last pass left
        // off: always starting at 0 would let a busy first socket starve the
        // rest, which is the failure mode this whole change exists to avoid.
        // One socket is the historical single `recv_batch` with an index.
        let mut batch_n = 0usize;
        let mut idx = rr;
        for _ in 0..receivers.len() {
            match receivers[idx].recv_batch() {
                Ok(0) => {}
                Ok(n) => {
                    batch_n = n;
                    break;
                }
                Err(ahp_platform_net::RecvError::WouldBlock) => {}
                Err(e) => return Err(format!("recv_batch: {e}")),
            }
            idx = (idx + 1) % receivers.len();
        }
        if batch_n == 0 {
            dbg_empty_polls += 1;
            // Every socket is empty — check the ACK timer, then brief yield.
            if last_ack.elapsed() >= ack_interval {
                for (si, stream) in streams.iter_mut().enumerate() {
                    if stream.since_ack > 0 {
                        let (hc, bm) = build_stream_ack_bitmap(stream);
                        let n = encode_ack_bitmap_into(
                            &mut ack_buf, conn_id, seq,
                            si as u32, stream.chunk_base, hc, &bm,
                        );
                        ack_sink.send(&ack_buf[..n], sock_for(si), peer_addr);
                        seq += 1;
                        stream.since_ack = 0;
                    }
                }
                last_ack = Instant::now();
            }
            std::thread::yield_now();
            continue 'recv;
        }
        rr = (idx + 1) % receivers.len();
        dbg_batches += 1;
        dbg_datagrams += batch_n as u64;
        dbg_per_fd[idx] += batch_n as u64;
        if batch_n >= RECV_BATCH {
            dbg_full_batches += 1;
        }
        // The socket this batch came off. Replies that are not attributable
        // to a stream go back out of it, so a peer sees answers from the
        // port it addressed.
        let cur_sock = &socks[idx];
        let receiver = &mut receivers[idx];

        for pkt_idx in 0..batch_n {
        // Source is copied out before the mutable packet borrow begins.
        let recv_from_addr = receiver.source(pkt_idx);
        let pkt = receiver.packet_mut(pkt_idx);
        let len = pkt.len();

        if len > 1 && pkt[1] == 0x20 {
            // Unprotect header before decoding (packet_type at [1] is not masked).
            if let Some(ref hp) = header_protector {
                hp.unprotect(&mut pkt[..len], HEADER_SIZE);
            }
            // Drop DATA that belongs to a different connection. The data port
            // is long-lived and shared across transfers, so late or
            // retransmitted packets from a previous transfer can still be
            // queued (or arrive in flight) when the next one starts. Without
            // this check they are decoded as if they belonged to the current
            // transfer and written into the output file — silently corrupting
            // it whenever the two transfers differ in encryption or
            // compression. connection_id is bytes 6..14, big-endian.
            if len >= 14 {
                let pkt_conn = u64::from_be_bytes([
                    pkt[6], pkt[7], pkt[8], pkt[9],
                    pkt[10], pkt[11], pkt[12], pkt[13],
                ]);
                if pkt_conn != conn_id {
                    continue;
                }
            }
            // Fast path: DATA packet — zero-copy inline decode.
            if let Some(dp) = decode_data_inline(&pkt[..len]) {
                // Oversized payloads are rejected before anything reads or
                // copies them, and before the inactivity clock is touched:
                // a packet no legitimate sender can produce is not evidence
                // that the peer is alive.
                if dp.data.len() > max_data_len {
                    continue;
                }
                // Live peer traffic for this connection — refresh the
                // inactivity clock (wrong-conn packets were dropped above).
                last_peer_activity = Instant::now();
                let sid = dp.stream_id as usize;
                let ci = dp.chunk_index as usize;

                if sid < streams.len() {
                    let stream = &mut streams[sid];
                    // Skip chunk indices outside this stream's
                    // [chunk_base, chunk_base + chunk_count) range with no
                    // bookkeeping side effects — a plain subtraction would
                    // underflow and the wrapped value would hang the NACK
                    // gap scan below (~2^64 iterations).
                    let Some(local_ci) = local_chunk_index(stream, dp.chunk_index) else {
                        continue;
                    };
                    if !stream.received[local_ci as usize] {
                        let offset = ci * payload_size;

                        // Pipeline: decrypt (optional) → decompress (optional) → write.
                        let raw_data = dp.data;

                        // Step 1: Decrypt if encrypted.
                        //
                        // The plaintext branch hands the received bytes
                        // straight through. They are already in the
                        // receiver's own buffer; the only reason to stage
                        // them in `decrypt_buf` was that the *encrypted*
                        // path needs somewhere to decrypt into, and copying
                        // regardless cost a second pass over every packet
                        // — 260 MB/s of memcpy and the cache it evicts, on
                        // a receive path measured at 12-26x TCP's CPU per
                        // byte (measured).
                        let payload: &[u8] = if let (Some(ref prot), Some(ref ng)) = (&data_protector, &data_nonce_gen) {
                            let pkt_num = u64::from_be_bytes([
                                pkt[18], pkt[19], pkt[20], pkt[21],
                                pkt[22], pkt[23], pkt[24], pkt[25],
                            ]);
                            let nonce = ng.nonce_for(pkt_num);
                            // AEAD associated data: the 42-byte fixed header
                            // as it appears on the wire AFTER header
                            // protection removal (i.e. the logical header —
                            // conn_id/packet_number unmasked, per-packet
                            // flags such as COMPRESSED included). The sender
                            // authenticates the identical bytes (RFC §14.4),
                            // so a tampered stream_id or flag fails the GCM
                            // tag check instead of silently misrouting data.
                            let aad = &pkt[..HEADER_SIZE];
                            decrypt_buf[..raw_data.len()].copy_from_slice(raw_data);
                            match prot.decrypt_in_place(&nonce, aad, &mut decrypt_buf, raw_data.len()) {
                                Ok(len) => &decrypt_buf[..len],
                                Err(_) => continue, // skip corrupted packet
                            }
                        } else {
                            raw_data
                        };

                        // Step 2: Decompress if this packet's COMPRESSED flag is set.
                        let pkt_flags = u16::from_be_bytes([pkt[2], pkt[3]]);
                        let is_pkt_compressed = (pkt_flags & COMPRESSED_FLAG) != 0;

                        if is_pkt_compressed {
                            if let (Some(ref decomp), Some(ref mut ctx)) = (&decompressor, &mut decomp_ctx) {
                                // Bounded decompression: a chunk expands to at
                                // most payload_size bytes; anything larger is a
                                // decompression bomb, not a valid chunk.
                                match decomp.decompress_bounded_with(ctx, payload, payload_size) {
                                    Ok(decompressed) => {
                                        write_chunk(&mut mmap, offset, &decompressed);
                                    }
                                    Err(_) => continue,
                                }
                            } else {
                                // Flag says compressed but no decompressor — write raw.
                                write_chunk(&mut mmap, offset, payload);
                            }
                        } else {
                            write_chunk(&mut mmap, offset, payload);
                        }

                        stream.mark_received(local_ci as usize);
                    }

                    stream.since_ack += 1;

                    // ── NACK gap detection (threaded, reorder-tolerant) ──
                    if nack_enabled && local_ci > stream.expected_next_local {
                        if stream.gap_start_local.is_none() {
                            stream.gap_start_local = Some(stream.expected_next_local);
                            stream.gap_first_seen = Some(Instant::now());
                            stream.gap_counter = 0;
                        }
                        stream.gap_counter += 1;

                        let elapsed_ms = stream.gap_first_seen
                            .map(|t| t.elapsed().as_millis()).unwrap_or(0);
                        if stream.gap_counter >= 32 || elapsed_ms >= 25 {
                            let gs = stream.gap_start_local
                                .unwrap_or(stream.expected_next_local) as usize;
                            let ge = local_ci as usize;
                            let mut ranges: Vec<(u64, u64)> = Vec::new();
                            let mut rs: Option<u64> = None;
                            for idx in gs..ge {
                                if idx < stream.received.len() && !stream.received[idx] {
                                    let g = idx as u64 + stream.chunk_base;
                                    if !stream.nacked_ranges.contains(&g) {
                                        if rs.is_none() { rs = Some(g); }
                                    } else if let Some(s) = rs.take() {
                                        ranges.push((s, g - 1));
                                    }
                                } else if let Some(s) = rs.take() {
                                    ranges.push((s, (idx as u64 - 1) + stream.chunk_base));
                                }
                            }
                            if let Some(s) = rs {
                                ranges.push((s, (ge as u64 - 1) + stream.chunk_base));
                            }
                            if !ranges.is_empty() {
                                for &(s, e) in &ranges {
                                    for pn in s..=e { stream.nacked_ranges.insert(pn); }
                                }
                                // Encode and send NackRange inline.
                                let nack = ahp_proto::data::NackRange {
                                    stream_id: sid as u32,
                                    ranges: ranges.clone(),
                                };
                                let mut nbuf = bytes::BytesMut::new();
                                nack.encode(&mut nbuf);
                                let mut pkt_buf = [0u8; 256];
                                // Header declares the payload length so the
                                // sender's decode_packet can extract the
                                // NackRange payload that follows it.
                                let n = encode_ctrl_packet_with_payload_into(
                                    &mut pkt_buf, PacketType::NackRange, conn_id, seq,
                                    nbuf.len() as u32,
                                );
                                // Header then payload, one datagram. Staged
                                // through a reused scratch buffer rather than
                                // two iovecs, so the wire format is unchanged
                                // and nothing is allocated per send.
                                send_raw_vectored(
                                    &pkt_buf[..n], &nbuf[..], &mut nack_tx_buf,
                                    sock_for(sid), peer_addr,
                                );
                                seq += 1;
                            }
                            stream.gap_start_local = None;
                            stream.gap_first_seen = None;
                            stream.gap_counter = 0;
                        }
                    }
                    if nack_enabled {
                        let next = local_ci + 1;
                        if next > stream.expected_next_local {
                            stream.expected_next_local = next;
                        }
                        if stream.nacked_ranges.len() > 10000 {
                            stream.nacked_ranges.clear();
                        }
                    }

                    if stream.since_ack >= ack_every {
                        let (hc, bm) = build_stream_ack_bitmap(stream);
                        let n = encode_ack_bitmap_into(
                            &mut ack_buf, conn_id, seq,
                            sid as u32, stream.chunk_base, hc, &bm,
                        );
                        ack_sink.send(&ack_buf[..n], sock_for(sid), peer_addr);
                        seq += 1;
                        stream.since_ack = 0;
                    }
                }

                // Completion check. The first time every chunk is in, send
                // the final all-acked ACKs 3× per stream (the repo's
                // redundancy idiom for fire-and-forget terminal datagrams,
                // cf. the post-transfer FINISH reply) — these are exactly
                // the packets whose loss strands the sender on its tail
                // retransmissions — and arm the tail responder instead of
                // exiting. Further retransmitted DATA is answered through
                // the normal ACK paths above (since_ack + the 15 ms timer),
                // which now always report the complete bitmap.
                if tail_start.is_none()
                    && streams.iter().map(|s| s.n_received).sum::<u64>() >= total_chunks
                {
                    for _ in 0..3 {
                        for (si, stream) in streams.iter().enumerate() {
                            let (hc, bm) = build_stream_ack_bitmap(stream);
                            let n = encode_ack_bitmap_into(
                                &mut ack_buf, conn_id, seq,
                                si as u32, stream.chunk_base, hc, &bm,
                            );
                            ack_sink.send(&ack_buf[..n], sock_for(si), peer_addr);
                            seq += 1;
                        }
                    }
                    tail_start = Some(Instant::now());
                }
            }
        } else if len > 0 {
            // Slow path: non-DATA packet (Finish, PathProbe, KeyUpdate).
            // These arrive with an unprotected header (control packets are
            // never header-protected), so decode directly.
            if let Ok(decoded) = decode_packet(&pkt[..len]) {
                // Drop stale control packets from previous transfers on this
                // long-lived, shared data port (e.g. a delayed FINISH). HELLO
                // is exempt: it belongs to a new connection by definition.
                if decoded.header.connection_id != conn_id
                    && decoded.header.packet_type != PacketType::Hello
                {
                    continue;
                }
                // Refresh the inactivity clock only for THIS transfer's peer —
                // a HELLO from a new connection says nothing about whether
                // the active peer is still alive.
                if decoded.header.connection_id == conn_id {
                    last_peer_activity = Instant::now();
                }
                match decoded.header.packet_type {
                    PacketType::Finish => {
                        // S3: an encrypted transfer's FINISH must authenticate
                        // under the control key — it finalizes/truncates the
                        // transfer, so a forged or cleartext FINISH is dropped,
                        // not processed. The AAD is the 42-byte header as it
                        // arrived on the wire (control packets are never
                        // header-protected).
                        if authenticate_ctrl(
                            key_epoch.as_ref(),
                            &pkt[..HEADER_SIZE],
                            decoded.header.packet_number,
                            &decoded.payload,
                        ).is_none() {
                            tracing::warn!("dropping unauthenticated FINISH");
                            continue;
                        }
                        for (si, stream) in streams.iter().enumerate() {
                            let (hc, bm) = build_stream_ack_bitmap(stream);
                            let n = encode_ack_bitmap_into(
                                &mut ack_buf, conn_id, seq,
                                si as u32, stream.chunk_base, hc, &bm,
                            );
                            ack_sink.send(&ack_buf[..n], sock_for(si), peer_addr);
                            seq += 1;
                        }
                        let n = encode_ctrl_packet_into(
                            &mut ack_buf, PacketType::Finish, conn_id, seq,
                        );
                        ack_sink.send(&ack_buf[..n], cur_sock, peer_addr);
                        finish_replied = true;
                        break 'recv;
                    }
                    PacketType::PathProbe => {
                        // Echo probe back.
                        let n = encode_ctrl_packet_into(
                            &mut ack_buf, PacketType::PathProbeAck, conn_id,
                            decoded.header.packet_number,
                        );
                        ack_sink.send(&ack_buf[..n], cur_sock, peer_addr);
                    }
                    PacketType::KeyUpdate => {
                        // Sender rotated keys — rotate our side to match, but
                        // only when this is exactly the next epoch. A duplicate
                        // (retransmitted KEY_UPDATE with the current epoch) is
                        // a no-op; anything older is stale or forged and must
                        // not desync the key schedule.
                        //
                        // S3: the update must first authenticate under the
                        // control key. The sender seals it with the OUTGOING
                        // epoch's keys, so the first delivery unseals under
                        // our current keys and retransmissions arriving after
                        // we rotated unseal via the previous-epoch grace
                        // window. A forged KEY_UPDATE can no longer force a
                        // premature rotation.
                        let authed = authenticate_ctrl(
                            key_epoch.as_ref(),
                            &pkt[..HEADER_SIZE],
                            decoded.header.packet_number,
                            &decoded.payload,
                        );
                        if let Some(payload) = authed {
                            if let Some(new_epoch) = ahp_crypto::key_update::decode_key_update(&payload) {
                                if let Some(ref mut ke) = key_epoch {
                                    if should_rotate(ke.epoch, new_epoch) {
                                        if let Ok(()) = ke.rotate() {
                                            data_protector = Some(ahp_crypto::packet_protection::Aes256GcmProtector::new(&ke.keys.data_key));
                                            data_nonce_gen = Some(ahp_crypto::NonceGenerator::new(ke.keys.data_iv));
                                            if header_protected {
                                                header_protector = Some(ahp_crypto::header_protection::HeaderProtector::new(&ke.keys.header_protection_key));
                                            }
                                            tracing::info!(epoch = new_epoch, "daemon key rotation");
                                        }
                                    }
                                }
                            }
                        } else {
                            tracing::warn!("dropping unauthenticated KEY_UPDATE");
                        }
                    }
                    PacketType::Hello => {
                        // A new sender is trying to connect while we're busy.
                        // Send HELLO_ACK immediately and queue for the main loop.
                        // The queued transfer is re-handled with an empty HELLO
                        // payload, i.e. plaintext — say so in the mode byte so an
                        // encrypting sender aborts instead of streaming data in a
                        // mode we will not expect.
                        let new_conn = decoded.header.connection_id;
                        let hello_from = match recv_from_addr {
                            a @ std::net::SocketAddr::V4(_) => a,
                            _ => peer_addr,
                        };
                        let n = encode_ctrl_packet_with_payload_into(
                            &mut ack_buf, PacketType::HelloAck, new_conn, 0, 1,
                        );
                        ack_buf[n] = HelloAckMode::Plaintext.to_byte();
                        send_raw(&ack_buf[..n + 1], cur_sock, hello_from);
                        pending_hello = Some((new_conn, recv_from_addr));
                        // In tail mode this transfer is already complete —
                        // exit promptly so the queued transfer takes the
                        // data port without waiting out the grace.
                        if tail_start.is_some() {
                            break 'recv;
                        }
                    }
                    _ => {}
                }
            }
        }

        } // end per-datagram loop over the received batch

        // Inline ACK timer — no tokio overhead.
        if last_ack.elapsed() >= ack_interval {
            for (si, stream) in streams.iter_mut().enumerate() {
                if stream.since_ack > 0 {
                    let (hc, bm) = build_stream_ack_bitmap(stream);
                    let n = encode_ack_bitmap_into(
                        &mut ack_buf, conn_id, seq,
                        si as u32, stream.chunk_base, hc, &bm,
                    );
                    ack_sink.send(&ack_buf[..n], sock_for(si), peer_addr);
                    seq += 1;
                    stream.since_ack = 0;
                }
            }
            last_ack = Instant::now();

            // Linux: drop mapping pages behind each stream's contiguous-
            // receive frontier. Runs on the same ~15 ms cadence as the ACK
            // timer; the granularity gate keeps it to one madvise per
            // 16 MiB per stream. The frontier is chunk-aligned and the
            // helper aligns inward to whole pages, so a partially received
            // tail page is never dropped.
            #[cfg(target_os = "linux")]
            for (si, stream) in streams.iter().enumerate() {
                let frontier = ((stream.chunk_base + stream.contig_prefix) as usize)
                    .saturating_mul(payload_size)
                    .min(mmap.len());
                if frontier >= pages_dropped_upto[si] + PAGE_DROP_GRANULARITY {
                    let from = pages_dropped_upto[si];
                    let span = frontier - from;
                    // Queue this window for writeback before dropping our
                    // page-table entries. Asynchronous: it costs a syscall
                    // and does not pace the transfer.
                    if let Some(fd) = dest_fd {
                        start_writeback(fd, from, span);
                    }
                    drop_mapping_pages(&mmap, from, span);
                    pages_dropped_upto[si] = frontier;

                    // If the not-yet-durable backlog is still growing past
                    // the bound, the disk is behind the link. Wait for the
                    // oldest window so the loop runs at disk speed rather
                    // than filling memory until the kernel stops it dead.
                    if let Some(fd) = dest_fd {
                        let dropped: usize = pages_dropped_upto.iter().sum();
                        if dropped.saturating_sub(writeback_waited_upto) > WRITEBACK_BACKLOG_LIMIT {
                            let wait_to = dropped - WRITEBACK_BACKLOG_LIMIT / 2;
                            await_writeback(
                                fd, writeback_waited_upto,
                                wait_to.saturating_sub(writeback_waited_upto),
                            );
                            writeback_waited_upto = wait_to;
                        }
                    }
                }
            }
        }
    }

    // Flush the ACK queue before returning: the completion burst and the
    // final all-acked ACKs are queued like any other, and the sender is
    // waiting on them. Dropping the sender closes the channel, which is
    // what ends the transmit thread.
    drop(ack_sink);
    if let Some(j) = ack_join {
        let _ = j.join();
    }

    if recv_debug {
        let secs = dbg_start.elapsed().as_secs_f64().max(1e-9);
        let polls = dbg_batches + dbg_empty_polls;
        tracing::info!(
            sockets = socks.len(),
            datagrams = dbg_datagrams,
            batches = dbg_batches,
            mean_batch = format!("{:.2}", dbg_datagrams as f64 / dbg_batches.max(1) as f64),
            batch_capacity = RECV_BATCH,
            full_batch_pct = format!(
                "{:.1}", 100.0 * dbg_full_batches as f64 / dbg_batches.max(1) as f64
            ),
            empty_poll_pct = format!(
                "{:.1}", 100.0 * dbg_empty_polls as f64 / polls.max(1) as f64
            ),
            per_socket = ?dbg_per_fd,
            dgram_per_s = format!("{:.0}", dbg_datagrams as f64 / secs),
            "RECV_SUMMARY"
        );
    }

    let n_received = streams.iter().map(|s| s.n_received).sum();
    Ok(ThreadedRecvResult { n_received, mmap, seq, pending_hello, finish_replied })
}


// ── Helpers ──────────────────────────────────────────────────────────────────


/// Attempt a 0-RTT resume from a HELLO ticket payload (`0x02` flag).
///
/// Returns the negotiated mode, the resumed session keys, and the fresh
/// server nonce to carry in HELLO_ACK (mixed into the key derivation on
/// both sides). Any failure — malformed payload, undecryptable or expired
/// ticket (the normal case after a daemon restart, since the ticket key is
/// per-instance), a replayed ticket (already present in `used_tickets`), or
/// key-derivation failure — falls back to `Plaintext`. The mode byte in
/// HELLO_ACK tells the client which happened, so it never derives resumed
/// keys the daemon does not have.
///
/// Replay protection is two-layered (S4): the fresh server nonce makes a
/// replayed (ticket, client_nonce) derive different session keys, and the
/// used-ticket cache rejects a ticket already presented to a previous
/// transfer. Legitimate HELLO retransmissions never reach this function
/// twice — they are answered by the duplicate-HELLO re-ACK path, which
/// re-sends the original HELLO_ACK (with the original server nonce)
/// verbatim, keeping the derived keys consistent.
fn resume_from_ticket(
    ticket_key: &ahp_crypto::session_ticket::TicketKey,
    used_tickets: &mut ahp_crypto::session_ticket::UsedTicketCache,
    hello_payload: &[u8],
) -> (HelloAckMode, Option<ahp_crypto::SessionKeys>, Option<[u8; 16]>) {
    let fallback = (HelloAckMode::Plaintext, None, None);
    if hello_payload.len() < 5 {
        return fallback;
    }
    let ticket_data_len = u32::from_be_bytes([
        hello_payload[1], hello_payload[2], hello_payload[3], hello_payload[4],
    ]) as usize;
    let ticket_end = 5 + ticket_data_len;
    if hello_payload.len() < ticket_end + 16 {
        return fallback;
    }
    let ticket_bytes = &hello_payload[5..ticket_end];
    let client_nonce = &hello_payload[ticket_end..ticket_end + 16];
    let Some(ticket) = ahp_crypto::session_ticket::decode_ticket(ticket_bytes) else {
        return fallback;
    };
    match ticket_key.decrypt(&ticket) {
        Ok(resume_secret) => {
            // Reject a ticket already used by a previous transfer: replaying
            // it would re-derive keys from the same resume_secret.
            if !used_tickets.check_and_record(&ticket) {
                tracing::warn!("replayed session ticket rejected, falling back to plaintext");
                return fallback;
            }
            // Fresh server nonce per transfer: even an identical (ticket,
            // client_nonce) pair yields fresh session keys.
            let server_nonce: [u8; 16] = rand::random();
            match ahp_crypto::session_ticket::derive_resumed_keys(&resume_secret, client_nonce, &server_nonce) {
                Ok(keys) => {
                    tracing::info!("encryption: 0-RTT session resumed from ticket");
                    (HelloAckMode::Resumed, Some(keys), Some(server_nonce))
                }
                Err(e) => {
                    tracing::warn!("resume key derivation failed ({e}), falling back to plaintext");
                    fallback
                }
            }
        }
        Err(e) => {
            tracing::warn!("ticket decryption failed ({e}), falling back to plaintext");
            fallback
        }
    }
}


/// Tell a sender "busy, come back" instead of dropping its HELLO.
///
/// A HELLO_ACK carrying no data port is the protocol's back-pressure
/// signal, and the sender has always understood it. Both decline paths in
/// the accept loop used to `continue` silently, on the reasoning that the
/// sender "retries every 2 s" — which it does, by waiting out its own
/// HELLO_ACK timeout. Measured on loopback with a 10-port pool: two of four
/// concurrent senders finished in 0.4 s and the other two in 2.3 s, and the
/// 2 s of that was a sender waiting for a reply that was never coming while
/// the sockets it wanted had already been handed back.
///
/// Failing to send it is not fatal — the sender still times out and retries,
/// which is exactly the old behaviour — so this logs and moves on.
async fn decline_busy(
    ctrl: &UdpSocket,
    to: SocketAddr,
    conn_id: u64,
) {
    let payload = encode_hello_ack_payload(
        HelloAckMode::Plaintext,
        None, // no data port == "busy, retry"
        None,
        None,
        ahp_proto::CAP_NONE,
    );
    if let Err(e) =
        send_ctrl_with_payload(ctrl, to, PacketType::HelloAck, conn_id, 0, &payload).await
    {
        tracing::debug!(conn_id, error = %e, "could not send busy HELLO_ACK");
    }
}

async fn send_ctrl_with_payload(
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

/// Maximum payload echoed back in a PathProbeAck. The stock sender's probes
/// carry a 4-byte probe index (see ahp-cli net_probe), so a small cap keeps
/// path probing working while stopping the daemon from reflecting arbitrarily
/// large attacker-chosen payloads to (possibly spoofed) sources — a UDP
/// reflection/amplification primitive.
const PROBE_ECHO_CAP: usize = 64;

/// Echo a PathProbe back as PathProbeAck, capping the reflected payload to
/// [`PROBE_ECHO_CAP`] bytes.
async fn echo_probe(
    socket: &UdpSocket,
    to: SocketAddr,
    probe: &Packet,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let payload = &probe.payload[..probe.payload.len().min(PROBE_ECHO_CAP)];
    let mut pkt = Packet {
        header: make_header(
            PacketType::PathProbeAck,
            probe.header.connection_id,
            probe.header.packet_number,
            payload.len() as u32,
        ),
        extensions: vec![],
        payload: Bytes::copy_from_slice(payload),
    };
    let buf = encode_packet_auto(&mut pkt);
    socket.send_to(&buf, to).await?;
    Ok(())
}

async fn send_ack_bitmap(
    socket: &UdpSocket,
    to: SocketAddr,
    conn_id: u64,
    seq: u64,
    stream_id: u32,
    base: u64,
    highest_contiguous: u64,
    bitmap: &[u8],
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let ack = AckBitmap {
        stream_id,
        base_packet_number: base,
        highest_contiguous,
        ack_delay_micros: 0,
        bitmap: Bytes::copy_from_slice(bitmap),
    };
    let mut ack_buf = BytesMut::new();
    ack.encode(&mut ack_buf);

    let mut pkt = Packet {
        header: make_header(PacketType::AckBitmap, conn_id, seq, ack_buf.len() as u32),
        extensions: vec![],
        payload: ack_buf.freeze(),
    };
    let buf = encode_packet_auto(&mut pkt);
    socket.send_to(&buf, to).await?;
    Ok(())
}

/// Decide whether an incoming KEY_UPDATE epoch should trigger a rotation.
///
/// Rotate only when `new_epoch` is exactly the next epoch; a KEY_UPDATE for
/// the current epoch is a duplicate retransmission (no-op) and anything
/// older is stale or forged and must be ignored, otherwise a single stray
/// packet would permanently desync the chained key schedule.
fn should_rotate(current_epoch: u64, new_epoch: u64) -> bool {
    new_epoch == current_epoch + 1
}

/// S3 control-plane authentication for FINISH / KEY_UPDATE on the data port.
///
/// Encrypted transfer (`key_epoch` is `Some`): the payload must AEAD-unseal
/// under the current epoch's control keys, falling back to the previous
/// epoch's keys for the post-rotation grace window (RFC §13.3) — anything
/// else is forged, stale, or cleartext and returns `None`, meaning drop the
/// packet without processing it. Plaintext transfer: the payload passes
/// through unauthenticated (cleartext control, as before).
fn authenticate_ctrl(
    key_epoch: Option<&ahp_crypto::key_update::KeyEpoch>,
    header_aad: &[u8],
    packet_number: u64,
    payload: &[u8],
) -> Option<Vec<u8>> {
    match key_epoch {
        Some(ke) => ahp_crypto::control::unseal_control(
            &ke.keys, ke.previous_keys(), packet_number, header_aad, payload,
        ),
        None => Some(payload.to_vec()),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        apply_resume_bitmap, authenticate_ctrl, build_merkle_resume, build_recv_streams,
        confine_dest_path, content_fingerprint, decode_resume_bitmap, encode_merkle_cache,
        finalize_transfer, hex, lexical_normalize, local_chunk_index, make_header,
        merkle_cache_path, read_merkle_cache, recv_manifest_packet, resume_from_ticket,
        should_rotate, validate_manifest, write_chunk,
        FileManifest, MerkleResumeResult, MAX_NUM_STREAMS, MAX_TOTAL_CHUNKS,
    };
    use ahp_crypto::session_ticket::{
        derive_resumed_keys, encode_ticket, TicketKey, UsedTicketCache, DEFAULT_TICKET_TTL,
    };
    use ahp_proto::{
        decode_data_inline, decode_hello_ack_payload, decode_packet,
        encode_ctrl_packet_into, encode_ctrl_packet_with_payload_into,
        encode_data_packet_into, encode_hello_ack_payload,
        encode_hello_ack_resumed, encode_packet_auto, HelloAckMode, Packet, PacketType,
        HEADER_SIZE,
    };
    use bytes::Bytes;

    #[test]
    fn key_update_epoch_guard() {
        // Next epoch: rotate.
        assert!(should_rotate(0, 1));
        assert!(should_rotate(7, 8));
        // Duplicate (retransmitted KEY_UPDATE): no-op.
        assert!(!should_rotate(1, 1));
        assert!(!should_rotate(0, 0));
        // Stale or forged: ignored.
        assert!(!should_rotate(3, 1));
        assert!(!should_rotate(3, 0));
        // Skipping an epoch is not allowed (chained key schedule).
        assert!(!should_rotate(0, 2));
    }

    // ── S1: destination confinement under --dest-root ────────────────────

    #[test]
    fn dest_root_accepts_in_root_paths() {
        let root = std::path::Path::new("/srv/incoming");
        assert_eq!(
            confine_dest_path(root, "file.bin").unwrap(),
            std::path::PathBuf::from("/srv/incoming/file.bin")
        );
        assert_eq!(
            confine_dest_path(root, "sub/dir/file.bin").unwrap(),
            std::path::PathBuf::from("/srv/incoming/sub/dir/file.bin")
        );
        // `.` and interior `..` that stay under the root are fine.
        assert_eq!(
            confine_dest_path(root, "a/../b/./file.bin").unwrap(),
            std::path::PathBuf::from("/srv/incoming/b/file.bin")
        );
        // Absolute path already under the root.
        assert_eq!(
            confine_dest_path(root, "/srv/incoming/file.bin").unwrap(),
            std::path::PathBuf::from("/srv/incoming/file.bin")
        );
    }

    #[test]
    fn dest_root_rejects_escapes() {
        let root = std::path::Path::new("/srv/incoming");
        // `..` climbs above the root.
        assert!(confine_dest_path(root, "../etc/passwd").is_err());
        assert!(confine_dest_path(root, "a/../../etc/passwd").is_err());
        // Absolute path outside the root (join discards the root).
        assert!(confine_dest_path(root, "/etc/passwd").is_err());
        assert!(confine_dest_path(root, "/srv/other/file.bin").is_err());
        // Root-relative but not root-equal prefix (/srv/incoming-evil).
        assert!(confine_dest_path(root, "/srv/incoming-evil/file.bin").is_err());
    }

    #[test]
    fn lexical_normalize_drops_excess_parent_dirs() {
        assert_eq!(
            lexical_normalize(std::path::Path::new("/a/b/../c/./d")),
            std::path::PathBuf::from("/a/c/d")
        );
        assert_eq!(
            lexical_normalize(std::path::Path::new("/a/../../b")),
            std::path::PathBuf::from("/b")
        );
    }

    // ── S5: Ed25519-authenticated full handshake ─────────────────────────

    #[test]
    fn identity_daemon_signs_verifiable_hello_ack() {
        use ahp_crypto::signatures::{SigningIdentity, VerifyingKeyRef};

        // Mirror the FullHandshake branch: the daemon signs with its DH
        // pubkey/nonce as "local", the client's as "remote".
        let identity = SigningIdentity::generate();
        let server_public = [0xD1; 32];
        let server_nonce = [0xD2; 16];
        let client_public = [0xC1; 32];
        let client_nonce = [0xC2; 16];

        let signature =
            identity.sign_handshake(&server_public, &client_public, &server_nonce, &client_nonce);
        let ack_payload = encode_hello_ack_payload(
            HelloAckMode::FullHandshake,
            Some(7801),
            Some((&server_public, &server_nonce)),
            Some((&identity.public_bytes(), &signature)),
            ahp_proto::CAP_NONE,
        );

        // Client side: decode, check the pin, verify the transcript signature.
        let ack = decode_hello_ack_payload(&ack_payload).unwrap();
        let (presented_pub, sig) = ack.auth_material.expect("identity daemon must present auth material");
        assert_eq!(presented_pub, identity.public_bytes());
        let (dh_pub, dh_nonce) = ack.dh_material.unwrap();
        let vk = VerifyingKeyRef::from_bytes(&presented_pub).unwrap();
        vk.verify_handshake(&dh_pub, &client_public, &dh_nonce, &client_nonce, &sig)
            .expect("wire signature must verify against the transcript");

        // A swapped DH pubkey (MitM substituted its own key) fails verification.
        let forged = [0xEE; 32];
        assert!(vk.verify_handshake(&forged, &client_public, &dh_nonce, &client_nonce, &sig).is_err());
    }

    /// Build a HELLO `0x02` payload: [flag] [4-byte ticket_len BE] [ticket] [16-byte nonce].
    fn resume_hello(ticket_bytes: &[u8], nonce: &[u8; 16]) -> Vec<u8> {
        let mut buf = Vec::with_capacity(1 + 4 + ticket_bytes.len() + 16);
        buf.push(0x02);
        buf.extend_from_slice(&(ticket_bytes.len() as u32).to_be_bytes());
        buf.extend_from_slice(ticket_bytes);
        buf.extend_from_slice(nonce);
        buf
    }

    #[test]
    fn ticket_len_is_big_endian_on_the_wire() {
        // Wire convention: multi-byte integers are network byte order,
        // matching every ahp-proto header field.
        let ticket = vec![0xAAu8; 0x0102];
        let hello = resume_hello(&ticket, &[0x07; 16]);
        assert_eq!(&hello[1..5], &[0x00, 0x00, 0x01, 0x02]);
    }

    #[test]
    fn resume_success_negotiates_resumed_mode() {
        let mut ticket_key = TicketKey::generate();
        let mut used = UsedTicketCache::new();
        let secret = [0x42; 32];
        let ticket = ticket_key.issue(&secret, DEFAULT_TICKET_TTL).unwrap();
        let nonce = [0x07; 16];
        let hello = resume_hello(&encode_ticket(&ticket), &nonce);

        let (mode, keys, server_nonce) = resume_from_ticket(&ticket_key, &mut used, &hello);
        assert_eq!(mode, HelloAckMode::Resumed);
        let keys = keys.expect("valid ticket must yield session keys");
        let server_nonce = server_nonce.expect("resumed ack must carry a server nonce");
        // Both sides derive from (resume_secret, client_nonce, server_nonce).
        let expected = derive_resumed_keys(&secret, &nonce, &server_nonce).unwrap();
        assert_eq!(keys.data_key, expected.data_key);

        // Mode + server nonce survive the HELLO_ACK wire round-trip.
        let ack = encode_hello_ack_resumed(Some(7801), &server_nonce, ahp_proto::CAP_NONE);
        let decoded = decode_hello_ack_payload(&ack).unwrap();
        assert_eq!(decoded.mode, HelloAckMode::Resumed);
        assert_eq!(decoded.resume_server_nonce, Some(server_nonce));
    }

    #[test]
    fn replayed_ticket_is_rejected() {
        // S4: a second transfer presenting the same ticket (attacker replay)
        // is rejected via the used-ticket cache and falls back to plaintext.
        let mut ticket_key = TicketKey::generate();
        let mut used = UsedTicketCache::new();
        let ticket = ticket_key.issue(&[0x42; 32], DEFAULT_TICKET_TTL).unwrap();
        let hello = resume_hello(&encode_ticket(&ticket), &[0x07; 16]);

        let (mode, keys, _) = resume_from_ticket(&ticket_key, &mut used, &hello);
        assert_eq!(mode, HelloAckMode::Resumed);
        assert!(keys.is_some());

        // Identical replay (same ticket + same client nonce): rejected.
        let (mode, keys, nonce) = resume_from_ticket(&ticket_key, &mut used, &hello);
        assert_eq!(mode, HelloAckMode::Plaintext);
        assert!(keys.is_none());
        assert!(nonce.is_none());

        // Replay with a different client nonce: still the same ticket — rejected.
        let hello2 = resume_hello(&encode_ticket(&ticket), &[0x99; 16]);
        let (mode, keys, _) = resume_from_ticket(&ticket_key, &mut used, &hello2);
        assert_eq!(mode, HelloAckMode::Plaintext);
        assert!(keys.is_none());
    }

    #[test]
    fn re_ack_reuses_original_server_nonce() {
        // The duplicate-HELLO re-ACK path re-sends the original ack payload
        // verbatim; since the server nonce rides inside it, a retransmitted
        // HELLO keeps the client on the originally derived keys.
        let server_nonce = [0xAB; 16];
        let ack1 = encode_hello_ack_resumed(Some(7801), &server_nonce, ahp_proto::CAP_NONE);
        let ack2 = ack1.clone(); // verbatim re-send
        let decoded = decode_hello_ack_payload(&ack2).unwrap();
        assert_eq!(decoded.resume_server_nonce, Some(server_nonce));
        assert_eq!(decoded.data_port, Some(7801));
    }

    #[test]
    fn daemon_restart_falls_back_to_plaintext() {
        // Ticket issued under the previous instance's key; the restarted
        // daemon (fresh TicketKey) cannot decrypt it.
        let mut old_key = TicketKey::generate();
        let ticket = old_key.issue(&[0x42; 32], DEFAULT_TICKET_TTL).unwrap();
        let hello = resume_hello(&encode_ticket(&ticket), &[0x07; 16]);

        let restarted_key = TicketKey::generate();
        let mut used = UsedTicketCache::new();
        let (mode, keys, _) = resume_from_ticket(&restarted_key, &mut used, &hello);
        assert_eq!(mode, HelloAckMode::Plaintext);
        assert!(keys.is_none());

        // The fallback ack must differ from the resume-success ack on the wire.
        let fallback = encode_hello_ack_payload(mode, Some(7801), None, None, ahp_proto::CAP_NONE);
        let success = encode_hello_ack_resumed(Some(7801), &[0x5A; 16], ahp_proto::CAP_NONE);
        assert_ne!(fallback, success);
        assert_eq!(decode_hello_ack_payload(&fallback).unwrap().mode, HelloAckMode::Plaintext);
    }

    #[test]
    fn malformed_resume_hellos_fall_back_to_plaintext() {
        let ticket_key = TicketKey::generate();
        let mut used = UsedTicketCache::new();
        // Truncated header, truncated ticket, garbage ticket bytes.
        for hello in [
            vec![0x02, 0x00, 0x00],
            resume_hello(&[0xDE, 0xAD, 0xBE, 0xEF], &[0x07; 16]),
            {
                let mut h = resume_hello(&[0xAA; 64], &[0x07; 16]);
                h.truncate(20); // declared ticket_len exceeds the payload
                h
            },
        ] {
            let (mode, keys, _) = resume_from_ticket(&ticket_key, &mut used, &hello);
            assert_eq!(mode, HelloAckMode::Plaintext);
            assert!(keys.is_none());
        }
    }

    // ── P1: crafted chunk indices ────────────────────────────────────────

    /// Build a wire-format DATA packet (42-byte header + DataPayload).
    fn data_packet(stream_id: u32, chunk_index: u64, data: &[u8]) -> Vec<u8> {
        let mut buf = vec![0u8; HEADER_SIZE + 22 + data.len()];
        buf[1] = 0x20; // DATA packet type
        buf[14..18].copy_from_slice(&stream_id.to_be_bytes());
        let dp = HEADER_SIZE;
        buf[dp..dp + 8].copy_from_slice(&1u64.to_be_bytes()); // file_id
        buf[dp + 8..dp + 16].copy_from_slice(&chunk_index.to_be_bytes());
        // chunk_offset = 0
        buf[dp + 20..dp + 22].copy_from_slice(&(data.len() as u16).to_be_bytes());
        buf[dp + 22..].copy_from_slice(data);
        buf
    }

    #[test]
    fn out_of_range_chunk_index_is_skipped_without_side_effects() {
        // Two streams: stream 0 owns chunks 0..5, stream 1 owns 5..10.
        let mut streams = build_recv_streams(10, 2);
        assert_eq!(streams[1].chunk_base, 5);
        assert_eq!(streams[1].chunk_count, 5);

        // ci < chunk_base (would underflow a plain subtraction), ci at/above
        // chunk_base + chunk_count, and the extreme wire value.
        for ci in [0u64, 4, 10, 11, u64::MAX] {
            let pkt = data_packet(1, ci, b"payload");
            let dp = decode_data_inline(&pkt).expect("test packet must decode");
            assert_eq!(dp.chunk_index, ci);

            // Mirror the fast-path guard in threaded_bitmap_recv.
            let s = &mut streams[1];
            if let Some(local_ci) = local_chunk_index(s, dp.chunk_index) {
                s.received[local_ci as usize] = true;
                s.n_received += 1;
            }

            // No panic, no state mutation.
            assert_eq!(s.n_received, 0);
            assert_eq!(s.expected_next_local, 0);
            assert_eq!(s.since_ack, 0);
            assert_eq!(s.gap_counter, 0);
            assert!(s.gap_start_local.is_none());
            assert!(s.received.iter().all(|&r| !r));
        }

        // In-range indices still map correctly.
        assert_eq!(local_chunk_index(&streams[1], 5), Some(0));
        assert_eq!(local_chunk_index(&streams[1], 9), Some(4));
        assert_eq!(local_chunk_index(&streams[0], 4), Some(4));
    }

    #[test]
    fn write_chunk_clamps_to_mapped_region() {
        let mut mmap = vec![0u8; 16];
        // Fully out of bounds: no panic, no write.
        write_chunk(&mut mmap, 20, &[1, 2, 3]);
        assert!(mmap.iter().all(|&b| b == 0));
        // Partially overlapping: clamped instead of copy_from_slice panic.
        write_chunk(&mut mmap, 12, &[1, 2, 3, 4, 5, 6]);
        assert_eq!(&mmap[12..], &[1, 2, 3, 4]);
        // Normal in-bounds write.
        write_chunk(&mut mmap, 0, &[9, 9]);
        assert_eq!(&mmap[..2], &[9, 9]);
    }

    // ── P3 / resource caps: manifest validation ─────────────────────────

    fn manifest(file_size: u64, payload_size: usize, total_chunks: u64) -> FileManifest {
        FileManifest {
            file_name: "f".into(),
            file_size,
            dest_path: "/tmp/f".into(),
            payload_size,
            total_chunks,
            ack_mode: ahp_proto::data::AckMode::Bitmap,
            num_streams: 1,
            compressed: false,
            header_protected: false,
            resume_mode: "none".into(),
            file_hash: None,
            merkle_root: None,
            features: Vec::new(),
        }
    }

    #[test]
    fn manifest_geometry_is_cross_validated() {
        // Valid geometries accepted.
        assert!(validate_manifest(&manifest(0, 1350, 0), None).is_ok());
        assert!(validate_manifest(&manifest(1000, 100, 10), None).is_ok());
        assert!(validate_manifest(&manifest(1001, 100, 11), None).is_ok()); // ceil rounds up
        // payload_size == 0 rejected (would divide-by-zero / infinite chunks).
        assert!(validate_manifest(&manifest(1000, 0, 0), None).is_err());
        // payload_size beyond the wire MTU rejected.
        assert!(validate_manifest(&manifest(1000, 1501, 1), None).is_err());
        // total_chunks inconsistent with file_size / payload_size.
        assert!(validate_manifest(&manifest(1000, 100, 11), None).is_err());
        assert!(validate_manifest(&manifest(1000, 100, 9), None).is_err());
        assert!(validate_manifest(&manifest(1000, 100, 0), None).is_err());
    }

    #[test]
    fn manifest_resource_caps_enforced() {
        // num_streams above the cap rejected; at the cap accepted.
        let mut m = manifest(1000, 100, 10);
        m.num_streams = MAX_NUM_STREAMS + 1;
        assert!(validate_manifest(&m, None).is_err());
        m.num_streams = MAX_NUM_STREAMS;
        assert!(validate_manifest(&m, None).is_ok());

        // total_chunks above the cap rejected even with consistent geometry
        // (the received-bitmap allocation would be unbounded otherwise).
        let tc = MAX_TOTAL_CHUNKS + 1;
        let m = manifest(tc * 1500, 1500, tc);
        assert!(validate_manifest(&m, None).is_err());

        // max_file_size enforced when configured; unchanged when not.
        assert!(validate_manifest(&manifest(2000, 100, 20), Some(1000)).is_err());
        assert!(validate_manifest(&manifest(1000, 100, 10), Some(1000)).is_ok());
        assert!(validate_manifest(&manifest(u64::MAX / 2, 1500, 1), None).is_err());
    }

    // ── B7: finalization failure semantics ──────────────────────────────

    fn b7_dest(tag: &str) -> (std::path::PathBuf, FileManifest) {
        let dir = std::env::temp_dir().join(format!("ahp_daemon_b7_{tag}_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut m = manifest(16, 4, 4);
        m.dest_path = dir.join("file.bin").to_string_lossy().into_owned();
        (dir, m)
    }

    #[test]
    fn finalize_hash_mismatch_fails_and_invalidates_cache() {
        let (dir, mut m) = b7_dest("hash");
        let data = [0xAAu8; 16];
        m.resume_mode = "merkle".into();
        // Hash of DIFFERENT contents than what is on disk.
        m.file_hash = Some(blake3::hash(b"other contents").to_hex().to_string());

        // Pre-existing cache entry for this destination — now suspect.
        let cache_path = merkle_cache_path(&m.dest_path);
        std::fs::create_dir_all(cache_path.parent().unwrap()).unwrap();
        std::fs::write(&cache_path, b"stale tree").unwrap();

        let err = finalize_transfer(&m, &data, 4).expect_err("hash mismatch must fail the transfer");
        assert!(err.contains("BLAKE3"), "unexpected error: {err}");
        assert!(!cache_path.exists(), "stale cache entry must be invalidated");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn finalize_incomplete_transfer_fails_without_cache() {
        let (dir, mut m) = b7_dest("incomplete");
        let data = [0xBBu8; 16];
        m.resume_mode = "merkle".into();
        // Hash matches the data — completeness alone must gate success.
        m.file_hash = Some(blake3::hash(&data).to_hex().to_string());

        let err = finalize_transfer(&m, &data, 3).expect_err("incomplete transfer must fail");
        assert!(err.contains("incomplete"), "unexpected error: {err}");
        assert!(
            !merkle_cache_path(&m.dest_path).exists(),
            "no cache may be written for an incomplete transfer"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn finalize_success_writes_merkle_cache() {
        let (dir, mut m) = b7_dest("ok");
        let data = [0xCCu8; 16];
        m.resume_mode = "merkle".into();
        m.file_hash = Some(blake3::hash(&data).to_hex().to_string());
        std::fs::write(&m.dest_path, data).unwrap();

        finalize_transfer(&m, &data, 4).expect("verified complete transfer must succeed");

        // B12: the cache is an envelope now; the validated reader must
        // recover the same tree for the unchanged file.
        let cache_path = merkle_cache_path(&m.dest_path);
        let tree = read_merkle_cache(&cache_path, std::path::Path::new(&m.dest_path))
            .expect("cache must validate for the unchanged file");
        assert_eq!(tree.root(), ahp_sync::merkle::build_file_merkle(&data, 4).root());

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn finalize_empty_file_succeeds() {
        // Zero-length transfer: total_chunks == 0 so n_received == 0 is
        // complete, and the BLAKE3 of empty content must verify.
        let (dir, mut m) = b7_dest("empty");
        m.file_size = 0;
        m.total_chunks = 0;
        m.file_hash = Some(blake3::hash(b"").to_hex().to_string());
        std::fs::write(&m.dest_path, b"").unwrap();

        finalize_transfer(&m, &[], 0).expect("empty transfer must finalize");

        std::fs::remove_dir_all(&dir).ok();
    }

    // ── B12: Merkle cache trust (same-name replacement) ─────────────────

    fn b12_dest(tag: &str) -> (std::path::PathBuf, FileManifest) {
        let dir = std::env::temp_dir().join(format!("ahp_daemon_b12_{tag}_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut m = manifest(16, 4, 4);
        m.dest_path = dir.join("file.bin").to_string_lossy().into_owned();
        m.resume_mode = "merkle".into();
        (dir, m)
    }

    fn merkle_root_hex(data: &[u8], payload_size: usize) -> String {
        hex::encode(ahp_sync::merkle::build_file_merkle(data, payload_size).root())
    }

    /// Content B: same size as A but different, with some all-zero chunks so
    /// the first-time fallback bitmap is distinguishable from all-ones.
    const B12_A: [u8; 16] = [0xAA; 16];
    const B12_B: [u8; 16] = [1, 1, 1, 1, 0, 0, 0, 0, 2, 2, 2, 2, 0, 0, 0, 0];
    /// Zero-check fallback for B12_B: chunks 0 and 2 present → 0b00000101.
    const B12_B_FALLBACK: [u8; 1] = [0x05];

    fn expect_bitmap(result: Option<MerkleResumeResult>) -> Vec<u8> {
        match result {
            Some(MerkleResumeResult::Bitmap(bm)) => bm,
            _ => panic!("expected a bitmap resume result"),
        }
    }

    #[test]
    fn merkle_cache_hit_for_unchanged_file() {
        let (dir, mut m) = b12_dest("hit");
        std::fs::write(&m.dest_path, B12_A).unwrap();
        m.merkle_root = Some(merkle_root_hex(&B12_A, 4));

        finalize_transfer(&m, &B12_A, 4).unwrap();
        let bm = expect_bitmap(build_merkle_resume(&m));
        assert_eq!(bm, vec![0x0F], "unchanged file must hit the all-ones fast path");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn same_name_different_content_is_a_cache_miss() {
        let (dir, mut m) = b12_dest("replace");
        // Cache built for A; the sender still holds A (root of A).
        std::fs::write(&m.dest_path, B12_A).unwrap();
        m.merkle_root = Some(merkle_root_hex(&B12_A, 4));
        finalize_transfer(&m, &B12_A, 4).unwrap();

        // User replaces the destination with unrelated content of the same size.
        std::fs::write(&m.dest_path, B12_B).unwrap();

        // The stale cache must NOT bless B as "all chunks present": the
        // resume falls back to per-chunk detection instead of all-ones.
        let bm = expect_bitmap(build_merkle_resume(&m));
        assert_eq!(bm, B12_B_FALLBACK, "stale cache must miss and trigger a fresh diff");

        // The miss re-cached the tree for B: resuming against B's root now
        // hits the fast path...
        m.merkle_root = Some(merkle_root_hex(&B12_B, 4));
        let bm = expect_bitmap(build_merkle_resume(&m));
        assert_eq!(bm, vec![0x0F], "re-cached tree must hit for the current file");

        // ...and a sender holding different content gets a real Merkle diff
        // computed from the validated cache, not skipped chunks.
        m.merkle_root = Some(merkle_root_hex(&B12_A, 4));
        match build_merkle_resume(&m) {
            Some(MerkleResumeResult::MerkleDiff(_)) => {}
            other => panic!("expected a merkle diff for differing roots, got bitmap: {:?}",
                matches!(other, Some(MerkleResumeResult::Bitmap(_)))),
        }

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn preserved_mtime_still_misses_via_fingerprint() {
        let (dir, mut m) = b12_dest("mtime");
        // Destination holds B; craft a cache entry that claims A but is
        // stamped with B's CURRENT mtime (simulating an mtime-preserving
        // replacement, e.g. `cp -p` or rsync -t).
        std::fs::write(&m.dest_path, B12_B).unwrap();
        m.merkle_root = Some(merkle_root_hex(&B12_A, 4));
        let mtime = std::fs::metadata(&m.dest_path).unwrap().modified().ok();
        let tree_a = ahp_sync::merkle::build_file_merkle(&B12_A, 4);
        let blob = encode_merkle_cache(&tree_a, 16, mtime, &content_fingerprint(&B12_A));
        let cache_path = merkle_cache_path(&m.dest_path);
        std::fs::create_dir_all(cache_path.parent().unwrap()).unwrap();
        std::fs::write(&cache_path, blob).unwrap();

        // Size and mtime both match; the head/tail fingerprint must still
        // force a miss.
        let bm = expect_bitmap(build_merkle_resume(&m));
        assert_eq!(bm, B12_B_FALLBACK, "mtime match must not rescue a stale cache");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn old_format_and_malformed_cache_are_clean_misses() {
        let (dir, mut m) = b12_dest("garbage");
        std::fs::write(&m.dest_path, B12_B).unwrap();
        m.merkle_root = Some(merkle_root_hex(&B12_A, 4));
        let cache_path = merkle_cache_path(&m.dest_path);
        std::fs::create_dir_all(cache_path.parent().unwrap()).unwrap();

        // Pre-B12 format: bare tree bytes (still a valid tree on its own).
        let tree_b = ahp_sync::merkle::build_file_merkle(&B12_B, 4);
        let bare = tree_b.to_bytes();
        assert!(ahp_sync::merkle::MerkleTree::from_bytes(&bare).is_some());
        // Garbage, a truncated envelope, and a valid envelope with a
        // truncated tree must all miss without panicking.
        let mut truncated_envelope = encode_merkle_cache(&tree_b, 16, None, &content_fingerprint(&B12_B));
        truncated_envelope.truncate(20);
        let mut truncated_tree = encode_merkle_cache(&tree_b, 16, None, &content_fingerprint(&B12_B));
        truncated_tree.truncate(64);

        for blob in [bare, b"junk".to_vec(), truncated_envelope, truncated_tree] {
            std::fs::write(&cache_path, blob).unwrap();
            let bm = expect_bitmap(build_merkle_resume(&m));
            assert_eq!(bm, B12_B_FALLBACK, "malformed cache must be a clean miss");
        }

        std::fs::remove_dir_all(&dir).ok();
    }

    // ── Merkle-diff resume: sender-reported skip bitmap ────────────────

    #[test]
    fn apply_resume_bitmap_marks_exactly_the_set_bits() {
        // 10 chunks over 2 streams (0..5, 5..10); skip chunks 0, 3, 9.
        let mut streams = build_recv_streams(10, 2);
        let bitmap = [0x09u8, 0x02u8]; // LSB-first: bits 0, 3 and bit 1 of byte 1
        let skipped = apply_resume_bitmap(&mut streams, &bitmap);
        assert_eq!(skipped, 3);
        assert_eq!(streams[0].n_received, 2);
        assert_eq!(streams[1].n_received, 1);
        assert!(streams[0].received[0] && streams[0].received[3]);
        assert!(streams[1].received[4]); // global 9 = local 4
        assert!(!streams[0].received[1] && !streams[1].received[0]);
    }

    #[test]
    fn decode_resume_bitmap_validates_dimensions() {
        // 10 chunks → exactly 2 bytes required, zstd-compressed or raw.
        let good = [0xFFu8, 0x03];
        let compressed = zstd::encode_all(&good[..], 1).unwrap();
        assert_eq!(decode_resume_bitmap(&compressed, 10).unwrap(), good);
        assert_eq!(decode_resume_bitmap(&good, 10).unwrap(), good);
        // Oversized, undersized, and empty payloads are all rejected.
        assert!(decode_resume_bitmap(&[0xFFu8; 3], 10).is_err());
        assert!(decode_resume_bitmap(&[0xFFu8; 1], 10).is_err());
        assert!(decode_resume_bitmap(&[], 10).is_err());
        // Byte boundary: 9 chunks need 2 bytes, 8 chunks exactly 1.
        assert!(decode_resume_bitmap(&[0xFFu8], 9).is_err());
        assert!(decode_resume_bitmap(&[0xFFu8], 8).is_ok());
    }

    #[test]
    fn resume_with_sender_bitmap_completes_after_diff_chunks() {
        let (dir, mut m) = b7_dest("resume_bitmap");
        let data = [0xDDu8; 16];
        m.resume_mode = "merkle".into();
        m.file_hash = Some(blake3::hash(&data).to_hex().to_string());
        std::fs::write(&m.dest_path, data).unwrap();

        // Sender reported chunks 0 and 2 as matching (skipped) → pre-populate.
        let bm = decode_resume_bitmap(&zstd::encode_all(&[0x05u8][..], 1).unwrap(), m.total_chunks)
            .expect("well-formed sender bitmap must decode");
        let mut streams = build_recv_streams(m.total_chunks, 1);
        assert_eq!(apply_resume_bitmap(&mut streams, &bm), 2);

        // Only the diff chunks (1 and 3) arrive during the data phase.
        for local_ci in [1usize, 3] {
            streams[0].received[local_ci] = true;
            streams[0].n_received += 1;
        }
        let n_received: u64 = streams.iter().map(|s| s.n_received).sum();
        assert_eq!(n_received, m.total_chunks);
        finalize_transfer(&m, &data, n_received)
            .expect("resume with an honest sender bitmap must succeed");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn dishonest_sender_bitmap_still_fails_hash_check() {
        let (dir, mut m) = b7_dest("resume_lie");
        // The destination actually holds different content than the sender's
        // file, but the sender claims every chunk matches (skip all).
        let data = [0xEEu8; 16];
        m.resume_mode = "merkle".into();
        m.file_hash = Some(blake3::hash(b"sender's real content").to_hex().to_string());
        std::fs::write(&m.dest_path, data).unwrap();

        let mut streams = build_recv_streams(m.total_chunks, 1);
        assert_eq!(apply_resume_bitmap(&mut streams, &[0x0F]), m.total_chunks);
        let n_received: u64 = streams.iter().map(|s| s.n_received).sum();

        // The accounting "completes", but the whole-file BLAKE3 backstop
        // must still fail the transfer — a wrong skip bitmap is never blessed.
        let err = finalize_transfer(&m, &data, n_received)
            .expect_err("lied-about skips must fail the hash check");
        assert!(err.contains("BLAKE3"), "unexpected error: {err}");

        std::fs::remove_dir_all(&dir).ok();
    }

    // ── S3: control-plane authentication (FINISH / KEY_UPDATE) ──────────

    /// Fixed test keys so "sender" and "receiver" epochs share key material.
    fn test_key_epoch() -> ahp_crypto::key_update::KeyEpoch {
        let mut keys = ahp_crypto::SessionKeys::zeroed();
        keys.control_key = [0x42; 32];
        keys.control_iv = [0x11; 12];
        ahp_crypto::key_update::KeyEpoch::new(keys)
    }

    /// Mirror of the sender's `encode_sealed_ctrl_packet`: header with
    /// `payload_length` covering ciphertext + tag, then the sealed payload.
    fn sealed_ctrl_wire(
        ptype: PacketType,
        keys: &ahp_crypto::SessionKeys,
        conn_id: u64,
        seq: u64,
        plaintext: &[u8],
    ) -> Vec<u8> {
        let sealed_len = plaintext.len() + 16;
        let mut buf = vec![0u8; HEADER_SIZE + sealed_len];
        let n = encode_ctrl_packet_with_payload_into(&mut buf, ptype, conn_id, seq, sealed_len as u32);
        let sealed = ahp_crypto::control::seal_control(keys, seq, &buf[..n], plaintext).unwrap();
        buf[n..].copy_from_slice(&sealed);
        buf
    }

    #[test]
    fn sealed_finish_authenticates() {
        let ke = test_key_epoch();
        let wire = sealed_ctrl_wire(PacketType::Finish, &ke.keys, 0xAB, 9, &[]);
        let pkt = decode_packet(&wire).unwrap();
        let opened = authenticate_ctrl(
            Some(&ke), &wire[..HEADER_SIZE], pkt.header.packet_number, &pkt.payload,
        )
        .expect("authentic sealed FINISH must be accepted");
        assert!(opened.is_empty());
    }

    #[test]
    fn forged_or_cleartext_finish_is_dropped() {
        let ke = test_key_epoch();
        let wire = sealed_ctrl_wire(PacketType::Finish, &ke.keys, 0xAB, 9, &[]);

        // Bad tag.
        let mut forged = wire.clone();
        let last = forged.len() - 1;
        forged[last] ^= 0xFF;
        let pkt = decode_packet(&forged).unwrap();
        assert!(authenticate_ctrl(
            Some(&ke), &forged[..HEADER_SIZE], pkt.header.packet_number, &pkt.payload,
        ).is_none());

        // Cleartext FINISH (empty payload) in an encrypted transfer.
        assert!(authenticate_ctrl(Some(&ke), &wire[..HEADER_SIZE], 9, &[]).is_none());

        // Wrong epoch's keys (sealed under next epoch, presented at epoch 0).
        let mut other = test_key_epoch();
        other.rotate().unwrap();
        let wrong = sealed_ctrl_wire(PacketType::Finish, &other.keys, 0xAB, 9, &[]);
        let pkt = decode_packet(&wrong).unwrap();
        assert!(authenticate_ctrl(
            Some(&ke), &wrong[..HEADER_SIZE], pkt.header.packet_number, &pkt.payload,
        ).is_none());
    }

    #[test]
    fn plaintext_transfer_passes_cleartext_control() {
        // No key epoch: FINISH/KEY_UPDATE stay cleartext (no regression).
        assert_eq!(authenticate_ctrl(None, &[], 3, &[]), Some(vec![]));
        assert_eq!(authenticate_ctrl(None, &[], 3, &[1, 0, 0, 0, 0, 0, 0, 0]), Some(vec![1, 0, 0, 0, 0, 0, 0, 0]));
    }

    #[test]
    fn control_grace_window_across_rotation() {
        let mut ke = test_key_epoch();
        // Control packet sealed under epoch 0.
        let wire_e0 = sealed_ctrl_wire(PacketType::Finish, &ke.keys, 1, 5, &[]);

        // After rotation to epoch 1 it still authenticates (grace window).
        ke.rotate().unwrap();
        assert!(authenticate_ctrl(Some(&ke), &wire_e0[..HEADER_SIZE], 5, &wire_e0[HEADER_SIZE..]).is_some());

        // After rotation to epoch 2 the epoch-0 packet falls out of the
        // one-epoch window and must be rejected.
        ke.rotate().unwrap();
        assert!(authenticate_ctrl(Some(&ke), &wire_e0[..HEADER_SIZE], 5, &wire_e0[HEADER_SIZE..]).is_none());
    }

    #[test]
    fn key_update_sealed_retransmission_flow() {
        use ahp_crypto::key_update::{decode_key_update, encode_key_update};

        let mut sender = test_key_epoch();
        let mut receiver = test_key_epoch();

        // Sender rotates, then seals KEY_UPDATE(1) with the OUTGOING keys.
        sender.rotate().unwrap();
        let wire = sealed_ctrl_wire(
            PacketType::KeyUpdate, sender.previous_keys().unwrap(), 1, 9, &encode_key_update(1),
        );

        // First delivery: authenticates under the receiver's current keys and
        // the epoch guard triggers rotation.
        let payload = authenticate_ctrl(Some(&receiver), &wire[..HEADER_SIZE], 9, &wire[HEADER_SIZE..])
            .expect("authentic KEY_UPDATE must unseal");
        let new_epoch = decode_key_update(&payload).unwrap();
        assert!(should_rotate(receiver.epoch, new_epoch));
        receiver.rotate().unwrap();
        assert_eq!(receiver.epoch, 1);

        // Retransmitted KEY_UPDATE after rotation: still authenticates via
        // the grace window, but the epoch guard makes it a no-op.
        let payload = authenticate_ctrl(Some(&receiver), &wire[..HEADER_SIZE], 9, &wire[HEADER_SIZE..])
            .expect("retransmitted KEY_UPDATE must still authenticate");
        let dup = decode_key_update(&payload).unwrap();
        assert!(!should_rotate(receiver.epoch, dup));

        // A replayed/stale update sealed two epochs back is rejected
        // outright once the window has moved past it.
        receiver.rotate().unwrap();
        assert!(authenticate_ctrl(Some(&receiver), &wire[..HEADER_SIZE], 9, &wire[HEADER_SIZE..]).is_none());
    }

    // ── P10: malformed datagrams while awaiting MANIFEST ────────────────

    #[tokio::test]
    async fn malformed_datagram_does_not_abort_manifest_wait() {
        let ctrl = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let sender = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let ctrl_addr = ctrl.local_addr().unwrap();
        let sender_addr = sender.local_addr().unwrap();

        // Garbage datagram that fails to decode.
        sender.send_to(&[0xFF, 0x00, 0x01], ctrl_addr).await.unwrap();
        // A decodable but irrelevant packet — also must not abort.
        let mut probe = Packet {
            header: make_header(PacketType::PathProbe, 99, 0, 0),
            extensions: vec![],
            payload: Bytes::new(),
        };
        let probe_buf = encode_packet_auto(&mut probe);
        sender.send_to(&probe_buf, ctrl_addr).await.unwrap();

        // Then the real MANIFEST.
        let manifest_json = br#"{"file_name":"f","file_size":10,"dest_path":"/tmp/f","payload_size":10,"total_chunks":1}"#;
        let mut mpkt = Packet {
            header: make_header(PacketType::Manifest, 42, 7, manifest_json.len() as u32),
            extensions: vec![],
            payload: Bytes::from_static(manifest_json),
        };
        let mbuf = encode_packet_auto(&mut mpkt);
        sender.send_to(&mbuf, ctrl_addr).await.unwrap();

        // The router owns the socket now, so drive the function the way the
        // daemon does: pump datagrams off the control socket into this
        // transfer's channel. The property under test is unchanged —
        // malformed and irrelevant datagrams must not abort the wait.
        let (tx, mut rx) =
            tokio::sync::mpsc::channel::<(Vec<u8>, std::net::SocketAddr)>(16);
        let ctrl = std::sync::Arc::new(ctrl);
        let pump_ctrl = ctrl.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 2048];
            while let Ok((len, from)) = pump_ctrl.recv_from(&mut buf).await {
                if tx.send((buf[..len].to_vec(), from)).await.is_err() {
                    break;
                }
            }
        });
        let pkt = recv_manifest_packet(&ctrl, &mut rx, sender_addr, 42, 1, &[0])
            .await
            .expect("malformed datagrams must not abort the MANIFEST wait");
        assert_eq!(pkt.header.packet_type, PacketType::Manifest);
        assert_eq!(pkt.payload.as_ref(), manifest_json);
    }

    // ── Incremental contiguous-prefix tracking ───────────────────────────

    /// Reference implementation of the old O(chunk_count) prefix scan +
    /// bitmap build (with the current cap), to validate the incremental
    /// `contig_prefix` against.
    fn ref_stream_ack_bitmap(s: &super::StreamRecvState) -> (u64, Vec<u8>) {
        let mut hc_local: i64 = -1;
        for (i, &r) in s.received.iter().enumerate() {
            if r {
                hc_local = i as i64;
            } else {
                break;
            }
        }
        let hc_pn = if hc_local >= 0 {
            s.chunk_base + hc_local as u64
        } else {
            s.chunk_base.wrapping_sub(1)
        };
        let start = (hc_local + 1) as usize;
        let remaining = if start < s.received.len() {
            &s.received[start..]
        } else {
            &[]
        };
        let len = remaining.len().div_ceil(8).min(super::MAX_ACK_BITMAP_BYTES);
        let mut bm = vec![0u8; len];
        for (i, &r) in remaining.iter().enumerate() {
            if i >= super::MAX_ACK_BITMAP_BYTES * 8 {
                break;
            }
            if r {
                bm[i / 8] |= 1 << (i % 8);
            }
        }
        (hc_pn, bm)
    }

    #[test]
    fn contig_prefix_matches_reference_scan_on_random_marks() {
        // xorshift64 — deterministic, no rand dependency in this crate.
        let mut x = 0x9E37_79B9_7F4A_7C15u64;
        let mut next = || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };

        for case in 0..20 {
            let count = 1 + (next() % 3000) as usize;
            let base = (next() % 3) * 5000; // exercise a non-zero chunk_base
            let mut s = super::StreamRecvState::new(base, count as u64);
            // Mark every chunk once, in random order.
            let mut order: Vec<usize> = (0..count).collect();
            for i in (1..count).rev() {
                let j = (next() as usize) % (i + 1);
                order.swap(i, j);
            }
            for (step, &ci) in order.iter().enumerate() {
                s.mark_received(ci);
                if step % 251 == 0 || step == count - 1 {
                    assert_eq!(
                        super::build_stream_ack_bitmap(&s),
                        ref_stream_ack_bitmap(&s),
                        "case {case}, step {step}/{count}"
                    );
                }
            }
            // Fully received: prefix spans the whole stream.
            assert_eq!(s.contig_prefix, count as u64);
            let (hc, bm) = super::build_stream_ack_bitmap(&s);
            assert_eq!(hc, base + count as u64 - 1);
            assert!(bm.is_empty());
        }
    }

    #[test]
    fn ack_bitmap_reports_reordering_beyond_old_256_bit_cap() {
        let mut s = super::StreamRecvState::new(0, 10000);
        s.mark_received(0);
        s.mark_received(4000);
        s.mark_received(9000);
        let (hc, bm) = super::build_stream_ack_bitmap(&s);
        assert_eq!(hc, 0);
        // Bit i reports chunk hc+1+i, so chunk 4000 is bit 3999: byte 499,
        // bit 7 — far beyond the old 32-byte (256-bit) cap.
        assert!(bm.len() > 32);
        assert_eq!(bm[499], 0x80);
        // Chunk 9000 (bit 8999) is beyond even the new 8192-bit cap and is
        // simply not reported; the bitmap is capped, never larger.
        assert_eq!(bm.len(), super::MAX_ACK_BITMAP_BYTES);
    }

    // ── Tail responder: retransmitted DATA after completion still gets ACKed ──

    /// Read datagrams until the socket's read timeout expires with none
    /// arriving; returns the decoded packets seen.
    fn collect_packets(sock: &std::net::UdpSocket) -> Vec<Packet> {
        let mut out = Vec::new();
        let mut buf = [0u8; 2048];
        loop {
            match sock.recv_from(&mut buf) {
                Ok((len, _)) => {
                    if let Ok(pkt) = decode_packet(&buf[..len]) {
                        out.push(pkt);
                    }
                }
                Err(_) => break,
            }
        }
        out
    }

    #[test]
    fn tail_responder_answers_retransmitted_data() {

        const CONN: u64 = 0x5AFE;
        const CHUNKS: u64 = 4;
        const PAYLOAD: usize = 64;

        // Daemon-side data socket: non-blocking, as the listener configures it.
        let daemon = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        daemon.set_nonblocking(true).unwrap();
        let daemon_addr = daemon.local_addr().unwrap();
        let sender = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        sender
            .set_read_timeout(Some(std::time::Duration::from_millis(200)))
            .unwrap();
        let peer_sin = match sender.local_addr().unwrap() {
            a @ std::net::SocketAddr::V4(_) => a,
            _ => panic!("IPv4 only"),
        };

        let streams = build_recv_streams(CHUNKS, 1);
        let mmap = memmap2::MmapMut::map_anon(CHUNKS as usize * PAYLOAD).unwrap();
        // `threaded_bitmap_recv` takes the sockets themselves. Adopting a
        // std socket into tokio requires a runtime context; the receive loop
        // never touches the reactor (it borrows the native handle), but the
        // registration must outlive the thread, so `rt` is held to the end.
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all().build().unwrap();
        let daemon_sock = {
            let _guard = rt.enter();
            std::sync::Arc::new(tokio::net::UdpSocket::from_std(daemon).unwrap())
        };
        let handle = std::thread::spawn(move || {
            super::threaded_bitmap_recv(
                vec![daemon_sock], None, peer_sin, CONN, 0, mmap, streams, PAYLOAD, CHUNKS,
                None, false, false, false,
            )
        });

        // Send every chunk once (chunk i filled with byte i+1).
        let mut wire = [0u8; 1500];
        let mut send_chunk = |ci: u64| {
            let data = [ci as u8 + 1; PAYLOAD];
            let n = encode_data_packet_into(&mut wire, CONN, ci, 0, 0, 0, ci, 0, &data);
            sender.send_to(&wire[..n], daemon_addr).unwrap();
        };
        for ci in 0..CHUNKS {
            send_chunk(ci);
        }

        // Completion burst: the final all-acked ACKs (3 copies), possibly
        // preceded by a timer ACK. All must report the full contiguous prefix.
        std::thread::sleep(std::time::Duration::from_millis(50));
        let burst = collect_packets(&sender);
        assert!(
            burst.iter().any(|p| p.header.packet_type == PacketType::AckBitmap),
            "expected final ACK bitmaps, got {:?}",
            burst.iter().map(|p| p.header.packet_type).collect::<Vec<_>>()
        );
        for p in &burst {
            if p.header.packet_type == PacketType::AckBitmap {
                // highest_contiguous at AckBitmap payload bytes 12..20.
                let hc = u64::from_be_bytes(p.payload[12..20].try_into().unwrap());
                assert_eq!(hc, CHUNKS - 1, "final ACK must report all chunks");
            }
        }

        // The bug: before the tail responder, the recv thread exited at
        // completion and these retransmissions hit a deaf port. Now each one
        // must be answered with another all-acked ACK bitmap.
        send_chunk(CHUNKS - 1);
        let answered = collect_packets(&sender);
        assert!(
            answered.iter().any(|p| p.header.packet_type == PacketType::AckBitmap),
            "tail responder did not answer a retransmitted tail chunk"
        );

        // FINISH ends the grace immediately, with a reply.
        let n = encode_ctrl_packet_into(&mut wire, PacketType::Finish, CONN, 100);
        sender.send_to(&wire[..n], daemon_addr).unwrap();
        let replied = collect_packets(&sender);
        assert!(
            replied.iter().any(|p| p.header.packet_type == PacketType::Finish),
            "expected a FINISH reply"
        );

        let result = handle
            .join()
            .expect("recv thread panicked")
            .expect("recv thread failed");
        assert!(result.finish_replied);
        assert_eq!(result.n_received, CHUNKS);
        for ci in 0..CHUNKS as usize {
            let off = ci * PAYLOAD;
            assert!(
                result.mmap[off..off + PAYLOAD].iter().all(|&b| b == ci as u8 + 1),
                "chunk {ci} content mismatch"
            );
        }
    }

    /// An oversized DATA payload must be dropped, not written and not
    /// copied.
    ///
    /// Before UDP_GRO the receive slot was MAX_PACKET, so the kernel
    /// truncated anything larger and the length could not lie. With a
    /// 64 KiB slot `data_len` is an attacker-controlled u16 that arrives
    /// intact, and two things depended on the old implicit bound: the
    /// plaintext path wrote it straight into the mapping (spanning chunks
    /// it never addressed), and the encrypted path copied it into a fixed
    /// MAX_PACKET buffer *before* checking the AEAD tag.
    ///
    /// The test sends a well-formed DATA packet whose payload is 30x the
    /// negotiated chunk size, then a legitimate one, and asserts the first
    /// changed nothing and the second still works — a receiver that
    /// rejected everything would pass a "no corruption" check on its own.
    #[test]
    fn oversized_data_payload_is_rejected_and_writes_nothing() {
        const CONN: u64 = 0x0DD5;
        const CHUNKS: u64 = 4;
        const PAYLOAD: usize = 64;

        let daemon = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        daemon.set_nonblocking(true).unwrap();
        let daemon_addr = daemon.local_addr().unwrap();
        let sender = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let peer_sin = match sender.local_addr().unwrap() {
            a @ std::net::SocketAddr::V4(_) => a,
            _ => panic!("IPv4 only"),
        };

        let streams = build_recv_streams(CHUNKS, 1);
        let mmap = memmap2::MmapMut::map_anon(CHUNKS as usize * PAYLOAD).unwrap();
        // `threaded_bitmap_recv` takes the sockets themselves. Adopting a
        // std socket into tokio requires a runtime context; the receive loop
        // never touches the reactor (it borrows the native handle), but the
        // registration must outlive the thread, so `rt` is held to the end.
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all().build().unwrap();
        let daemon_sock = {
            let _guard = rt.enter();
            std::sync::Arc::new(tokio::net::UdpSocket::from_std(daemon).unwrap())
        };
        let handle = std::thread::spawn(move || {
            super::threaded_bitmap_recv(
                vec![daemon_sock], None, peer_sin, CONN, 0, mmap, streams, PAYLOAD, CHUNKS,
                None, false, false, false,
            )
        });

        // 30 chunks' worth of payload in one packet, addressed at chunk 0.
        // Unchecked, `write_chunk` would clamp it to the mapping and
        // overwrite all four chunks.
        let mut big = vec![0u8; 8192];
        let flood = vec![0xEEu8; PAYLOAD * 30];
        let n = encode_data_packet_into(&mut big, CONN, 0, 0, 0, 0, 0, 0, &flood);
        sender.send_to(&big[..n], daemon_addr).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(50));

        // Now the legitimate chunks, so the transfer completes and the
        // thread returns its mmap for inspection.
        let mut wire = [0u8; 1500];
        for ci in 0..CHUNKS {
            let data = [ci as u8 + 1; PAYLOAD];
            let n = encode_data_packet_into(&mut wire, CONN, ci, 0, 0, 0, ci, 0, &data);
            sender.send_to(&wire[..n], daemon_addr).unwrap();
        }

        let result = handle.join().expect("receive thread must not panic").unwrap();
        assert_eq!(result.n_received, CHUNKS);
        for ci in 0..CHUNKS as usize {
            let off = ci * PAYLOAD;
            assert!(
                result.mmap[off..off + PAYLOAD].iter().all(|&b| b == ci as u8 + 1),
                "chunk {ci} was overwritten by the oversized packet"
            );
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn merkle_drop_chase_matches_slice_build() {
        // The windowed, page-dropping merkle build must produce tree bytes
        // identical to the slice-based build the resume cache was designed
        // around — cache validity and future diff computations depend on
        // the exact bytes. A payload size that does not divide the 16 MiB
        // window exercises the builder's partial-chunk carry.
        let dir = std::env::temp_dir().join(format!("ahp_daemon_chase_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("file.bin");
        let payload_size = 1350;
        for size in [0usize, 1, 4097, 16 * 1024 * 1024, 16 * 1024 * 1024 + 12345] {
            let data: Vec<u8> = (0..size).map(|i| (i as u32 % 251) as u8).collect();
            let mmap = if size == 0 {
                // Zero-length files map as a 1-byte placeholder on the
                // transfer path; the chase reads len == 0 of it.
                memmap2::MmapMut::map_anon(1).unwrap()
            } else {
                std::fs::write(&path, &data).unwrap();
                let file = std::fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(&path)
                    .unwrap();
                // File-backed MAP_SHARED: dirty pages must survive
                // MADV_DONTNEED, as on the transfer path.
                unsafe { memmap2::MmapMut::map_mut(&file).unwrap() }
            };
            let chased = super::merkle_with_drop_chase(&mmap, size, payload_size);
            let sliced = ahp_sync::merkle::build_file_merkle(&data, payload_size);
            assert_eq!(chased.root(), sliced.root(), "root mismatch at size {size}");
            assert_eq!(
                chased.to_bytes(),
                sliced.to_bytes(),
                "tree bytes mismatch at size {size}"
            );
            // The drop chase must leave the file content intact on re-read.
            assert_eq!(
                &mmap[..size],
                &data[..],
                "drop chase corrupted the mapping at size {size}"
            );
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    /// **0-RTT replay protection must survive concurrency.**
    ///
    /// Transfers now run in parallel, so two handshakes can present the same
    /// session ticket at the same instant. `UsedTicketCache::check_and_record`
    /// tests and records under one lock acquisition; the danger is a future
    /// refactor splitting it into `contains` then `insert`, which reads
    /// correctly in a serial daemon and admits a replay in a parallel one.
    ///
    /// This drives one ticket through many concurrent claimants and asserts
    /// exactly one wins. It is the gate on running transfers in parallel at
    /// all — see the README.
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn one_ticket_is_accepted_exactly_once_under_concurrency() {
        use std::sync::{Arc, Mutex};
        let mut raw_key = ahp_crypto::session_ticket::TicketKey::generate();
        let ticket = raw_key
            .issue(&[0x7Au8; 32], ahp_crypto::session_ticket::DEFAULT_TICKET_TTL)
            .expect("issue");
        // A 0-RTT resume HELLO: [0x02][4-byte ticket_len BE][ticket][16-byte nonce].
        // Big-endian: the sender writes `to_be_bytes` and the daemon parses
        // `from_be_bytes`. hello.rs's module doc said LE and was wrong —
        // caught by this test failing with 0 accepted rather than 1.
        let encoded = ahp_crypto::session_ticket::encode_ticket(&ticket);
        let mut hello_payload = vec![0x02u8];
        hello_payload.extend_from_slice(&(encoded.len() as u32).to_be_bytes());
        hello_payload.extend_from_slice(&encoded);
        hello_payload.extend_from_slice(&[0xC1u8; 16]);

        let key = Arc::new(Mutex::new(raw_key));
        let cache = Arc::new(Mutex::new(
            ahp_crypto::session_ticket::UsedTicketCache::new(),
        ));

        const CLAIMANTS: usize = 64;
        let barrier = Arc::new(tokio::sync::Barrier::new(CLAIMANTS));
        let mut tasks = Vec::with_capacity(CLAIMANTS);
        for _ in 0..CLAIMANTS {
            let cache = cache.clone();
            let key = key.clone();
            let barrier = barrier.clone();
            let hello = hello_payload.clone();
            tasks.push(tokio::spawn(async move {
                // Line them up so the claims genuinely overlap.
                barrier.wait().await;
                // Exactly what `handle_transfer` does: take both locks and
                // run the real resume path. Asserting on `check_and_record`
                // alone would pass even if the daemon later split the
                // check and the record across two lock acquisitions —
                // this exercises the composition that actually ships.
                let tk = key.lock().expect("key mutex poisoned");
                let mut ut = cache.lock().expect("cache mutex poisoned");
                let (_mode, keys, _nonce) = super::resume_from_ticket(&tk, &mut ut, &hello);
                keys.is_some()
            }));
        }
        let mut accepted = 0usize;
        for t in tasks {
            if t.await.expect("task panicked") {
                accepted += 1;
            }
        }
        assert_eq!(
            accepted, 1,
            "exactly one concurrent claim on a ticket may succeed; {accepted} did — \
0-RTT replay protection is broken under concurrency"
        );
    }


    /// Per-stream sockets derive stream *i*'s port as `base + i`, so the
    /// allocator must return a genuine run — a set of the right size that
    /// is not consecutive would send half the streams into the void.
    #[tokio::test]
    async fn contiguous_ports_are_found_returned_in_order_and_gaps_respected() {
        async fn pool_on(ports: &[u16]) -> Vec<std::sync::Arc<tokio::net::UdpSocket>> {
            let mut v = Vec::new();
            for p in ports {
                let a: std::net::SocketAddr = format!("127.0.0.1:{p}").parse().unwrap();
                if let Ok(s) = super::bind_transfer_data_socket(a, 1) {
                    v.push(std::sync::Arc::new(s));
                }
            }
            v
        }
        // A contiguous block, deliberately shuffled in pool order.
        let mut pool = pool_on(&[24103, 24101, 24104, 24102]).await;
        if pool.len() == 4 {
            let got = super::take_contiguous_ports(&mut pool, 3).expect("a run of 3 exists");
            let ports: Vec<u16> = got.iter().map(|s| s.local_addr().unwrap().port()).collect();
            assert_eq!(ports.len(), 3);
            for w in ports.windows(2) {
                assert_eq!(w[1], w[0] + 1, "returned ports must be consecutive and ascending: {ports:?}");
            }
            assert_eq!(pool.len(), 1, "taken sockets must leave the pool");
        }

        // Enough sockets, but no run: 4 ports with a hole after each pair.
        let mut holed = pool_on(&[24201, 24202, 24301, 24302]).await;
        if holed.len() == 4 {
            assert!(
                super::take_contiguous_ports(&mut holed, 3).is_none(),
                "four sockets in two runs of two must not satisfy a request for three"
            );
            assert_eq!(holed.len(), 4, "a failed request must not consume the pool");
            assert!(super::take_contiguous_ports(&mut holed, 2).is_some(), "a run of 2 does exist");
        }

        // Degenerate requests.
        let mut empty: Vec<std::sync::Arc<tokio::net::UdpSocket>> = Vec::new();
        assert!(super::take_contiguous_ports(&mut empty, 1).is_none());
        let mut one = pool_on(&[24401]).await;
        if one.len() == 1 {
            assert!(super::take_contiguous_ports(&mut one, 2).is_none(), "cannot over-serve");
            assert!(super::take_contiguous_ports(&mut one, 0).is_none(), "zero is not a request");
        }
    }

    /// One transfer may take at most half the pool, and a transfer that
    /// finds nothing free gets `None` — which the accept loop turns into
    /// "decline, let the sender retry" rather than "carry on with the
    /// shared socket". That inversion is the whole policy: the cap is
    /// fairness, and the emptiness is back-pressure.
    #[tokio::test]
    async fn a_port_run_is_capped_at_half_the_pool_and_runs_out_honestly() {
        async fn pool_on(ports: &[u16]) -> Vec<std::sync::Arc<tokio::net::UdpSocket>> {
            let mut v = Vec::new();
            for p in ports {
                let a: std::net::SocketAddr = format!("127.0.0.1:{p}").parse().unwrap();
                if let Ok(s) = super::bind_transfer_data_socket(a, 1) {
                    v.push(std::sync::Arc::new(s));
                }
            }
            v
        }
        // The cap itself: half the pool, floored at 1, capped at the max run.
        assert_eq!(super::per_transfer_cap(0), 1);
        assert_eq!(super::per_transfer_cap(1), 1, "one socket cannot be split");
        assert_eq!(super::per_transfer_cap(3), 1, "too small to leave a second transfer a run");
        assert_eq!(super::per_transfer_cap(4), 2);
        assert_eq!(super::per_transfer_cap(8), 4);
        assert_eq!(
            super::per_transfer_cap(64), super::MAX_PER_STREAM_PORTS,
            "a huge pool must not hand one transfer an unbounded run"
        );

        let sockets = pool_on(&[24501, 24502, 24503, 24504]).await;
        if sockets.len() != 4 {
            return; // ports in use on this machine; nothing to assert
        }
        let pool = std::sync::Arc::new(tokio::sync::Mutex::new(sockets));
        let cap = super::per_transfer_cap(4);

        // Two transfers, each getting a run of 2 out of a pool of 4.
        let first = super::take_transfer_sockets(&pool, cap).await.expect("a run exists");
        assert_eq!(first.len(), 2, "half the pool, no more");
        let ports: Vec<u16> = first.iter().map(|s| s.local_addr().unwrap().port()).collect();
        assert_eq!(ports[1], ports[0] + 1, "a run must be consecutive: {ports:?}");
        let second = super::take_transfer_sockets(&pool, cap).await.expect("the other half");
        assert_eq!(second.len(), 2);
        assert!(pool.lock().await.is_empty());

        // A third finds nothing. The accept loop declines on this and the
        // sender retries; nothing falls back to the shared data socket.
        assert!(
            super::take_transfer_sockets(&pool, cap).await.is_none(),
            "an empty pool must report empty, not hand out something unsafe"
        );

        // Returning one transfer's run makes it available again.
        pool.lock().await.extend(first);
        let third = super::take_transfer_sockets(&pool, cap).await.expect("returned run");
        assert_eq!(third.len(), 2);
    }

    /// A run reserved before `num_streams` was known must shrink to what
    /// the transfer can actually address, and the remainder must be usable
    /// by someone else immediately — not held until teardown. A one-stream
    /// transfer holding a run of five is two concurrent transfers out of a
    /// ten-port pool instead of ten.
    #[tokio::test]
    async fn an_oversized_run_returns_its_tail_as_soon_as_num_streams_is_known() {
        async fn pool_on(ports: &[u16]) -> Vec<std::sync::Arc<tokio::net::UdpSocket>> {
            let mut v = Vec::new();
            for p in ports {
                let a: std::net::SocketAddr = format!("127.0.0.1:{p}").parse().unwrap();
                if let Ok(s) = super::bind_transfer_data_socket(a, 1) {
                    v.push(std::sync::Arc::new(s));
                }
            }
            v
        }
        let sockets = pool_on(&[24601, 24602, 24603, 24604]).await;
        if sockets.len() != 4 {
            return; // ports in use on this machine
        }
        let pool = std::sync::Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let run = sockets.clone();
        let base_port = run[0].local_addr().unwrap().port();
        let r = super::SocketReturn::new(pool.clone(), run);

        // One stream: keep the base, give back the other three.
        r.release_tail(1).await;
        assert_eq!(pool.lock().await.len(), 3, "the tail must be available at once");

        // Idempotent, and never gives back what is still in use.
        r.release_tail(1).await;
        assert_eq!(pool.lock().await.len(), 3);
        r.release_tail(0).await;
        assert_eq!(pool.lock().await.len(), 3, "keep=0 is not a request to return everything");

        // The kept socket is the base — the one the sender was told about.
        r.release().await;
        let back = pool.lock().await;
        assert_eq!(back.len(), 4, "the whole run is back after the final release");
        assert!(
            back.iter().any(|s| s.local_addr().unwrap().port() == base_port),
            "the advertised base port must be among the returned sockets"
        );
    }
}

