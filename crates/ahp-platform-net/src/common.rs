// Favonius — high-performance file transfer over UDP
// Copyright (c) 2025-2026 Vantino SàRL
// SPDX-License-Identifier: Apache-2.0

//! Common types shared by all platform backends.

use std::time::Duration;

/// Maximum consecutive retries when a non-blocking send reports
/// WOULDBLOCK/EAGAIN before the flush gives up and surfaces the error.
pub const WOULD_BLOCK_MAX_ATTEMPTS: usize = 64;

/// Delay between WOULDBLOCK retries. 64 × 100 µs bounds the worst-case
/// stall of a single flush to ~6.4 ms under sustained backpressure.
pub const WOULD_BLOCK_RETRY_DELAY: Duration = Duration::from_micros(100);

/// Decide whether a failed non-blocking send should be retried.
///
/// `attempt` is the number of retries already performed for this flush.
/// Returns `Some(delay)` to sleep briefly and retry, or `None` to surface
/// the error. Only `WouldBlock` (ordinary backpressure on a non-blocking
/// socket) is retryable — anything else is a real error.
pub fn would_block_retry(kind: std::io::ErrorKind, attempt: usize) -> Option<Duration> {
    if kind == std::io::ErrorKind::WouldBlock && attempt < WOULD_BLOCK_MAX_ATTEMPTS {
        Some(WOULD_BLOCK_RETRY_DELAY)
    } else {
        None
    }
}

/// Chunk size for splitting a batch of `len` packets into at most
/// `max_chunks` contiguous runs (via `slice::chunks`). Consecutive packets
/// stay in the same run, so a worker that sends one run preserves the
/// original stage order within it.
pub fn contiguous_chunk_size(len: usize, max_chunks: usize) -> usize {
    debug_assert!(max_chunks > 0);
    len.div_ceil(max_chunks).max(1)
}

#[derive(Debug, thiserror::Error)]
pub enum SendError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("batch full")]
    BatchFull,
    #[error("backend unavailable: {0}")]
    Unavailable(String),
}

/// Capabilities advertised by a batched UDP sender backend.
#[derive(Debug, Clone, Copy)]
pub struct Capabilities {
    /// Maximum number of packets per flush.
    pub max_batch_size: usize,
    /// Whether the backend uses kernel/NIC segmentation offload (GSO/USO).
    /// When true, the backend processes a single buffer of N*segment_size
    /// bytes and the kernel splits it at segment boundaries.
    pub supports_segmentation_offload: bool,
    /// Whether the backend can avoid copying packet payloads (e.g., AF_XDP UMEM).
    pub supports_zero_copy: bool,
    /// Approximate sustained throughput on a 1 Gbps link in MB/s.
    /// Used as a heuristic by the AHP send loop to size its work batches.
    pub typical_throughput_mbps: u32,
}

/// Trait implemented by all platform-specific batched UDP senders.
///
/// The AHP send loop interacts with the network exclusively through this
/// trait, so the OS-specific code is isolated to a single layer.
pub trait PacketBatchSender: Send {
    /// Stage a single packet into the current batch.
    ///
    /// The backend may copy the data into an internal buffer (Linux GSO,
    /// Windows USO) or reference it directly (zero-copy implementations).
    /// Returns the wire size of the staged packet.
    ///
    /// Segmentation-offload backends (GSO/USO) split the flush buffer at
    /// fixed segment_size boundaries, so a packet shorter than their
    /// segment_size can only be the final segment: staging one flushes
    /// the pending batch first, and a pending short tail is flushed
    /// before anything is staged behind it. Short packets are never
    /// emitted as padded mid-batch segments.
    fn stage(&mut self, packet: &[u8]) -> Result<usize, SendError>;

    /// Flush all staged packets to the wire. Returns the count actually sent.
    fn flush(&mut self) -> Result<usize, SendError>;

    /// Whether the batch is at capacity and must be flushed before more
    /// packets can be staged.
    fn is_full(&self) -> bool;

    /// Number of packets currently staged but not yet flushed.
    fn pending(&self) -> usize;

    /// Provide mutable access to the last staged packet's bytes via a
    /// closure. Used by the AHP send loop to apply header protection,
    /// set per-packet flags, or otherwise mutate already-staged data.
    ///
    /// Backends that buffer packets contiguously (Linux GSO, Windows USO,
    /// sendmmsg) override this to give the caller a slice into their
    /// internal buffer. Backends that send asynchronously (e.g., macOS
    /// parallel sendmsg) cannot support post-stage modification — the
    /// default no-op signals to the caller that mutations must be applied
    /// before staging.
    ///
    /// Returns true if the closure was invoked, false if the backend
    /// doesn't support post-stage modification.
    fn modify_last_packet(&mut self, _f: &mut dyn FnMut(&mut [u8])) -> bool {
        false
    }

    /// Whether this backend supports `modify_last_packet`. Used by the
    /// caller to decide whether header protection must be applied
    /// pre-stage or post-stage.
    fn supports_post_stage_mutation(&self) -> bool {
        false
    }

    /// Capabilities of this backend.
    fn capabilities(&self) -> Capabilities;

    /// Backend identifier for logs and benchmarks.
    fn name(&self) -> &'static str;
}

// ── Receive side ─────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum RecvError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// No datagram was available on a non-blocking socket. The caller should
    /// spin-wait / poll and retry — this is the equivalent of `EAGAIN`.
    #[error("would block")]
    WouldBlock,
    #[error("backend unavailable: {0}")]
    Unavailable(String),
}

/// Capabilities advertised by a batched UDP receiver backend.
#[derive(Debug, Clone, Copy)]
pub struct RecvCapabilities {
    /// Maximum number of datagrams a single `recv_batch` call can return.
    pub max_batch_size: usize,
    /// Whether the backend pulls multiple datagrams per syscall (Linux
    /// `recvmmsg`). When false, each `recv_batch` returns at most one
    /// datagram (Windows/macOS single-`recvfrom` backends).
    pub supports_batched_syscall: bool,
    /// The `max_packet` size the backend was constructed with.
    ///
    /// **Not a guaranteed ceiling on what `packet()` returns.** The Linux
    /// backend reads into 64 KiB slots whenever UDP_GRO is active, so it can
    /// hand back a datagram substantially larger than this value; the macOS
    /// and Windows backends truncate to it. Read it as the size the caller
    /// asked for, not a limit the caller may rely on — anything that must
    /// reject oversized packets has to check the length it actually got.
    pub max_packet_size: usize,
}

/// Trait implemented by all platform-specific batched UDP receivers.
///
/// Mirrors [`PacketBatchSender`] on the receive path. The receiver owns its
/// buffers so the caller can process packets in place (header unprotect,
/// in-place decrypt) without copying: call [`recv_batch`], then for each of
/// the `n` returned datagrams read [`packet_mut`] / [`source`].
///
/// [`recv_batch`]: PacketBatchReceiver::recv_batch
/// [`packet_mut`]: PacketBatchReceiver::packet_mut
/// [`source`]: PacketBatchReceiver::source
pub trait PacketBatchReceiver: Send {
    /// Receive a batch of datagrams into the receiver's internal buffers in
    /// as few syscalls as the backend allows. Returns the number received
    /// (`0..=max_batch_size`). The bytes and source of datagram `i` remain
    /// valid via [`packet`]/[`packet_mut`]/[`source`] until the next
    /// `recv_batch` call.
    ///
    /// On a non-blocking socket with no datagram ready, returns
    /// [`RecvError::WouldBlock`].
    ///
    /// [`packet`]: PacketBatchReceiver::packet
    /// [`packet_mut`]: PacketBatchReceiver::packet_mut
    /// [`source`]: PacketBatchReceiver::source
    fn recv_batch(&mut self) -> Result<usize, RecvError>;

    /// Bytes of the `i`-th datagram from the most recent `recv_batch`.
    /// Panics if `i` is outside the last returned count.
    fn packet(&self, i: usize) -> &[u8];

    /// Mutable bytes of the `i`-th datagram — for in-place header unprotect
    /// and decryption. Panics if `i` is outside the last returned count.
    fn packet_mut(&mut self, i: usize) -> &mut [u8];

    /// Source address of the `i`-th datagram.
    /// Panics if `i` is outside the last returned count.
    fn source(&self, i: usize) -> std::net::SocketAddr;

    /// Capabilities of this backend.
    fn capabilities(&self) -> RecvCapabilities;

    /// Backend identifier for logs and benchmarks.
    fn name(&self) -> &'static str;
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::ErrorKind;

    #[test]
    fn would_block_is_retried_up_to_the_bound() {
        assert_eq!(
            would_block_retry(ErrorKind::WouldBlock, 0),
            Some(WOULD_BLOCK_RETRY_DELAY)
        );
        assert_eq!(
            would_block_retry(ErrorKind::WouldBlock, WOULD_BLOCK_MAX_ATTEMPTS - 1),
            Some(WOULD_BLOCK_RETRY_DELAY)
        );
        // Retries exhausted: surface the error instead of hanging the flush.
        assert_eq!(
            would_block_retry(ErrorKind::WouldBlock, WOULD_BLOCK_MAX_ATTEMPTS),
            None
        );
    }

    #[test]
    fn non_would_block_errors_are_never_retried() {
        for kind in [
            ErrorKind::ConnectionRefused,
            ErrorKind::PermissionDenied,
            ErrorKind::AddrNotAvailable,
            ErrorKind::Other,
        ] {
            assert_eq!(would_block_retry(kind, 0), None);
        }
    }

    #[test]
    fn contiguous_chunks_cover_the_batch_in_order() {
        let v: Vec<usize> = (0..10).collect();

        // 10 packets over 4 workers: chunk size 3 → runs of 3,3,3,1,
        // each preserving stage order.
        let size = contiguous_chunk_size(10, 4);
        let chunks: Vec<&[usize]> = v.chunks(size).collect();
        assert_eq!(chunks.len(), 4);
        assert_eq!(chunks[0], &[0, 1, 2]);
        assert_eq!(chunks[1], &[3, 4, 5]);
        assert_eq!(chunks[2], &[6, 7, 8]);
        assert_eq!(chunks[3], &[9]);

        // Fewer packets than workers: one packet per chunk, no empty runs.
        let size = contiguous_chunk_size(3, 4);
        assert_eq!(size, 1);
        assert_eq!(v[..3].chunks(size).count(), 3);

        // A single worker takes the whole batch in order.
        assert_eq!(contiguous_chunk_size(64, 1), 64);

        // An empty batch must not divide by zero or produce a zero size.
        assert!(contiguous_chunk_size(0, 4) >= 1);
    }
}
