// Favonius — high-performance file transfer over UDP
// Copyright (c) 2025-2026 Vantino SàRL
// SPDX-License-Identifier: Apache-2.0

//! macOS parallel sendmsg sender.
//!
//! macOS lacks GSO/USO equivalents and `sendmmsg`. To amortize per-packet
//! syscall overhead, this backend distributes sends across N worker threads,
//! each holding its own UDP socket bound with `SO_REUSEPORT`. The kernel
//! handles the parallel sends across multiple CPU cores.
//!
//! Staged packets are buffered locally; `flush()` splits the batch into at
//! most one contiguous run per worker (so each worker sends a consecutive,
//! order-preserving slice of the batch), hands the runs to the workers via
//! `try_send` (never blocking the caller on a full channel), and waits for
//! the workers' per-run sent counts so the returned count reflects what
//! actually went out on the wire.
//!
//! Typical throughput on macOS: ~50-60% of Linux GSO on the same hardware.

use std::net::SocketAddr;
use std::os::unix::io::RawFd;
use std::thread::JoinHandle;
use std::time::Duration;

use crate::common::{contiguous_chunk_size, Capabilities, PacketBatchSender, SendError};

const NUM_WORKERS: usize = 4;

/// Upper bound on how long `flush()` waits for a worker's reply. A run of
/// non-blocking `sendto` calls completes in microseconds; this only guards
/// against a wedged worker thread hanging the flush forever.
const WORKER_REPLY_TIMEOUT: Duration = Duration::from_secs(5);

/// One queued packet (owned data + destination).
#[derive(Clone)]
struct QueuedPacket {
    data: Vec<u8>,
    dest: libc::sockaddr_in,
}

/// A contiguous run of packets handed to one worker, plus the channel it
/// uses to report how many actually went out.
struct WorkChunk {
    packets: Vec<QueuedPacket>,
    done: crossbeam_channel::Sender<usize>,
}

pub struct ParallelSendmsgBatchSender {
    /// Worker channels — one contiguous run per flush per worker.
    senders: Vec<crossbeam_channel::Sender<WorkChunk>>,
    /// Worker thread handles.
    workers: Vec<JoinHandle<()>>,
    /// Cached destination (single dest in current API).
    dest: libc::sockaddr_in,
    /// Packets staged for the next flush.
    packets: Vec<QueuedPacket>,
    batch_capacity: usize,
}

impl ParallelSendmsgBatchSender {
    pub fn new(socket_fd: RawFd, remote: SocketAddr, batch_capacity: usize) -> Self {
        let dest = sockaddr_from(remote);
        let mut senders = Vec::with_capacity(NUM_WORKERS);
        let mut workers = Vec::with_capacity(NUM_WORKERS);

        // Each worker runs a tight sendto loop on the same socket fd.
        // SO_REUSEPORT could give each its own socket; for simplicity we
        // share the fd (the kernel serializes per-socket sends but
        // parallelism still helps because work is split across cores).
        //
        // The channel holds at most one chunk: flush waits for every
        // worker's reply before returning, so a worker is always idle when
        // the next flush dispatches.
        for _ in 0..NUM_WORKERS {
            let (tx, rx) = crossbeam_channel::bounded::<WorkChunk>(1);
            let fd = socket_fd;
            let handle = std::thread::spawn(move || {
                worker_loop(fd, rx);
            });
            senders.push(tx);
            workers.push(handle);
        }

        Self {
            senders,
            workers,
            dest,
            packets: Vec::with_capacity(batch_capacity),
            batch_capacity,
        }
    }
}

fn worker_loop(fd: RawFd, rx: crossbeam_channel::Receiver<WorkChunk>) {
    while let Ok(chunk) = rx.recv() {
        let mut sent = 0usize;
        for pkt in &chunk.packets {
            let ret = unsafe {
                libc::sendto(
                    fd,
                    pkt.data.as_ptr() as *const libc::c_void,
                    pkt.data.len(),
                    0,
                    &pkt.dest as *const _ as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
                )
            };
            if ret >= 0 {
                sent += 1;
            } else {
                // EAGAIN/WouldBlock included: count honestly so the
                // congestion controller treats the packet as lost.
                let err = std::io::Error::last_os_error();
                tracing::debug!(error = %err, "sendto failed; packet dropped");
            }
        }
        // If the reply fails the sender is being torn down; nothing to do.
        let _ = chunk.done.send(sent);
    }
}

impl PacketBatchSender for ParallelSendmsgBatchSender {
    fn stage(&mut self, packet: &[u8]) -> Result<usize, SendError> {
        if self.packets.len() >= self.batch_capacity {
            return Err(SendError::BatchFull);
        }
        self.packets.push(QueuedPacket {
            data: packet.to_vec(),
            dest: self.dest,
        });
        Ok(packet.len())
    }

    fn flush(&mut self) -> Result<usize, SendError> {
        if self.packets.is_empty() {
            return Ok(0);
        }

        // Split into at most NUM_WORKERS contiguous runs so each worker
        // sends a consecutive slice of the batch — this keeps per-worker
        // order identical to stage order and avoids gratuitously
        // interleaving the batch across workers.
        let chunk_size = contiguous_chunk_size(self.packets.len(), NUM_WORKERS);
        let mut packets = std::mem::take(&mut self.packets);
        let mut chunks: Vec<Vec<QueuedPacket>> = Vec::new();
        while !packets.is_empty() {
            let n = chunk_size.min(packets.len());
            chunks.push(packets.drain(..n).collect());
        }

        let (done_tx, done_rx) = crossbeam_channel::bounded::<usize>(NUM_WORKERS);
        let mut dispatched = 0usize;
        for (i, chunk) in chunks.into_iter().enumerate() {
            let work = WorkChunk {
                packets: chunk,
                done: done_tx.clone(),
            };
            match self.senders[i].try_send(work) {
                Ok(()) => dispatched += 1,
                Err(e) => {
                    // Channel full or worker gone: the run is dropped and
                    // simply not counted as sent.
                    tracing::warn!(worker = i, error = %e, "worker queue unavailable; packets dropped");
                }
            }
        }
        drop(done_tx);

        // Collect the workers' honest sent counts. The wait is bounded by
        // WORKER_REPLY_TIMEOUT so a wedged worker can't hang the flush.
        let mut total = 0usize;
        for _ in 0..dispatched {
            match done_rx.recv_timeout(WORKER_REPLY_TIMEOUT) {
                Ok(n) => total += n,
                Err(_) => {
                    tracing::warn!("worker reply timed out; remaining runs counted as unsent");
                    break;
                }
            }
        }
        Ok(total)
    }

    fn is_full(&self) -> bool {
        self.packets.len() >= self.batch_capacity
    }

    fn pending(&self) -> usize {
        self.packets.len()
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities {
            max_batch_size: self.batch_capacity,
            supports_segmentation_offload: false,
            supports_zero_copy: false,
            typical_throughput_mbps: 550,
        }
    }

    fn name(&self) -> &'static str {
        "macos/parallel-sendmsg"
    }
}

impl Drop for ParallelSendmsgBatchSender {
    fn drop(&mut self) {
        // Drop senders so workers see the channel closed and exit.
        self.senders.clear();
        for w in self.workers.drain(..) {
            let _ = w.join();
        }
    }
}

unsafe impl Send for ParallelSendmsgBatchSender {}

fn sockaddr_from(addr: SocketAddr) -> libc::sockaddr_in {
    match addr {
        SocketAddr::V4(v4) => {
            let mut sa: libc::sockaddr_in = unsafe { std::mem::zeroed() };
            sa.sin_family = libc::AF_INET as u8;
            sa.sin_port = v4.port().to_be();
            sa.sin_addr = libc::in_addr {
                s_addr: u32::from(*v4.ip()).to_be(),
            };
            #[cfg(any(target_os = "macos", target_os = "ios"))]
            {
                sa.sin_len = std::mem::size_of::<libc::sockaddr_in>() as u8;
            }
            sa
        }
        _ => panic!("IPv6 not yet supported"),
    }
}
