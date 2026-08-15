// Favonius — high-performance file transfer over UDP
// Copyright (c) 2025-2026 Vantino SàRL
// SPDX-License-Identifier: Apache-2.0

//! Cross-platform UDP batched send abstraction.
//!
//! This crate provides a trait-based abstraction over high-performance UDP
//! send paths on Linux, Windows, and macOS. The AHP send loop uses the
//! trait; each platform has its own implementation gated by `cfg(target_os)`.
//!
//! Backends:
//! - **Linux**: GSO (default), sendmmsg fallback
//! - **Windows**: USO (UDP Send Offload, Win10 2004+), WSASendTo loop fallback
//! - **macOS**: Parallel sendmsg with worker threads
//!
//! See `docs/OPTIMIZATION.md` for the technical background.

use std::net::SocketAddr;

pub mod common;

#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(target_os = "windows")]
pub mod windows;

#[cfg(target_os = "macos")]
pub mod macos;

pub use common::{
    Capabilities, PacketBatchReceiver, PacketBatchSender, RecvCapabilities, RecvError, SendError,
};

/// Default largest datagram the receive backends will accept, in bytes.
/// AHP wire packets are <= 1500 bytes; 2048 leaves headroom.
pub const DEFAULT_MAX_PACKET: usize = 2048;

/// Create the best available batched UDP sender for the current platform.
///
/// Probes the OS for available batching primitives and returns the highest-
/// performing implementation. Falls back to per-packet sends if no batching
/// primitive is available.
///
/// Arguments:
/// - `socket`: an already-bound UDP socket
/// - `dest`: destination address (all packets go here)
/// - `batch_capacity`: max packets per flush
/// - `segment_size`: per-packet wire size (used for GSO/USO; ignored on macOS)
pub fn create_best_sender(
    socket_fd: RawSocket,
    dest: SocketAddr,
    batch_capacity: usize,
    #[cfg_attr(target_os = "macos", allow(unused_variables))]
    segment_size: usize,
) -> Box<dyn PacketBatchSender> {
    #[cfg(target_os = "linux")]
    {
        if linux::probe_gso(socket_fd) {
            tracing::info!(backend = "linux/gso", "selected send backend");
            return Box::new(linux::GsoBatchSender::new(socket_fd, dest, batch_capacity, segment_size));
        }
        tracing::info!(backend = "linux/sendmmsg", "selected send backend (no GSO)");
        return Box::new(linux::SendmmsgBatchSender::new(socket_fd, dest, batch_capacity));
    }

    #[cfg(target_os = "windows")]
    {
        if windows::probe_uso() {
            // Construction fails if the UDP_SEND_MSG_SIZE setsockopt is
            // rejected (e.g. driver without USO support); fall back to the
            // per-packet loop rather than run in a corrupt mode.
            if let Some(sender) = windows::UsoBatchSender::new(socket_fd, dest, batch_capacity, segment_size) {
                tracing::info!(backend = "windows/uso", "selected send backend");
                return Box::new(sender);
            }
            tracing::warn!("USO unavailable despite OS support; falling back to sendto loop");
        }
        tracing::info!(backend = "windows/sendto-loop", "selected send backend (no USO)");
        return Box::new(windows::SendtoLoopSender::new(socket_fd, dest, batch_capacity));
    }

    #[cfg(target_os = "macos")]
    {
        tracing::info!(backend = "macos/parallel-sendmsg", "selected send backend");
        return Box::new(macos::ParallelSendmsgBatchSender::new(socket_fd, dest, batch_capacity));
    }

    #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
    {
        compile_error!("ahp-platform-net only supports Linux, Windows, and macOS");
    }
}

/// Create the best available batched UDP receiver for the current platform.
///
/// The receiver owns its buffers; the caller drives it as
/// `recv_batch()` → iterate `packet_mut(i)`/`source(i)` for the returned
/// count. On Linux this uses `recvmmsg(2)` to pull up to `batch_capacity`
/// datagrams per syscall; on Windows and macOS (no batched-receive syscall)
/// each call returns a single datagram.
///
/// Arguments:
/// - `socket_fd`: an already-bound UDP socket
/// - `batch_capacity`: max datagrams per `recv_batch` (Linux only; others cap at 1)
/// - `max_packet`: largest single datagram to accept, in bytes
pub fn create_best_receiver(
    socket_fd: RawSocket,
    #[cfg_attr(not(target_os = "linux"), allow(unused_variables))] batch_capacity: usize,
    max_packet: usize,
) -> Box<dyn PacketBatchReceiver> {
    #[cfg(target_os = "linux")]
    {
        // Report the backend the receiver actually became, not the one this
        // arm selects: whether the kernel accepted UDP_GRO is the
        // difference between coalescing and not, and a hardcoded string
        // hides it.
        let rx = linux::RecvmmsgReceiver::new(socket_fd, batch_capacity, max_packet);
        tracing::info!(backend = rx.name(), gro = rx.gro_enabled(), "selected receive backend");
        return Box::new(rx);
    }

    #[cfg(target_os = "windows")]
    {
        tracing::info!(backend = "windows/recvfrom", "selected receive backend");
        return Box::new(windows::RecvfromReceiver::new(socket_fd, max_packet));
    }

    #[cfg(target_os = "macos")]
    {
        tracing::info!(backend = "macos/recvfrom", "selected receive backend");
        return Box::new(macos::RecvmsgReceiver::new(socket_fd, max_packet));
    }

    #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
    {
        compile_error!("ahp-platform-net only supports Linux, Windows, and macOS");
    }
}

/// Platform-specific raw socket type.
#[cfg(unix)]
pub type RawSocket = std::os::unix::io::RawFd;

#[cfg(windows)]
pub type RawSocket = std::os::windows::io::RawSocket;

/// Borrow a socket's platform-native handle.
///
/// The two families spell this differently — `AsRawFd::as_raw_fd` on Unix,
/// `AsRawSocket::as_raw_socket` on Windows — and a caller that only wants a
/// [`RawSocket`] to hand to [`create_best_sender`] or
/// [`create_best_receiver`] should not have to carry a `cfg` of its own.
///
/// The handle is *borrowed*: it is valid only while `sock` is alive, and
/// closing it remains the owner's business.
#[cfg(unix)]
#[inline]
pub fn raw_socket<S: std::os::unix::io::AsRawFd + ?Sized>(sock: &S) -> RawSocket {
    sock.as_raw_fd()
}

/// Borrow a socket's platform-native handle. See the Unix variant for docs.
#[cfg(windows)]
#[inline]
pub fn raw_socket<S: std::os::windows::io::AsRawSocket + ?Sized>(sock: &S) -> RawSocket {
    sock.as_raw_socket()
}
