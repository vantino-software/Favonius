// Favonius — high-performance file transfer over UDP
// Copyright (c) 2025-2026 Vantino SàRL
// SPDX-License-Identifier: Apache-2.0

//! Windows fallback: per-packet `sendto` loop.
//! Used when USO is unavailable (Windows < 10 build 19041).

use std::net::SocketAddr;
use std::os::windows::io::RawSocket;

use windows_sys::Win32::Networking::WinSock::{
    sendto, WSAGetLastError, SOCKADDR, SOCKADDR_IN, SOCKET, SOCKET_ERROR, AF_INET, IN_ADDR, IN_ADDR_0,
};

use crate::common::{Capabilities, PacketBatchSender, SendError};

pub struct SendtoLoopSender {
    socket: SOCKET,
    packets: Vec<Vec<u8>>,
    batch_capacity: usize,
    dest: SOCKADDR_IN,
}

impl SendtoLoopSender {
    pub fn new(raw_socket: RawSocket, remote: SocketAddr, batch_capacity: usize) -> Self {
        let socket = raw_socket as SOCKET;
        let dest = match remote {
            SocketAddr::V4(v4) => {
                let mut sa: SOCKADDR_IN = unsafe { std::mem::zeroed() };
                sa.sin_family = AF_INET;
                sa.sin_port = v4.port().to_be();
                sa.sin_addr = IN_ADDR {
                    S_un: IN_ADDR_0 { S_addr: u32::from(*v4.ip()).to_be() },
                };
                sa
            }
            _ => panic!("IPv6 not yet supported"),
        };
        Self { socket, packets: Vec::with_capacity(batch_capacity), batch_capacity, dest }
    }
}

impl PacketBatchSender for SendtoLoopSender {
    fn stage(&mut self, packet: &[u8]) -> Result<usize, SendError> {
        if self.packets.len() >= self.batch_capacity {
            return Err(SendError::BatchFull);
        }
        self.packets.push(packet.to_vec());
        Ok(packet.len())
    }

    fn flush(&mut self) -> Result<usize, SendError> {
        // Count only packets that actually went out: the congestion
        // controller treats anything short of the staged count as lost,
        // so reporting failures as sent would corrupt its accounting.
        let mut sent = 0usize;
        for pkt in self.packets.drain(..) {
            let ret = unsafe {
                sendto(
                    self.socket,
                    pkt.as_ptr(),
                    pkt.len() as i32,
                    0,
                    &self.dest as *const _ as *const SOCKADDR,
                    std::mem::size_of::<SOCKADDR_IN>() as i32,
                )
            };
            if ret == SOCKET_ERROR {
                let err = std::io::Error::from_raw_os_error(unsafe { WSAGetLastError() });
                if err.kind() == std::io::ErrorKind::WouldBlock {
                    // Ordinary backpressure on a non-blocking socket.
                    tracing::debug!(error = %err, "sendto would block; packet dropped");
                } else {
                    tracing::warn!(error = %err, "sendto failed; packet dropped");
                }
            } else {
                sent += 1;
            }
        }
        Ok(sent)
    }

    fn is_full(&self) -> bool {
        self.packets.len() >= self.batch_capacity
    }

    fn pending(&self) -> usize {
        self.packets.len()
    }

    fn modify_last_packet(&mut self, f: &mut dyn FnMut(&mut [u8])) -> bool {
        if let Some(last) = self.packets.last_mut() {
            f(last.as_mut_slice());
            true
        } else {
            false
        }
    }

    fn supports_post_stage_mutation(&self) -> bool {
        true
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities {
            max_batch_size: self.batch_capacity,
            supports_segmentation_offload: false,
            supports_zero_copy: false,
            typical_throughput_mbps: 175,
        }
    }

    fn name(&self) -> &'static str {
        "windows/sendto-loop"
    }
}
