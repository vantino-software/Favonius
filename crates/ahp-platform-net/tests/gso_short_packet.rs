// Favonius — high-performance file transfer over UDP
// Copyright (c) 2025-2026 Vantino SàRL
// SPDX-License-Identifier: Apache-2.0

//! Linux GSO regression tests: a packet shorter than segment_size must
//! never go on the wire as a padded mid-batch segment (UDP GSO splits the
//! flush buffer at fixed segment_size boundaries, so only the final
//! segment may be short).

#![cfg(target_os = "linux")]

use std::net::SocketAddr;
use std::net::UdpSocket;
use std::os::unix::io::AsRawFd;
use std::time::Duration;

use ahp_platform_net::linux::{probe_gso, GsoBatchSender};
use ahp_platform_net::PacketBatchSender;

const SEGMENT_SIZE: usize = 64;

/// Deterministic payload tagged so different packets are distinguishable.
fn payload(tag: u8, len: usize) -> Vec<u8> {
    (0..len).map(|i| tag ^ (i as u8)).collect()
}

fn loopback_pair() -> (UdpSocket, UdpSocket, SocketAddr) {
    let receiver = UdpSocket::bind("127.0.0.1:0").expect("bind receiver");
    receiver
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("set recv timeout");
    let recv_addr = receiver.local_addr().expect("recv addr");
    let sender = UdpSocket::bind("127.0.0.1:0").expect("bind sender");
    (sender, receiver, recv_addr)
}

/// Receive exactly `expected` datagrams and return their payloads.
fn recv_all(receiver: &UdpSocket, expected: usize) -> Vec<Vec<u8>> {
    let mut out = Vec::with_capacity(expected);
    let mut buf = vec![0u8; 2048];
    for _ in 0..expected {
        let (n, _) = receiver.recv_from(&mut buf).expect("recv");
        out.push(buf[..n].to_vec());
    }
    out
}

/// Stage [full, full, short, full]: the short packet must terminate the
/// current batch (full-size run flushed first) and go out unpadded as its
/// own datagram — never as a segment_size datagram carrying stale bytes.
#[test]
fn short_mid_batch_packet_is_never_padded() {
    let (sender, receiver, recv_addr) = loopback_pair();
    let fd = sender.as_raw_fd();
    if !probe_gso(fd) {
        eprintln!("UDP GSO not supported on this kernel, skipping");
        return;
    }
    let mut gso = GsoBatchSender::new(fd, recv_addr, 8, SEGMENT_SIZE);

    let p0 = payload(0x11, SEGMENT_SIZE);
    let p1 = payload(0x22, SEGMENT_SIZE);
    let p2 = payload(0x33, 30); // short
    let p3 = payload(0x44, SEGMENT_SIZE);

    gso.stage(&p0).expect("stage p0");
    gso.stage(&p1).expect("stage p1");
    assert_eq!(gso.pending(), 2);

    // Staging the short packet flushes the pending full-size run first,
    // then becomes the lone tail of a fresh batch.
    gso.stage(&p2).expect("stage p2");
    assert_eq!(gso.pending(), 1, "short packet must flush the full-size run");

    // Staging behind a short tail flushes the tail alone first.
    gso.stage(&p3).expect("stage p3");
    assert_eq!(gso.pending(), 1, "short tail must flush before p3 is staged");

    gso.flush().expect("flush");

    let got = recv_all(&receiver, 4);
    for p in [&p0, &p1, &p2, &p3] {
        assert!(
            got.iter().any(|d| d == p),
            "missing exact payload of len {} (tag {:#x})",
            p.len(),
            p[0]
        );
    }
    // The short packet must arrive at its true length — no padding.
    let short = got.iter().find(|d| d.len() == 30).expect("short datagram");
    assert_eq!(*short, p2, "short packet must not be padded or carry stale bytes");
}

/// `modify_last_packet` must hand the closure a slice covering exactly
/// the last packet — both for a full-size tail at exact batch capacity
/// and for a short tail (which under flush-on-short is always alone in
/// its batch, so capacity 1 makes the batch exactly full).
#[test]
fn modify_last_packet_at_exact_full_batch() {
    let (sender, receiver, recv_addr) = loopback_pair();
    let fd = sender.as_raw_fd();
    if !probe_gso(fd) {
        eprintln!("UDP GSO not supported on this kernel, skipping");
        return;
    }

    // Full-size tail, batch exactly full (count == capacity == 2).
    let mut gso = GsoBatchSender::new(fd, recv_addr, 2, SEGMENT_SIZE);
    let p0 = payload(0x11, SEGMENT_SIZE);
    let p1 = payload(0x22, SEGMENT_SIZE);
    gso.stage(&p0).expect("stage p0");
    gso.stage(&p1).expect("stage p1");
    assert!(gso.is_full());

    let mut seen_len = 0;
    assert!(gso.modify_last_packet(&mut |pkt: &mut [u8]| {
        seen_len = pkt.len();
        pkt[0] = 0xAB;
    }));
    assert_eq!(seen_len, SEGMENT_SIZE);
    assert_eq!(gso.flush().expect("flush"), 2);

    let got = recv_all(&receiver, 2);
    let mut expected = p1.clone();
    expected[0] = 0xAB;
    assert!(
        got.contains(&expected),
        "mutation must land on the last full segment"
    );
    assert!(got.contains(&p0), "first segment must be untouched");

    // Short tail, batch exactly full (count == capacity == 1). The
    // mutation slice must cover the 30-byte packet, not a full slot.
    let mut gso = GsoBatchSender::new(fd, recv_addr, 1, SEGMENT_SIZE);
    let short = payload(0x33, 30);
    gso.stage(&short).expect("stage short");
    assert!(gso.is_full());

    let mut seen_len = 0;
    assert!(gso.modify_last_packet(&mut |pkt: &mut [u8]| {
        seen_len = pkt.len();
        pkt[0] = 0xCD;
    }));
    assert_eq!(seen_len, 30, "mutation slice must match the short tail length");
    assert_eq!(gso.flush().expect("flush"), 1);

    let got = recv_all(&receiver, 1);
    let mut expected = short.clone();
    expected[0] = 0xCD;
    assert_eq!(got[0], expected, "mutation must land on the short tail");
}

/// Compression-like pattern: every packet a different short length (plus
/// one full-size). The receiver must get each payload byte-exact — no
/// padding, no stale bytes, no coalescing across short packets.
#[test]
fn variable_length_packets_round_trip_exact() {
    let (sender, receiver, recv_addr) = loopback_pair();
    let fd = sender.as_raw_fd();
    if !probe_gso(fd) {
        eprintln!("UDP GSO not supported on this kernel, skipping");
        return;
    }
    let mut gso = GsoBatchSender::new(fd, recv_addr, 8, SEGMENT_SIZE);

    let lengths = [17usize, 63, 5, SEGMENT_SIZE, 31, 1, 48];
    let payloads: Vec<Vec<u8>> = lengths
        .iter()
        .enumerate()
        .map(|(i, &l)| payload(i as u8 + 1, l))
        .collect();

    for p in &payloads {
        gso.stage(p).expect("stage");
    }
    gso.flush().expect("flush");

    let got = recv_all(&receiver, payloads.len());
    for p in &payloads {
        assert!(
            got.iter().any(|d| d == p),
            "missing exact payload of len {}",
            p.len()
        );
    }
}
