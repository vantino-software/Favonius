// Favonius — high-performance file transfer over UDP
// Copyright (c) 2025-2026 Vantino SàRL
// SPDX-License-Identifier: Apache-2.0

//! Cross-platform smoke test for the `PacketBatchSender` trait.
//!
//! Runs on Linux, Windows, and macOS. Binds two UDP sockets on the
//! loopback interface, uses `create_best_sender` to build the best
//! available batched sender for the current platform, stages a small
//! batch of packets, flushes them, and verifies the receiver gets
//! every packet back unmodified.

use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;

use ahp_platform_net::{
    create_best_receiver, create_best_sender, RawSocket, DEFAULT_MAX_PACKET,
};

const SEGMENT_SIZE: usize = 1200;
const NUM_PACKETS: usize = 8;

#[cfg(unix)]
fn raw_socket_of(socket: &UdpSocket) -> RawSocket {
    use std::os::unix::io::AsRawFd;
    socket.as_raw_fd()
}

#[cfg(windows)]
fn raw_socket_of(socket: &UdpSocket) -> RawSocket {
    use std::os::windows::io::AsRawSocket;
    socket.as_raw_socket()
}

/// Build a fixed-size payload that encodes its packet index in the
/// first two bytes so the receiver can verify ordering.
fn make_payload(idx: usize) -> Vec<u8> {
    let mut buf = vec![0u8; SEGMENT_SIZE];
    buf[0] = (idx & 0xff) as u8;
    buf[1] = ((idx >> 8) & 0xff) as u8;
    // Fill the rest with a deterministic pattern.
    for (i, b) in buf.iter_mut().enumerate().skip(2) {
        *b = ((i ^ idx) & 0xff) as u8;
    }
    buf
}

#[test]
fn create_best_sender_round_trip() {
    let receiver = UdpSocket::bind("127.0.0.1:0").expect("bind receiver");
    receiver
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("set recv timeout");
    let recv_addr: SocketAddr = receiver.local_addr().expect("recv addr");

    let sender = UdpSocket::bind("127.0.0.1:0").expect("bind sender");
    let raw = raw_socket_of(&sender);

    let mut batch = create_best_sender(raw, recv_addr, NUM_PACKETS, SEGMENT_SIZE);

    // Sanity-check the trait surface before we send anything.
    let caps = batch.capabilities();
    assert!(caps.max_batch_size >= NUM_PACKETS, "batch capacity too small: {}", caps.max_batch_size);
    assert!(!batch.name().is_empty(), "backend name must be non-empty");
    assert_eq!(batch.pending(), 0);
    assert!(!batch.is_full());

    // Stage the batch.
    let payloads: Vec<Vec<u8>> = (0..NUM_PACKETS).map(make_payload).collect();
    for (i, payload) in payloads.iter().enumerate() {
        let n = batch.stage(payload).expect("stage packet");
        assert_eq!(n, SEGMENT_SIZE, "wire size mismatch on packet {i}");
    }
    assert_eq!(batch.pending(), NUM_PACKETS);

    // Flush them to the wire.
    let sent = batch.flush().expect("flush");
    assert_eq!(sent, NUM_PACKETS, "expected {} sent, got {}", NUM_PACKETS, sent);
    assert_eq!(batch.pending(), 0);

    // Sender's bookkeeping must be reset after flush so a second batch
    // can be staged immediately. We don't actually send a second batch —
    // just exercise the state.
    assert!(!batch.is_full());

    // Receive them back. UDP doesn't guarantee ordering even on
    // loopback, so collect by index and verify the multiset matches.
    let mut got = vec![false; NUM_PACKETS];
    let mut buf = vec![0u8; 2048];
    for _ in 0..NUM_PACKETS {
        let (n, _from) = receiver.recv_from(&mut buf).expect("recv");
        assert_eq!(n, SEGMENT_SIZE, "received packet wrong size");
        let idx = (buf[0] as usize) | ((buf[1] as usize) << 8);
        assert!(idx < NUM_PACKETS, "received out-of-range index {idx}");
        assert!(!got[idx], "duplicate packet for index {idx}");
        // Verify the deterministic body matches what we sent.
        for (i, b) in buf[..SEGMENT_SIZE].iter().enumerate().skip(2) {
            assert_eq!(*b, ((i ^ idx) & 0xff) as u8, "payload byte mismatch at {i} for packet {idx}");
        }
        got[idx] = true;
    }
    assert!(got.iter().all(|&g| g), "missing packets: {:?}", got);
}

#[test]
fn modify_last_packet_when_supported() {
    // Build a sender, stage one packet, then mutate it post-stage.
    // Backends that support post-stage mutation (Linux GSO/sendmmsg,
    // Windows USO/sendto-loop) will report `true` and the receiver
    // should see the mutated bytes. Backends that don't (macOS
    // parallel sendmsg) report `false` and we accept either outcome.
    let receiver = UdpSocket::bind("127.0.0.1:0").expect("bind receiver");
    receiver
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("set recv timeout");
    let recv_addr: SocketAddr = receiver.local_addr().expect("recv addr");

    let sender = UdpSocket::bind("127.0.0.1:0").expect("bind sender");
    let raw = raw_socket_of(&sender);
    let mut batch = create_best_sender(raw, recv_addr, 4, SEGMENT_SIZE);

    let payload = make_payload(0);
    batch.stage(&payload).expect("stage");

    // Try to flip the first byte to a sentinel value.
    let supports = batch.supports_post_stage_mutation();
    let mutated = batch.modify_last_packet(&mut |pkt: &mut [u8]| {
        pkt[0] = 0xAB;
    });
    assert_eq!(supports, mutated, "supports_post_stage_mutation must agree with modify_last_packet return value");

    batch.flush().expect("flush");

    let mut buf = vec![0u8; 2048];
    let (n, _) = receiver.recv_from(&mut buf).expect("recv");
    assert_eq!(n, SEGMENT_SIZE);

    if supports {
        assert_eq!(buf[0], 0xAB, "post-stage mutation should be visible on the wire");
    } else {
        // Async backend (macOS parallel sendmsg): the staged payload
        // is queued in a worker channel and cannot be mutated, so the
        // original byte (set by `make_payload(0)`) arrives.
        assert_eq!(buf[0], 0x00, "unmutated packet should arrive untouched");
    }
}

/// Send a batch with `create_best_sender` and receive it back through
/// `create_best_receiver`, verifying every datagram round-trips with the
/// correct bytes and a plausible source address. On Linux the receiver
/// pulls the whole batch via `recvmmsg`; on Windows/macOS it returns one
/// datagram per call — the loop below handles both by draining until every
/// packet has arrived.
#[test]
fn create_best_receiver_round_trip() {
    let receiver_sock = UdpSocket::bind("127.0.0.1:0").expect("bind receiver");
    receiver_sock
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("set recv timeout");
    let recv_addr: SocketAddr = receiver_sock.local_addr().expect("recv addr");
    let recv_raw = raw_socket_of(&receiver_sock);

    let sender_sock = UdpSocket::bind("127.0.0.1:0").expect("bind sender");
    let send_raw = raw_socket_of(&sender_sock);
    let sender_addr: SocketAddr = sender_sock.local_addr().expect("sender addr");

    // Send the batch.
    let mut batch = create_best_sender(send_raw, recv_addr, NUM_PACKETS, SEGMENT_SIZE);
    let payloads: Vec<Vec<u8>> = (0..NUM_PACKETS).map(make_payload).collect();
    for payload in &payloads {
        batch.stage(payload).expect("stage");
    }
    let sent = batch.flush().expect("flush");
    assert_eq!(sent, NUM_PACKETS);

    // Receive via the platform receiver.
    let mut rx = create_best_receiver(recv_raw, NUM_PACKETS, DEFAULT_MAX_PACKET);
    let caps = rx.capabilities();
    assert!(caps.max_batch_size >= 1);
    assert!(!rx.name().is_empty());

    let mut got = vec![false; NUM_PACKETS];
    let mut received = 0usize;
    // Bound the number of recv_batch calls so a lost packet fails the test
    // instead of hanging (the blocking socket read-timeout also guards this).
    for _ in 0..(NUM_PACKETS * 4) {
        if received == NUM_PACKETS {
            break;
        }
        let n = match rx.recv_batch() {
            Ok(n) => n,
            Err(_) => break, // timeout / would-block
        };
        for i in 0..n {
            let pkt = rx.packet(i);
            assert_eq!(pkt.len(), SEGMENT_SIZE, "datagram wrong size");
            let idx = (pkt[0] as usize) | ((pkt[1] as usize) << 8);
            assert!(idx < NUM_PACKETS, "out-of-range index {idx}");
            assert!(!got[idx], "duplicate packet {idx}");
            for (j, b) in pkt.iter().enumerate().skip(2) {
                assert_eq!(*b, ((j ^ idx) & 0xff) as u8, "payload mismatch at {j} for packet {idx}");
            }
            // Source must be the sender's loopback address/port.
            let src = rx.source(i);
            assert_eq!(src.port(), sender_addr.port(), "unexpected source port");
            got[idx] = true;
            received += 1;
        }
    }
    assert_eq!(received, NUM_PACKETS, "missing packets: {:?}", got);
    assert!(got.iter().all(|&g| g));
}
