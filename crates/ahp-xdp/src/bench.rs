// Favonius — high-performance file transfer over UDP
// Copyright (c) 2025-2026 Vantino SàRL
// SPDX-License-Identifier: Apache-2.0

// Favonius: AF_XDP benchmark
// Usage: sudo cargo run -p ahp-xdp --example bench_xdp

use std::time::Instant;

use ahp_xdp::packet::PacketBuilder;
use ahp_xdp::socket::{XdpSocket, XdpSocketConfig};
use ahp_xdp::umem::{Umem, UmemConfig};

fn main() {
    println!("=== AF_XDP TX Benchmark ===\n");

    // Check probe.
    if !XdpSocket::probe() {
        eprintln!("AF_XDP not available (need root / CAP_NET_ADMIN)");
        std::process::exit(1);
    }
    println!("AF_XDP: supported");

    // Get veth-host interface index (from benchmark namespace).
    let ifname = std::env::args().nth(1).unwrap_or_else(|| "lo".into());
    let ifindex = get_ifindex(&ifname);
    println!("Interface: {} (ifindex={})", ifname, ifindex);

    // Allocate UMEM.
    let mut umem = Umem::new(&UmemConfig {
        frame_size: 4096,
        frame_count: 4096,
        fill_size: 2048,
        comp_size: 2048,
    }).expect("UMEM alloc");
    println!("UMEM: {} frames x {} bytes = {} MB",
        4096, 4096, 4096 * 4096 / 1_048_576);

    // Create socket.
    let config = XdpSocketConfig {
        ifindex,
        queue_id: 0,
        tx_size: 2048,
        fill_size: 2048,
        comp_size: 2048,
        zero_copy: false,
    };

    let mut sock = match XdpSocket::new(&mut umem, &config) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Socket creation failed: {}", e);
            eprintln!("(try: sudo, or a different interface)");
            std::process::exit(1);
        }
    };
    println!("Socket: created\n");

    // Build packet template.
    let builder = PacketBuilder {
        src_mac: ahp_xdp::packet::get_interface_mac(&ifname).unwrap_or([0; 6]),
        dst_mac: [0xFF; 6], // broadcast for testing
        src_ip: std::net::Ipv4Addr::new(10, 0, 0, 1),
        dst_ip: std::net::Ipv4Addr::new(10, 0, 0, 2),
        src_port: 12345,
        dst_port: 7801,
    };

    // Benchmark: submit N frames, measure throughput.
    let payload = [0xAA; 1400]; // Typical AHP packet size
    let n_packets: u64 = 100_000;
    let packet_size = ahp_xdp::packet::L2_L3_L4_OVERHEAD + payload.len();
    let total_bytes = n_packets * packet_size as u64;

    println!("Sending {} packets ({} bytes each, {} MB total)...",
        n_packets, packet_size, total_bytes / 1_048_576);

    let start = Instant::now();
    let mut sent = 0u64;
    let mut completed = 0u64;
    let batch_size = 64;

    while sent < n_packets {
        // Stage a batch.
        let batch_end = (sent + batch_size).min(n_packets);
        for _ in sent..batch_end {
            // Alloc a frame, build packet.
            let frame_idx = match umem.alloc_frame() {
                Ok(idx) => idx,
                Err(_) => {
                    // Out of frames — drain completions.
                    let addrs = sock.tx_complete();
                    for addr in &addrs {
                        let idx = (*addr / umem.frame_size() as u64) as u32;
                        umem.free_frame(idx);
                    }
                    completed += addrs.len() as u64;
                    match umem.alloc_frame() {
                        Ok(idx) => idx,
                        Err(_) => break, // Still no frames, skip
                    }
                }
            };

            let frame = umem.frame_slice_mut(frame_idx).expect("alloc_frame returned out-of-bounds frame");
            let len = builder.build_frame(frame, &payload);
            let addr = umem.frame_addr(frame_idx);

            if sock.tx_submit(addr, len as u32).is_err() {
                umem.free_frame(frame_idx);
                break;
            }
        }

        // Kick kernel.
        let _ = sock.tx_kick();
        sent = batch_end;

        // Drain completions periodically.
        if sent % (batch_size * 4) == 0 {
            let addrs = sock.tx_complete();
            for addr in &addrs {
                let idx = (*addr / umem.frame_size() as u64) as u32;
                umem.free_frame(idx);
            }
            completed += addrs.len() as u64;
        }
    }

    // Final drain.
    for _ in 0..100 {
        let addrs = sock.tx_complete();
        if addrs.is_empty() { break; }
        for addr in &addrs {
            let idx = (*addr / umem.frame_size() as u64) as u32;
            umem.free_frame(idx);
        }
        completed += addrs.len() as u64;
        std::thread::sleep(std::time::Duration::from_millis(1));
    }

    let elapsed = start.elapsed();
    let secs = elapsed.as_secs_f64();
    let mbps = (total_bytes as f64 / 1_048_576.0) / secs;
    let pps = sent as f64 / secs;

    println!("\n=== Results ===");
    println!("Sent:      {} packets", sent);
    println!("Completed: {} packets", completed);
    println!("Time:      {:.3}s", secs);
    println!("Throughput: {:.1} MB/s", mbps);
    println!("Packet rate: {:.0} pps", pps);
}

fn get_ifindex(name: &str) -> u32 {
    let path = format!("/sys/class/net/{}/ifindex", name);
    std::fs::read_to_string(&path)
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0)
}
