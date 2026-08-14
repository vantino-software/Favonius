// Favonius — high-performance file transfer over UDP
// Copyright (c) 2025-2026 Vantino SàRL
// SPDX-License-Identifier: Apache-2.0

//! Raw packet construction for AF_XDP.
//!
//! Builds complete Ethernet + IPv4 + UDP + AHP frames in UMEM frames.
//! All headers are constructed in userspace since AF_XDP bypasses the
//! kernel network stack.

use std::net::Ipv4Addr;

/// L2/L3/L4 overhead: Ethernet(14) + IPv4(20) + UDP(8) = 42 bytes.
pub const L2_L3_L4_OVERHEAD: usize = 14 + 20 + 8;

/// Ethernet + IPv4 + UDP packet builder for AF_XDP frames.
pub struct PacketBuilder {
    /// Source MAC address.
    pub src_mac: [u8; 6],
    /// Destination MAC address.
    pub dst_mac: [u8; 6],
    /// Source IP.
    pub src_ip: Ipv4Addr,
    /// Destination IP.
    pub dst_ip: Ipv4Addr,
    /// Source UDP port.
    pub src_port: u16,
    /// Destination UDP port.
    pub dst_port: u16,
}

impl PacketBuilder {
    /// Build a complete Ethernet + IPv4 + UDP frame in the provided buffer.
    ///
    /// Returns the total frame length (L2+L3+L4 headers + payload).
    /// The `payload` is the AHP packet (header + data).
    pub fn build_frame(&self, frame: &mut [u8], payload: &[u8]) -> usize {
        let total_len = L2_L3_L4_OVERHEAD + payload.len();
        assert!(frame.len() >= total_len);

        // ── Ethernet header (14 bytes) ──────────────────────────────
        frame[0..6].copy_from_slice(&self.dst_mac);
        frame[6..12].copy_from_slice(&self.src_mac);
        frame[12..14].copy_from_slice(&(0x0800u16).to_be_bytes()); // EtherType: IPv4

        // ── IPv4 header (20 bytes, no options) ──────────────────────
        let ip_total = (20 + 8 + payload.len()) as u16;
        let ip = &mut frame[14..34];
        ip[0] = 0x45;              // Version(4) + IHL(5)
        ip[1] = 0;                 // DSCP + ECN
        ip[2..4].copy_from_slice(&ip_total.to_be_bytes()); // Total length
        ip[4..6].copy_from_slice(&0u16.to_be_bytes());     // Identification
        ip[6..8].copy_from_slice(&0x4000u16.to_be_bytes()); // Flags: Don't Fragment
        ip[8] = 64;               // TTL
        ip[9] = 17;               // Protocol: UDP
        ip[10..12].copy_from_slice(&0u16.to_be_bytes());   // Checksum (0 = let NIC offload)
        ip[12..16].copy_from_slice(&self.src_ip.octets());
        ip[16..20].copy_from_slice(&self.dst_ip.octets());

        // Compute IP header checksum.
        let cksum = ip_checksum(&frame[14..34]);
        frame[24..26].copy_from_slice(&cksum.to_be_bytes());

        // ── UDP header (8 bytes) ────────────────────────────────────
        let udp_len = (8 + payload.len()) as u16;
        let udp = &mut frame[34..42];
        udp[0..2].copy_from_slice(&self.src_port.to_be_bytes());
        udp[2..4].copy_from_slice(&self.dst_port.to_be_bytes());
        udp[4..6].copy_from_slice(&udp_len.to_be_bytes());
        udp[6..8].copy_from_slice(&0u16.to_be_bytes()); // Checksum 0 (optional for IPv4 UDP)

        // ── Payload (AHP packet) ────────────────────────────────────
        frame[42..42 + payload.len()].copy_from_slice(payload);

        total_len
    }

    /// Build a frame with the AHP payload already in place at offset 42.
    /// Only writes the L2/L3/L4 headers — avoids copying the payload.
    pub fn build_headers_only(&self, frame: &mut [u8], payload_len: usize) -> usize {
        let total_len = L2_L3_L4_OVERHEAD + payload_len;

        // Ethernet
        frame[0..6].copy_from_slice(&self.dst_mac);
        frame[6..12].copy_from_slice(&self.src_mac);
        frame[12..14].copy_from_slice(&(0x0800u16).to_be_bytes());

        // IPv4
        let ip_total = (20 + 8 + payload_len) as u16;
        let ip = &mut frame[14..34];
        ip[0] = 0x45;
        ip[1] = 0;
        ip[2..4].copy_from_slice(&ip_total.to_be_bytes());
        ip[4..6].copy_from_slice(&0u16.to_be_bytes());
        ip[6..8].copy_from_slice(&0x4000u16.to_be_bytes());
        ip[8] = 64;
        ip[9] = 17;
        ip[10..12].copy_from_slice(&0u16.to_be_bytes());
        ip[12..16].copy_from_slice(&self.src_ip.octets());
        ip[16..20].copy_from_slice(&self.dst_ip.octets());

        let cksum = ip_checksum(&frame[14..34]);
        frame[24..26].copy_from_slice(&cksum.to_be_bytes());

        // UDP
        let udp_len = (8 + payload_len) as u16;
        let udp = &mut frame[34..42];
        udp[0..2].copy_from_slice(&self.src_port.to_be_bytes());
        udp[2..4].copy_from_slice(&self.dst_port.to_be_bytes());
        udp[4..6].copy_from_slice(&udp_len.to_be_bytes());
        udp[6..8].copy_from_slice(&0u16.to_be_bytes());

        total_len
    }
}

/// Compute IPv4 header checksum (RFC 1071 one's complement sum).
fn ip_checksum(header: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for i in (0..header.len()).step_by(2) {
        let word = if i + 1 < header.len() {
            ((header[i] as u32) << 8) | (header[i + 1] as u32)
        } else {
            (header[i] as u32) << 8
        };
        sum += word;
    }
    // Fold carries.
    while sum > 0xFFFF {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// Resolve the MAC address of a gateway/neighbor via ARP cache.
/// Falls back to broadcast if not found.
pub fn resolve_mac(ip: Ipv4Addr) -> [u8; 6] {
    // Read /proc/net/arp for the IP.
    if let Ok(arp) = std::fs::read_to_string("/proc/net/arp") {
        let ip_str = ip.to_string();
        for line in arp.lines().skip(1) {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() >= 4 && fields[0] == ip_str {
                if let Ok(mac) = parse_mac(fields[3]) {
                    return mac;
                }
            }
        }
    }
    // Broadcast fallback.
    [0xFF; 6]
}

/// Get the MAC address of a local interface.
pub fn get_interface_mac(ifname: &str) -> Result<[u8; 6], std::io::Error> {
    let path = format!("/sys/class/net/{}/address", ifname);
    let mac_str = std::fs::read_to_string(path)?.trim().to_string();
    parse_mac(&mac_str).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
}

fn parse_mac(s: &str) -> Result<[u8; 6], String> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 6 {
        return Err(format!("invalid MAC: {s}"));
    }
    let mut mac = [0u8; 6];
    for (i, p) in parts.iter().enumerate() {
        mac[i] = u8::from_str_radix(p, 16).map_err(|e| format!("bad MAC octet: {e}"))?;
    }
    Ok(mac)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ip_checksum_rfc() {
        // RFC 1071 example.
        let header = [
            0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00,
            0x40, 0x11, 0x00, 0x00, 0xC0, 0xA8, 0x00, 0x01,
            0xC0, 0xA8, 0x00, 0xC7,
        ];
        let cksum = ip_checksum(&header);
        assert_ne!(cksum, 0);
    }

    #[test]
    fn build_frame_roundtrip() {
        let builder = PacketBuilder {
            src_mac: [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            dst_mac: [0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB],
            src_ip: Ipv4Addr::new(10, 0, 0, 1),
            dst_ip: Ipv4Addr::new(10, 0, 0, 2),
            src_port: 12345,
            dst_port: 7801,
        };

        let payload = [0xAA; 100];
        let mut frame = [0u8; 2048];
        let len = builder.build_frame(&mut frame, &payload);

        assert_eq!(len, L2_L3_L4_OVERHEAD + 100);
        // Check EtherType.
        assert_eq!(frame[12], 0x08);
        assert_eq!(frame[13], 0x00);
        // Check IP protocol = UDP.
        assert_eq!(frame[23], 17);
        // Check dst port.
        assert_eq!(u16::from_be_bytes([frame[36], frame[37]]), 7801);
        // Check payload.
        assert_eq!(frame[42], 0xAA);
    }
}
