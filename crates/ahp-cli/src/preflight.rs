// Favonius — high-performance file transfer over UDP
// Copyright (c) 2025-2026 Vantino SàRL
// SPDX-License-Identifier: Apache-2.0

//! `favonius check` — will this network carry a transfer?
//!
//! # Why this is a command and not a paragraph in the README
//!
//! The first thing that stops a Favonius deployment is not the security
//! review. It is the firewall. Enterprise ingress is closed by default,
//! reaching a daemon needs inbound UDP permitted, and plenty of policies
//! decline that outright. Without a way to find out early, the sequence is:
//! evaluate for a week, involve the security team, ask the network team for
//! a rule, wait three weeks, discover the answer is no.
//!
//! This turns that into a five-second answer at the start, and — when the
//! answer is bad — prints the sentence to send the network team rather
//! than leaving someone to compose it.
//!
//! # What it checks, and in what order
//!
//! 1. **DNS** — does the name resolve at all.
//! 2. **TCP to the control port** — the fallback path, and a cheap signal
//!    that something is listening rather than a black hole.
//! 3. **UDP to the control port** — the real data plane. A HELLO is sent
//!    and a reply awaited: the only honest test of a datagram path is a
//!    datagram that comes back.
//! 4. **UDP to the data port** — transfers move here after the handshake.
//!    An idle daemon does not read this socket, so **silence here is
//!    expected and is not a failure**. It is probed anyway because a
//!    reply, or an ICMP rejection, is still informative — and because a
//!    firewall that permits the control port and not the data port is
//!    common enough that the rule below must name both.
//!
//! UDP silence is ambiguous by nature — dropped by a firewall, dropped by
//! congestion, or nobody listening — and this says so rather than
//! reporting a definite failure it cannot prove. Reporting a healthy
//! daemon as unreachable would be worse than not checking: the first
//! draft did exactly that, before the daemon learned to answer the probe.

use std::net::{SocketAddr, ToSocketAddrs};
use std::time::{Duration, Instant};

/// How long to wait for a UDP reply before calling it silence.
const UDP_WAIT: Duration = Duration::from_millis(1500);
/// How long to wait for a TCP connection.
const TCP_WAIT: Duration = Duration::from_millis(3000);

#[derive(Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Confirmed working.
    Works,
    /// Confirmed not working, with a reason.
    Blocked(String),
    /// No answer. For UDP this is genuinely ambiguous.
    Silent,
    /// Could not be attempted.
    Skipped(String),
}

impl Verdict {
    fn mark(&self) -> &'static str {
        match self {
            Self::Works => "ok  ",
            Self::Blocked(_) => "FAIL",
            Self::Silent => "?   ",
            Self::Skipped(_) => "-   ",
        }
    }
}

pub struct Report {
    pub host: String,
    pub control_port: u16,
    pub data_port: u16,
    pub resolved: Option<SocketAddr>,
    pub tcp_control: Verdict,
    pub udp_control: Verdict,
    pub udp_data: Verdict,
}

impl Report {
    /// True when a transfer can happen by some route.
    pub fn transfer_possible(&self) -> bool {
        self.udp_control == Verdict::Works || self.tcp_control == Verdict::Works
    }
}

/// Run the checks against `host:port`.
///
/// `control_port` is the AHP control port (7801 by default); the data port
/// defaults to the next one up, matching the daemon's own defaults.
pub async fn run(host: &str, control_port: u16, data_port: u16) -> Report {
    let mut report = Report {
        host: host.to_string(),
        control_port,
        data_port,
        resolved: None,
        tcp_control: Verdict::Skipped("not attempted".into()),
        udp_control: Verdict::Skipped("not attempted".into()),
        udp_data: Verdict::Skipped("not attempted".into()),
    };

    // 1. DNS. Everything else is meaningless without it, so a failure
    //    here stops rather than producing three more confusing lines.
    let addr = match (host, control_port).to_socket_addrs() {
        Ok(mut it) => match it.next() {
            Some(a) => a,
            None => {
                report.tcp_control = Verdict::Blocked(format!("{host} resolved to no addresses"));
                return report;
            }
        },
        Err(e) => {
            report.tcp_control = Verdict::Blocked(format!("{host} does not resolve: {e}"));
            return report;
        }
    };
    report.resolved = Some(addr);

    report.tcp_control = check_tcp(addr).await;
    report.udp_control = check_udp(addr).await;

    let mut data_addr = addr;
    data_addr.set_port(data_port);
    report.udp_data = check_udp(data_addr).await;

    report
}

async fn check_tcp(addr: SocketAddr) -> Verdict {
    match tokio::time::timeout(TCP_WAIT, tokio::net::TcpStream::connect(addr)).await {
        Ok(Ok(_)) => Verdict::Works,
        Ok(Err(e)) => Verdict::Blocked(e.to_string()),
        Err(_) => Verdict::Silent,
    }
}

/// Probe a UDP port by sending a datagram and waiting for anything back.
///
/// The payload is a deliberately malformed AHP packet: a daemon that
/// receives it answers or errors, and either proves the round trip. What
/// matters is that a datagram left and a datagram returned — not what it
/// said.
async fn check_udp(addr: SocketAddr) -> Verdict {
    let bind: SocketAddr = if addr.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" }
        .parse()
        .expect("static bind address");

    let sock = match tokio::net::UdpSocket::bind(bind).await {
        Ok(s) => s,
        Err(e) => return Verdict::Skipped(format!("could not open a local socket: {e}")),
    };
    if let Err(e) = sock.connect(addr).await {
        return Verdict::Blocked(e.to_string());
    }

    // A probe the daemon will not mistake for a transfer, and answers
    // with a reply of exactly the same length.
    if let Err(e) = sock.send(ahp_proto::fallback::PROBE).await {
        return Verdict::Blocked(e.to_string());
    }

    let mut buf = [0u8; 2048];
    match tokio::time::timeout(UDP_WAIT, sock.recv(&mut buf)).await {
        Ok(Ok(_)) => Verdict::Works,
        // An ICMP port-unreachable surfaces here on Linux: something is
        // reachable and nothing is listening, which is a different problem
        // from a firewall and deserves a different message.
        Ok(Err(e)) => Verdict::Blocked(format!("{e} (nothing listening?)")),
        Err(_) => Verdict::Silent,
    }
}

/// Print the report, and what to do about it.
pub fn print(report: &Report) {
    let started = Instant::now();
    println!();
    println!("  Favonius connectivity check — {}", report.host);
    if let Some(a) = report.resolved {
        println!("  resolved to {}", a.ip());
    }
    println!();
    println!(
        "    [{}] TCP {:<5}  fallback path",
        report.tcp_control.mark(),
        report.control_port
    );
    println!(
        "    [{}] UDP {:<5}  control — handshake",
        report.udp_control.mark(),
        report.control_port
    );
    println!(
        "    [{}] UDP {:<5}  data — silent when idle, which is normal",
        report.udp_data.mark(),
        report.data_port
    );
    for (label, v) in [
        ("TCP control", &report.tcp_control),
        ("UDP control", &report.udp_control),
        ("UDP data", &report.udp_data),
    ] {
        match v {
            Verdict::Blocked(why) => println!("         {label}: {why}"),
            Verdict::Skipped(why) => println!("         {label}: {why}"),
            _ => {}
        }
    }
    println!();

    // The data port is judged only on a *definite* rejection. An idle
    // daemon does not read that socket, so silence there says nothing —
    // and treating it as failure would send an evaluator to their network
    // team over a working deployment.
    let data_rejected = matches!(report.udp_data, Verdict::Blocked(_));
    let udp_ok = report.udp_control == Verdict::Works && !data_rejected;
    let tcp_ok = report.tcp_control == Verdict::Works;

    if udp_ok {
        println!("  Transfers will use UDP, which is what Favonius is for.");
    } else if tcp_ok {
        println!("  UDP did not answer, so transfers will fall back to TCP.");
        println!("  They will work and they will be slower — the acceleration is in");
        println!("  the UDP path. To get it, ask for this rule:");
        println!();
        print_rule(report);
    } else {
        println!("  Nothing answered. A transfer to this host will not work yet.");
        println!();
        println!("  Check the daemon is running, then ask for this rule:");
        println!();
        print_rule(report);
    }

    if report.udp_control == Verdict::Silent {
        println!();
        println!("  Note: UDP silence is ambiguous — a firewall dropping the packet, a");
        println!("  daemon that is not running, and a lossy link look identical from");
        println!("  here. The TCP result above distinguishes the first from the second:");
        println!("  if TCP connects, something is listening and UDP is being filtered.");
    }
    if report.udp_data == Verdict::Silent && report.udp_control == Verdict::Works {
        println!();
        println!("  The data port did not answer, which is expected: an idle daemon");
        println!("  does not read it. It still has to be open — the rule above names");
        println!("  it — but this line is not a problem to chase.");
    }
    println!();
    let _ = started;
}

fn print_rule(report: &Report) {
    let host = report
        .resolved
        .map(|a| a.ip().to_string())
        .unwrap_or_else(|| report.host.clone());
    println!("      permit inbound UDP {} and {} to {}", report.control_port, report.data_port, host);
    println!("      permit inbound TCP {} to {}   (fallback)", report.control_port, host);
    println!();
    println!("  Per-stream ports: with `--streams N` the daemon may use a range");
    println!("  above {}. See `--data-port-range` on the daemon and the Firewall", report.data_port);
    println!("  Rules section of the README.");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_name_that_does_not_resolve_stops_early() {
        let r = run("this-host-does-not-exist.invalid", 7801, 7802).await;
        assert!(matches!(r.tcp_control, Verdict::Blocked(_)));
        assert_eq!(r.resolved, None);
        assert!(!r.transfer_possible());
    }

    #[tokio::test]
    async fn a_closed_tcp_port_is_blocked_not_silent() {
        // Port 1 on loopback: reachable, nothing listening. Distinguishing
        // this from a firewall drop is the whole value of the TCP probe.
        let r = check_tcp("127.0.0.1:1".parse().unwrap()).await;
        assert!(matches!(r, Verdict::Blocked(_)), "got {r:?}");
    }

    #[tokio::test]
    async fn a_listening_tcp_port_works() {
        // The control: without this, the test above passes for a checker
        // that reports everything as blocked.
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move { let _ = l.accept().await; });
        assert_eq!(check_tcp(addr).await, Verdict::Works);
    }

    #[tokio::test]
    async fn a_udp_port_that_answers_works() {
        let s = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = s.local_addr().unwrap();
        tokio::spawn(async move {
            let mut b = [0u8; 64];
            if let Ok((_, peer)) = s.recv_from(&mut b).await {
                let _ = s.send_to(b"pong", peer).await;
            }
        });
        assert_eq!(check_udp(addr).await, Verdict::Works);
    }

    #[test]
    fn transfer_is_possible_when_either_path_works() {
        let mut r = Report {
            host: "h".into(), control_port: 7801, data_port: 7802, resolved: None,
            tcp_control: Verdict::Silent,
            udp_control: Verdict::Silent,
            udp_data: Verdict::Silent,
        };
        assert!(!r.transfer_possible());
        r.tcp_control = Verdict::Works;
        assert!(r.transfer_possible(), "TCP alone must count as possible");
        r.tcp_control = Verdict::Silent;
        r.udp_control = Verdict::Works;
        assert!(r.transfer_possible(), "UDP alone must count as possible");
    }
}
