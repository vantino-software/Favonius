// Favonius — high-performance file transfer over UDP
// Copyright (c) 2025-2026 Vantino SàRL
// SPDX-License-Identifier: Apache-2.0

//! AHP congestion control algorithms.
//!
//! Provides three congestion control profiles for the Adaptive Hybrid Protocol:
//!
//! - **Classic**: Hybrid delay/rate-based algorithm that uses RTT inflation to
//!   detect congestion before loss, with a loss-based fallback.
//! - **Model**: BBR-inspired model-based algorithm that maintains estimates of
//!   bottleneck bandwidth and minimum RTT.
//! - **Fair**: Conservative AIMD algorithm designed to be TCP-friendly on
//!   shared networks, with optional rate capping.

pub mod classic;
pub mod pathsim;
pub mod fair;
pub mod metrics;
pub mod model;
pub mod pacer;
pub mod rl;
pub mod udt;
pub mod wifi;

use std::fmt;
use std::time::{Duration, Instant};

/// Congestion control profile selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CongestionProfile {
    /// Hybrid delay and rate-based. Good default for most scenarios.
    Classic,
    /// BBR-inspired model-based. Best for high-bandwidth, long-RTT paths.
    Model,
    /// Conservative AIMD. TCP-friendly for shared networks.
    Fair,
    /// Rate probing tolerant of non-congestion loss; for dedicated
    /// wireless LANs.
    Wifi,
    /// UDT-style rate-based CC. Gentle loss response (~11% decrease).
    Udt,
    /// Probe/drain/cruise gain cycle over a windowed-max delivery
    /// estimate. Named `Rl` for history and selected as `cycle`; **no
    /// learned policy ships** — the MLP path is dead code in the shipped
    /// configuration, and nine attempts at a learned policy failed to beat
    /// the fixed cycle.
    Rl,
}

impl fmt::Display for CongestionProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CongestionProfile::Classic => write!(f, "Classic"),
            CongestionProfile::Model => write!(f, "Model"),
            CongestionProfile::Fair => write!(f, "Fair"),
            CongestionProfile::Wifi => write!(f, "Wifi"),
            CongestionProfile::Udt => write!(f, "Udt"),
            // The profile is documented as `cycle`; `Rl` is the historical
            // name kept as a CLI alias. Printing "Rl" made `--congestion
            // cycle` echo a name the docs no longer use.
            CongestionProfile::Rl => write!(f, "Cycle"),
        }
    }
}

impl CongestionProfile {
    /// Parse a profile name, accepting the historical aliases. `None` for
    /// anything unrecognised — every caller has a different right answer
    /// for that (the CLI rejects, a policy file warns and keeps what it
    /// had), so this does not choose one.
    ///
    /// One list, because there are three places that need it — the CLI
    /// argument, the adaptive policy's `cc_profile` string, and the `auto`
    /// default's lookup of the policy's per-link choice — and three copies
    /// of a mapping like this drift silently. They already had: the CLI
    /// rejected an unknown name while the policy path substituted one.
    pub fn from_name(name: &str) -> Option<Self> {
        Some(match name {
            "classic" | "cubic" => CongestionProfile::Classic,
            "model" | "bbr" => CongestionProfile::Model,
            "fair" | "aimd" => CongestionProfile::Fair,
            "wifi" => CongestionProfile::Wifi,
            "udt" => CongestionProfile::Udt,
            // `cycle` is the accurate name: a probe/drain/cruise gain cycle
            // with no learned component. `rl` is what it shipped as.
            "cycle" | "rl" => CongestionProfile::Rl,
            _ => return None,
        })
    }

    /// The names accepted by [`from_name`](Self::from_name), for error
    /// messages, so a new profile cannot be added without the help text
    /// following it.
    pub const NAMES: &'static str = "classic, model, fair, wifi, udt, cycle";
}

/// Information about an acknowledged packet, provided by the transport layer.
///
/// Packet numbers throughout this trait are **global chunk indices**, not wire
/// sequence numbers: loss detection happens in chunk-index space, and the wire
/// sequence grows faster than the chunk index space (retransmits consume extra
/// sequence numbers), which would distort epoch/round tracking.
#[derive(Debug, Clone)]
pub struct AckInfo {
    /// The packet number (global chunk index) being acknowledged.
    pub packet_number: u64,
    /// The delay between receiving the packet and sending the ACK (reported by peer).
    pub ack_delay: Duration,
    /// Number of bytes delivered by this ACK.
    pub delivered_bytes: u64,
    /// Delivery rate estimated at the receiver (bytes per second), or 0 if unknown.
    pub delivery_rate: u64,
}

/// Aggregated path metrics for monitoring and diagnostics.
#[derive(Debug, Clone)]
pub struct PathMetrics {
    /// Smoothed round-trip time estimate.
    pub smoothed_rtt: Option<Duration>,
    /// Minimum RTT observed.
    pub min_rtt: Option<Duration>,
    /// Latest RTT sample.
    pub latest_rtt: Duration,
    /// RTT variance.
    pub rtt_var: Duration,
    /// Current congestion window in bytes.
    pub congestion_window: usize,
    /// Current send rate in bytes per second, if pacing is active.
    pub send_rate: Option<u64>,
    /// Recent loss rate (0.0 to 1.0).
    pub loss_rate: f64,
    /// Estimated bandwidth in bytes per second.
    pub bandwidth_estimate: u64,
}

/// Core trait for congestion controllers.
///
/// Implementations receive feedback from the transport layer (sent packets,
/// ACKs, losses, RTT samples) and compute sending constraints (congestion
/// window, pacing rate).
pub trait CongestionController: Send + fmt::Debug {
    /// Called when a packet is sent. `packet_number` is the global chunk
    /// index of the chunk being (re-)sent; retransmits re-report the same
    /// index, so implementations should treat it as a high-water mark.
    fn on_packet_sent(&mut self, packet_number: u64, bytes: usize, now: Instant);

    /// Called when an ACK is received.
    fn on_ack_received(&mut self, acked: &AckInfo, now: Instant);

    /// Called when packets are detected as lost. `lost` holds global chunk
    /// indices. Reports may repeat for the same chunk across congestion
    /// epochs; implementations are expected to suppress duplicate reactions
    /// within one epoch.
    fn on_packet_lost(&mut self, lost: &[u64], now: Instant);

    /// Returns the current congestion window in bytes.
    fn congestion_window(&self) -> usize;

    /// Returns the current send rate in bytes per second, if pacing is active.
    fn send_rate(&self) -> Option<u64>;

    /// Returns whether a new packet can be sent given the current bytes in flight.
    fn can_send(&self, bytes_in_flight: usize) -> bool;

    /// Called when a new RTT sample is available.
    fn on_rtt_update(&mut self, rtt: Duration);

    /// Returns the recommended pacing interval between packets of the given size.
    fn pacing_interval(&self, packet_size: usize) -> Duration;

    // `seed_bandwidth` was here. It bootstrapped a controller from "probe
    // data" that was never measured: the sender passed
    // `min_cwnd_floor / base_rtt`, and the floor is a minimum window, not
    // a bottleneck. Controllers set their pacing rate and their startup
    // plateau baseline from it, so the fabricated figure became a ceiling
    // on measured delivery and the estimator locked onto it -- Model held
    // 52.8% of a link it reaches 87.5% of unseeded, and 0.3% on a
    // longer-RTT path. Removed rather than fixed, because nothing in the
    // probe measures bandwidth for it to carry. Startup finds the
    // bottleneck in ~10 round trips.

    /// Feed an ACK batch's mean and minimum RTT separately.
    ///
    /// The default routes the mean to `on_rtt_update`, which is the
    /// correct signal for anything delay-based; controllers that hold an
    /// `RttEstimator` should override to keep an unqueued minimum too.
    fn on_rtt_batch(&mut self, mean: Duration, _min: Duration) {
        self.on_rtt_update(mean);
    }

    /// One line of controller-internal state for operational tracing, if
    /// the controller has any worth reporting.
    ///
    /// `congestion_window()` alone cannot explain a transition, and the
    /// interesting failures are all transitions. Default is `None`.
    fn diag_line(&self) -> Option<String> {
        None
    }

    /// Whether this CC wants timeout-driven loss signals. Rate-based CCs
    /// (UDT) should return false — they only respond to receiver-detected
    /// loss (NACKs/ACK gaps), not sender-side retransmit timeouts.
    /// Receiver-detected loss (NACK ranges) is always delivered via
    /// `on_packet_lost` regardless of this flag.
    fn wants_timeout_loss(&self) -> bool { true }

    /// Which internal transition ended the controller's startup phase, if
    /// it has one and it has ended. Diagnostic only — never consulted by
    /// the transport, and returning None is always correct.
    fn exit_reason(&self) -> Option<&'static str> { None }
}

/// Create a congestion controller for the given profile.
pub fn create_controller(profile: CongestionProfile) -> Box<dyn CongestionController> {
    match profile {
        CongestionProfile::Classic => {
            tracing::info!("creating Classic congestion controller");
            Box::new(classic::ClassicController::new())
        }
        CongestionProfile::Model => {
            tracing::info!("creating Model (BBR-like) congestion controller");
            Box::new(model::ModelController::new())
        }
        CongestionProfile::Fair => {
            tracing::info!("creating Fair (AIMD) congestion controller");
            Box::new(fair::FairController::new())
        }
        CongestionProfile::Wifi => {
            tracing::info!("creating WiFi (fixed-rate) congestion controller");
            Box::new(wifi::WifiController::new())
        }
        CongestionProfile::Udt => {
            tracing::info!("creating UDT (rate-based) congestion controller");
            Box::new(udt::UdtController::new())
        }
        CongestionProfile::Rl => {
            tracing::info!("creating RL (learned) congestion controller");
            Box::new(rl::RlController::new())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_classic_controller() {
        let cc = create_controller(CongestionProfile::Classic);
        assert!(cc.congestion_window() > 0);
        assert!(cc.can_send(0));
    }

    #[test]
    fn create_model_controller() {
        let cc = create_controller(CongestionProfile::Model);
        assert!(cc.congestion_window() > 0);
        assert!(cc.can_send(0));
    }

    #[test]
    fn create_fair_controller() {
        let cc = create_controller(CongestionProfile::Fair);
        assert!(cc.congestion_window() > 0);
        assert!(cc.can_send(0));
    }

    #[test]
    fn congestion_profile_display() {
        assert_eq!(CongestionProfile::Classic.to_string(), "Classic");
        assert_eq!(CongestionProfile::Model.to_string(), "Model");
        assert_eq!(CongestionProfile::Fair.to_string(), "Fair");
        assert_eq!(CongestionProfile::Udt.to_string(), "Udt");
        // The enum variant is still `Rl`; the user-facing name is `cycle`.
        // Printing "Rl" made `--congestion cycle` echo a name no document
        // uses any more.
        assert_eq!(CongestionProfile::Rl.to_string(), "Cycle");
    }

    #[test]
    fn all_controllers_handle_full_lifecycle() {
        for profile in [
            CongestionProfile::Classic,
            CongestionProfile::Model,
            CongestionProfile::Fair,
            CongestionProfile::Udt,
            CongestionProfile::Rl,
        ] {
            let mut cc = create_controller(profile);
            let now = Instant::now();

            // RTT update.
            cc.on_rtt_update(Duration::from_millis(50));

            // Send packets.
            for i in 0..5 {
                cc.on_packet_sent(i, 1200, now + Duration::from_millis(i * 10));
            }

            // ACK some.
            let ack = AckInfo {
                packet_number: 2,
                ack_delay: Duration::from_millis(5),
                delivered_bytes: 3600,
                delivery_rate: 1_000_000,
            };
            cc.on_ack_received(&ack, now + Duration::from_millis(60));

            // Lose some.
            cc.on_packet_lost(&[3, 4], now + Duration::from_millis(120));

            // Verify still functional.
            assert!(cc.congestion_window() > 0);
            let _ = cc.send_rate();
            let _ = cc.pacing_interval(1200);
        }
    }

    #[test]
    fn ack_info_construction() {
        let info = AckInfo {
            packet_number: 42,
            ack_delay: Duration::from_millis(10),
            delivered_bytes: 2400,
            delivery_rate: 500_000,
        };
        assert_eq!(info.packet_number, 42);
        assert_eq!(info.delivered_bytes, 2400);
    }

    #[test]
    fn path_metrics_construction() {
        let metrics = PathMetrics {
            smoothed_rtt: Some(Duration::from_millis(50)),
            min_rtt: Some(Duration::from_millis(40)),
            latest_rtt: Duration::from_millis(55),
            rtt_var: Duration::from_millis(5),
            congestion_window: 12000,
            send_rate: Some(240_000),
            loss_rate: 0.01,
            bandwidth_estimate: 1_000_000,
        };
        assert_eq!(metrics.congestion_window, 12000);
        assert!(metrics.loss_rate < 0.02);
    }
}
