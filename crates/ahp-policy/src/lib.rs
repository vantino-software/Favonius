// Favonius — high-performance file transfer over UDP
// Copyright (c) 2025-2026 Vantino SàRL
// SPDX-License-Identifier: Apache-2.0

//! Adaptive transfer policy engine for AHP.
//!
//! Uses hill-climbing optimisation to learn good transfer parameters
//! (retransmission timeout, congestion window floor, batch size, ACK
//! interval) for each observed network context.  Training records are
//! persisted as JSON so improvements carry over across runs.

use std::path::{Path, PathBuf};

/// Maximum number of training records retained per link type.
///
/// `suggest_params` only needs the best-scoring record per similar context,
/// and hill-climbing means recent records dominate older ones, so a few
/// hundred records per link type is ample.  Bounding the history also keeps
/// `save()` (an O(n) full-file rewrite on every record) from degenerating
/// into O(n^2) total write work as records accumulate.
const MAX_RECORDS_PER_LINK_TYPE: usize = 256;

/// Link type vocabulary shared between the policy engine and the CLI path
/// prober (`ahp-cli::net_probe`).
///
/// The canonical string forms are the values persisted in `policy.json`
/// training records; they must never change, or existing history files would
/// stop matching.
///
/// Backward-compatibility rule: deserializing an unrecognized string yields
/// [`LinkType::Unknown`] rather than an error, so history files containing
/// link types written by newer (or older) versions still load.  Re-saving
/// such a record rewrites the raw string as `"unknown"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LinkType {
    /// Loopback — sub-millisecond RTT, no real network.
    Loopback,
    /// Wired LAN — low RTT, low jitter.
    LanEthernet,
    /// WiFi LAN — low RTT but high jitter / spurious loss.
    LanWifi,
    /// Wide-area network — high RTT.
    Wan,
    /// Could not classify, or a link type string this version does not know.
    Unknown,
}

impl LinkType {
    /// The canonical string persisted in `policy.json`.
    pub fn as_str(&self) -> &'static str {
        match self {
            LinkType::Loopback => "loopback",
            LinkType::LanEthernet => "LAN/ethernet",
            LinkType::LanWifi => "LAN/wifi",
            LinkType::Wan => "WAN",
            LinkType::Unknown => "unknown",
        }
    }
}

impl std::fmt::Display for LinkType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for LinkType {
    type Err = String;

    /// Strict parse: only the canonical strings are accepted.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "loopback" => Ok(LinkType::Loopback),
            "LAN/ethernet" => Ok(LinkType::LanEthernet),
            "LAN/wifi" => Ok(LinkType::LanWifi),
            "WAN" => Ok(LinkType::Wan),
            "unknown" => Ok(LinkType::Unknown),
            other => Err(format!("unknown link type: {:?}", other)),
        }
    }
}

impl serde::Serialize for LinkType {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for LinkType {
    /// Lenient parse: unrecognized strings map to [`LinkType::Unknown`]
    /// instead of failing, so existing history files always load.
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = <String as serde::Deserialize>::deserialize(deserializer)?;
        Ok(s.parse().unwrap_or(LinkType::Unknown))
    }
}

/// Tunable transfer parameters for AHP connections.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PolicyParams {
    /// Retransmission timeout in milliseconds (default: 100).
    pub retx_timeout_ms: u64,
    /// Minimum congestion window in KB (default varies by link type).
    pub min_cwnd_kb: usize,
    /// Maximum packets sent per batch (default: 32).
    pub batch_size: usize,
    /// Interval between progress ACKs in NACK mode, in ms (default: 75).
    pub progress_ack_interval_ms: u64,
    /// Congestion control profile: any name `ahp-congestion` accepts —
    /// "classic", "model", "fair", "wifi", "udt", "cycle" (alias "rl").
    /// The list lived here as three of those and drifted; the authority is
    /// `CongestionProfile::from_name`, which every reader now goes through.
    #[serde(default = "default_cc_profile")]
    pub cc_profile: String,
    /// ACK mode: "bitmap" or "nack".
    #[serde(default = "default_ack_mode")]
    pub ack_mode: String,
    /// UDP socket send/receive buffer size in KB (default: 208).
    #[serde(default = "default_socket_buf_kb")]
    pub socket_buf_kb: usize,
    /// Max data payload per UDP packet in bytes (default: 1350).
    #[serde(default = "default_payload_size")]
    pub payload_size: usize,
    /// Number of parallel streams for multi-stream multiplexing (default: 4).
    #[serde(default = "default_num_streams")]
    pub num_streams: u32,
}

fn default_cc_profile() -> String { "classic".into() }
fn default_ack_mode() -> String { "bitmap".into() }
fn default_socket_buf_kb() -> usize { 208 }
fn default_payload_size() -> usize { 1350 }
fn default_num_streams() -> u32 { 4 }

impl Default for PolicyParams {
    fn default() -> Self {
        Self {
            retx_timeout_ms: 100,
            min_cwnd_kb: 128,
            batch_size: 32,
            progress_ack_interval_ms: 75,
            cc_profile: "classic".into(),
            ack_mode: "bitmap".into(),
            socket_buf_kb: 208,
            payload_size: 1350,
            num_streams: 4,
        }
    }
}

/// Observed network properties that parameterize policy selection.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct NetworkContext {
    /// Canonical link type string — one of "loopback", "LAN/ethernet",
    /// "LAN/wifi", "WAN", "unknown" (see [`LinkType`]).
    ///
    /// Kept as a raw string because this is the persisted form in
    /// `policy.json`; use [`Self::link_type`] for the typed value.
    pub link_type: String,
    /// Baseline round-trip time in microseconds.
    pub base_rtt_us: u64,
    /// Jitter (variation in RTT) in microseconds.
    pub jitter_us: u64,
    /// Observed packet loss rate (0.0 .. 1.0).
    pub loss_rate: f64,
}

impl NetworkContext {
    /// The typed link type.  Unrecognized strings map to
    /// [`LinkType::Unknown`] (same rule as [`LinkType`]'s deserialization).
    pub fn link_type(&self) -> LinkType {
        self.link_type.parse().unwrap_or(LinkType::Unknown)
    }
}

/// A single training observation pairing a context + params with the outcome.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct TrainingRecord {
    context: NetworkContext,
    params: PolicyParams,
    /// Throughput in bytes/sec achieved with these params.
    throughput: f64,
    /// Retransmit ratio (retx / total_packets).
    retx_ratio: f64,
    /// Composite score: throughput * (1.0 - retx_ratio).
    score: f64,
}

impl TrainingRecord {
    /// A record is usable when all its measured values are finite and in
    /// range.  Records failing this (e.g. NaN scores persisted by older
    /// versions) must never reach the argmax in `suggest_params`.
    fn is_valid(&self) -> bool {
        self.throughput.is_finite()
            && self.throughput >= 0.0
            && self.retx_ratio.is_finite()
            && (0.0..=1.0).contains(&self.retx_ratio)
            && self.score.is_finite()
            && self.score >= 0.0
    }
}

/// The main adaptive policy engine.
///
/// Maintains a history of [`TrainingRecord`]s and uses hill-climbing
/// optimisation to converge on good transfer parameters for each
/// observed [`NetworkContext`].
pub struct AdaptivePolicy {
    records: Vec<TrainingRecord>,
    config_path: PathBuf,
}

impl AdaptivePolicy {
    /// Create a new policy engine, loading any previously saved records from
    /// `config_path` (a JSON file).  If the file does not exist the engine
    /// starts with an empty history.  If the file exists but cannot be
    /// parsed it is moved aside to `<config_path>.corrupt` (with a warning
    /// log) and the engine starts fresh — history is never silently
    /// discarded.
    ///
    /// Records with non-finite or negative scores/throughput (e.g. written
    /// by older, unvalidated versions) are filtered out on load so they
    /// cannot poison the argmax in [`Self::suggest_params`].
    pub fn new(config_path: PathBuf) -> Self {
        let records = match std::fs::read_to_string(&config_path) {
            Ok(data) => match serde_json::from_str::<Vec<TrainingRecord>>(&data) {
                Ok(records) => {
                    let before = records.len();
                    let records: Vec<_> =
                        records.into_iter().filter(|r| r.is_valid()).collect();
                    let dropped = before - records.len();
                    if dropped > 0 {
                        tracing::warn!(
                            dropped,
                            path = %config_path.display(),
                            "ahp-policy: dropped invalid history records on load"
                        );
                    }
                    records
                }
                Err(e) => {
                    let backup = corrupt_backup_path(&config_path);
                    tracing::warn!(
                        path = %config_path.display(),
                        backup = %backup.display(),
                        error = %e,
                        "ahp-policy: unparsable history file; moving it aside and starting fresh"
                    );
                    if let Err(e) = std::fs::rename(&config_path, &backup) {
                        tracing::warn!(
                            error = %e,
                            "ahp-policy: failed to move corrupt history file aside"
                        );
                    }
                    Vec::new()
                }
            },
            Err(e) => {
                if e.kind() != std::io::ErrorKind::NotFound {
                    tracing::warn!(
                        path = %config_path.display(),
                        error = %e,
                        "ahp-policy: history file unreadable; starting fresh"
                    );
                }
                Vec::new()
            }
        };

        Self {
            records,
            config_path,
        }
    }

    /// Persist the current set of records to disk as JSON.
    ///
    /// The write is atomic: records are serialized to a uniquely-named
    /// temporary file in the same directory, fsynced, then renamed over
    /// `config_path`, so a crash mid-save can never leave a truncated
    /// history file.  The directory is fsynced afterwards (best-effort) so
    /// the rename itself is durable.
    pub fn save(&self) -> Result<(), std::io::Error> {
        use std::io::Write;

        let json = serde_json::to_string_pretty(&self.records)
            .map_err(std::io::Error::other)?;

        // Ensure the parent directory exists.
        if let Some(parent) = self.config_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let tmp_path = self
            .config_path
            .with_extension(format!("tmp.{}", std::process::id()));

        {
            let mut file = std::fs::File::create(&tmp_path)?;
            file.write_all(json.as_bytes())?;
            file.sync_all()?;
        }
        std::fs::rename(&tmp_path, &self.config_path)?;

        // Best-effort directory fsync so the rename survives a crash.
        if let Some(parent) = self.config_path.parent() {
            if let Ok(dir) = std::fs::File::open(parent) {
                let _ = dir.sync_all();
            }
        }

        Ok(())
    }

    /// Suggest the best known params for the given [`NetworkContext`].
    ///
    /// The highest-scoring record with a *similar* context (same
    /// `link_type`, `base_rtt` within 2x) wins — **but only if the link-type
    /// defaults have been tried and beaten**. Otherwise the defaults are
    /// returned.
    ///
    /// The `has_beaten_anchor` condition is the whole point, and its
    /// absence made this function actively harmful. History used to win
    /// whenever it was non-empty, so the first few transfers populated a
    /// region and every later transfer was pinned inside it: hill-climbing
    /// perturbs one parameter at a time from the current best, and it
    /// cannot cross a valley three parameters wide.
    ///
    /// Measured 2026-08-12: on a wifi link, `--adaptive` ran at **7.7 MB/s
    /// against 40.9** without it — a 5x penalty for passing the flag whose
    /// purpose is to go faster — because 36 stored records all carried
    /// `batch=32 cwnd=128KB sock=208KB` and the link-type row
    /// (`batch=128 cwnd=512KB sock=2048KB`) appeared in none of them. On a
    /// WAN path with no history it was 19% down, which is the same defect
    /// with less time to compound.
    ///
    /// The anchor is also the answer to stale history: a record scored on a
    /// good radio day pins the parameters on a bad one, and nothing in an
    /// argmax over history notices that the *conditions* changed. Requiring
    /// history to have out-scored the anchor at least once means a table
    /// nobody has beaten is never trusted.
    pub fn suggest_params(&self, ctx: &NetworkContext) -> PolicyParams {
        let link_type = ctx.link_type();
        let anchor = defaults_for_link_type(link_type);

        let similar = || {
            self.records.iter().filter(|r| {
                r.context.link_type == ctx.link_type
                    && rtts_are_similar(r.context.base_rtt_us, ctx.base_rtt_us)
            })
        };

        // The best score achieved *by the anchor itself* on this link.
        // `None` means it has never been tried here, so it is what to try.
        let anchor_score = similar()
            .filter(|r| params_match_anchor(&r.params, &anchor))
            .map(|r| r.score)
            .fold(None::<f64>, |acc, s| Some(acc.map_or(s, |a: f64| a.max(s))));

        let best = similar()
            .max_by(|a, b| a.score.partial_cmp(&b.score).unwrap_or(std::cmp::Ordering::Equal));

        match (best, anchor_score) {
            // History exists and has out-scored the link-type defaults.
            (Some(record), Some(anchor_best)) if record.score > anchor_best => record.params.clone(),
            // History exists but the anchor has never been tried, or never
            // beaten: use the anchor. This is what breaks the pin.
            _ => anchor,
        }
    }

    /// Record the outcome of a transfer attempt.  The composite score is
    /// computed as `throughput * (1.0 - retx_ratio)` and the record is
    /// appended and saved to disk.
    ///
    /// Returns `true` when the record was accepted.  Outcomes with
    /// non-finite or out-of-range values (NaN/infinite/negative throughput,
    /// `retx_ratio` outside \[0, 1\]) are **rejected** — not recorded and
    /// not saved — because a NaN score compares "equal" during the argmax
    /// in [`Self::suggest_params`] and would permanently poison future
    /// suggestions.
    ///
    /// History is capped at [`MAX_RECORDS_PER_LINK_TYPE`] records per link
    /// type; the oldest records of that link type are evicted first.
    pub fn record_outcome(
        &mut self,
        ctx: NetworkContext,
        params: PolicyParams,
        throughput: f64,
        retx_ratio: f64,
    ) -> bool {
        if !throughput.is_finite() || throughput < 0.0 {
            tracing::warn!(
                throughput,
                "ahp-policy: rejecting outcome with invalid throughput"
            );
            return false;
        }
        if !retx_ratio.is_finite() || !(0.0..=1.0).contains(&retx_ratio) {
            tracing::warn!(
                retx_ratio,
                "ahp-policy: rejecting outcome with invalid retx_ratio"
            );
            return false;
        }

        let score = throughput * (1.0 - retx_ratio);
        self.records.push(TrainingRecord {
            context: ctx,
            params,
            throughput,
            retx_ratio,
            score,
        });
        self.enforce_history_cap();

        // Best-effort save -- callers may also call save() explicitly.
        let _ = self.save();
        true
    }

    /// Evict the oldest records of any link type that exceeds
    /// [`MAX_RECORDS_PER_LINK_TYPE`].
    fn enforce_history_cap(&mut self) {
        let mut counts: std::collections::HashMap<&str, usize> =
            std::collections::HashMap::new();
        for r in &self.records {
            *counts.entry(r.context.link_type.as_str()).or_insert(0) += 1;
        }
        // Number of records to drop per over-cap link type.  Records are
        // oldest-first, so dropping the first `excess` matches of each
        // over-cap type evicts the oldest.
        let mut excess: std::collections::HashMap<String, usize> = counts
            .into_iter()
            .filter_map(|(k, n)| {
                n.checked_sub(MAX_RECORDS_PER_LINK_TYPE)
                    .map(|e| (k.to_string(), e))
            })
            .collect();
        if excess.is_empty() {
            return;
        }
        self.records.retain(|r| {
            match excess.get_mut(r.context.link_type.as_str()) {
                Some(e) if *e > 0 => {
                    *e -= 1;
                    false
                }
                _ => true,
            }
        });
    }

    /// Return a perturbed copy of `base` for exploration.
    ///
    /// One parameter is chosen at random.  Numeric parameters are multiplied
    /// by a factor drawn uniformly from \[0.7, 1.3\] and clamped to their
    /// valid range.  Categorical parameters are randomly swapped to a
    /// different value.
    pub fn explore_params(&self, base: &PolicyParams) -> PolicyParams {
        let mut out = base.clone();

        // Pick which parameter to perturb (0..9).
        let choice = (rand::random::<f64>() * 9.0) as u32;

        // Random factor in [0.7, 1.3] (used for numeric params).
        let factor = 0.7 + rand::random::<f64>() * 0.6;

        match choice {
            0 => {
                let v = (base.retx_timeout_ms as f64 * factor).round() as u64;
                out.retx_timeout_ms = v.clamp(20, 500);
            }
            1 => {
                let v = (base.min_cwnd_kb as f64 * factor).round() as usize;
                out.min_cwnd_kb = v.clamp(8, 512);
            }
            2 => {
                let v = (base.batch_size as f64 * factor).round() as usize;
                out.batch_size = v.clamp(4, 128);
            }
            3 => {
                let v = (base.progress_ack_interval_ms as f64 * factor).round() as u64;
                out.progress_ack_interval_ms = v.clamp(20, 200);
            }
            4 => {
                // Categorical: swap CC profile to a different one.
                // `fair` is deliberately absent. It loses every netem
                // cell by 4-13x (6.7 MiB/s against classic's 48.0
                // cross-country) and 17x on the real WAN pair, so drawing
                // it costs a user a real transfer at 1/17th speed to learn
                // what is already recorded. Exploration is for questions
                // that are open.
                let profiles = ["classic", "model", "wifi", "rl"];
                let others: Vec<_> = profiles.iter()
                    .filter(|p| **p != base.cc_profile)
                    .collect();
                let idx = (rand::random::<f64>() * others.len() as f64) as usize;
                out.cc_profile = others[idx.min(others.len() - 1)].to_string();
            }
            5 => {
                // Categorical: swap ACK mode.
                out.ack_mode = if base.ack_mode == "nack" {
                    "bitmap".into()
                } else {
                    "nack".into()
                };
            }
            6 => {
                let v = (base.socket_buf_kb as f64 * factor).round() as usize;
                out.socket_buf_kb = v.clamp(64, 4096);
            }
            7 => {
                let v = (base.payload_size as f64 * factor).round() as usize;
                out.payload_size = v.clamp(500, 1400);
            }
            _ => {
                let v = (base.num_streams as f64 * factor).round() as u32;
                out.num_streams = v.clamp(1, 16);
            }
        }

        out
    }

    /// Number of training records currently held.
    pub fn record_count(&self) -> usize {
        self.records.len()
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Two RTT values are considered similar when neither exceeds 2x the other.
fn rtts_are_similar(a: u64, b: u64) -> bool {
    if a == 0 || b == 0 {
        // If either is zero treat them as similar only when both are zero.
        return a == b;
    }
    let (lo, hi) = if a < b { (a, b) } else { (b, a) };
    hi <= lo * 2
}

/// Path an unparsable history file is moved to (`<path>.corrupt`).
fn corrupt_backup_path(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(".corrupt");
    PathBuf::from(name)
}

/// Are these params the link-type anchor?
///
/// Compared on the fields the anchor actually sets, not by equality of the
/// whole struct: a record is written back with whatever the transfer used,
/// and an exact match would fail on any field a future version adds.
fn params_match_anchor(p: &PolicyParams, anchor: &PolicyParams) -> bool {
    p.cc_profile == anchor.cc_profile
        && p.ack_mode == anchor.ack_mode
        && p.batch_size == anchor.batch_size
        && p.min_cwnd_kb == anchor.min_cwnd_kb
        && p.socket_buf_kb == anchor.socket_buf_kb
        && p.payload_size == anchor.payload_size
        && p.num_streams == anchor.num_streams
}

/// Return sensible default [`PolicyParams`] tuned for the given link type.
pub fn defaults_for_link_type(link_type: LinkType) -> PolicyParams {
    match link_type {
        LinkType::Loopback => PolicyParams {
            retx_timeout_ms: 50,
            min_cwnd_kb: 512,
            batch_size: 256,
            progress_ack_interval_ms: 50,
            cc_profile: "classic".into(),
            ack_mode: "bitmap".into(),
            socket_buf_kb: 2048,
            payload_size: 1350,
            num_streams: 1,
        },
        LinkType::LanEthernet => PolicyParams {
            retx_timeout_ms: 50,
            min_cwnd_kb: 384,
            batch_size: 128,
            progress_ack_interval_ms: 50,
            cc_profile: "model".into(),
            ack_mode: "bitmap".into(),
            socket_buf_kb: 2048,
            payload_size: 1350,
            num_streams: 4,
        },
        LinkType::LanWifi => PolicyParams {
            retx_timeout_ms: 150,
            min_cwnd_kb: 512,
            batch_size: 128,
            progress_ack_interval_ms: 75,
            cc_profile: "model".into(),
            ack_mode: "bitmap".into(),
            socket_buf_kb: 2048,
            payload_size: 1350,
            num_streams: 4,
        },
        LinkType::Wan => PolicyParams {
            retx_timeout_ms: 200,
            min_cwnd_kb: 16,
            batch_size: 16,
            progress_ack_interval_ms: 100,
            // Was `fair`, which is the worst profile in every WAN-shaped
            // netem cell this repo has measured, by 4-13x:
            //
            //   cell            fair   classic   model
            //   cross-country    6.7      48.0    90.7   MiB/s, n=3
            //   transatlantic    4.0      26.6    37.3
            //   metro           56.0     211.4   186.8
            //   congested        4.1      73.6    40.1
            //
            // (benchmarks/results/netem_tcp_vs_favonius_2026-08-12.csv.)
            // This is not a hypothetical default: `suggest_params` falls
            // back to this table whenever it has no history for the link
            // type, so `--adaptive` on any WAN path was already selecting
            // it — a 7x regression behind a flag whose entire purpose is to
            // choose better parameters than the caller would.
            //
            // `classic`, not the per-cell winner, deliberately. Which
            // profile is best depends on whether loss is congestion-induced
            // or random, the probe cannot tell those apart (measured), and
            // a rate-based profile shipped by default on a shared link
            // fails as an unfriendly neighbour rather than as a
            // throughput number. Unambiguous cases only; `classic`
            // otherwise.
            cc_profile: "classic".into(),
            ack_mode: "bitmap".into(),
            socket_buf_kb: 128,
            payload_size: 1200,
            num_streams: 2,
        },
        _ => PolicyParams {
            retx_timeout_ms: 100,
            min_cwnd_kb: 64,
            batch_size: 32,
            progress_ack_interval_ms: 75,
            cc_profile: "classic".into(),
            ack_mode: "bitmap".into(),
            socket_buf_kb: 208,
            payload_size: 1350,
            num_streams: 4,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_params() {
        let p = PolicyParams::default();
        assert_eq!(p.retx_timeout_ms, 100);
        assert_eq!(p.min_cwnd_kb, 128);
        assert_eq!(p.batch_size, 32);
        assert_eq!(p.progress_ack_interval_ms, 75);
        assert_eq!(p.cc_profile, "classic");
        assert_eq!(p.ack_mode, "bitmap");
        assert_eq!(p.socket_buf_kb, 208);
        assert_eq!(p.payload_size, 1350);
        assert_eq!(p.num_streams, 4);
    }

    #[test]
    fn suggest_defaults_when_empty() {
        let policy = AdaptivePolicy::new(PathBuf::from("/tmp/ahp_test_nonexistent.json"));
        let ctx = NetworkContext {
            link_type: "loopback".into(),
            base_rtt_us: 50,
            jitter_us: 5,
            loss_rate: 0.0,
        };
        let params = policy.suggest_params(&ctx);
        // Empty policy -> defaults_for_link_type(LinkType::Loopback).
        assert_eq!(params.retx_timeout_ms, 50);
        assert_eq!(params.min_cwnd_kb, 512);
        assert_eq!(params.batch_size, 256);
    }

    #[test]
    fn link_type_display_and_from_str() {
        for (lt, s) in [
            (LinkType::Loopback, "loopback"),
            (LinkType::LanEthernet, "LAN/ethernet"),
            (LinkType::LanWifi, "LAN/wifi"),
            (LinkType::Wan, "WAN"),
            (LinkType::Unknown, "unknown"),
        ] {
            assert_eq!(lt.as_str(), s);
            assert_eq!(lt.to_string(), s);
            assert_eq!(s.parse::<LinkType>().unwrap(), lt);
        }
        // Strict parsing rejects anything else.
        assert!("satellite".parse::<LinkType>().is_err());
        assert!("lan/ethernet".parse::<LinkType>().is_err());
    }

    #[test]
    fn link_type_serde_round_trip() {
        for lt in [
            LinkType::Loopback,
            LinkType::LanEthernet,
            LinkType::LanWifi,
            LinkType::Wan,
            LinkType::Unknown,
        ] {
            let json = serde_json::to_string(&lt).unwrap();
            assert_eq!(json, format!("\"{}\"", lt.as_str()));
            assert_eq!(serde_json::from_str::<LinkType>(&json).unwrap(), lt);
        }
    }

    #[test]
    fn link_type_deserialize_unknown_string_is_lenient() {
        // History files written by another version may contain link type
        // strings this version does not know; they must still load.
        assert_eq!(
            serde_json::from_str::<LinkType>("\"satellite\"").unwrap(),
            LinkType::Unknown
        );
    }

    #[test]
    fn history_with_unknown_link_type_still_loads() {
        let path = PathBuf::from(format!(
            "/tmp/ahp_adaptive_test_unknown_link_{}.json",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);

        // A record in the existing on-disk format, with a link type string
        // this version does not recognize.
        let json = r#"[{
            "context": {"link_type": "satellite", "base_rtt_us": 500,
                        "jitter_us": 50, "loss_rate": 0.001},
            "params": {"retx_timeout_ms": 100, "min_cwnd_kb": 128,
                       "batch_size": 32, "progress_ack_interval_ms": 75},
            "throughput": 1000.0, "retx_ratio": 0.01, "score": 990.0
        }]"#;
        std::fs::write(&path, json).unwrap();

        let policy = AdaptivePolicy::new(path.clone());
        assert_eq!(policy.record_count(), 1);
        // The unknown link type matches itself in history lookups...
        let suggested = policy.suggest_params(&test_ctx("satellite"));
        assert_eq!(suggested.retx_timeout_ms, 100);
        // ...and an unknown context with no history gets the generic
        // (Unknown) defaults instead of crashing.
        let fresh = AdaptivePolicy::new(PathBuf::from("/tmp/ahp_test_nonexistent.json"));
        let params = fresh.suggest_params(&test_ctx("satellite"));
        assert_eq!(params.retx_timeout_ms, 100);
        assert_eq!(params.min_cwnd_kb, 64);
        assert_eq!(params.batch_size, 32);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn record_and_suggest() {
        let path = PathBuf::from("/tmp/ahp_adaptive_test_record.json");
        let _ = std::fs::remove_file(&path);

        let mut policy = AdaptivePolicy::new(path.clone());
        let ctx = NetworkContext {
            link_type: "LAN/ethernet".into(),
            base_rtt_us: 500,
            jitter_us: 50,
            loss_rate: 0.001,
        };

        let good_params = PolicyParams {
            retx_timeout_ms: 60,
            min_cwnd_kb: 200,
            batch_size: 50,
            progress_ack_interval_ms: 40,
            ..PolicyParams::default()
        };

        // History alone is NOT enough any more. Until the link-type anchor
        // has been tried and beaten, it is what gets suggested — otherwise
        // the first few transfers pin every later one inside whatever
        // region they happened to explore (measured at a 5x penalty on
        // wifi, 2026-08-12).
        policy.record_outcome(ctx.clone(), good_params.clone(), 1_000_000.0, 0.01);
        let anchor = defaults_for_link_type(LinkType::LanEthernet);
        let suggested = policy.suggest_params(&ctx);
        assert_eq!(
            suggested.batch_size, anchor.batch_size,
            "an unbeaten anchor must be suggested even when history exists"
        );

        // Record the anchor doing WORSE than the stored params. Now history
        // has beaten it on this link and earns the suggestion.
        policy.record_outcome(ctx.clone(), anchor.clone(), 500_000.0, 0.01);
        let suggested = policy.suggest_params(&ctx);
        assert_eq!(suggested.retx_timeout_ms, good_params.retx_timeout_ms);
        assert_eq!(suggested.batch_size, good_params.batch_size);

        // And if the anchor then does better than anything in history, the
        // suggestion goes back to it — which is what makes stale records
        // (a good radio day pinning a bad one) recoverable.
        policy.record_outcome(ctx.clone(), anchor.clone(), 9_000_000.0, 0.0);
        assert_eq!(policy.suggest_params(&ctx).batch_size, anchor.batch_size);

        let _ = std::fs::remove_file(&path);
    }

    /// The WAN row selected `fair`, which is the worst profile in every
    /// WAN-shaped netem cell measured — 6.7 MiB/s against classic's 48.0
    /// cross-country, 4.0 against 26.6 transatlantic, and 4.1 against 73.6
    /// congested (n=3,
    /// benchmarks/results/netem_tcp_vs_favonius_2026-08-12.csv).
    ///
    /// It was not a dormant table entry: `suggest_params` falls back here
    /// whenever it has no history for a link type, so every `--adaptive`
    /// transfer over a WAN path took it. A flag whose purpose is to choose
    /// better parameters than the caller chose a 7x regression.
    #[test]
    fn wan_default_is_not_the_profile_that_loses_every_wan_cell() {
        assert_ne!(
            defaults_for_link_type(LinkType::Wan).cc_profile, "fair",
            "the WAN default must not be the slowest profile on every WAN cell measured"
        );
        // The fail-safe rule, not the per-cell winner: which profile is best
        // depends on whether loss is congestion-induced or random, and the
        // probe cannot tell those apart (measured; see the congestion-control notes).
        assert_eq!(defaults_for_link_type(LinkType::Wan).cc_profile, "classic");
    }

    #[test]
    fn explore_stays_in_range() {
        let policy = AdaptivePolicy::new(PathBuf::from("/tmp/ahp_test_nonexistent.json"));
        let base = PolicyParams::default();
        let valid_cc = ["classic", "model", "wifi", "rl"];
        let valid_ack = ["bitmap", "nack"];
        for _ in 0..400 {
            let p = policy.explore_params(&base);
            assert!((20..=500).contains(&p.retx_timeout_ms));
            assert!((8..=512).contains(&p.min_cwnd_kb));
            assert!((4..=128).contains(&p.batch_size));
            assert!((20..=200).contains(&p.progress_ack_interval_ms));
            assert!(valid_cc.contains(&p.cc_profile.as_str()));
            assert!(valid_ack.contains(&p.ack_mode.as_str()));
            assert!((64..=4096).contains(&p.socket_buf_kb));
            assert!((500..=1400).contains(&p.payload_size));
            assert!((1..=16).contains(&p.num_streams));
        }
    }

    #[test]
    fn rtt_similarity() {
        assert!(rtts_are_similar(100, 100));
        assert!(rtts_are_similar(100, 200));
        assert!(rtts_are_similar(200, 100));
        assert!(!rtts_are_similar(100, 201));
        assert!(rtts_are_similar(0, 0));
        assert!(!rtts_are_similar(0, 1));
    }

    #[test]
    fn persistence_round_trip() {
        let path = PathBuf::from("/tmp/ahp_adaptive_test_persist.json");
        let _ = std::fs::remove_file(&path);

        let ctx = NetworkContext {
            link_type: "WAN".into(),
            base_rtt_us: 30_000,
            jitter_us: 5_000,
            loss_rate: 0.02,
        };

        {
            let mut policy = AdaptivePolicy::new(path.clone());
            policy.record_outcome(ctx.clone(), PolicyParams::default(), 500_000.0, 0.05);
        }

        // Reload from disk.
        let policy = AdaptivePolicy::new(path.clone());
        assert_eq!(policy.record_count(), 1);
        // The record carries `PolicyParams::default()`, which is not the
        // WAN link-type anchor, and the anchor has never been tried — so
        // the anchor is suggested, not the record. What this test is for is
        // that the record survived the round trip, which `record_count`
        // shows.
        let suggested = policy.suggest_params(&ctx);
        assert_eq!(suggested.retx_timeout_ms, defaults_for_link_type(LinkType::Wan).retx_timeout_ms);

        let _ = std::fs::remove_file(&path);
    }

    fn test_ctx(link_type: &str) -> NetworkContext {
        NetworkContext {
            link_type: link_type.into(),
            base_rtt_us: 500,
            jitter_us: 50,
            loss_rate: 0.001,
        }
    }

    #[test]
    fn record_rejects_invalid_scores() {
        let path = PathBuf::from(format!(
            "/tmp/ahp_adaptive_test_reject_{}.json",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);

        let mut policy = AdaptivePolicy::new(path.clone());
        let ctx = test_ctx("LAN/ethernet");

        // NaN / infinite / negative throughput: rejected.
        assert!(!policy.record_outcome(ctx.clone(), PolicyParams::default(), f64::NAN, 0.01));
        assert!(!policy.record_outcome(ctx.clone(), PolicyParams::default(), f64::INFINITY, 0.01));
        assert!(!policy.record_outcome(ctx.clone(), PolicyParams::default(), -1.0, 0.01));
        // NaN / out-of-range retx_ratio: rejected.
        assert!(!policy.record_outcome(ctx.clone(), PolicyParams::default(), 1000.0, f64::NAN));
        assert!(!policy.record_outcome(ctx.clone(), PolicyParams::default(), 1000.0, -0.5));
        assert!(!policy.record_outcome(ctx.clone(), PolicyParams::default(), 1000.0, 1.5));
        assert_eq!(policy.record_count(), 0);

        // Boundary values are valid.
        assert!(policy.record_outcome(ctx.clone(), PolicyParams::default(), 0.0, 1.0));
        assert!(policy.record_outcome(ctx, PolicyParams::default(), 1000.0, 0.0));
        assert_eq!(policy.record_count(), 2);

        let _ = std::fs::remove_file(&path);
    }

    /// The defect this rule exists to prevent, reproduced from the shape
    /// of the real policy file that caused it.
    ///
    /// 36 LAN/wifi records, every one carrying `PolicyParams::default()`
    /// values (`batch=32 cwnd=128KB sock=208KB`), none carrying the
    /// link-type row (`batch=128 cwnd=512KB sock=2048KB`). Under the old
    /// argmax-over-history rule the anchor was unreachable and `--adaptive`
    /// ran at 7.7 MB/s where not passing it ran at 40.9.
    #[test]
    fn history_that_never_tried_the_anchor_cannot_pin_the_suggestion() {
        let path = PathBuf::from(format!(
            "/tmp/ahp_adaptive_test_pin_{}.json",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let mut policy = AdaptivePolicy::new(path.clone());
        let ctx = NetworkContext {
            link_type: "LAN/wifi".into(),
            base_rtt_us: 3_000,
            jitter_us: 800,
            loss_rate: 0.001,
        };
        // A mediocre region, populated many times over — exactly what a few
        // dozen transfers with the old rule produced.
        for i in 0..36 {
            policy.record_outcome(ctx.clone(), PolicyParams::default(), 19_000_000.0 + i as f64, 0.0);
        }
        let anchor = defaults_for_link_type(LinkType::LanWifi);
        let s = policy.suggest_params(&ctx);
        assert_eq!(s.batch_size, anchor.batch_size, "36 records must not pin out the anchor");
        assert_eq!(s.min_cwnd_kb, anchor.min_cwnd_kb);
        assert_eq!(s.socket_buf_kb, anchor.socket_buf_kb);

        // Once the anchor has been tried and lost, history is trusted again
        // — the rule is "beaten", not "ignored".
        policy.record_outcome(ctx.clone(), anchor.clone(), 1_000_000.0, 0.0);
        assert_eq!(policy.suggest_params(&ctx).batch_size, PolicyParams::default().batch_size);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn load_filters_invalid_records() {
        let path = PathBuf::from(format!(
            "/tmp/ahp_adaptive_test_filter_{}.json",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);

        // Persist one valid record, then hand-inject a negative-score record
        // (as an old unvalidated version could have written).
        {
            let mut policy = AdaptivePolicy::new(path.clone());
            policy.record_outcome(test_ctx("LAN/ethernet"), PolicyParams::default(), 1_000_000.0, 0.01);
        }
        let data = std::fs::read_to_string(&path).unwrap();
        let mut records: serde_json::Value = serde_json::from_str(&data).unwrap();
        let valid = records[0].clone();
        let mut bad = valid;
        bad["score"] = serde_json::json!(-5.0);
        bad["retx_ratio"] = serde_json::json!(1.5);
        records.as_array_mut().unwrap().push(bad);
        std::fs::write(&path, serde_json::to_string_pretty(&records).unwrap()).unwrap();

        // On load the invalid record is filtered, the valid one survives.
        // What this asserts is the count: the surviving record carries
        // `PolicyParams::default()`, which is not the LAN/ethernet anchor,
        // so the suggestion is the anchor either way and cannot
        // distinguish "filtered" from "kept".
        let policy = AdaptivePolicy::new(path.clone());
        assert_eq!(policy.record_count(), 1);
        let suggested = policy.suggest_params(&test_ctx("LAN/ethernet"));
        assert_eq!(
            suggested.retx_timeout_ms,
            defaults_for_link_type(LinkType::LanEthernet).retx_timeout_ms
        );

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn corrupt_history_moved_aside_not_nuked() {
        let path = PathBuf::from(format!(
            "/tmp/ahp_adaptive_test_corrupt_{}.json",
            std::process::id()
        ));
        let backup = corrupt_backup_path(&path);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&backup);

        // A truncated/torn file, as a crash during the old non-atomic save
        // could leave behind.
        std::fs::write(&path, "[{\"context\": {\"link_type\": \"LAN/eth").unwrap();

        let mut policy = AdaptivePolicy::new(path.clone());
        assert_eq!(policy.record_count(), 0);
        // The corrupt content is preserved at the backup path.
        assert!(!path.exists());
        assert_eq!(
            std::fs::read_to_string(&backup).unwrap(),
            "[{\"context\": {\"link_type\": \"LAN/eth"
        );

        // New records can be saved again without touching the backup.
        assert!(policy.record_outcome(test_ctx("WAN"), PolicyParams::default(), 1000.0, 0.1));
        assert!(path.exists());
        assert!(backup.exists());

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&backup);
    }

    #[test]
    fn save_is_atomic_and_leaves_no_temp_files() {
        let dir = std::env::temp_dir().join(format!("ahp_policy_atomic_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("policy.json");

        let mut policy = AdaptivePolicy::new(path.clone());
        assert!(policy.record_outcome(test_ctx("WAN"), PolicyParams::default(), 1000.0, 0.1));
        policy.save().unwrap();

        // The final file parses and no temp files remain.
        let policy = AdaptivePolicy::new(path.clone());
        assert_eq!(policy.record_count(), 1);
        let leftover: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name() != "policy.json")
            .collect();
        assert!(leftover.is_empty(), "temp files left behind: {leftover:?}");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn history_cap_enforced_per_link_type() {
        let path = PathBuf::from(format!(
            "/tmp/ahp_adaptive_test_cap_{}.json",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);

        let mut policy = AdaptivePolicy::new(path.clone());
        let ctx = test_ctx("LAN/ethernet");

        for i in 0..MAX_RECORDS_PER_LINK_TYPE + 10 {
            assert!(policy.record_outcome(
                ctx.clone(),
                PolicyParams::default(),
                1000.0 + i as f64,
                0.01,
            ));
        }
        assert_eq!(policy.record_count(), MAX_RECORDS_PER_LINK_TYPE);

        // Records of another link type are not evicted.
        for _ in 0..5 {
            assert!(policy.record_outcome(test_ctx("WAN"), PolicyParams::default(), 1000.0, 0.01));
        }
        assert_eq!(policy.record_count(), MAX_RECORDS_PER_LINK_TYPE + 5);

        // The oldest records were evicted: the best surviving score is the
        // most recent (highest throughput) one.
        let best = policy
            .records
            .iter()
            .filter(|r| r.context.link_type == "LAN/ethernet")
            .map(|r| r.throughput)
            .fold(0.0f64, f64::max);
        assert_eq!(best, 1000.0 + (MAX_RECORDS_PER_LINK_TYPE + 9) as f64);

        // The cap survives a reload.
        let policy = AdaptivePolicy::new(path.clone());
        assert_eq!(policy.record_count(), MAX_RECORDS_PER_LINK_TYPE + 5);

        let _ = std::fs::remove_file(&path);
    }
}
