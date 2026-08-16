// Favonius — high-performance file transfer over UDP
// Copyright (c) 2025-2026 Vantino SàRL
// SPDX-License-Identifier: Apache-2.0

use clap::{Parser, Subcommand};
use ahp_cli::sync_plan::{self, Compare, SyncMode};
use ahp_cli::{fs_tree, FavoniusClient, CliError, net_sender, preflight, tcp_sender, udt_transport};
use ahp_congestion::CongestionProfile;
use ahp_policy::{AdaptivePolicy, NetworkContext};
use ahp_proto::data::AckMode;

/// Default HTTP control-API endpoint. Named so `sync` can tell "the user
/// chose loopback" from "the user said nothing".
const DEFAULT_DAEMON: &str = "127.0.0.1:7800";

#[derive(Parser, Debug)]
#[command(name = "favonius", version, about = "Favonius — high-speed file transfer and sync")]
struct Cli {
    #[arg(long, default_value = "warn", global = true)]
    log_level: String,

    #[arg(long, default_value = DEFAULT_DAEMON, global = true)]
    daemon: String,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Check whether this network will carry a transfer
    ///
    /// Run this before anything else. The first thing that stops a
    /// deployment is not the security review, it is the firewall — and
    /// finding that out in five seconds is worth more than finding out in
    /// three weeks.
    Check {
        /// Destination host, with an optional control port: `host` or
        /// `host:7801`
        target: String,
        /// AHP data port. Defaults to the control port plus one, which is
        /// the daemon's own default.
        #[arg(long)]
        data_port: Option<u16>,
    },
    /// Send files to a destination
    Send {
        source: String,
        destination: String,
        /// Compression profile: none, fast, balanced, streaming
        #[arg(long, default_value = "none")]
        compression: String,
        /// Not implemented. Accepted so existing command lines keep
        /// working, and rejected loudly rather than silently ignored:
        /// a bandwidth cap that does nothing is worse than no flag.
        #[arg(long, default_value_t = 0)]
        bandwidth_limit: u64,
        /// Congestion control profile: auto (default — chosen from the
        /// probed link type), classic, model, fair, wifi, udt, cycle
        /// (`rl` is accepted as a deprecated alias for `cycle`)
        #[arg(long, default_value = "auto")]
        congestion: String,
        /// ACK mode for AHP transfers: bitmap, nack
        #[arg(long, default_value = "bitmap")]
        ack_mode: String,
        /// Number of parallel streams for multi-stream multiplexing
        #[arg(long, default_value_t = 4)]
        streams: u32,
        /// Pacing mode: auto, batch (GSO/sendmmsg, default), perpacket, iouring (slower than GSO, debug only), xdp (experimental)
        #[arg(long, default_value = "auto")]
        pacing: String,
        /// Transport backend: ahp (default), tcp (fallback for networks
        /// that block UDP — correct but not accelerated), udt
        /// (sendfile/recvfile), xdp (AF_XDP zero-copy)
        #[arg(long, default_value = "ahp")]
        transport: String,
        /// Encrypt the transfer using AES-256-GCM with X25519 key exchange
        #[arg(long)]
        encrypt: bool,
        /// Protect packet headers (mask connection_id + packet_number). Requires --encrypt.
        #[arg(long)]
        header_protect: bool,
        /// Resume an interrupted transfer (skip already-received chunks)
        #[arg(long)]
        resume: bool,
        /// Pin the daemon's Ed25519 identity public key (64 hex chars, or a
        /// file containing it — see `favonius-daemon keygen`). Without it the
        /// encrypted handshake is anonymous (unauthenticated).
        #[arg(long)]
        server_key: Option<String>,
        /// Use adaptive policy (learns optimal parameters over time)
        #[arg(long)]
        adaptive: bool,
        /// Path to adaptive policy training data
        #[arg(long, default_value = "~/.config/favonius/policy.json")]
        policy_path: String,
        /// Comma-separated glob patterns; only matching files are sent
        /// (directory sources only)
        #[arg(long)]
        include: Option<String>,
        /// Comma-separated glob patterns to skip (directory sources only)
        #[arg(long)]
        exclude: Option<String>,
        /// List what would be transferred and exit
        #[arg(long)]
        dry_run: bool,
    },
    /// Sync a directory to a remote destination
    ///
    /// Stateless: the plan is recomputed on every run by diffing the local
    /// tree against the destination. Modes needing change history
    /// (bidirectional, snapshot, version-preserving) are out of scope by
    /// design — see COMPATIBILITY notes in the README.
    Sync {
        source: String,
        /// Remote destination directory, `host:port:/path`
        destination: String,
        /// one-way (default), mirror, or append-only
        #[arg(long, default_value = "one-way")]
        mode: String,
        /// Compare file contents by BLAKE3 rather than by size alone.
        /// Catches edits that preserve file length, at the cost of reading
        /// every file on both sides.
        #[arg(long)]
        checksum: bool,
        /// Show the plan and exit without transferring or deleting
        #[arg(long)]
        dry_run: bool,
        /// Required to actually delete files in mirror mode
        #[arg(long)]
        confirm_delete: bool,
        #[arg(long)]
        include: Option<String>,
        #[arg(long)]
        exclude: Option<String>,
        /// Congestion control profile: auto (default — chosen from the
        /// probed link type), classic, model, fair, wifi, udt, cycle
        #[arg(long, default_value = "auto")]
        congestion: String,
        #[arg(long, default_value_t = 4)]
        streams: u32,
        #[arg(long)]
        encrypt: bool,
        #[arg(long, default_value = "none")]
        compression: String,
    },
    /// Watch a directory
    Watch {
        directory: String,
        destination: String,
        #[arg(long)]
        include: Option<String>,
        #[arg(long)]
        exclude: Option<String>,
    },
    /// Resume an interrupted transfer
    Resume {
        transfer_id: String,
    },
    /// Show transfer status
    Status {
        transfer_id: Option<String>,
        #[arg(long)]
        active: bool,
    },
}


/// Parse a `--congestion` value, rejecting anything unrecognised.
///
/// `Ok(None)` is `auto`: the profile is chosen after the path probe, from
/// the per-link-type defaults `ahp-policy` already carries. Returning the
/// undecided case rather than a placeholder profile is what keeps the
/// decision at the only point where the link type is known.
///
/// The named case was `_ => CongestionProfile::Classic` at both call sites,
/// so `--congestion bbr2` or a typo like `modle` silently ran Classic. The
/// user asked for a specific controller and got a different one with no
/// indication, which is the same failure that made a rejected
/// `FAVONIUS_RL_MODEL` file silently swap the RL controller for a constant.
/// A wrong congestion controller is not a cosmetic difference: on
/// transatlantic these profiles differ by 12% of throughput and, in
/// Classic's case, by whether the cell is bimodal.
fn parse_congestion(name: &str) -> Result<Option<CongestionProfile>, String> {
    if name == "auto" {
        return Ok(None);
    }
    match CongestionProfile::from_name(name) {
        Some(p) => Ok(Some(p)),
        None => Err(format!(
            "unknown congestion profile {name:?}; expected auto or one of: {}",
            CongestionProfile::NAMES
        )),
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(&cli.log_level)),
        )
        .init();

    let client = FavoniusClient::new(&cli.daemon);

    match cli.command {
        // ── Connectivity ─────────────────────────────────────────────
        Command::Check { target, data_port } => {
            let (host, control_port) = match target.rsplit_once(':') {
                // Guard against an IPv6 literal being split on its own colons.
                Some((h, p)) if !h.contains(':') || h.starts_with('[') => {
                    match p.parse::<u16>() {
                        Ok(port) => (h.trim_matches(|c| c == '[' || c == ']').to_string(), port),
                        Err(_) => (target.clone(), 7801),
                    }
                }
                _ => (target.clone(), 7801),
            };
            let data = data_port.unwrap_or(control_port.saturating_add(1));
            let report = preflight::run(&host, control_port, data).await;
            preflight::print(&report);
            // A non-zero exit so this can gate a script or a CI step, not
            // only inform a person reading a terminal.
            if !report.transfer_possible() {
                std::process::exit(1);
            }
            return Ok(());
        }

        Command::Send { source, destination, compression, congestion, ack_mode, streams, pacing, transport, encrypt, header_protect, resume, server_key, adaptive, policy_path, include, exclude, dry_run, bandwidth_limit } => {
            // No code path reads this. It was destructured away with `..`,
            // so `--bandwidth-limit 10` capped nothing and said nothing —
            // the user asked for a rate limit and got line rate. Fail
            // instead: a cap that silently does not apply is worse than an
            // absent flag, because it is trusted.
            if bandwidth_limit != 0 {
                return Err(Box::<dyn std::error::Error>::from(CliError::Config(
                    "--bandwidth-limit is not implemented; it would silently \
                     not apply. Use --congestion fair, or shape the link \
                     (tc/qdisc), until it is.".into(),
                )));
            }
            // TCP fallback: no AHP, no congestion control, no speed claim.
            // Chosen explicitly here; `net_sender` falls back to it on its
            // own when a handshake finds nothing at the far end.
            if transport == "tcp" {
                let Some((remote_addr, dest_path)) = net_sender::parse_remote_dest(&destination)
                else {
                    return Err(Box::<dyn std::error::Error>::from(CliError::Config(
                        "--transport tcp needs a remote destination, host:port:/path".into(),
                    )));
                };
                eprintln!("Transport: TCP fallback (no acceleration — see `favonius check`)");
                match tcp_sender::send_file(
                    std::path::Path::new(&source), remote_addr, &dest_path,
                ).await {
                    Ok(s) => {
                        println!(
                            "TCP fallback complete: {} bytes in {:.2}s ({:.1} MiB/s)",
                            s.bytes_sent, s.elapsed.as_secs_f64(), s.throughput_mib_s(),
                        );
                        return Ok(());
                    }
                    Err(e) => {
                        eprintln!("error: {e}");
                        std::process::exit(1);
                    }
                }
            }

            // UDT transport: bypass AHP entirely, use sendfile/recvfile.
            if transport == "udt" {
                eprintln!("Transport: UDT (sendfile/recvfile baseline)");
                match udt_transport::send_via_udt(
                    std::path::Path::new(&source),
                    &destination,
                ).await {
                    Ok(stats) => {
                        println!(
                            "UDT transfer complete: {:.1} MiB/s ({} bytes in {:.2}s)",
                            stats.throughput_mbps(),
                            stats.bytes_sent,
                            stats.elapsed.as_secs_f64(),
                        );
                    }
                    Err(e) => {
                        eprintln!("UDT error: {}", e);
                        std::process::exit(1);
                    }
                }
                return Ok(());
            }

            // Check if destination is a remote AHP target: host:port:/path
            if let Some((remote_addr, dest_path)) = net_sender::parse_remote_dest(&destination) {
                let cc_profile = match parse_congestion(&congestion) {
                    Ok(p) => p,
                    Err(e) => { eprintln!("error: {e}"); std::process::exit(2); }
                };
                let ack = match ack_mode.as_str() {
                    "nack" => AckMode::Nack,
                    _ => AckMode::Bitmap,
                };

                // Resolve policy path (expand ~)
                let policy_file = policy_path.replace('~', &dirs_or_home());
                let mut adaptive_policy = if adaptive {
                    Some(AdaptivePolicy::new(std::path::PathBuf::from(&policy_file)))
                } else {
                    None
                };

                let compress_profile = match compression.as_str() {
                    "fast" => ahp_compression::CompressionProfile::ZstdFast,
                    "balanced" => ahp_compression::CompressionProfile::ZstdBalanced,
                    "streaming" => ahp_compression::CompressionProfile::ZstdStreaming,
                    _ => ahp_compression::CompressionProfile::None,
                };
                let pinned_key = match server_key.as_deref().map(net_sender::parse_server_key_pin) {
                    Some(Ok(key)) => Some(key),
                    Some(Err(e)) => {
                        eprintln!("Error: {e}");
                        std::process::exit(1);
                    }
                    None => None,
                };
                if pinned_key.is_some() && !encrypt {
                    eprintln!("Warning: --server-key has no effect without --encrypt");
                }
                let src_path = std::path::PathBuf::from(&source);
                let meta = match std::fs::metadata(&src_path) {
                    Ok(m) => m,
                    Err(e) => {
                        eprintln!("Error: cannot read {source}: {e}");
                        std::process::exit(1);
                    }
                };

                // A directory source fans out into one transfer per file,
                // keyed by its path relative to the source root.
                let items: Vec<(std::path::PathBuf, String)> = if meta.is_dir() {
                    let filters = fs_tree::Filters::new(include.as_deref(), exclude.as_deref());
                    let entries = match fs_tree::walk(&src_path, &filters) {
                        Ok(e) => e,
                        Err(e) => {
                            eprintln!("Error: cannot walk {source}: {e}");
                            std::process::exit(1);
                        }
                    };
                    if entries.is_empty() {
                        eprintln!("Nothing to send: no files under {source} matched the filters.");
                        return Ok(());
                    }
                    entries
                        .into_iter()
                        .filter_map(|e| {
                            match fs_tree::join_dest(&dest_path, &e.rel) {
                                Some(d) => Some((e.abs, d)),
                                None => {
                                    eprintln!("Skipping unsafe relative path: {}", e.rel);
                                    None
                                }
                            }
                        })
                        .collect()
                } else {
                    if include.is_some() || exclude.is_some() {
                        eprintln!("Warning: --include/--exclude apply to directory sources only.");
                    }
                    vec![(src_path, dest_path.clone())]
                };

                let total_bytes: u64 = items
                    .iter()
                    .map(|(p, _)| std::fs::metadata(p).map(|m| m.len()).unwrap_or(0))
                    .sum();

                if dry_run {
                    println!("Dry run — {} file(s), {}:", items.len(), human_bytes(total_bytes));
                    for (src, dst) in &items {
                        println!("  {} -> {}", src.display(), dst);
                    }
                    return Ok(());
                }

                eprintln!(
                    "AHP send: {} ({} file(s), {}) -> {}:{} (cc: {}, ack: {:?}, streams: {}{}{}{}{})",
                    source, items.len(), human_bytes(total_bytes), remote_addr, dest_path,
                    // "auto" until the probe runs; the resolved profile is
                    // logged by the sender once the link type is known.
                    cc_profile.map_or("auto".to_string(), |p| p.to_string()),
                    ack, streams,
                    if adaptive { ", adaptive" } else { "" },
                    if encrypt { ", encrypted" } else { "" },
                    if header_protect { ", header-protected" } else { "" },
                    if compress_profile != ahp_compression::CompressionProfile::None {
                        format!(", compress: {:?}", compress_profile)
                    } else { String::new() },
                );

                let failed = run_ahp_sends(
                    remote_addr, &items, cc_profile, ack, streams, &pacing, encrypt,
                    compress_profile, resume, adaptive_policy.as_mut(), header_protect,
                    pinned_key,
                ).await;
                if failed > 0 {
                    eprintln!("{failed} of {} transfer(s) failed.", items.len());
                    std::process::exit(1);
                }
            } else if destination.contains(":/") {
                // It was *meant* as a remote AHP target and did not parse.
                //
                // Falling through to the HTTP API here would silently use a
                // different transfer mechanism than the user asked for, with
                // no indication that the UDP fast path was skipped. Say why
                // instead.
                eprintln!(
                    "Error: '{destination}' looks like a remote destination but did not parse — {}",
                    net_sender::parse_remote_dest_detailed(&destination).unwrap_err()
                );
                std::process::exit(2);
            } else {
                // Local transfer via daemon HTTP API
                let compress = compression != "none";
                let resp = match client.create_transfer(&source, &destination, Some(compress), Some(true)).await {
                    Ok(resp) => {
                        println!("Transfer created:");
                        println!("  ID:          {}", resp.id);
                        println!("  State:       {}", resp.state);
                        println!("  Source:      {}", resp.source);
                        println!("  Destination: {}", resp.destination);
                        resp
                    }
                    Err(e) => {
                        eprintln!("Error: {}", e);
                        std::process::exit(1);
                    }
                };

                await_completion(&client, &resp.id, "Transfer", true).await;
            }
        }
        Command::Sync {
            source, destination, mode, checksum, dry_run, confirm_delete,
            include, exclude, congestion, streams, encrypt, compression,
        } => {
            let sync_mode = match SyncMode::parse(&mode) {
                Ok(m) => m,
                Err(e) => {
                    eprintln!("Error: {e}");
                    std::process::exit(1);
                }
            };
            let remote = net_sender::parse_remote_dest_detailed(&destination);
            let Ok((remote_addr, dest_root)) = remote else {
                eprintln!(
                    "Error: sync needs a remote destination of the form \
                     host:port:/path — {}",
                    remote.unwrap_err()
                );
                std::process::exit(1);
            };

            // `sync` plans and deletes over the HTTP control API, which is
            // addressed by --daemon, while the DATA goes to the host in the
            // destination string. Those are two different machines the
            // moment the destination is remote, and nothing tied them
            // together: with --daemon left at its default, a sync to
            // `remote:7801:/srv/p` listed the LOCAL filesystem and, in
            // mirror mode, deleted local files the user believed were on
            // the far end. Demonstrated 2026-08-11 against an unroutable
            // destination (192.0.2.99): the plan still said
            // `delete precious.txt`, a local file.
            //
            // So the API host follows the destination unless the caller
            // named one explicitly.
            let api_endpoint = if cli.daemon == DEFAULT_DAEMON && !remote_addr.ip().is_loopback() {
                let derived = format!("{}:7800", remote_addr.ip());
                eprintln!(
                    "note: planning against {derived} (the destination host). \
                     Pass --daemon to override; the receiver must serve its \
                     HTTP API on a reachable address."
                );
                derived
            } else {
                cli.daemon.clone()
            };
            let client = FavoniusClient::new(&api_endpoint);

            let src_root = std::path::PathBuf::from(&source);
            if !src_root.is_dir() {
                eprintln!("Error: sync source must be a directory (got '{source}').");
                std::process::exit(1);
            }

            // ── Local side ──────────────────────────────────────────────
            let filters = fs_tree::Filters::new(include.as_deref(), exclude.as_deref());
            let local = match fs_tree::walk(&src_root, &filters) {
                Ok(e) => e,
                Err(e) => {
                    eprintln!("Error: cannot walk {source}: {e}");
                    std::process::exit(1);
                }
            };

            // ── Remote side ─────────────────────────────────────────────
            let compare = if checksum { Compare::Checksum } else { Compare::Size };
            let remote = match client.fs_list(&dest_root, checksum).await {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("Error: cannot list destination: {e}");
                    std::process::exit(1);
                }
            };

            let local_hashes: Vec<Option<String>> = if checksum {
                local.iter().map(|e| blake3_file(&e.abs).ok()).collect()
            } else {
                Vec::new()
            };

            let plan = sync_plan::plan(&local, &remote, sync_mode, compare, &local_hashes);

            // ── Report ──────────────────────────────────────────────────
            println!(
                "Sync {source} -> {destination} [{mode}, compare: {}]",
                if checksum { "blake3" } else { "size" }
            );
            println!(
                "  {} to transfer ({}), {} unchanged{}{}",
                plan.transfers.len(),
                human_bytes(plan.bytes()),
                plan.unchanged,
                if plan.protected > 0 {
                    format!(", {} protected (append-only)", plan.protected)
                } else { String::new() },
                if plan.deletes.is_empty() {
                    String::new()
                } else {
                    format!(", {} to delete", plan.deletes.len())
                },
            );

            if dry_run {
                for t in &plan.transfers {
                    println!("  {:>6}  {}", format!("{:?}", t.action).to_lowercase(), t.entry.rel);
                }
                for d in &plan.deletes {
                    println!("  delete  {d}");
                }
                return Ok(());
            }
            if plan.is_empty() {
                println!("Already in sync.");
                return Ok(());
            }

            // Deleting is the one irreversible thing sync does, and a
            // mirror of an empty or mis-typed source deletes the lot — so
            // it takes a second, explicit flag rather than riding along
            // with --mode mirror.
            if !plan.deletes.is_empty() && !confirm_delete {
                eprintln!(
                    "Refusing to delete {} destination file(s) without --confirm-delete. \
                     Re-run with --dry-run to see the list.",
                    plan.deletes.len()
                );
                std::process::exit(1);
            }

            // ── Transfer ────────────────────────────────────────────────
            let cc_profile = match parse_congestion(&congestion) {
                Ok(p) => p,
                Err(e) => { eprintln!("error: {e}"); std::process::exit(2); }
            };
            let compress_profile = match compression.as_str() {
                "fast" => ahp_compression::CompressionProfile::ZstdFast,
                "balanced" => ahp_compression::CompressionProfile::ZstdBalanced,
                "streaming" => ahp_compression::CompressionProfile::ZstdStreaming,
                _ => ahp_compression::CompressionProfile::None,
            };

            let items: Vec<(std::path::PathBuf, String)> = plan
                .transfers
                .iter()
                .filter_map(|t| {
                    fs_tree::join_dest(&dest_root, &t.entry.rel)
                        .map(|d| (t.entry.abs.clone(), d))
                })
                .collect();

            let mut failed = 0usize;
            if !items.is_empty() {
                failed = run_ahp_sends(
                    remote_addr, &items, cc_profile, AckMode::Bitmap, streams, "auto",
                    encrypt, compress_profile, false, None, false, None,
                ).await;
            }

            // ── Delete ──────────────────────────────────────────────────
            let mut delete_failed = 0usize;
            for rel in &plan.deletes {
                let Some(abs) = fs_tree::join_dest(&dest_root, rel) else {
                    continue;
                };
                if let Err(e) = client.fs_delete(&abs).await {
                    delete_failed += 1;
                    eprintln!("Error deleting {rel}: {e}");
                } else {
                    println!("  deleted {rel}");
                }
            }

            if failed > 0 || delete_failed > 0 {
                eprintln!("Sync incomplete: {failed} transfer(s) and {delete_failed} delete(s) failed.");
                std::process::exit(1);
            }
            println!("Sync complete.");
        }
        Command::Watch { directory, destination, include, exclude } => {
            if include.is_some() || exclude.is_some() {
                eprintln!("Warning: --include/--exclude are not implemented and have no effect.");
            }
            match client.create_transfer(&directory, &destination, Some(true), Some(true)).await {
                Ok(resp) => {
                    println!("Watch started:");
                    println!("  ID:          {}", resp.id);
                    println!("  Directory:   {}", resp.source);
                    println!("  Destination: {}", resp.destination);
                    await_completion(&client, &resp.id, "Watch", false).await;
                }
                Err(e) => {
                    eprintln!("Error: {}", e);
                    std::process::exit(1);
                }
            }
        }
        Command::Resume { transfer_id } => {
            match client.resume_transfer(&transfer_id).await {
                Ok(resp) => {
                    println!("Transfer resumed:");
                    println!("  ID:    {}", resp.id);
                    println!("  State: {}", resp.state);
                }
                Err(CliError::NotFound(id)) => {
                    eprintln!("Error: transfer '{}' not found", id);
                    std::process::exit(1);
                }
                Err(e) => {
                    eprintln!("Error: {}", e);
                    std::process::exit(1);
                }
            }
        }
        Command::Status { transfer_id, active } => {
            match transfer_id {
                Some(id) => {
                    match client.get_transfer(&id).await {
                        Ok(resp) => print_transfer(&resp),
                        Err(CliError::NotFound(id)) => {
                            eprintln!("Error: transfer '{}' not found", id);
                            std::process::exit(1);
                        }
                        Err(e) => {
                            eprintln!("Error: {}", e);
                            std::process::exit(1);
                        }
                    }
                }
                None => {
                    match client.list_transfers().await {
                        Ok(transfers) => {
                            let filtered: Vec<_> = if active {
                                transfers.iter().filter(|t| t.state == "Active" || t.state == "Resuming").collect()
                            } else {
                                transfers.iter().collect()
                            };
                            if filtered.is_empty() {
                                println!("No transfers found.");
                            } else {
                                // Print a table header
                                println!("{:<38} {:<12} {:>8} {}", "ID", "STATE", "PROGRESS", "SOURCE -> DESTINATION");
                                println!("{}", "-".repeat(90));
                                for t in &filtered {
                                    println!(
                                        "{:<38} {:<12} {:>7.1}% {} -> {}",
                                        t.id,
                                        t.state,
                                        t.progress * 100.0,
                                        t.source,
                                        t.destination
                                    );
                                }
                                println!();
                                println!("{} transfer(s)", filtered.len());
                            }
                        }
                        Err(e) => {
                            eprintln!("Error: {}", e);
                            std::process::exit(1);
                        }
                    }
                }
            }
        }
    }

    Ok(())
}

/// Poll a daemon-side transfer until it reaches a terminal state.
///
/// Every command that submits work to the HTTP API must go through this:
/// `create_transfer` only *queues* the job, so a command that printed its
/// response and returned would report success for work that had not yet
/// run — and would keep reporting success when it later failed. That is
/// how `sync` and `watch` came to exit 0 while copying nothing.
///
/// Exits the process with status 1 on failure, after printing the reason
/// the daemon recorded.
async fn await_completion(
    client: &FavoniusClient,
    transfer_id: &str,
    label: &str,
    show_progress: bool,
) {
    loop {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        let status = match client.get_transfer(transfer_id).await {
            Ok(s) => s,
            Err(e) => {
                eprintln!("\nError polling transfer: {e}");
                std::process::exit(1);
            }
        };
        if show_progress {
            eprint!(
                "\r  Progress: {:>5.1}%  ({} / {} bytes)  [{}]",
                status.progress * 100.0,
                status.bytes_transferred,
                status.bytes_total,
                status.state
            );
        }
        match status.state.as_str() {
            "Complete" | "Verified" => {
                if show_progress {
                    eprintln!();
                }
                println!("{label} complete ({} bytes).", status.bytes_transferred);
                return;
            }
            "Failed" | "Aborted" => {
                if show_progress {
                    eprintln!();
                }
                eprintln!(
                    "Error: {} {} ({transfer_id}){}",
                    label.to_lowercase(),
                    status.state.to_lowercase(),
                    status
                        .error
                        .as_deref()
                        .map(|e| format!(": {e}"))
                        .unwrap_or_default()
                );
                std::process::exit(1);
            }
            _ => {} // keep polling
        }
    }
}

/// Send a batch of (local path, remote path) pairs over AHP, one transfer
/// per file. Returns the number that failed.
///
/// Failures do not abort the batch: on a thousand-file tree, one
/// unreadable file should not discard the 999 that would have succeeded.
/// The count is surfaced so the caller can still exit non-zero.
#[allow(clippy::too_many_arguments)]
async fn run_ahp_sends(
    remote_addr: std::net::SocketAddr,
    items: &[(std::path::PathBuf, String)],
    // `None` is `--congestion auto`: resolved per transfer, after the path
    // probe, from the policy's per-link-type default.
    cc_profile: Option<CongestionProfile>,
    ack: AckMode,
    streams: u32,
    pacing: &str,
    encrypt: bool,
    compress_profile: ahp_compression::CompressionProfile,
    resume: bool,
    mut adaptive_policy: Option<&mut AdaptivePolicy>,
    header_protect: bool,
    pinned_key: Option<[u8; 32]>,
) -> usize {
    let multi = items.len() > 1;
    let mut failed = 0usize;
    let mut sent_bytes = 0u64;
    let started = std::time::Instant::now();

    for (i, (src, dst)) in items.iter().enumerate() {
        if multi {
            eprintln!("[{}/{}] {}", i + 1, items.len(), src.display());
        }
        match net_sender::send_file(
            remote_addr, src, dst, cc_profile, ack, streams, pacing, encrypt,
            compress_profile, resume, adaptive_policy.as_deref(), header_protect, pinned_key,
        ).await {
            Ok(stats) => {
                sent_bytes += stats.bytes_sent;
                if multi {
                    eprintln!(
                        "      {:.1} MiB/s ({} in {:.2}s)",
                        stats.throughput_mbps(), human_bytes(stats.bytes_sent),
                        stats.elapsed.as_secs_f64(),
                    );
                } else {
                    println!(
                        "Transfer complete: {:.1} MiB/s ({} bytes in {:.2}s, {} pkts, {} retx) [{}]",
                        stats.throughput_mbps(), stats.bytes_sent, stats.elapsed.as_secs_f64(),
                        stats.packets_sent, stats.retransmits, stats.profile.link_type,
                    );
                }
                if let Some(policy) = adaptive_policy.as_deref_mut() {
                    let ctx = NetworkContext {
                        link_type: stats.profile.link_type.to_string(),
                        base_rtt_us: stats.profile.base_rtt.as_micros() as u64,
                        jitter_us: stats.profile.rtt_jitter.as_micros() as u64,
                        loss_rate: stats.profile.probe_loss_rate,
                    };
                    let throughput = if stats.elapsed.as_secs_f64() > 0.0 {
                        stats.bytes_sent as f64 / stats.elapsed.as_secs_f64()
                    } else { 0.0 };
                    let retx_ratio = if stats.packets_sent > 0 {
                        stats.retransmits as f64 / stats.packets_sent as f64
                    } else { 0.0 };
                    let params = stats.policy_params.unwrap_or_else(|| {
                        ahp_policy::defaults_for_link_type(ctx.link_type())
                    });
                    policy.record_outcome(ctx, params, throughput, retx_ratio);
                }
            }
            Err(e) => {
                failed += 1;
                eprintln!("Error sending {}: {e}", src.display());
            }
        }
    }

    if multi {
        let secs = started.elapsed().as_secs_f64();
        println!(
            "Sent {}/{} file(s), {} in {:.2}s ({:.1} MiB/s aggregate).",
            items.len() - failed, items.len(), human_bytes(sent_bytes), secs,
            if secs > 0.0 { sent_bytes as f64 / secs / (1024.0 * 1024.0) } else { 0.0 },
        );
    }
    failed
}

/// BLAKE3 of a local file, streamed (matches the daemon's `fs/list?hash`).
fn blake3_file(path: &std::path::Path) -> std::io::Result<String> {
    use std::io::Read;
    let mut f = std::fs::File::open(path)?;
    let mut hasher = blake3::Hasher::new();
    let mut buf = vec![0u8; 256 * 1024];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 { break; }
        hasher.update(&buf[..n]);
    }
    Ok(hasher.finalize().to_hex().to_string())
}

/// Human-readable byte count for progress output.
fn human_bytes(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = n as f64;
    let mut u = 0;
    while v >= 1024.0 && u < UNITS.len() - 1 {
        v /= 1024.0;
        u += 1;
    }
    if u == 0 { format!("{n} B") } else { format!("{v:.1} {}", UNITS[u]) }
}

fn dirs_or_home() -> String {
    std::env::var("HOME").unwrap_or_else(|_| "/tmp".into())
}

fn print_transfer(t: &ahp_api::TransferResponse) {
    println!("Transfer {}:", t.id);
    println!("  State:       {}", t.state);
    println!("  Progress:    {:.1}%", t.progress * 100.0);
    println!("  Transferred: {} bytes", t.bytes_transferred);
    println!("  Total:       {} bytes", t.bytes_total);
    println!("  Source:      {}", t.source);
    println!("  Destination: {}", t.destination);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `auto` is the undecided case, not a profile. Returning `None` is
    /// what defers the choice to the point after the path probe where the
    /// link type is known — a placeholder profile here would be
    /// indistinguishable from the user asking for it.
    #[test]
    fn congestion_auto_parses_as_undecided() {
        assert_eq!(parse_congestion("auto"), Ok(None));
    }

    /// Every name the sender and the policy files accept must parse here
    /// too, aliases included: three copies of this list drifted before it
    /// was shared, and the CLI's copy is the one users type against.
    #[test]
    fn congestion_names_and_aliases_all_parse() {
        for (name, expect) in [
            ("classic", CongestionProfile::Classic),
            ("cubic", CongestionProfile::Classic),
            ("model", CongestionProfile::Model),
            ("bbr", CongestionProfile::Model),
            ("fair", CongestionProfile::Fair),
            ("aimd", CongestionProfile::Fair),
            ("wifi", CongestionProfile::Wifi),
            ("udt", CongestionProfile::Udt),
            ("cycle", CongestionProfile::Rl),
            ("rl", CongestionProfile::Rl),
        ] {
            assert_eq!(parse_congestion(name), Ok(Some(expect)), "{name}");
        }
    }

    /// A typo must not silently run a different controller — the failure
    /// this function exists to prevent. The message names `auto` as well,
    /// since it is now the default and not in the profile list.
    #[test]
    fn unknown_congestion_is_rejected_and_says_what_is_valid() {
        let err = parse_congestion("modle").expect_err("a typo must not parse");
        assert!(err.contains("modle"), "the rejected value must appear: {err}");
        assert!(err.contains("auto"), "auto must be offered: {err}");
        assert!(err.contains("classic"), "the valid names must appear: {err}");
        assert!(parse_congestion("").is_err());
        assert!(parse_congestion("AUTO").is_err(), "matching is exact");
    }

    /// Every link type the probe can report must resolve to a profile that
    /// actually exists. This is the lookup `--congestion auto` performs;
    /// if the policy table and the controller list ever disagree, the
    /// sender silently falls back to classic and only a log line says so.
    #[test]
    fn every_link_type_default_names_a_real_profile() {
        for lt in [
            ahp_policy::LinkType::Loopback,
            ahp_policy::LinkType::LanEthernet,
            ahp_policy::LinkType::LanWifi,
            ahp_policy::LinkType::Wan,
            ahp_policy::LinkType::Unknown,
        ] {
            let name = ahp_policy::defaults_for_link_type(lt).cc_profile;
            assert!(
                CongestionProfile::from_name(&name).is_some(),
                "{lt} defaults to {name:?}, which is not a congestion profile"
            );
        }
    }

    /// The change this default exists for: the wifi path must not resolve
    /// to `classic`, which measured 27.3 MB/s at cv 47.6% on a real 5 GHz
    /// radio against `model`'s 34.2 and `cycle`'s 35.5.
    #[test]
    fn wifi_does_not_default_to_classic() {
        let name = ahp_policy::defaults_for_link_type(ahp_policy::LinkType::LanWifi).cc_profile;
        assert_ne!(
            CongestionProfile::from_name(&name), Some(CongestionProfile::Classic),
            "a wifi link resolving to classic gives back the 25% this default was for"
        );
    }
}
