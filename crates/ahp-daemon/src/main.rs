// Favonius — high-performance file transfer over UDP
// Copyright (c) 2025-2026 Vantino SàRL
// SPDX-License-Identifier: Apache-2.0

use clap::{Parser, Subcommand};
use ahp_api::AppState;
use tokio::net::TcpListener;

#[derive(Parser, Debug)]
#[command(name = "favonius-daemon", version, about = "Favonius transfer daemon")]
struct Args {
    #[command(subcommand)]
    command: Option<Command>,
    /// HTTP API listen address. Loopback by default; opt back into a
    /// wildcard bind with e.g. `--listen 0.0.0.0:7800` (requires
    /// FAVONIUS_API_TOKEN to be set — ahp_api::serve refuses otherwise).
    #[arg(long, default_value = "127.0.0.1:7800")]
    listen: String,
    /// AHP control (UDP) listen address — handles HELLO, MANIFEST, FINISH
    #[arg(long, default_value = "0.0.0.0:7801")]
    protocol_listen: String,
    /// AHP data (UDP) listen address — handles DATA + ACKs during transfers
    #[arg(long, default_value = "0.0.0.0:7802")]
    data_listen: String,
    #[arg(long, default_value = "info")]
    log_level: String,
    /// Maximum concurrent transfers (0 = unlimited)
    #[arg(long, default_value_t = 4)]
    max_concurrent: usize,
    /// Extra data ports for parallel transfers, e.g. `7803-7810`.
    ///
    /// Parallelism needs a data socket per transfer — two transfers sharing
    /// one socket steal each other's DATA — so without this the daemon
    /// serves one transfer at a time and `--max-concurrent` is only a queue
    /// depth. The range is bound at startup and fails loudly if a port is
    /// taken, so the firewall rule an operator must open is exactly the
    /// range they typed, known before any traffic arrives. That
    /// predictability is the whole reason this exists rather than
    /// ephemeral ports: UDP reachability is this project's most common
    /// support issue and "open some high ports" is not a rule anyone can
    /// write.
    #[arg(long)]
    data_port_range: Option<String>,
    /// Maximum file size per transfer in MB (0 = unlimited)
    #[arg(long, default_value_t = 0)]
    max_file_size_mb: u64,
    /// Confine every transfer destination under this directory. Required
    /// unless --allow-any-dest is passed (S1)
    #[arg(long)]
    dest_root: Option<std::path::PathBuf>,

    /// Do not listen for TCP fallback transfers.
    ///
    /// The fallback is on by default: it exists for the deployment whose
    /// firewall drops UDP, and that is precisely the deployment where
    /// nobody would know to enable it. Turn it off where the extra
    /// listener is unwanted -- noting it is the same unauthenticated
    /// posture as the UDP path, not a new one.
    #[arg(long)]
    no_tcp_fallback: bool,
    /// Accept arbitrary sender-chosen absolute destination paths.
    ///
    /// This grants any peer that can reach the control port the ability to
    /// write any file the daemon's user can write, with no authentication.
    /// A peer can write /etc/cron.d/… and obtain remote code execution.
    /// It was the behaviour when --dest-root was merely absent, which made
    /// the insecure configuration the default one; it now has to be asked
    /// for by name.
    #[arg(long, default_value_t = false)]
    allow_any_dest: bool,
    /// Ed25519 identity key file (see `keygen`): the daemon signs each full
    /// handshake so clients can authenticate it via --server-key (S5)
    #[arg(long)]
    identity: Option<std::path::PathBuf>,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Generate a new Ed25519 identity key file and print its public key
    Keygen {
        /// Output path for the identity key file (created with 0600 perms)
        #[arg(long, default_value = "favonius-identity.key")]
        output: std::path::PathBuf,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let args = Args::parse();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(&args.log_level)),
        )
        .with_target(true)
        .init();

    if let Some(Command::Keygen { output }) = &args.command {
        let identity = ahp_crypto::signatures::SigningIdentity::generate();
        identity.save_to_file(output)?;
        println!("identity written to {}", output.display());
        println!(
            "public key (pin with `favonius send --server-key`):\n{}",
            ahp_crypto::signatures::hex_encode(&identity.public_bytes())
        );
        return Ok(());
    }

    // Load the Ed25519 identity, if configured.
    let identity = match &args.identity {
        Some(path) => Some(ahp_crypto::signatures::SigningIdentity::load_from_file(path)?),
        None => None,
    };

    // Refuse to start in the configuration that hands an unauthenticated
    // peer arbitrary file write. Verified on 2026-08-11: with no
    // --dest-root, a sender reaching the control port wrote /root/PWNED.bin
    // and /etc/cron.d/pwn on the receiver — remote code execution on any
    // host with cron, requiring no key and no --encrypt. The daemon warned
    // and continued, which is not enough: the insecure mode was reachable
    // by running the documented command line with a flag left off.
    if args.dest_root.is_none() && !args.allow_any_dest {
        eprintln!(
            "favonius-daemon: refusing to start without --dest-root.\n\
             \n\
             Without it the daemon writes to any absolute path a sender asks\n\
             for, with no authentication — including paths like /etc/cron.d,\n\
             which is remote code execution.\n\
             \n\
             Confine incoming transfers:\n    --dest-root /srv/incoming\n\
             \n\
             If you genuinely intend a daemon that accepts arbitrary paths\n\
             from any peer that can reach it, say so explicitly:\n    --allow-any-dest"
        );
        std::process::exit(2);
    }

    // Start AHP protocol listener with separate control + data ports.
    let control_addr: std::net::SocketAddr = args.protocol_listen.parse()?;

    // The TCP fallback shares the control port's *number* on the TCP
    // socket, so a deployment asks its network team for one port rather
    // than two: "permit 7801 to this host, UDP for speed and TCP as the
    // fallback." UDP and TCP sockets on the same number do not conflict.
    //
    // Enabled unless refused, because the case it exists for -- an
    // evaluator whose firewall drops UDP -- is exactly the case where
    // nobody knows to turn it on.
    if !args.no_tcp_fallback {
        let fb_root = args.dest_root.clone();
        match tokio::net::TcpListener::bind(control_addr).await {
            Ok(l) => {
                tokio::spawn(async move {
                    if let Err(e) = ahp_daemon::tcp_fallback::serve(l, fb_root).await {
                        tracing::error!(error = %e, "TCP fallback listener stopped");
                    }
                });
            }
            Err(e) => {
                // Not fatal: the UDP path is the product, and a taken TCP
                // port should not stop the daemon serving it.
                tracing::warn!(addr = %control_addr, error = %e,
                    "could not bind the TCP fallback; UDP transfers are unaffected");
            }
        }
    }
    let data_addr: std::net::SocketAddr = args.data_listen.parse()?;
    let max_concurrent = args.max_concurrent;
    // Parsed here so a malformed range is a startup error with a usage
    // message, not a surprise at the first parallel transfer.
    let data_port_range: Option<(u16, u16)> = match args.data_port_range.as_deref() {
        None => None,
        Some(spec) => {
            let (lo, hi) = spec
                .split_once('-')
                .ok_or_else(|| format!("--data-port-range must be LOW-HIGH, got {spec:?}"))?;
            let lo: u16 = lo.trim().parse().map_err(|_| format!("bad low port in {spec:?}"))?;
            let hi: u16 = hi.trim().parse().map_err(|_| format!("bad high port in {spec:?}"))?;
            if hi < lo {
                return Err(format!("--data-port-range {spec:?} is inverted").into());
            }
            Some((lo, hi))
        }
    };
    let max_file_size = if args.max_file_size_mb > 0 {
        Some(args.max_file_size_mb * 1024 * 1024)
    } else {
        None
    };
    let dest_root = args.dest_root.clone();
    tokio::spawn(async move {
        if let Err(e) = ahp_daemon::net_receiver::run_protocol_listener(
            control_addr, data_addr, max_concurrent, data_port_range, max_file_size, dest_root,
            identity,
        ).await {
            tracing::error!("protocol listener failed: {}", e);
        }
    });

    // Start HTTP API server. `serve` refuses a non-loopback bind without a
    // bearer token (FAVONIUS_API_TOKEN). API concurrency mirrors the UDP
    // listener's --max-concurrent (0 = unlimited -> generous headroom).
    let mut state = AppState::new(if args.max_concurrent > 0 { args.max_concurrent } else { 1024 });
    // The filesystem endpoints (used by `favonius sync` to diff against the
    // destination) are only enabled when a root confines them.
    if let Some(ref root) = args.dest_root {
        state = state.with_dest_root(root);
    }
    let listener = TcpListener::bind(&args.listen).await?;
    tracing::info!(
        listen = %args.listen, control = %args.protocol_listen, data = %args.data_listen,
        "starting favonius daemon"
    );

    ahp_api::serve(listener, state).await?;

    Ok(())
}
