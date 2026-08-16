// Favonius — high-performance file transfer over UDP
// Copyright (c) 2025-2026 Vantino SàRL
// SPDX-License-Identifier: Apache-2.0

//! End-to-end: who is allowed to send to a daemon.
//!
//! `--dest-root` confines *where* a transfer may write. It never answered
//! whether a stranger may write at all — any host that could reach the
//! control port could. A client may now append its Ed25519 identity to
//! HELLO, and the daemon can insist on one and check it against a list.
//!
//! Every arm here asserts on the **destination directory**, not on an exit
//! code. A refusal that logs loudly and still writes the file is the
//! failure mode worth catching, and it is invisible from the client's side.
//!
//! The compatibility arms matter as much as the enforcing ones: the auth
//! material is appended where an older daemon reads nothing, so a client
//! carrying an identity must still transfer to a daemon that has never
//! heard of one.

use ahp_cli::net_sender::send_file;
use ahp_compression::CompressionProfile;
use ahp_congestion::CongestionProfile;
use ahp_crypto::signatures::SigningIdentity;
use ahp_daemon::peer_auth::PeerPolicy;
use ahp_proto::data::AckMode;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Option<Self> {
        let dir = std::env::temp_dir()
            .join(format!("favonius-test-{tag}-{:016x}", rand::random::<u64>()));
        std::fs::create_dir_all(&dir).ok()?;
        Some(Scratch(dir))
    }
    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn free_port_run(n: u16) -> Option<u16> {
    for _ in 0..32 {
        let base: u16 = 20_000 + (rand::random::<u16>() % 40_000);
        if base.checked_add(n).is_none() {
            continue;
        }
        let mut held = Vec::new();
        let mut ok = true;
        for i in 0..n {
            match std::net::UdpSocket::bind(("127.0.0.1", base + i)) {
                Ok(s) => held.push(s),
                Err(_) => {
                    ok = false;
                    break;
                }
            }
        }
        drop(held);
        if ok {
            return Some(base);
        }
    }
    None
}

struct Daemon {
    control: SocketAddr,
    _scratch: Scratch,
    dest_root: PathBuf,
    /// The daemon's own identity, so the client can pin it — required,
    /// because the client presents its identity only on an encrypted
    /// handshake.
    server_key: [u8; 32],
}

/// Start a loopback daemon under `policy`.
async fn start_daemon(policy: PeerPolicy) -> Option<Daemon> {
    let base = free_port_run(2)?;
    let control: SocketAddr = format!("127.0.0.1:{base}").parse().unwrap();
    let data: SocketAddr = format!("127.0.0.1:{}", base + 1).parse().unwrap();

    let dir = Scratch::new("peer-auth")?;
    let dest_root = dir.path().to_path_buf();
    let root = dest_root.clone();

    let identity = SigningIdentity::generate();
    let server_key = identity.public_bytes();

    tokio::spawn(async move {
        let _ = ahp_daemon::net_receiver::run_protocol_listener(
            control,
            data,
            4,
            None,
            None,
            Some(root),
            Some(identity),
            policy,
        )
        .await;
    });
    tokio::time::sleep(std::time::Duration::from_millis(400)).await;
    Some(Daemon { control, _scratch: dir, dest_root, server_key })
}

/// Attempt one transfer. Returns whether the client reported success.
async fn attempt(
    daemon: &Daemon,
    name: &str,
    client_identity: Option<&SigningIdentity>,
    require_peer_auth: bool,
) -> bool {
    let src_dir = Scratch::new("peer-auth-src").expect("scratch");
    let source = src_dir.path().join("payload.bin");
    std::fs::write(&source, b"the quick brown fox").expect("write source");
    let dest = daemon.dest_root.join(name);

    tokio::time::timeout(
        std::time::Duration::from_secs(30),
        send_file(
            daemon.control,
            &source,
            dest.to_str().unwrap(),
            Some(CongestionProfile::Classic),
            AckMode::Bitmap,
            1,
            "auto",
            true, // encrypt: the identity rides inside the encrypted handshake
            CompressionProfile::None,
            false,
            None,
            false,
            Some(daemon.server_key),
            client_identity,
            require_peer_auth,
        ),
    )
    .await
    .map(|r| r.is_ok())
    .unwrap_or(false)
}

/// What actually matters: did the bytes land?
fn landed(daemon: &Daemon, name: &str) -> bool {
    daemon.dest_root.join(name).exists()
}

// ── Enforcing ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn an_allowlisted_sender_transfers() {
    let client = SigningIdentity::generate();
    let Some(d) = start_daemon(PeerPolicy::new([client.public_bytes()], true)).await else {
        eprintln!("skipped: no free ports");
        return;
    };
    assert!(attempt(&d, "ok.bin", Some(&client), true).await, "allowlisted sender refused");
    assert!(landed(&d, "ok.bin"), "reported success but nothing landed");
}

#[tokio::test]
async fn a_sender_not_on_the_allowlist_writes_nothing() {
    let allowed = SigningIdentity::generate();
    let stranger = SigningIdentity::generate();
    let Some(d) = start_daemon(PeerPolicy::new([allowed.public_bytes()], true)).await else {
        eprintln!("skipped: no free ports");
        return;
    };
    assert!(!attempt(&d, "stranger.bin", Some(&stranger), false).await, "stranger transferred");
    assert!(!landed(&d, "stranger.bin"), "a refused sender still wrote a file");
}

#[tokio::test]
async fn an_unauthenticated_sender_writes_nothing_when_auth_is_required() {
    let Some(d) = start_daemon(PeerPolicy::new([], true)).await else {
        eprintln!("skipped: no free ports");
        return;
    };
    assert!(!attempt(&d, "anon.bin", None, false).await, "anonymous sender transferred");
    assert!(!landed(&d, "anon.bin"), "an anonymous sender wrote a file");
}

// ── Not enforcing: the behaviour that must not change ─────────────────────

#[tokio::test]
async fn a_daemon_with_no_policy_still_accepts_anonymous_senders() {
    // The compatibility floor. If this breaks, upgrading the daemon breaks
    // every deployment that has never heard of identities.
    let Some(d) = start_daemon(PeerPolicy::default()).await else {
        eprintln!("skipped: no free ports");
        return;
    };
    assert!(attempt(&d, "anon.bin", None, false).await, "default daemon refused a plain sender");
    assert!(landed(&d, "anon.bin"));
}

#[tokio::test]
async fn a_daemon_with_no_policy_accepts_a_client_that_carries_an_identity() {
    // The append must be ignorable. A client configured with an identity
    // has to keep working against a daemon that does not check it —
    // otherwise rolling out client identities breaks transfers before the
    // daemons are upgraded.
    let client = SigningIdentity::generate();
    let Some(d) = start_daemon(PeerPolicy::default()).await else {
        eprintln!("skipped: no free ports");
        return;
    };
    assert!(attempt(&d, "carried.bin", Some(&client), false).await, "identity broke the handshake");
    assert!(landed(&d, "carried.bin"));
}

#[tokio::test]
async fn requiring_auth_against_a_daemon_with_no_policy_transfers_nothing() {
    // The client asked to be authenticated; this daemon never checked. It
    // must abort rather than transfer and let the caller believe it was
    // authenticated — the case a capability bit exists to distinguish.
    let client = SigningIdentity::generate();
    let Some(d) = start_daemon(PeerPolicy::default()).await else {
        eprintln!("skipped: no free ports");
        return;
    };
    assert!(
        !attempt(&d, "unchecked.bin", Some(&client), true).await,
        "client believed it was authenticated by a daemon with no policy"
    );
    assert!(!landed(&d, "unchecked.bin"));
}

// ── Migration ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn an_allowlist_without_require_still_admits_anonymous_senders() {
    // Deliberate, and the way an estate migrates: populate the allowlist
    // and watch it while nothing is being turned away, then require. It
    // looks like a bug from outside, so it is pinned here.
    let allowed = SigningIdentity::generate();
    let Some(d) = start_daemon(PeerPolicy::new([allowed.public_bytes()], false)).await else {
        eprintln!("skipped: no free ports");
        return;
    };
    assert!(attempt(&d, "anon.bin", None, false).await, "migration posture refused a plain sender");
    assert!(landed(&d, "anon.bin"));
}
