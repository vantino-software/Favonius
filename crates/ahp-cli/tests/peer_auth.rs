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
use ahp_crypto::grant::Grant;
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

/// Start a loopback daemon under a policy built from its own identity.
///
/// The policy is built *here* rather than passed in, because a grant names
/// the daemon it was issued for: the policy has to be told the identity the
/// daemon will actually run with, and the two must be the same key.
async fn start_daemon_with(
    make_policy: impl FnOnce([u8; 32]) -> PeerPolicy,
) -> Option<Daemon> {
    let identity = SigningIdentity::generate();
    let own = identity.public_bytes();
    start_daemon_inner(make_policy(own), identity).await
}

/// Start a loopback daemon under `policy`.
async fn start_daemon(policy: PeerPolicy) -> Option<Daemon> {
    start_daemon_inner(policy, SigningIdentity::generate()).await
}

async fn start_daemon_inner(policy: PeerPolicy, identity: SigningIdentity) -> Option<Daemon> {
    let base = free_port_run(2)?;
    let control: SocketAddr = format!("127.0.0.1:{base}").parse().unwrap();
    let data: SocketAddr = format!("127.0.0.1:{}", base + 1).parse().unwrap();

    let dir = Scratch::new("peer-auth")?;
    let dest_root = dir.path().to_path_buf();
    let root = dest_root.clone();

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
    attempt_with_grant(daemon, name, client_identity, None, require_peer_auth).await
}

async fn attempt_with_grant(
    daemon: &Daemon,
    name: &str,
    client_identity: Option<&SigningIdentity>,
    grant: Option<&[u8]>,
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
            grant,
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

// ── Grants ────────────────────────────────────────────────────────────────

fn grant_bytes(
    anchor: &SigningIdentity,
    source: [u8; 32],
    destination: [u8; 32],
    prefix: &str,
    not_after: u64,
) -> Vec<u8> {
    Grant {
        source,
        destination,
        not_after,
        run_id: "run-under-test".into(),
        path_prefix: prefix.into(),
    }
    .sign(anchor)
}

fn in_five_minutes() -> u64 {
    ahp_crypto::grant::now_unix() + 300
}

#[tokio::test]
async fn a_valid_grant_transfers() {
    let anchor = SigningIdentity::generate();
    let client = SigningIdentity::generate();
    let anchor_pub = anchor.public_bytes();
    let Some(d) = start_daemon_with(|own| {
        PeerPolicy::new([], true).with_trust_anchors([anchor_pub], true, Some(own))
    })
    .await
    else {
        eprintln!("skipped: no free ports");
        return;
    };
    let g = grant_bytes(
        &anchor,
        client.public_bytes(),
        d.server_key,
        d.dest_root.to_str().unwrap(),
        in_five_minutes(),
    );
    assert!(
        attempt_with_grant(&d, "ok.bin", Some(&client), Some(&g), true).await,
        "a valid grant was refused"
    );
    assert!(landed(&d, "ok.bin"));
}

#[tokio::test]
async fn an_authenticated_sender_without_a_grant_writes_nothing() {
    // The whole point of --require-grant: being a known sender is no longer
    // enough on its own.
    let anchor = SigningIdentity::generate();
    let client = SigningIdentity::generate();
    let anchor_pub = anchor.public_bytes();
    let Some(d) = start_daemon_with(|own| {
        PeerPolicy::new([], true).with_trust_anchors([anchor_pub], true, Some(own))
    })
    .await
    else {
        eprintln!("skipped: no free ports");
        return;
    };
    assert!(!attempt(&d, "nogrant.bin", Some(&client), false).await);
    assert!(!landed(&d, "nogrant.bin"), "a sender with no grant wrote a file");
}

#[tokio::test]
async fn a_grant_from_an_untrusted_issuer_writes_nothing() {
    let anchor = SigningIdentity::generate();
    let impostor = SigningIdentity::generate();
    let client = SigningIdentity::generate();
    let anchor_pub = anchor.public_bytes();
    let Some(d) = start_daemon_with(|own| {
        PeerPolicy::new([], true).with_trust_anchors([anchor_pub], true, Some(own))
    })
    .await
    else {
        eprintln!("skipped: no free ports");
        return;
    };
    let g = grant_bytes(
        &impostor,
        client.public_bytes(),
        d.server_key,
        d.dest_root.to_str().unwrap(),
        in_five_minutes(),
    );
    assert!(!attempt_with_grant(&d, "forged.bin", Some(&client), Some(&g), false).await);
    assert!(!landed(&d, "forged.bin"), "a forged grant wrote a file");
}

#[tokio::test]
async fn an_expired_grant_writes_nothing() {
    let anchor = SigningIdentity::generate();
    let client = SigningIdentity::generate();
    let anchor_pub = anchor.public_bytes();
    let Some(d) = start_daemon_with(|own| {
        PeerPolicy::new([], true).with_trust_anchors([anchor_pub], true, Some(own))
    })
    .await
    else {
        eprintln!("skipped: no free ports");
        return;
    };
    let g = grant_bytes(
        &anchor,
        client.public_bytes(),
        d.server_key,
        d.dest_root.to_str().unwrap(),
        ahp_crypto::grant::now_unix() - 1,
    );
    assert!(!attempt_with_grant(&d, "stale.bin", Some(&client), Some(&g), false).await);
    assert!(!landed(&d, "stale.bin"), "an expired grant wrote a file");
}

#[tokio::test]
async fn a_grant_issued_for_another_daemon_writes_nothing() {
    // Without the destination binding, one permission would be a permission
    // everywhere the same anchor is trusted.
    let anchor = SigningIdentity::generate();
    let client = SigningIdentity::generate();
    let anchor_pub = anchor.public_bytes();
    let Some(d) = start_daemon_with(|own| {
        PeerPolicy::new([], true).with_trust_anchors([anchor_pub], true, Some(own))
    })
    .await
    else {
        eprintln!("skipped: no free ports");
        return;
    };
    let elsewhere = SigningIdentity::generate().public_bytes();
    let g = grant_bytes(
        &anchor,
        client.public_bytes(),
        elsewhere,
        d.dest_root.to_str().unwrap(),
        in_five_minutes(),
    );
    assert!(!attempt_with_grant(&d, "wrongdest.bin", Some(&client), Some(&g), false).await);
    assert!(!landed(&d, "wrongdest.bin"), "a grant for another daemon wrote a file");
}

#[tokio::test]
async fn a_write_outside_the_granted_prefix_is_refused() {
    // The path scope is enforced after the manifest names a destination,
    // which is a different code path from everything above — and the one
    // that would silently do nothing if it were never wired up.
    let anchor = SigningIdentity::generate();
    let client = SigningIdentity::generate();
    let anchor_pub = anchor.public_bytes();
    let Some(d) = start_daemon_with(|own| {
        PeerPolicy::new([], true).with_trust_anchors([anchor_pub], true, Some(own))
    })
    .await
    else {
        eprintln!("skipped: no free ports");
        return;
    };
    // Permit only a subdirectory, then try to write beside it.
    let permitted = d.dest_root.join("allowed");
    std::fs::create_dir_all(&permitted).expect("mkdir");
    let g = grant_bytes(
        &anchor,
        client.public_bytes(),
        d.server_key,
        permitted.to_str().unwrap(),
        in_five_minutes(),
    );

    assert!(
        attempt_with_grant(&d, "allowed/inside.bin", Some(&client), Some(&g), true).await,
        "a write inside the prefix was refused"
    );
    assert!(landed(&d, "allowed/inside.bin"));

    assert!(
        !attempt_with_grant(&d, "outside.bin", Some(&client), Some(&g), false).await,
        "a write outside the prefix succeeded"
    );
    assert!(!landed(&d, "outside.bin"), "a write outside the granted prefix landed");
}

#[tokio::test]
async fn a_daemon_that_accepts_grants_still_serves_a_sender_that_brings_none() {
    // Anchors configured but not required: the migration posture again, one
    // layer up. Grants are checked when presented and their absence is not
    // an error.
    let anchor = SigningIdentity::generate();
    let client = SigningIdentity::generate();
    let anchor_pub = anchor.public_bytes();
    let Some(d) = start_daemon_with(|own| {
        PeerPolicy::new([], true).with_trust_anchors([anchor_pub], false, Some(own))
    })
    .await
    else {
        eprintln!("skipped: no free ports");
        return;
    };
    assert!(attempt(&d, "nogrant.bin", Some(&client), false).await, "refused without a grant");
    assert!(landed(&d, "nogrant.bin"));
}

#[tokio::test]
async fn a_second_transfer_cannot_skip_the_checks_by_resuming() {
    // The hole this pins shut: a successful transfer used to earn a 0-RTT
    // session ticket, and a HELLO carrying a ticket took a branch that ran
    // none of the authorisation checks. A sender authorised for one
    // directory and five minutes could then write anywhere under
    // --dest-root for as long as the ticket lived.
    //
    // The client caches tickets per process, so doing both transfers in one
    // test is what makes this reachable at all.
    let anchor = SigningIdentity::generate();
    let client = SigningIdentity::generate();
    let anchor_pub = anchor.public_bytes();
    let Some(d) = start_daemon_with(|own| {
        PeerPolicy::new([], true).with_trust_anchors([anchor_pub], true, Some(own))
    })
    .await
    else {
        eprintln!("skipped: no free ports");
        return;
    };

    let g = grant_bytes(
        &anchor,
        client.public_bytes(),
        d.server_key,
        d.dest_root.to_str().unwrap(),
        in_five_minutes(),
    );
    assert!(
        attempt_with_grant(&d, "first.bin", Some(&client), Some(&g), true).await,
        "the authorised transfer should succeed"
    );
    assert!(landed(&d, "first.bin"));

    // Same process, same client, now with no grant at all. If a ticket from
    // the first transfer could be replayed, this would land.
    assert!(
        !attempt(&d, "second.bin", Some(&client), false).await,
        "a second transfer got in without presenting a grant"
    );
    assert!(!landed(&d, "second.bin"), "a resumed session wrote a file it was not granted");
}
