// Favonius — high-performance file transfer over UDP
// Copyright (c) 2025-2026 Vantino SàRL
// SPDX-License-Identifier: Apache-2.0

//! Receiving a transfer over TCP, when UDP cannot get through.
//!
//! See [`ahp_proto::fallback`] for why this exists and what the frame
//! looks like. In short: a network team that will not permit inbound UDP
//! is common, and a transfer that arrives slowly beats one that needs a
//! change request.
//!
//! # It inherits the same confinement, deliberately
//!
//! This path writes files a remote peer named, so it goes through exactly
//! the `--dest-root` check the UDP receiver uses. A second write path with
//! its own idea of where files may land is how a confinement bug is
//! introduced — the check is called here rather than reimplemented.
//!
//! It also inherits the same limitation: like the UDP listener, this does
//! **not authenticate senders**. Any peer that can reach the port can
//! transfer, exactly as `SECURITY.md` says. Adding a second unauthenticated
//! entry point does not change the posture, but it does widen it from one
//! protocol to two, and a deployment should permit both or neither.
//!
//! # Committing
//!
//! Bytes stream to a `.part` file beside the destination and are hashed on
//! the way past. Only when the payload is complete *and* the trailing
//! BLAKE3 matches is the file renamed into place. A truncated transfer, a
//! dropped connection, or an altered payload leaves the `.part` and never
//! the real name — so a partial file is never mistaken for a delivered one.

use std::path::{Path, PathBuf};

use ahp_proto::fallback::{FallbackHeader, FallbackReply, HEADER_LEN};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Streaming buffer. Large enough that the syscall rate is not the limit,
/// small enough that many concurrent transfers do not add up to much.
const COPY_BUFFER: usize = 256 * 1024;

/// How long a peer may hold a connection without sending anything.
const IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);

/// Serve the TCP fallback until the process ends.
///
/// Binds the **TCP** socket bearing the control port's number, so a
/// deployment opens one port rather than two.
pub async fn serve(
    listener: TcpListener,
    dest_root: Option<PathBuf>,
) -> std::io::Result<()> {
    let local = listener.local_addr()?;
    match &dest_root {
        Some(root) => tracing::info!(
            listen = %local, root = %root.display(),
            "TCP fallback ready (used when UDP is blocked)"
        ),
        None => tracing::warn!(
            listen = %local,
            "TCP fallback ready with NO --dest-root: a peer may name any \
             absolute path. This matches the UDP path's --allow-any-dest \
             behaviour and is only safe on a trusted network."
        ),
    }

    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(error = %e, "TCP fallback accept failed");
                continue;
            }
        };
        let root = dest_root.clone();
        tokio::spawn(async move {
            if let Err(e) = handle(stream, peer, root).await {
                tracing::warn!(%peer, error = %e, "TCP fallback transfer failed");
            }
        });
    }
}

async fn handle(
    mut stream: TcpStream,
    peer: std::net::SocketAddr,
    dest_root: Option<PathBuf>,
) -> std::io::Result<()> {
    let result = receive(&mut stream, peer, dest_root).await;
    let reply = match &result {
        Ok(path) => {
            tracing::info!(%peer, dest = %path.display(), "TCP fallback transfer complete");
            FallbackReply::Accepted
        }
        Err(reason) => {
            tracing::warn!(%peer, reason = %reason, "TCP fallback transfer refused");
            FallbackReply::Refused(reason.clone())
        }
    };
    stream.write_all(&reply.encode()).await?;
    stream.flush().await?;
    Ok(())
}

/// The transfer itself. `Err` carries a reason meant for a person.
async fn receive(
    stream: &mut TcpStream,
    peer: std::net::SocketAddr,
    dest_root: Option<PathBuf>,
) -> Result<PathBuf, String> {
    let deadline = || tokio::time::timeout(IDLE_TIMEOUT, std::future::pending::<()>());
    let _ = deadline; // documented intent; per-read timeouts below

    let mut head = [0u8; HEADER_LEN];
    read_exact(stream, &mut head).await?;
    let (path_len, size) =
        FallbackHeader::decode_head(&head).map_err(|e| e.to_string())?;

    let mut path_bytes = vec![0u8; path_len];
    read_exact(stream, &mut path_bytes).await?;
    let header =
        FallbackHeader::from_parts(&path_bytes, size).map_err(|e| e.to_string())?;

    // The same confinement the UDP receiver applies. A remote peer names
    // the path; it does not choose where the root is.
    let dest = match &dest_root {
        Some(root) => crate::net_receiver::confine_dest_path(root, &header.path)?,
        None => PathBuf::from(&header.path),
    };

    if let Some(parent) = dest.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .map_err(|e| format!("creating {}: {e}", parent.display()))?;
    }

    // Stage beside the destination, commit by rename. A crash or a
    // truncated stream leaves the .part, never a short file under the
    // real name.
    let staging = staging_path(&dest);
    let mut file = tokio::fs::File::create(&staging)
        .await
        .map_err(|e| format!("creating {}: {e}", staging.display()))?;

    let mut hasher = blake3::Hasher::new();
    let mut buf = vec![0u8; COPY_BUFFER];
    let mut remaining = header.size;

    tracing::info!(%peer, dest = %dest.display(), bytes = header.size,
        "TCP fallback transfer starting");

    while remaining > 0 {
        let want = (remaining as usize).min(buf.len());
        let n = tokio::time::timeout(IDLE_TIMEOUT, stream.read(&mut buf[..want]))
            .await
            .map_err(|_| "peer stopped sending".to_string())?
            .map_err(|e| format!("reading payload: {e}"))?;
        if n == 0 {
            let _ = tokio::fs::remove_file(&staging).await;
            return Err(format!(
                "connection closed with {remaining} of {} bytes still to come",
                header.size
            ));
        }
        hasher.update(&buf[..n]);
        file.write_all(&buf[..n])
            .await
            .map_err(|e| format!("writing {}: {e}", staging.display()))?;
        remaining -= n as u64;
    }

    let mut claimed = [0u8; 32];
    if let Err(e) = read_exact(stream, &mut claimed).await {
        let _ = tokio::fs::remove_file(&staging).await;
        return Err(format!("payload arrived but its hash did not: {e}"));
    }

    let actual = hasher.finalize();
    if actual.as_bytes() != &claimed {
        let _ = tokio::fs::remove_file(&staging).await;
        return Err(format!(
            "hash mismatch: sender said {}, {} bytes received hash to {}",
            hex(&claimed),
            header.size,
            actual.to_hex()
        ));
    }

    // Durable before visible: the rename is the moment the file exists
    // under its real name, and it must not name a file the kernel has not
    // written yet.
    file.flush().await.map_err(|e| format!("flushing: {e}"))?;
    file.sync_all().await.map_err(|e| format!("syncing: {e}"))?;
    drop(file);

    tokio::fs::rename(&staging, &dest)
        .await
        .map_err(|e| format!("committing {}: {e}", dest.display()))?;

    Ok(dest)
}

async fn read_exact(stream: &mut TcpStream, buf: &mut [u8]) -> Result<(), String> {
    tokio::time::timeout(IDLE_TIMEOUT, stream.read_exact(buf))
        .await
        .map_err(|_| "peer stopped sending".to_string())?
        .map_err(|e| format!("short read: {e}"))?;
    Ok(())
}

fn staging_path(dest: &Path) -> PathBuf {
    let mut name = dest.file_name().unwrap_or_default().to_os_string();
    name.push(".part");
    dest.with_file_name(name)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn staging_sits_beside_the_destination() {
        // Beside, not in a temp directory: a rename across filesystems is
        // not atomic, and the whole point of staging is the atomic commit.
        assert_eq!(
            staging_path(Path::new("/srv/incoming/a/b.bin")),
            PathBuf::from("/srv/incoming/a/b.bin.part")
        );
    }
}
