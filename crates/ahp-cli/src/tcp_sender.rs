// Favonius — high-performance file transfer over UDP
// Copyright (c) 2025-2026 Vantino SàRL
// SPDX-License-Identifier: Apache-2.0

//! Sending over TCP, when UDP cannot get through.
//!
//! See [`ahp_proto::fallback`] for the frame and the reasoning. This side
//! is deliberately dull: open a connection, announce the file, stream it
//! while hashing, send the hash, read the verdict.
//!
//! It makes **no performance claim**. The kernel's TCP stack does the
//! work, none of the congestion control or multi-stream machinery is
//! involved, and on the impaired links Favonius is built for this will be
//! markedly slower than the UDP path. That is the trade: a transfer that
//! arrives beats one that needs a firewall change request.

use std::path::Path;
use std::time::{Duration, Instant};

use ahp_proto::fallback::{FallbackHeader, FallbackReply};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const COPY_BUFFER: usize = 256 * 1024;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Debug)]
pub struct TcpTransferStats {
    pub bytes_sent: u64,
    pub elapsed: Duration,
}

impl TcpTransferStats {
    pub fn throughput_mib_s(&self) -> f64 {
        let secs = self.elapsed.as_secs_f64();
        if secs <= 0.0 {
            return 0.0;
        }
        self.bytes_sent as f64 / 1_048_576.0 / secs
    }
}

/// Send one file to `addr`, to be written at `dest_path` under the
/// daemon's `--dest-root`.
pub async fn send_file(
    source: &Path,
    addr: std::net::SocketAddr,
    dest_path: &str,
) -> Result<TcpTransferStats, String> {
    let meta = tokio::fs::metadata(source)
        .await
        .map_err(|e| format!("cannot read {}: {e}", source.display()))?;
    if !meta.is_file() {
        return Err(format!(
            "{} is not a regular file; the TCP fallback sends one file at a time",
            source.display()
        ));
    }
    let size = meta.len();

    let mut stream = tokio::time::timeout(
        CONNECT_TIMEOUT,
        tokio::net::TcpStream::connect(addr),
    )
    .await
    .map_err(|_| format!("timed out connecting to {addr}"))?
    .map_err(|e| format!("cannot connect to {addr}: {e}"))?;

    // Latency matters more than packing here: the receiver is waiting on
    // a header before it can do anything.
    let _ = stream.set_nodelay(true);

    let header = FallbackHeader { path: dest_path.to_string(), size };
    let encoded = header.encode().map_err(|e| e.to_string())?;
    stream
        .write_all(&encoded)
        .await
        .map_err(|e| format!("sending the header: {e}"))?;

    let started = Instant::now();
    let mut file = tokio::fs::File::open(source)
        .await
        .map_err(|e| format!("opening {}: {e}", source.display()))?;

    let mut hasher = blake3::Hasher::new();
    let mut buf = vec![0u8; COPY_BUFFER];
    let mut sent = 0u64;

    loop {
        let n = file
            .read(&mut buf)
            .await
            .map_err(|e| format!("reading {}: {e}", source.display()))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        if let Err(e) = stream.write_all(&buf[..n]).await {
            // The daemon refuses *after* reading the header — a path
            // outside its --dest-root, say — then stops reading and
            // closes. The write then fails with "broken pipe" while the
            // real reason is sitting unread on the socket. Reporting the
            // pipe error would send someone to look at their network for
            // a destination they mis-typed, so read the verdict first.
            if let Some(reason) = drain_refusal(&mut stream).await {
                return Err(format!("daemon refused: {reason}"));
            }
            return Err(format!("sending payload: {e}"));
        }
        sent += n as u64;
    }

    // The size in the header is what the receiver waits for. If the file
    // changed under us the transfer would hang or truncate, so say so
    // here rather than let the peer time out.
    if sent != size {
        return Err(format!(
            "{} changed while being sent: announced {size} bytes, read {sent}",
            source.display()
        ));
    }

    stream
        .write_all(hasher.finalize().as_bytes())
        .await
        .map_err(|e| format!("sending the hash: {e}"))?;
    stream.flush().await.map_err(|e| format!("flushing: {e}"))?;

    let mut reply = vec![0u8; 3 + 512];
    let n = stream
        .read(&mut reply)
        .await
        .map_err(|e| format!("waiting for the daemon's verdict: {e}"))?;

    match FallbackReply::decode(&reply[..n]) {
        Some(FallbackReply::Accepted) => Ok(TcpTransferStats {
            bytes_sent: sent,
            elapsed: started.elapsed(),
        }),
        Some(FallbackReply::Refused(reason)) => Err(format!("daemon refused: {reason}")),
        // An unreadable verdict is not success. The bytes may be on disk
        // and may not; reporting a transfer complete on a reply we could
        // not parse is the one direction that must never happen.
        None => Err(
            "the daemon's reply could not be read, so the transfer is not confirmed. \
             Check the destination before assuming it arrived."
                .into(),
        ),
    }
}

/// Read a refusal the daemon may have sent before closing.
///
/// Best effort and short: the connection is already failing, and a client
/// that hangs here has turned a clear error into a stall.
async fn drain_refusal(stream: &mut tokio::net::TcpStream) -> Option<String> {
    let mut buf = vec![0u8; 3 + 512];
    let n = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut buf))
        .await
        .ok()?
        .ok()?;
    match FallbackReply::decode(&buf[..n]) {
        Some(FallbackReply::Refused(reason)) => Some(reason),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn throughput_of_an_instant_transfer_is_not_infinite() {
        let s = TcpTransferStats { bytes_sent: 1024, elapsed: Duration::ZERO };
        assert_eq!(s.throughput_mib_s(), 0.0);
    }

    #[test]
    fn throughput_is_mib_per_second() {
        let s = TcpTransferStats {
            bytes_sent: 10 * 1_048_576,
            elapsed: Duration::from_secs(2),
        };
        assert!((s.throughput_mib_s() - 5.0).abs() < 1e-9, "{}", s.throughput_mib_s());
    }

    #[tokio::test]
    async fn sending_a_directory_is_refused_with_a_reason() {
        let dir = tempfile::tempdir().unwrap();
        let err = send_file(dir.path(), "127.0.0.1:1".parse().unwrap(), "x")
            .await
            .unwrap_err();
        assert!(err.contains("not a regular file"), "{err}");
    }
}
