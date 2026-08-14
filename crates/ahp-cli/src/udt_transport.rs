// Favonius — high-performance file transfer over UDP
// Copyright (c) 2025-2026 Vantino SàRL
// SPDX-License-Identifier: Apache-2.0

//! UDT transport wrapper — uses UDT's sendfile/recvfile for file transfer.
//!
//! Provides a baseline 77 MB/s reference on WiFi LAN. The UDT binaries are
//! shelled out to, giving identical throughput to standalone UDT while
//! integrating with Favonius's CLI interface.

use std::path::Path;
use std::time::{Duration, Instant};

pub struct UdtStats {
    pub bytes_sent: u64,
    pub elapsed: Duration,
}

impl UdtStats {
    pub fn throughput_mbps(&self) -> f64 {
        if self.elapsed.as_secs_f64() > 0.0 {
            self.bytes_sent as f64 / self.elapsed.as_secs_f64() / (1024.0 * 1024.0)
        } else {
            0.0
        }
    }
}

/// Find the UDT sendfile binary.
fn find_sendfile() -> Option<std::path::PathBuf> {
    // 1. FAVONIUS_UDT_DIR env
    if let Ok(dir) = std::env::var("FAVONIUS_UDT_DIR") {
        let p = std::path::PathBuf::from(dir).join("sendfile");
        if p.is_file() {
            return Some(p);
        }
    }

    // 2. Relative to executable
    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            // Try repo layout: exe is in target/release/, UDT is in benchmarks/UDT/
            let repo_root = parent.join("../../benchmarks/UDT/sendfile");
            if repo_root.is_file() {
                return Some(repo_root);
            }
        }
    }

    // 3. Relative to CWD
    let cwd = std::path::PathBuf::from("benchmarks/UDT/sendfile");
    if cwd.is_file() {
        return Some(cwd);
    }

    None
}

/// Determine local IP address facing the remote host.
fn local_ip_for(remote: &str) -> Option<String> {
    let output = std::process::Command::new("ip")
        .args(["route", "get", remote])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&output.stdout);
    // Parse "... src 192.168.0.123 ..."
    let parts: Vec<&str> = text.split_whitespace().collect();
    for (i, &word) in parts.iter().enumerate() {
        if word == "src" && i + 1 < parts.len() {
            return Some(parts[i + 1].to_string());
        }
    }
    None
}

/// Parse remote destination: `[user@]host:port:/path`.
///
/// Returns `(ssh_host, remote_ip, remote_path, ssh_port)`:
/// - `ssh_host` is `user@host` when a user is given, else bare `host`
///   (ssh then defaults to the current local user — never hardcode one).
/// - `remote_ip` is the host part without the user, for route lookup.
/// - `ssh_port` is the destination port, passed to ssh via `-p`.
fn parse_udt_dest(dest: &str) -> Option<(String, String, String, Option<u16>)> {
    // Try host:port:/path format (same as AHP)
    if let Some(first_colon) = dest.find(':') {
        let rest = &dest[first_colon + 1..];
        if let Some(second_colon) = rest.find(':') {
            let host = &dest[..first_colon];
            let port_str = &rest[..second_colon];
            let path = &rest[second_colon + 1..];
            if path.starts_with('/') && !host.is_empty() {
                let ip = if host.contains('@') {
                    host.split('@').last().unwrap_or(host).to_string()
                } else {
                    host.to_string()
                };
                let port = port_str.parse::<u16>().ok();
                return Some((host.to_string(), ip, path.to_string(), port));
            }
        }
    }
    None
}

/// Single-quote a string for safe interpolation into a POSIX shell command.
/// Anything may appear inside except a single quote, which is escaped as
/// `'\''`. Prevents word-splitting on spaces and remote command execution
/// via `$(...)`, backticks, etc.
fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// Build the remote recvfile command line with every interpolated value
/// shell-quoted (port is numeric and needs no quoting).
fn build_recv_cmd(
    remote_lib: &str,
    remote_recvfile: &str,
    local_ip: &str,
    port: u16,
    source: &str,
    remote_path: &str,
) -> String {
    format!(
        "LD_LIBRARY_PATH={} {} {} {} {} {}",
        shell_quote(remote_lib),
        shell_quote(remote_recvfile),
        shell_quote(local_ip),
        port,
        shell_quote(source),
        shell_quote(remote_path),
    )
}

/// Interpret the recvfile result. Returns `Some(error)` on failure.
///
/// A non-zero exit status, or the "Connection setup failure" message that
/// recvfile prints to stderr, means the file was NOT transferred — the old
/// code swallowed this and reported the full file as sent.
fn recvfile_error(success: bool, stderr: &str) -> Option<String> {
    let stderr = stderr.trim();
    if !success {
        return Some(format!("recvfile failed: {}", stderr));
    }
    if stderr.contains("Connection setup failure") {
        return Some(format!("UDT connection setup failed: {}", stderr));
    }
    None
}

/// Send a file via UDT's sendfile/recvfile.
pub async fn send_via_udt(
    source: &Path,
    destination: &str,
) -> Result<UdtStats, Box<dyn std::error::Error + Send + Sync>> {
    let sendfile_bin = find_sendfile()
        .ok_or("UDT sendfile binary not found. Set FAVONIUS_UDT_DIR or build in benchmarks/UDT/")?;

    let (ssh_host, remote_ip, remote_path, ssh_port) = parse_udt_dest(destination)
        .ok_or("Invalid destination. Expected: host:port:/path or user@host:port:/path")?;

    let local_ip = local_ip_for(&remote_ip)
        .ok_or("Could not determine local IP for the remote host")?;

    let file_size = std::fs::metadata(source)?.len();
    let source_str = source.to_string_lossy().to_string();

    // Pick a random port for UDT.
    let port: u16 = 9000 + (rand::random::<u16>() % 500);

    eprintln!(
        "UDT send: {} -> {}:{} (via sendfile port {})",
        source_str, ssh_host, remote_path, port
    );

    // Start local sendfile server.
    let mut server = tokio::process::Command::new(&sendfile_bin)
        .arg(port.to_string())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()?;

    // Wait for server to bind.
    tokio::time::sleep(Duration::from_millis(1000)).await;

    // Determine remote UDT paths from env or defaults.
    let remote_recvfile = std::env::var("FAVONIUS_UDT_REMOTE_BIN")
        .unwrap_or_else(|_| "/tmp/udt-bench/recvfile".to_string());
    let remote_lib = std::env::var("FAVONIUS_UDT_REMOTE_LIB")
        .unwrap_or_else(|_| "/tmp/udt-src/src".to_string());

    // Launch recvfile on the remote via SSH. All interpolated values are
    // single-quote escaped so paths with spaces work and shell metachars
    // cannot execute on the remote.
    let start = Instant::now();
    let recv_cmd = build_recv_cmd(
        &remote_lib,
        &remote_recvfile,
        &local_ip,
        port,
        &source_str,
        &remote_path,
    );

    let mut ssh_args: Vec<String> = Vec::new();
    if let Some(p) = ssh_port {
        ssh_args.push("-p".to_string());
        ssh_args.push(p.to_string());
    }
    ssh_args.push(ssh_host.clone());
    ssh_args.push(recv_cmd);

    let output = tokio::process::Command::new("ssh")
        .args(&ssh_args)
        .output()
        .await?;

    let elapsed = start.elapsed();

    // Kill the server.
    server.kill().await.ok();

    // Only report success when the remote actually received the file.
    let stderr = String::from_utf8_lossy(&output.stderr);
    if let Some(err) = recvfile_error(output.status.success(), &stderr) {
        return Err(err.into());
    }

    Ok(UdtStats {
        bytes_sent: file_size,
        elapsed,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shell_quote_plain_string() {
        assert_eq!(shell_quote("/tmp/file.bin"), "'/tmp/file.bin'");
    }

    #[test]
    fn shell_quote_spaces_and_metachars() {
        // Spaces must not split the argument...
        assert_eq!(shell_quote("/tmp/my file.bin"), "'/tmp/my file.bin'");
        // ...and command substitution must stay inert inside quotes.
        assert_eq!(
            shell_quote("$(touch /tmp/pwned)"),
            "'$(touch /tmp/pwned)'"
        );
        assert_eq!(shell_quote("`id`"), "'`id`'");
        assert_eq!(shell_quote("a;rm -rf /"), "'a;rm -rf /'");
    }

    #[test]
    fn shell_quote_embedded_single_quote() {
        assert_eq!(shell_quote("it's"), "'it'\\''s'");
    }

    #[test]
    fn recv_cmd_quotes_everything() {
        let cmd = build_recv_cmd(
            "/tmp/udt src",
            "/tmp/udt-bench/recvfile",
            "192.168.1.5",
            9123,
            "/home/pi/my file.bin",
            "/data/$(reboot)",
        );
        let expected = "LD_LIBRARY_PATH='/tmp/udt src' '/tmp/udt-bench/recvfile' '192.168.1.5' 9123 '/home/pi/my file.bin' '/data/$(reboot)'";
        assert_eq!(cmd, expected);
    }

    #[test]
    fn parse_dest_with_port_and_user() {
        let (ssh_host, ip, path, port) =
            parse_udt_dest("alice@example.com:2222:/data/out.bin").unwrap();
        assert_eq!(ssh_host, "alice@example.com");
        assert_eq!(ip, "example.com");
        assert_eq!(path, "/data/out.bin");
        assert_eq!(port, Some(2222));
    }

    #[test]
    fn parse_dest_without_user_has_no_hardcoded_default() {
        // No user in the destination -> bare host, ssh uses the current
        // local user (the old code hardcoded "pi@").
        let (ssh_host, ip, path, port) = parse_udt_dest("nas.lan:22:/backup/f").unwrap();
        assert_eq!(ssh_host, "nas.lan");
        assert_eq!(ip, "nas.lan");
        assert_eq!(path, "/backup/f");
        assert_eq!(port, Some(22));
    }

    #[test]
    fn parse_dest_rejects_garbage() {
        assert!(parse_udt_dest("no-path-here").is_none());
        assert!(parse_udt_dest("host:22:relative/path").is_none());
        assert!(parse_udt_dest(":22:/path").is_none());
    }

    #[test]
    fn connection_setup_failure_is_an_error() {
        // recvfile prints this to stderr when it cannot reach sendfile;
        // exit status may be 0 either way — it must still surface as Err.
        let err = recvfile_error(true, "connect: Connection setup failure");
        assert!(err.is_some());
        let err = recvfile_error(false, "connect: Connection setup failure");
        assert!(err.is_some());
    }

    #[test]
    fn nonzero_exit_is_an_error() {
        assert!(recvfile_error(false, "some other error").is_some());
        assert!(recvfile_error(false, "").is_some());
    }

    #[test]
    fn clean_run_is_ok() {
        assert!(recvfile_error(true, "").is_none());
        assert!(recvfile_error(true, "Speed: 100 MB/s\n").is_none());
    }
}
