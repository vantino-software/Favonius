// Favonius — high-performance file transfer over UDP
// Copyright (c) 2025-2026 Vantino SàRL
// SPDX-License-Identifier: Apache-2.0

//! Favonius REST and gRPC API.
//!
//! Provides the HTTP API for managing transfers, querying status, and
//! interacting with the transfer engine. The gRPC interface will be added
//! for high-performance inter-node communication.
//!
//! # Authentication
//!
//! All endpoints except `GET /health` require a bearer token when one is
//! configured: `Authorization: Bearer <token>`, otherwise `401 Unauthorized`.
//! The token is taken from the `FAVONIUS_API_TOKEN` environment variable
//! (see [`AppState::new`]) or set programmatically via [`AppState::with_token`].
//!
//! When no token is configured the API runs unauthenticated — this is only
//! acceptable on a loopback bind, so a loud warning is logged at startup.
//! [`serve`] refuses to bind a non-loopback address without a token; the
//! daemon should always bind `127.0.0.1` unless remote API access is
//! explicitly intended (and a token configured).

pub mod manifest;
pub mod types;

use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex, MutexGuard};

use axum::{
    extract::{Path, State},
    http::{Request, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use ahp_observability::metrics::encode_prometheus_text;
use ahp_observability::TransferMetrics;
use manifest::{chunk_byte_range, FileEntry, ManifestBuilder, ManifestMode};
use types::{Transfer, TransferConfig, TransferEngine, TransferState};

/// Environment variable carrying the API bearer token.
pub const API_TOKEN_ENV: &str = "FAVONIUS_API_TOKEN";

/// Shared application state wrapping the transfer engine and metrics.
#[derive(Clone)]
pub struct AppState {
    pub engine: Arc<Mutex<TransferEngine>>,
    pub metrics: &'static TransferMetrics,
    auth_token: Option<Arc<str>>,
    /// Directory the filesystem endpoints are confined to, mirroring the
    /// receiver's `--dest-root`. `None` disables those endpoints entirely
    /// rather than exposing the whole filesystem: a listing API with no
    /// root is a directory-traversal oracle, and the safe default for
    /// "unconfigured" is "off".
    dest_root: Option<Arc<std::path::Path>>,
}

impl AppState {
    /// Create a new AppState with the given engine concurrency limit.
    ///
    /// Reads the bearer token from the `FAVONIUS_API_TOKEN` environment
    /// variable; an unset or empty variable means no token is configured.
    pub fn new(max_concurrent: usize) -> Self {
        // The process-wide instance, so the UDP data plane's counters and
        // the ones /metrics exports are the same counters.
        let metrics = ahp_observability::global();
        let auth_token = std::env::var(API_TOKEN_ENV)
            .ok()
            .filter(|t| !t.is_empty())
            .map(Arc::from);
        Self {
            engine: Arc::new(Mutex::new(TransferEngine::new(max_concurrent))),
            metrics,
            auth_token,
            dest_root: None,
        }
    }

    /// Confine the filesystem endpoints to `root`, enabling them.
    ///
    /// The path is canonicalized once here so every later containment
    /// check compares two resolved paths; comparing unresolved ones lets
    /// a symlink inside the root point anywhere.
    pub fn with_dest_root(mut self, root: impl AsRef<std::path::Path>) -> Self {
        self.dest_root = std::fs::canonicalize(root.as_ref())
            .ok()
            .map(|p| Arc::from(p.as_path()));
        self
    }

    /// The configured filesystem root, if the endpoints are enabled.
    pub fn dest_root(&self) -> Option<&std::path::Path> {
        self.dest_root.as_deref()
    }

    /// Resolve a client-supplied path inside `dest_root`.
    ///
    /// Returns None when the endpoints are disabled, when the path escapes
    /// the root, or when it cannot be resolved. Resolution is done on the
    /// nearest existing ancestor so a not-yet-created path is still
    /// checked against the root rather than being waved through.
    fn resolve_in_root(&self, path: &str) -> Option<std::path::PathBuf> {
        let root = self.dest_root.as_deref()?;
        let requested = std::path::Path::new(path);
        if !requested.is_absolute() {
            return None;
        }
        // Walk up to the nearest existing ancestor, canonicalize that, then
        // re-apply the remainder. `canonicalize` on the full path would
        // fail for paths that do not exist yet.
        let mut existing = requested;
        let mut tail = Vec::new();
        let resolved = loop {
            match std::fs::canonicalize(existing) {
                Ok(p) => break p,
                Err(_) => {
                    let parent = existing.parent()?;
                    tail.push(existing.file_name()?.to_owned());
                    existing = parent;
                }
            }
        };
        let mut full = resolved;
        for part in tail.into_iter().rev() {
            // Reject traversal components outright; `..` after
            // canonicalization of the prefix would still escape.
            if part == ".." || part == "." {
                return None;
            }
            full.push(part);
        }
        full.starts_with(root).then_some(full)
    }

    /// Override the bearer token (primarily for tests and embedding).
    pub fn with_token(mut self, token: impl Into<String>) -> Self {
        let token = token.into();
        self.auth_token = if token.is_empty() {
            None
        } else {
            Some(Arc::from(token.as_str()))
        };
        self
    }

    /// The configured bearer token, if any.
    pub fn auth_token(&self) -> Option<&str> {
        self.auth_token.as_deref()
    }
}

/// Lock the engine mutex, recovering from poisoning instead of panicking.
///
/// A panic in one request handler must not permanently wedge every
/// subsequent request (the engine state itself is still usable).
fn lock_engine(engine: &Arc<Mutex<TransferEngine>>) -> MutexGuard<'_, TransferEngine> {
    engine.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// One entry in an `fs/list` response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FsEntry {
    /// Path relative to the listed root, `/`-separated.
    pub path: String,
    /// Size in bytes.
    pub size: u64,
    /// Modification time, whole seconds since the Unix epoch.
    pub mtime: i64,
    /// BLAKE3 of the file contents, hex-encoded. Only computed when the
    /// caller asks for it (`?hash=true`), since it costs a full read of
    /// every file in the tree.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hash: Option<String>,
}

/// Response body for `GET /fs/list`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FsListResponse {
    pub entries: Vec<FsEntry>,
}

#[derive(Debug, Deserialize)]
pub struct FsPathQuery {
    pub path: String,
    /// Compute a BLAKE3 content hash per entry. Off by default: it turns
    /// a metadata listing into a full read of the destination tree.
    #[serde(default)]
    pub hash: bool,
}

/// Maximum entries returned by one `fs/list` call. A sync client that
/// needs more than this is not a sync client Favonius should serve — the
/// bound keeps a single request from pinning unbounded daemon memory.
const FS_LIST_MAX_ENTRIES: usize = 1_000_000;

/// `GET /fs/list?path=<absolute path>` — recursively list regular files
/// under a directory, for stateless sync diffing.
///
/// Requires `--dest-root`; without it the endpoint is disabled (404)
/// rather than serving the whole filesystem.
async fn fs_list(
    State(state): State<AppState>,
    axum::extract::Query(q): axum::extract::Query<FsPathQuery>,
) -> Response {
    let Some(root) = state.resolve_in_root(&q.path) else {
        return fs_disabled_or_forbidden(&state);
    };
    if !root.is_dir() {
        // A missing destination is normal on a first sync — an empty
        // listing says "nothing there yet", which is exactly right.
        return (StatusCode::OK, Json(FsListResponse { entries: vec![] })).into_response();
    }
    let mut entries = Vec::new();
    if let Err(e) = collect_entries(&root, &root, &mut entries, q.hash) {
        tracing::warn!(error = %e, path = %q.path, "fs list failed");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        )
            .into_response();
    }
    entries.sort_by(|a: &FsEntry, b: &FsEntry| a.path.cmp(&b.path));
    (StatusCode::OK, Json(FsListResponse { entries })).into_response()
}

fn collect_entries(
    root: &std::path::Path,
    dir: &std::path::Path,
    out: &mut Vec<FsEntry>,
    want_hash: bool,
) -> std::io::Result<()> {
    for child in std::fs::read_dir(dir)? {
        let child = child?;
        let path = child.path();
        if out.len() >= FS_LIST_MAX_ENTRIES {
            return Ok(());
        }
        // Do not traverse symlinked directories: the same cycle risk the
        // sender's walker avoids, and following one could also report
        // files from outside the root.
        let link_meta = std::fs::symlink_metadata(&path)?;
        if link_meta.file_type().is_symlink() {
            continue;
        }
        if link_meta.is_dir() {
            collect_entries(root, &path, out, want_hash)?;
        } else if link_meta.is_file() {
            let rel = path
                .strip_prefix(root)
                .unwrap_or(&path)
                .components()
                .map(|c| c.as_os_str().to_string_lossy().into_owned())
                .collect::<Vec<_>>()
                .join("/");
            let hash = if want_hash {
                blake3_file(&path).ok()
            } else {
                None
            };
            out.push(FsEntry {
                path: rel,
                size: link_meta.len(),
                hash,
                mtime: link_meta
                    .modified()
                    .ok()
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                    .map(|d| d.as_secs() as i64)
                    .unwrap_or(0),
            });
        }
    }
    Ok(())
}

/// `DELETE /fs/entry?path=<absolute path>` — remove one regular file,
/// used by `sync --mode mirror` to prune extraneous destination files.
///
/// Deliberately narrow: files only, never directories, and only inside
/// `--dest-root`. Recursive deletion over a network API is a footgun with
/// no upside here, since the sync client knows exactly which files it
/// wants gone and can ask for them one at a time.
async fn fs_delete(
    State(state): State<AppState>,
    axum::extract::Query(q): axum::extract::Query<FsPathQuery>,
) -> Response {
    let Some(path) = state.resolve_in_root(&q.path) else {
        return fs_disabled_or_forbidden(&state);
    };
    match std::fs::symlink_metadata(&path) {
        Ok(m) if m.is_file() || m.file_type().is_symlink() => match std::fs::remove_file(&path) {
            Ok(()) => {
                tracing::info!(path = %q.path, "fs delete");
                StatusCode::NO_CONTENT.into_response()
            }
            Err(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": e.to_string()})),
            )
                .into_response(),
        },
        Ok(_) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "not a regular file"})),
        )
            .into_response(),
        Err(_) => StatusCode::NOT_FOUND.into_response(),
    }
}

/// BLAKE3 of a file, streamed so a multi-GB destination file does not have
/// to fit in memory to be compared.
fn blake3_file(path: &std::path::Path) -> std::io::Result<String> {
    use std::io::Read;
    let mut f = std::fs::File::open(path)?;
    let mut hasher = blake3::Hasher::new();
    let mut buf = vec![0u8; 256 * 1024];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hasher.finalize().to_hex().to_string())
}

fn fs_disabled_or_forbidden(state: &AppState) -> Response {
    if state.dest_root().is_none() {
        (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "error": "filesystem endpoints are disabled; start the daemon with --dest-root"
            })),
        )
            .into_response()
    } else {
        (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "path is outside --dest-root"})),
        )
            .into_response()
    }
}

/// Request body for creating a new transfer.
#[derive(Debug, Serialize, Deserialize)]
pub struct CreateTransferRequest {
    /// Source path or URI.
    pub source: String,
    /// Destination path or URI.
    pub destination: String,
    /// Compression profile name (none, fast, balanced, streaming).
    pub compression: Option<bool>,
    /// Whether to enable encryption.
    pub encryption: Option<bool>,
}

/// Response body for transfer operations.
#[derive(Debug, Serialize, Deserialize)]
pub struct TransferResponse {
    /// Transfer ID.
    pub id: String,
    /// Current state.
    pub state: String,
    /// Progress as a fraction [0.0, 1.0].
    pub progress: f64,
    /// Bytes transferred so far.
    pub bytes_transferred: u64,
    /// Total bytes expected.
    pub bytes_total: u64,
    /// Source path.
    pub source: String,
    /// Destination path.
    pub destination: String,
    /// Failure reason, present only when `state` is `Failed`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Map a TransferState enum to its string representation.
fn state_to_string(state: TransferState) -> String {
    match state {
        TransferState::New => "New".to_string(),
        TransferState::Manifested => "Manifested".to_string(),
        TransferState::Queued => "Queued".to_string(),
        TransferState::Active => "Active".to_string(),
        TransferState::Partial => "Partial".to_string(),
        TransferState::Paused => "Paused".to_string(),
        TransferState::Resuming => "Resuming".to_string(),
        TransferState::Complete => "Complete".to_string(),
        TransferState::Verified => "Verified".to_string(),
        TransferState::Failed => "Failed".to_string(),
        TransferState::Aborted => "Aborted".to_string(),
    }
}

/// Build a TransferResponse from a Transfer reference.
fn transfer_to_response(t: &Transfer) -> TransferResponse {
    TransferResponse {
        id: t.id.clone(),
        state: state_to_string(t.state),
        progress: t.progress(),
        bytes_transferred: t.bytes_transferred.load(Ordering::Relaxed),
        bytes_total: t.bytes_total,
        source: t.config.source.clone(),
        destination: t.config.destination.clone(),
        error: t.error.clone(),
    }
}

/// Build the API router with all transfer management routes.
pub fn api_router(state: AppState) -> Router {
    if state.auth_token().is_none() {
        tracing::warn!(
            "{API_TOKEN_ENV} is not set — the HTTP API is UNAUTHENTICATED; \
             this is only safe when bound to a loopback address"
        );
    }

    let protected = Router::new()
        .route("/fs/list", get(fs_list))
        .route("/fs/entry", axum::routing::delete(fs_delete))
        .route("/transfers", post(create_transfer))
        .route("/transfers", get(list_transfers))
        .route("/transfers/:id", get(get_transfer))
        .route("/transfers/:id/resume", post(resume_transfer))
        .route("/metrics", get(prometheus_metrics))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            require_auth,
        ));

    // /health stays unauthenticated for load-balancer / liveness probes.
    let public = Router::new().route("/health", get(health_check));

    Router::new()
        .merge(protected)
        .merge(public)
        .with_state(state)
}

/// Serve the API on `listener`, refusing to start when the bind address is
/// not loopback and no bearer token is configured.
pub async fn serve(
    listener: tokio::net::TcpListener,
    state: AppState,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let addr = listener.local_addr()?;
    if !addr.ip().is_loopback() && state.auth_token().is_none() {
        return Err(format!(
            "refusing to serve the API on non-loopback address {addr} without \
             a bearer token — set {API_TOKEN_ENV} or bind 127.0.0.1"
        )
        .into());
    }
    tracing::info!(addr = %addr, "API server listening");
    axum::serve(listener, api_router(state)).await?;
    Ok(())
}

/// Auth middleware: require `Authorization: Bearer <token>` on every
/// protected endpoint when a token is configured. With no token configured
/// the request is allowed (loopback-only deployments; a warning was logged
/// at router construction).
async fn require_auth(
    State(state): State<AppState>,
    req: Request<axum::body::Body>,
    next: Next,
) -> Response {
    let Some(expected) = state.auth_token() else {
        return next.run(req).await;
    };

    let presented = req
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));

    match presented {
        Some(token) if tokens_equal(token, expected) => next.run(req).await,
        _ => (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "missing or invalid bearer token"})),
        )
            .into_response(),
    }
}

/// Constant-time token comparison.
fn tokens_equal(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// POST /transfers -- create a new transfer.
async fn create_transfer(
    State(state): State<AppState>,
    Json(req): Json<CreateTransferRequest>,
) -> Response {
    // Reject overlapping source/destination before anything touches the
    // filesystem: copying a file onto itself truncates the source first.
    if let Err(msg) = check_paths_disjoint(&req.source, &req.destination) {
        tracing::warn!(error = %msg, "rejecting transfer request");
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": msg})),
        )
            .into_response();
    }

    let id = Uuid::new_v4().to_string();
    tracing::info!(transfer_id = %id, source = %req.source, destination = %req.destination, "create transfer");

    let config = TransferConfig {
        source: req.source,
        destination: req.destination,
        compression: req.compression.unwrap_or(true),
        encryption: req.encryption.unwrap_or(true),
        ..TransferConfig::default()
    };

    let transfer = Transfer::new(id.clone(), config);
    let response = transfer_to_response(&transfer);

    let mut engine = lock_engine(&state.engine);
    match engine.submit(transfer) {
        Ok(()) => {
            state.metrics.active_transfers.inc();

            // Spawn background task to execute the local file copy.
            let bg_state = state.clone();
            let bg_id = id.clone();
            tokio::spawn(async move {
                if let Err(e) = execute_local_transfer(bg_state.clone(), bg_id.clone()).await {
                    tracing::error!(transfer_id = %bg_id, error = %e, "transfer failed");
                    let mut eng = lock_engine(&bg_state.engine);
                    if let Some(t) = eng.get_mut(&bg_id) {
                        t.state = TransferState::Failed;
                        t.error = Some(e.to_string());
                    }
                }
                bg_state.metrics.active_transfers.dec();
            });

            (StatusCode::CREATED, Json(response)).into_response()
        }
        Err(e) => {
            tracing::error!(error = %e, "failed to submit transfer");
            let err_response = TransferResponse {
                id,
                state: "Failed".to_string(),
                progress: 0.0,
                bytes_transferred: 0,
                bytes_total: 0,
                source: response.source,
                destination: response.destination,
                error: Some(e.to_string()),
            };
            (StatusCode::SERVICE_UNAVAILABLE, Json(err_response)).into_response()
        }
    }
}

/// Returns true when both paths are local filesystem paths (no URI scheme).
fn is_local_path(p: &str) -> bool {
    !p.contains("://") && !p.contains(':')
}

/// Reject transfers whose source and destination overlap.
///
/// The chunked copy path opens the destination with `create + truncate`
/// before reading the source, so `source == destination` would destroy the
/// data. Only meaningful when both endpoints are local paths.
fn check_paths_disjoint(source: &str, destination: &str) -> Result<(), String> {
    if !is_local_path(source) || !is_local_path(destination) {
        return Ok(());
    }
    let src = resolve_for_compare(std::path::Path::new(source));
    let dst = resolve_for_compare(std::path::Path::new(destination));
    if src == dst {
        return Err("source and destination are the same path".to_string());
    }
    if src.is_dir() && dst.starts_with(&src) {
        return Err("destination lies inside the source directory".to_string());
    }
    Ok(())
}

/// Best-effort absolute form of a path for overlap comparison: canonicalize
/// what exists (resolving symlinks and `..`), canonicalize the parent for
/// not-yet-created files, and fall back to lexical normalization.
fn resolve_for_compare(path: &std::path::Path) -> std::path::PathBuf {
    if let Ok(canon) = path.canonicalize() {
        return canon;
    }
    if let (Some(parent), Some(name)) = (path.parent(), path.file_name()) {
        if let Ok(canon_parent) = parent.canonicalize() {
            return canon_parent.join(name);
        }
    }
    let mut out = std::path::PathBuf::new();
    for comp in path.components() {
        match comp {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                out.pop();
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

/// Execute a local file transfer using kernel-level copy_file_range when
/// both endpoints are local, falling back to chunked I/O otherwise.
async fn execute_local_transfer(
    state: AppState,
    transfer_id: String,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // 1. Read config from the transfer.
    let (source, destination, chunk_size) = {
        let engine = lock_engine(&state.engine);
        let t = engine.get(&transfer_id).ok_or("transfer not found")?;
        (
            t.config.source.clone(),
            t.config.destination.clone(),
            t.config.chunk_size,
        )
    };

    let source_path = std::path::PathBuf::from(&source);
    let dest_path = std::path::PathBuf::from(&destination);

    // ── Fast path: kernel-level copy (copy_file_range on Linux) ─────────
    if is_local_path(&source) && is_local_path(&destination) {
        let file_size = tokio::fs::metadata(&source_path).await?.len();

        tracing::info!(
            transfer_id = %transfer_id,
            file_size = file_size,
            "starting local transfer (kernel fast path)"
        );

        // Transition to Active.
        {
            let mut engine = lock_engine(&state.engine);
            if let Some(t) = engine.get_mut(&transfer_id) {
                t.bytes_total = file_size;
                t.state = TransferState::Active;
            }
        }

        // Ensure destination directory exists.
        if let Some(parent) = dest_path.parent() {
            tokio::fs::create_dir_all(parent).await.ok();
        }

        // Single syscall copy — uses copy_file_range on Linux (zero-copy,
        // data never leaves kernel space).
        let copied = tokio::fs::copy(&source_path, &dest_path).await?;

        // Mark complete.
        {
            let mut engine = lock_engine(&state.engine);
            if let Some(t) = engine.get_mut(&transfer_id) {
                t.bytes_transferred.store(copied, Ordering::Relaxed);
                t.state = TransferState::Complete;
            }
        }

        tracing::info!(transfer_id = %transfer_id, bytes = copied, "transfer complete (kernel fast path)");
        return Ok(());
    }

    // ── Chunked path: for remote/cloud endpoints or mixed local+remote ──

    let file_size = tokio::fs::metadata(&source_path).await?.len();

    tracing::info!(
        transfer_id = %transfer_id,
        file_size = file_size,
        chunk_size = chunk_size,
        "starting local transfer (chunked path)"
    );

    // Build manifest.
    let src_name = source_path
        .file_name()
        .ok_or("source has no filename")?;
    let mut builder = ManifestBuilder::new(&transfer_id, ManifestMode::Send, chunk_size);
    builder.add_file(FileEntry {
        path: std::path::PathBuf::from(src_name),
        size: file_size,
        hash: None,
    });
    let manifest = builder.build()?;
    let total_chunks = manifest.total_chunks;

    // Transition to Active.
    {
        let mut engine = lock_engine(&state.engine);
        if let Some(t) = engine.get_mut(&transfer_id) {
            t.manifest = Some(manifest);
            t.bytes_total = file_size;
            t.state = TransferState::Active;
        }
    }

    // Ensure destination directory exists.
    if let Some(parent) = dest_path.parent() {
        tokio::fs::create_dir_all(parent).await.ok();
    }

    // Run the entire chunk loop on a single blocking thread to avoid
    // tokio spawn_blocking overhead per I/O call. Sequential bulk I/O
    // benefits from staying on one thread with warm CPU caches.
    let engine_arc = state.engine.clone();
    let tid = transfer_id.clone();
    let result: Result<(), Box<dyn std::error::Error + Send + Sync>> =
        tokio::task::spawn_blocking(move || {
            use std::io::{Read, Write, BufWriter};

            let mut src = std::fs::File::open(&source_path)?;
            let dst = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&dest_path)?;

            // Preallocate destination to avoid incremental metadata updates.
            dst.set_len(file_size)?;

            let mut writer = BufWriter::with_capacity(chunk_size as usize, dst);
            let mut buf = vec![0u8; chunk_size as usize];
            let mut total_written = 0u64;

            for chunk_idx in 0..total_chunks {
                let (_offset, length) = chunk_byte_range(file_size, chunk_size, chunk_idx as u32);
                let len = length as usize;

                src.read_exact(&mut buf[..len])?;
                writer.write_all(&buf[..len])?;
                total_written += len as u64;

                // Atomic progress update (no mutex needed for the counter itself).
                {
                    let engine = lock_engine(&engine_arc);
                    if let Some(t) = engine.get(&tid) {
                        t.bytes_transferred.store(total_written, Ordering::Relaxed);
                    }
                }
            }

            // Single flush at the end.
            writer.flush()?;

            Ok(())
        })
        .await?;

    result?;

    // Mark complete.
    {
        let mut engine = lock_engine(&state.engine);
        if let Some(t) = engine.get_mut(&transfer_id) {
            t.state = TransferState::Complete;
        }
    }

    tracing::info!(transfer_id = %transfer_id, bytes = file_size, "transfer complete");
    Ok(())
}

/// GET /transfers -- list all transfers.
async fn list_transfers(State(state): State<AppState>) -> impl IntoResponse {
    tracing::debug!("list transfers");
    let engine = lock_engine(&state.engine);
    let transfers: Vec<TransferResponse> = engine.list().iter().map(transfer_to_response).collect();
    Json(transfers)
}

/// GET /transfers/:id -- get a specific transfer.
async fn get_transfer(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<TransferResponse>, StatusCode> {
    tracing::debug!(transfer_id = %id, "get transfer");
    let engine = lock_engine(&state.engine);
    match engine.get(&id) {
        Some(t) => Ok(Json(transfer_to_response(t))),
        None => Err(StatusCode::NOT_FOUND),
    }
}

/// POST /transfers/:id/resume -- resume an interrupted transfer.
async fn resume_transfer(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<TransferResponse>, StatusCode> {
    tracing::info!(transfer_id = %id, "resume transfer");
    let mut engine = lock_engine(&state.engine);
    match engine.get_mut(&id) {
        Some(t) => {
            t.state = TransferState::Resuming;
            Ok(Json(transfer_to_response(t)))
        }
        None => Err(StatusCode::NOT_FOUND),
    }
}

/// GET /metrics -- Prometheus metrics endpoint.
async fn prometheus_metrics(State(state): State<AppState>) -> impl IntoResponse {
    let text = encode_prometheus_text(&state.metrics.registry);
    (
        StatusCode::OK,
        [("content-type", "text/plain; version=0.0.4; charset=utf-8")],
        text,
    )
}

/// GET /health -- health check endpoint.
async fn health_check() -> impl IntoResponse {
    Json(serde_json::json!({"status": "ok"}))
}
