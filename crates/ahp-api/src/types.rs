// Favonius — high-performance file transfer over UDP
// Copyright (c) 2025-2026 Vantino SàRL
// SPDX-License-Identifier: Apache-2.0

//! Transfer bookkeeping types used by the API's in-memory engine.
//!
//! Extracted from the former `ahp-transfer` crate (removed as dead code;
//! see git history), trimmed to what the HTTP API actually uses.

use std::sync::atomic::{AtomicU64, Ordering};

use crate::manifest::Manifest;

/// Lifecycle state of a transfer from initiation to completion.
///
/// Progresses linearly under normal operation, with `Paused`, `Resuming`, and
/// `Failed`/`Aborted` as exceptional side-states.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TransferState {
    /// Transfer created but not yet processed.
    New,
    /// Manifest has been built (file list, chunk map, hashes computed).
    Manifested,
    /// Queued for execution (waiting for available engine capacity).
    Queued,
    /// Actively transferring data.
    Active,
    /// Partially complete (some chunks committed, transfer interrupted).
    Partial,
    /// Explicitly paused by user or policy.
    Paused,
    /// Resuming from a checkpoint after interruption.
    Resuming,
    /// All chunks transferred and committed.
    Complete,
    /// Post-transfer integrity verification passed.
    Verified,
    /// Transfer failed due to an unrecoverable error.
    Failed,
    /// Transfer cancelled by user.
    Aborted,
}

impl TransferState {
    /// Returns `true` if the transfer is in a terminal state.
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Verified | Self::Failed | Self::Aborted)
    }

    /// Returns `true` if the transfer is doing active work.
    pub fn is_active(&self) -> bool {
        matches!(self, Self::Active | Self::Resuming)
    }

    /// Returns `true` while the transfer still occupies an engine capacity
    /// slot — i.e. it has not finished, successfully or not. Submitted
    /// transfers sit in `New` (or `Queued`/`Manifested`) until their
    /// background task transitions them, so counting only `Active` work
    /// would let unlimited submissions through before the first task even
    /// starts.
    pub fn holds_capacity(&self) -> bool {
        !matches!(
            self,
            Self::Complete | Self::Verified | Self::Failed | Self::Aborted
        )
    }
}

/// A single transfer job.
///
/// Represents a complete file transfer (one or many files) between a source
/// and destination, tracked through the `TransferState` lifecycle.
///
/// `bytes_transferred` uses `AtomicU64` so the background transfer task can
/// update progress without acquiring the engine-wide mutex on every chunk.
pub struct Transfer {
    /// Unique transfer identifier (UUID v7 for time-ordering).
    pub id: String,
    /// Current lifecycle state.
    pub state: TransferState,
    /// Transfer manifest (file list, chunk layout, hashes).
    pub manifest: Option<Manifest>,
    /// Configuration for this transfer.
    pub config: TransferConfig,
    /// Total bytes transferred so far (lock-free updates from transfer task).
    pub bytes_transferred: AtomicU64,
    /// Total bytes expected (sum of all file sizes in manifest).
    pub bytes_total: u64,
    /// Why the transfer failed, when `state` is `Failed`. Without this the
    /// reason exists only in the daemon's log, and a client polling the
    /// API can report that a transfer failed but not what went wrong.
    pub error: Option<String>,
}

impl std::fmt::Debug for Transfer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Transfer")
            .field("id", &self.id)
            .field("state", &self.state)
            .field("manifest", &self.manifest)
            .field("config", &self.config)
            .field("bytes_transferred", &self.bytes_transferred.load(Ordering::Relaxed))
            .field("bytes_total", &self.bytes_total)
            .field("error", &self.error)
            .finish()
    }
}

impl Transfer {
    /// Create a new transfer in the `New` state.
    pub fn new(id: String, config: TransferConfig) -> Self {
        Self {
            id,
            state: TransferState::New,
            manifest: None,
            config,
            bytes_transferred: AtomicU64::new(0),
            bytes_total: 0,
            error: None,
        }
    }

    /// Progress fraction in [0.0, 1.0].
    pub fn progress(&self) -> f64 {
        if self.bytes_total == 0 {
            return 0.0;
        }
        let transferred = self.bytes_transferred.load(Ordering::Relaxed);
        (transferred as f64 / self.bytes_total as f64).min(1.0)
    }
}

/// Configuration for a transfer.
#[derive(Debug, Clone)]
pub struct TransferConfig {
    /// Source path or URI.
    pub source: String,
    /// Destination path or URI.
    pub destination: String,
    /// Whether to enable compression.
    pub compression: bool,
    /// Whether to enable encryption (always true in production).
    pub encryption: bool,
    /// Chunk size in bytes.
    pub chunk_size: u32,
    /// Maximum number of concurrent streams.
    pub max_streams: u16,
    /// Whether to persist checkpoints for resumability.
    pub checkpoint_enabled: bool,
    /// Maximum bandwidth to use (bytes/sec), or `None` for unlimited.
    pub bandwidth_limit: Option<u64>,
}

impl Default for TransferConfig {
    fn default() -> Self {
        Self {
            source: String::new(),
            destination: String::new(),
            compression: true,
            encryption: true,
            chunk_size: 16 * 1024 * 1024, // 16 MiB
            max_streams: 8,
            checkpoint_enabled: true,
            bandwidth_limit: None,
        }
    }
}

/// The transfer engine that manages concurrent transfers.
///
/// In-memory bookkeeping only: tracks submitted transfers and enforces the
/// concurrency limit; the actual data movement is driven by the API's
/// background tasks.
pub struct TransferEngine {
    /// Active transfers indexed by transfer ID.
    transfers: Vec<Transfer>,
    /// Maximum number of concurrent active transfers.
    max_concurrent: usize,
}

impl TransferEngine {
    /// Create a new transfer engine.
    pub fn new(max_concurrent: usize) -> Self {
        Self {
            transfers: Vec::new(),
            max_concurrent,
        }
    }

    /// Submit a new transfer for execution.
    pub fn submit(&mut self, transfer: Transfer) -> Result<(), TransferError> {
        let occupied = self
            .transfers
            .iter()
            .filter(|t| t.state.holds_capacity())
            .count();
        if occupied >= self.max_concurrent {
            return Err(TransferError::CapacityExceeded {
                active: occupied,
                max: self.max_concurrent,
            });
        }
        tracing::info!(transfer_id = %transfer.id, "transfer submitted");
        self.transfers.push(transfer);
        Ok(())
    }

    /// Look up a transfer by ID.
    pub fn get(&self, id: &str) -> Option<&Transfer> {
        self.transfers.iter().find(|t| t.id == id)
    }

    /// Look up a transfer by ID (mutable).
    pub fn get_mut(&mut self, id: &str) -> Option<&mut Transfer> {
        self.transfers.iter_mut().find(|t| t.id == id)
    }

    /// List all transfers.
    pub fn list(&self) -> &[Transfer] {
        &self.transfers
    }
}

/// Errors from transfer engine operations.
#[derive(Debug, thiserror::Error)]
pub enum TransferError {
    #[error("engine at capacity: {active}/{max} active transfers")]
    CapacityExceeded { active: usize, max: usize },

    #[error("manifest build failed: {0}")]
    ManifestError(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn transfer(id: &str) -> Transfer {
        Transfer::new(id.to_string(), TransferConfig::default())
    }

    #[test]
    fn capacity_counts_submitted_not_yet_active_transfers() {
        // Transfers sit in `New` until their background task transitions
        // them — they must still occupy capacity, otherwise back-to-back
        // submissions are unbounded and the 503 path never fires.
        let mut engine = TransferEngine::new(2);
        engine.submit(transfer("a")).unwrap();
        engine.submit(transfer("b")).unwrap();
        let err = engine.submit(transfer("c")).unwrap_err();
        assert!(matches!(
            err,
            TransferError::CapacityExceeded { active: 2, max: 2 }
        ));
    }

    #[test]
    fn in_flight_states_hold_capacity() {
        for state in [
            TransferState::New,
            TransferState::Manifested,
            TransferState::Queued,
            TransferState::Active,
            TransferState::Partial,
            TransferState::Paused,
            TransferState::Resuming,
        ] {
            let mut engine = TransferEngine::new(1);
            engine.submit(transfer("a")).unwrap();
            engine.get_mut("a").unwrap().state = state;
            assert!(
                engine.submit(transfer("b")).is_err(),
                "state {state:?} must hold capacity"
            );
        }
    }

    #[test]
    fn finished_transfers_free_capacity() {
        for state in [
            TransferState::Complete,
            TransferState::Verified,
            TransferState::Failed,
            TransferState::Aborted,
        ] {
            let mut engine = TransferEngine::new(1);
            engine.submit(transfer("a")).unwrap();
            engine.get_mut("a").unwrap().state = state;
            engine
                .submit(transfer("b"))
                .unwrap_or_else(|e| panic!("state {state:?} must free capacity: {e}"));
        }
    }
}
