// Favonius — high-performance file transfer over UDP
// Copyright (c) 2025-2026 Vantino SàRL
// SPDX-License-Identifier: Apache-2.0

//! Stateless sync planning: diff a local tree against a remote listing.
//!
//! "Stateless" is the defining constraint. Favonius keeps no database, no
//! catalog and no history; a plan is recomputed from scratch on every run
//! by comparing what is on disk here with what the daemon reports there.
//! That is what bounds this module to the three modes below — one-way,
//! mirror and append-only are all decidable from two listings, whereas
//! bidirectional reconciliation, conflict resolution and version
//! preservation need to know what happened *last* time, which is exactly
//! the state Favonius does not keep.

use ahp_api::FsEntry;

use crate::fs_tree::TreeEntry;

/// How the destination is reconciled with the source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncMode {
    /// Copy new and changed files. Never delete, never touch anything at
    /// the destination that the source does not have.
    OneWay,
    /// One-way, plus delete destination files with no source counterpart,
    /// so the destination ends up an exact image of the source.
    Mirror,
    /// Copy only files absent at the destination. Never overwrite and
    /// never delete — for write-once targets and audit trails.
    AppendOnly,
}

impl SyncMode {
    pub fn parse(s: &str) -> Result<Self, String> {
        match s {
            "one-way" | "oneway" => Ok(Self::OneWay),
            "mirror" => Ok(Self::Mirror),
            "append-only" | "append" => Ok(Self::AppendOnly),
            // Name the stateful modes explicitly. A user asking for
            // "bidirectional" has a real need, and "unknown mode" would
            // leave them guessing whether they typo'd it.
            "two-way" | "bidirectional" | "snapshot" | "version-preserving" => Err(format!(
                "'{s}' needs persistent state (change history and conflict \
                 lineage) which Favonius deliberately does not keep. \
                 Available modes: one-way, mirror, append-only."
            )),
            _ => Err(format!(
                "unknown sync mode '{s}'. Available: one-way, mirror, append-only."
            )),
        }
    }
}

/// How two sides are judged same-or-different.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Compare {
    /// Sizes differ => transfer. Cheap, and the only check available
    /// without reading file contents on both sides.
    ///
    /// This is `rsync --size-only` semantics, and it carries the same
    /// caveat: an edit that preserves the file's length is invisible.
    /// Modification time is deliberately *not* used — Favonius does not
    /// propagate mtime to the destination, so comparing it would mark
    /// every file as changed on every run.
    Size,
    /// BLAKE3 of the contents on both sides. Correct regardless of how a
    /// file changed, at the cost of a full read on each side.
    Checksum,
}

/// What one file is going to have done to it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Not at the destination at all.
    Create,
    /// Present but different.
    Update,
}

/// A planned file transfer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedTransfer {
    pub entry: TreeEntry,
    pub action: Action,
}

/// The full reconciliation plan.
#[derive(Debug, Default, Clone)]
pub struct Plan {
    /// Files to send, in listing order.
    pub transfers: Vec<PlannedTransfer>,
    /// Destination-relative paths to delete (mirror mode only).
    pub deletes: Vec<String>,
    /// Files judged identical and skipped.
    pub unchanged: usize,
    /// Files present at the destination and different, but left alone
    /// because append-only mode never overwrites.
    pub protected: usize,
}

impl Plan {
    pub fn is_empty(&self) -> bool {
        self.transfers.is_empty() && self.deletes.is_empty()
    }

    /// Total bytes the plan will put on the wire.
    pub fn bytes(&self) -> u64 {
        self.transfers.iter().map(|t| t.entry.size).sum()
    }
}

/// Build a reconciliation plan from a local walk and a remote listing.
///
/// `local_hashes` supplies the local BLAKE3 for `Compare::Checksum`,
/// parallel to `local`; it is ignored for `Compare::Size`. Remote hashes
/// ride along in [`FsEntry::hash`].
pub fn plan(
    local: &[TreeEntry],
    remote: &[FsEntry],
    mode: SyncMode,
    compare: Compare,
    local_hashes: &[Option<String>],
) -> Plan {
    use std::collections::HashMap;

    let remote_by_path: HashMap<&str, &FsEntry> =
        remote.iter().map(|e| (e.path.as_str(), e)).collect();

    let mut out = Plan::default();

    for (i, entry) in local.iter().enumerate() {
        match remote_by_path.get(entry.rel.as_str()) {
            None => out.transfers.push(PlannedTransfer {
                entry: entry.clone(),
                action: Action::Create,
            }),
            Some(r) => {
                if mode == SyncMode::AppendOnly {
                    // The file exists; append-only stops there without
                    // even asking whether it differs.
                    out.protected += 1;
                    continue;
                }
                let same = match compare {
                    Compare::Size => entry.size == r.size,
                    Compare::Checksum => match (local_hashes.get(i).and_then(|h| h.as_deref()), r.hash.as_deref()) {
                        (Some(a), Some(b)) => a == b,
                        // A missing hash on either side means "unknown",
                        // and the safe reading of unknown is "different":
                        // re-sending a file costs bandwidth, skipping a
                        // changed one loses data.
                        _ => false,
                    },
                };
                if same {
                    out.unchanged += 1;
                } else {
                    out.transfers.push(PlannedTransfer {
                        entry: entry.clone(),
                        action: Action::Update,
                    });
                }
            }
        }
    }

    if mode == SyncMode::Mirror {
        let local_paths: std::collections::HashSet<&str> =
            local.iter().map(|e| e.rel.as_str()).collect();
        for r in remote {
            if !local_paths.contains(r.path.as_str()) {
                out.deletes.push(r.path.clone());
            }
        }
        out.deletes.sort();
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn local(rel: &str, size: u64) -> TreeEntry {
        TreeEntry {
            abs: PathBuf::from(format!("/src/{rel}")),
            rel: rel.to_string(),
            size,
            mtime: 1000,
        }
    }

    fn remote(path: &str, size: u64) -> FsEntry {
        FsEntry {
            path: path.to_string(),
            size,
            mtime: 2000,
            hash: None,
        }
    }

    fn rels(p: &Plan) -> Vec<&str> {
        p.transfers.iter().map(|t| t.entry.rel.as_str()).collect()
    }

    #[test]
    fn one_way_creates_and_updates_but_never_deletes() {
        let l = vec![local("new.bin", 10), local("changed.bin", 20), local("same.bin", 30)];
        let r = vec![remote("changed.bin", 99), remote("same.bin", 30), remote("extra.bin", 5)];

        let p = plan(&l, &r, SyncMode::OneWay, Compare::Size, &[]);
        assert_eq!(rels(&p), vec!["new.bin", "changed.bin"]);
        assert_eq!(p.transfers[0].action, Action::Create);
        assert_eq!(p.transfers[1].action, Action::Update);
        assert_eq!(p.unchanged, 1);
        assert!(p.deletes.is_empty(), "one-way must never delete");
    }

    #[test]
    fn mirror_deletes_only_what_the_source_lacks() {
        let l = vec![local("keep.bin", 10)];
        let r = vec![remote("keep.bin", 10), remote("gone.bin", 5), remote("d/old.bin", 7)];

        let p = plan(&l, &r, SyncMode::Mirror, Compare::Size, &[]);
        assert!(p.transfers.is_empty());
        assert_eq!(p.deletes, vec!["d/old.bin", "gone.bin"]);
    }

    #[test]
    fn append_only_never_overwrites_or_deletes() {
        let l = vec![local("new.bin", 10), local("existing.bin", 20)];
        // `existing.bin` differs in size, but append-only still leaves it.
        let r = vec![remote("existing.bin", 999), remote("extra.bin", 1)];

        let p = plan(&l, &r, SyncMode::AppendOnly, Compare::Size, &[]);
        assert_eq!(rels(&p), vec!["new.bin"]);
        assert_eq!(p.protected, 1);
        assert!(p.deletes.is_empty());
    }

    #[test]
    fn checksum_catches_a_same_size_edit_that_size_misses() {
        // The precise gap the --checksum flag exists to close.
        let l = vec![local("a.bin", 100)];
        let mut r = vec![remote("a.bin", 100)];
        r[0].hash = Some("bbbb".into());
        let local_hashes = vec![Some("aaaa".to_string())];

        let by_size = plan(&l, &r, SyncMode::OneWay, Compare::Size, &local_hashes);
        assert!(by_size.transfers.is_empty(), "size-only cannot see this");
        assert_eq!(by_size.unchanged, 1);

        let by_hash = plan(&l, &r, SyncMode::OneWay, Compare::Checksum, &local_hashes);
        assert_eq!(rels(&by_hash), vec!["a.bin"]);
    }

    #[test]
    fn checksum_skips_when_both_hashes_match() {
        let l = vec![local("a.bin", 100)];
        let mut r = vec![remote("a.bin", 100)];
        r[0].hash = Some("aaaa".into());
        let p = plan(&l, &r, SyncMode::OneWay, Compare::Checksum, &[Some("aaaa".into())]);
        assert!(p.transfers.is_empty());
        assert_eq!(p.unchanged, 1);
    }

    #[test]
    fn missing_hash_is_treated_as_different() {
        // Fail toward re-sending, never toward silently skipping.
        let l = vec![local("a.bin", 100)];
        let r = vec![remote("a.bin", 100)]; // hash: None
        let p = plan(&l, &r, SyncMode::OneWay, Compare::Checksum, &[Some("aaaa".into())]);
        assert_eq!(rels(&p), vec!["a.bin"]);
    }

    #[test]
    fn empty_remote_transfers_everything() {
        let l = vec![local("a.bin", 1), local("d/b.bin", 2)];
        let p = plan(&l, &[], SyncMode::OneWay, Compare::Size, &[]);
        assert_eq!(rels(&p), vec!["a.bin", "d/b.bin"]);
        assert!(p.transfers.iter().all(|t| t.action == Action::Create));
        assert_eq!(p.bytes(), 3);
    }

    #[test]
    fn mirror_of_an_empty_source_deletes_everything() {
        // Worth pinning: this is the destructive edge that makes --dry-run
        // and the confirmation prompt matter.
        let r = vec![remote("a.bin", 1), remote("b.bin", 2)];
        let p = plan(&[], &r, SyncMode::Mirror, Compare::Size, &[]);
        assert!(p.transfers.is_empty());
        assert_eq!(p.deletes, vec!["a.bin", "b.bin"]);
    }

    #[test]
    fn stateful_modes_are_rejected_by_name() {
        assert_eq!(SyncMode::parse("one-way"), Ok(SyncMode::OneWay));
        assert_eq!(SyncMode::parse("mirror"), Ok(SyncMode::Mirror));
        assert_eq!(SyncMode::parse("append-only"), Ok(SyncMode::AppendOnly));

        let err = SyncMode::parse("bidirectional").unwrap_err();
        assert!(err.contains("persistent state"), "{err}");
        assert!(SyncMode::parse("two-way").is_err());
        assert!(SyncMode::parse("nonsense").unwrap_err().contains("unknown"));
    }
}
