// Favonius — high-performance file transfer over UDP
// Copyright (c) 2025-2026 Vantino SàRL
// SPDX-License-Identifier: Apache-2.0

//! Manifest construction for file transfers.
//!
//! Builds a `Manifest` from a list of files, computing chunk layouts and
//! content hashes.
//!
//! Extracted from the former `ahp-transfer` crate (removed as dead code;
//! see git history), trimmed to what the HTTP API actually uses.

use std::path::PathBuf;

use crate::types::TransferError;

/// Transfer manifest describing the complete set of files and their chunk layout.
///
/// Exchanged between peers via MANIFEST packets during session establishment.
/// Both sides must agree on the manifest before data transfer begins.
#[derive(Debug, Clone)]
pub struct Manifest {
    /// Transfer ID this manifest belongs to.
    pub transfer_id: String,
    /// Sync mode (one-way send, two-way sync, etc.).
    pub mode: ManifestMode,
    /// Files included in this transfer.
    pub files: Vec<ManifestFile>,
    /// BLAKE3 hash of the manifest's canonical serialization (transfer ID,
    /// mode, chunk size, and per-file entries in order), used for integrity
    /// verification and for matching manifests on resume.
    pub hash: [u8; 32],
    /// Total number of chunks across all files.
    pub total_chunks: u64,
}

/// Transfer mode encoded in the manifest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ManifestMode {
    /// One-shot send from source to destination.
    Send,
    /// Bidirectional sync.
    Sync,
    /// Growing file (live) transfer.
    Live,
}

/// A single file entry within a transfer manifest.
#[derive(Debug, Clone)]
pub struct ManifestFile {
    /// File index (0-based, used to reference in DATA packets).
    pub index: u32,
    /// Relative path from the transfer root.
    pub path: PathBuf,
    /// File size in bytes.
    pub size: u64,
    /// BLAKE3 hash of the complete file.
    pub hash: [u8; 32],
    /// Index of the first chunk belonging to this file (global chunk space).
    pub first_chunk: u64,
    /// Number of chunks for this file.
    pub chunk_count: u32,
}

/// Builder for constructing a transfer manifest.
pub struct ManifestBuilder {
    transfer_id: String,
    mode: ManifestMode,
    chunk_size: u32,
    files: Vec<FileEntry>,
}

/// Input file entry for the manifest builder.
#[derive(Debug, Clone)]
pub struct FileEntry {
    /// Relative path from the transfer root.
    pub path: PathBuf,
    /// File size in bytes.
    pub size: u64,
    /// Pre-computed BLAKE3 hash of the file contents (if available).
    pub hash: Option<[u8; 32]>,
}

impl ManifestBuilder {
    /// Create a new manifest builder.
    pub fn new(transfer_id: impl Into<String>, mode: ManifestMode, chunk_size: u32) -> Self {
        Self {
            transfer_id: transfer_id.into(),
            mode,
            chunk_size,
            files: Vec::new(),
        }
    }

    /// Add a file to the manifest.
    pub fn add_file(&mut self, entry: FileEntry) -> &mut Self {
        self.files.push(entry);
        self
    }

    /// Add multiple files at once.
    pub fn add_files(&mut self, entries: impl IntoIterator<Item = FileEntry>) -> &mut Self {
        self.files.extend(entries);
        self
    }

    /// Compute the chunk layout and build the manifest.
    pub fn build(self) -> Result<Manifest, TransferError> {
        if self.chunk_size == 0 {
            return Err(TransferError::ManifestError(
                "chunk size must be non-zero".into(),
            ));
        }

        let mut manifest_files = Vec::with_capacity(self.files.len());
        let mut global_chunk_offset: u64 = 0;

        for (index, entry) in self.files.iter().enumerate() {
            let chunk_count = chunks_for_size(entry.size, self.chunk_size)?;
            let hash = entry.hash.unwrap_or([0u8; 32]);

            manifest_files.push(ManifestFile {
                index: index as u32,
                path: entry.path.clone(),
                size: entry.size,
                hash,
                first_chunk: global_chunk_offset,
                chunk_count,
            });

            global_chunk_offset += chunk_count as u64;
        }

        let total_chunks = global_chunk_offset;

        // Compute manifest hash from a deterministic representation.
        let manifest_hash =
            compute_manifest_hash(&self.transfer_id, self.mode, self.chunk_size, &manifest_files);

        Ok(Manifest {
            transfer_id: self.transfer_id,
            mode: self.mode,
            files: manifest_files,
            hash: manifest_hash,
            total_chunks,
        })
    }

    /// Number of files added so far.
    pub fn file_count(&self) -> usize {
        self.files.len()
    }
}

/// Calculate the number of chunks needed for a file of the given size.
///
/// Uses overflow-safe ceiling division. Returns an error when `chunk_size`
/// is zero or when the chunk count does not fit in a `u32` (the manifest's
/// `chunk_count` field width), instead of silently wrapping or truncating.
pub fn chunks_for_size(file_size: u64, chunk_size: u32) -> Result<u32, TransferError> {
    if chunk_size == 0 {
        return Err(TransferError::ManifestError(
            "chunk size must be non-zero".into(),
        ));
    }
    if file_size == 0 {
        return Ok(0);
    }
    let cs = u64::from(chunk_size);
    // ceil(file_size / cs) without the overflowing `file_size + cs - 1` form.
    let count = file_size / cs + u64::from(!file_size.is_multiple_of(cs));
    u32::try_from(count).map_err(|_| {
        TransferError::ManifestError(format!(
            "file size {file_size} needs {count} chunks of {chunk_size} bytes, exceeding u32 chunk addressing"
        ))
    })
}

/// Compute the manifest's BLAKE3 hash for integrity verification.
///
/// The hash covers a canonical, length-prefixed serialization of everything
/// that defines the transfer's chunk layout, in a stable field order:
///
/// - transfer ID (length-prefixed bytes),
/// - manifest mode (single byte),
/// - chunk size (u32 LE),
/// - file count (u32 LE),
/// - per file, in manifest order: index (u32 LE), path (length-prefixed
///   bytes), size (u64 LE), content hash (32 bytes), first chunk (u64 LE),
///   chunk count (u32 LE).
///
/// Files are kept in a `Vec` in insertion order, so the serialization is
/// fully deterministic (no map-iteration nondeterminism). Any change to the
/// file set, sizes, hashes, or chunk layout changes the hash, which is what
/// the resume protocol relies on when matching manifests.
fn compute_manifest_hash(
    transfer_id: &str,
    mode: ManifestMode,
    chunk_size: u32,
    files: &[ManifestFile],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&(transfer_id.len() as u32).to_le_bytes());
    hasher.update(transfer_id.as_bytes());
    hasher.update(&[mode as u8]);
    hasher.update(&chunk_size.to_le_bytes());
    hasher.update(&(files.len() as u32).to_le_bytes());
    for f in files {
        hasher.update(&f.index.to_le_bytes());
        let path = f.path.to_string_lossy();
        hasher.update(&(path.len() as u32).to_le_bytes());
        hasher.update(path.as_bytes());
        hasher.update(&f.size.to_le_bytes());
        hasher.update(&f.hash);
        hasher.update(&f.first_chunk.to_le_bytes());
        hasher.update(&f.chunk_count.to_le_bytes());
    }
    *hasher.finalize().as_bytes()
}

/// Compute the byte range within a file for a given local chunk index.
pub fn chunk_byte_range(file_size: u64, chunk_size: u32, local_chunk: u32) -> (u64, u64) {
    let cs = chunk_size as u64;
    let offset = local_chunk as u64 * cs;
    let length = cs.min(file_size.saturating_sub(offset));
    (offset, length)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chunks_for_various_sizes() {
        assert_eq!(chunks_for_size(0, 1024).unwrap(), 0);
        assert_eq!(chunks_for_size(1, 1024).unwrap(), 1);
        assert_eq!(chunks_for_size(1024, 1024).unwrap(), 1);
        assert_eq!(chunks_for_size(1025, 1024).unwrap(), 2);
        assert_eq!(chunks_for_size(4096, 1024).unwrap(), 4);
        assert_eq!(chunks_for_size(4097, 1024).unwrap(), 5);
    }

    #[test]
    fn chunks_for_size_boundaries() {
        // Zero chunk size is an explicit error, not a division by zero.
        assert!(chunks_for_size(100, 0).is_err());
        // Largest count that still fits the u32 chunk_count field.
        assert_eq!(
            chunks_for_size(u64::from(u32::MAX) * 1024, 1024).unwrap(),
            u32::MAX
        );
        // One byte beyond: too many chunks to address — error, no truncation.
        assert!(chunks_for_size(u64::from(u32::MAX) * 1024 + 1, 1024).is_err());
        // Near u64::MAX the naive `size + cs - 1` form would wrap; must error.
        assert!(chunks_for_size(u64::MAX, 1024).is_err());
        assert!(chunks_for_size(u64::MAX, u32::MAX).is_err());
        assert!(chunks_for_size(u64::MAX - 1023, 1024).is_err());
    }

    #[test]
    fn build_empty_manifest() {
        let builder = ManifestBuilder::new("tx-1", ManifestMode::Send, 1024);
        let manifest = builder.build().unwrap();
        assert_eq!(manifest.files.len(), 0);
        assert_eq!(manifest.total_chunks, 0);
    }

    #[test]
    fn build_single_file() {
        let mut builder = ManifestBuilder::new("tx-2", ManifestMode::Send, 1024);
        builder.add_file(FileEntry {
            path: PathBuf::from("data.bin"),
            size: 3000,
            hash: Some([0xAB; 32]),
        });
        let manifest = builder.build().unwrap();

        assert_eq!(manifest.files.len(), 1);
        assert_eq!(manifest.files[0].index, 0);
        assert_eq!(manifest.files[0].size, 3000);
        assert_eq!(manifest.files[0].first_chunk, 0);
        assert_eq!(manifest.files[0].chunk_count, 3); // ceil(3000/1024)
        assert_eq!(manifest.total_chunks, 3);
        assert_eq!(manifest.files[0].hash, [0xAB; 32]);
    }

    #[test]
    fn build_multiple_files() {
        let mut builder = ManifestBuilder::new("tx-3", ManifestMode::Sync, 512);
        builder.add_files(vec![
            FileEntry {
                path: PathBuf::from("a.txt"),
                size: 1024, // 2 chunks
                hash: None,
            },
            FileEntry {
                path: PathBuf::from("b.txt"),
                size: 600, // 2 chunks
                hash: None,
            },
            FileEntry {
                path: PathBuf::from("c.txt"),
                size: 0, // 0 chunks
                hash: None,
            },
        ]);
        let manifest = builder.build().unwrap();

        assert_eq!(manifest.files.len(), 3);
        assert_eq!(manifest.files[0].first_chunk, 0);
        assert_eq!(manifest.files[0].chunk_count, 2);
        assert_eq!(manifest.files[1].first_chunk, 2);
        assert_eq!(manifest.files[1].chunk_count, 2);
        assert_eq!(manifest.files[2].first_chunk, 4);
        assert_eq!(manifest.files[2].chunk_count, 0);
        assert_eq!(manifest.total_chunks, 4);
        assert_eq!(manifest.mode, ManifestMode::Sync);
    }

    #[test]
    fn zero_chunk_size_errors() {
        let builder = ManifestBuilder::new("tx-4", ManifestMode::Send, 0);
        assert!(builder.build().is_err());
    }

    #[test]
    fn chunk_byte_ranges() {
        // File of 3000 bytes, 1024-byte chunks.
        let (offset0, len0) = chunk_byte_range(3000, 1024, 0);
        assert_eq!(offset0, 0);
        assert_eq!(len0, 1024);

        let (offset1, len1) = chunk_byte_range(3000, 1024, 1);
        assert_eq!(offset1, 1024);
        assert_eq!(len1, 1024);

        let (offset2, len2) = chunk_byte_range(3000, 1024, 2);
        assert_eq!(offset2, 2048);
        assert_eq!(len2, 952); // 3000 - 2048
    }

    #[test]
    fn manifest_hash_deterministic() {
        let build = || {
            let mut b = ManifestBuilder::new("tx-det", ManifestMode::Send, 1024);
            b.add_file(FileEntry {
                path: PathBuf::from("file.bin"),
                size: 2048,
                hash: Some([0x42; 32]),
            });
            b.build().unwrap().hash
        };

        let h1 = build();
        let h2 = build();
        assert_eq!(h1, h2);
    }

    #[test]
    fn manifest_hash_is_blake3() {
        let mut b = ManifestBuilder::new("tx-b3", ManifestMode::Send, 1024);
        b.add_file(FileEntry {
            path: PathBuf::from("file.bin"),
            size: 2048,
            hash: Some([0x42; 32]),
        });
        let manifest = b.build().unwrap();

        // Independently reconstruct the canonical byte stream and hash it
        // with the blake3 crate directly.
        let mut canonical = Vec::new();
        canonical.extend_from_slice(&5u32.to_le_bytes()); // len("tx-b3")
        canonical.extend_from_slice(b"tx-b3");
        canonical.push(0u8); // ManifestMode::Send
        canonical.extend_from_slice(&1024u32.to_le_bytes()); // chunk size
        canonical.extend_from_slice(&1u32.to_le_bytes()); // file count
        let f = &manifest.files[0];
        canonical.extend_from_slice(&f.index.to_le_bytes());
        canonical.extend_from_slice(&8u32.to_le_bytes()); // len("file.bin")
        canonical.extend_from_slice(b"file.bin");
        canonical.extend_from_slice(&f.size.to_le_bytes());
        canonical.extend_from_slice(&f.hash);
        canonical.extend_from_slice(&f.first_chunk.to_le_bytes());
        canonical.extend_from_slice(&f.chunk_count.to_le_bytes());

        assert_eq!(manifest.hash, *blake3::hash(&canonical).as_bytes());
    }

    #[test]
    fn manifest_hash_changes_with_content() {
        let build = |id: &str, mode: ManifestMode, chunk_size: u32, size: u64| {
            let mut b = ManifestBuilder::new(id, mode, chunk_size);
            b.add_file(FileEntry {
                path: PathBuf::from("file.bin"),
                size,
                hash: Some([0x42; 32]),
            });
            b.build().unwrap().hash
        };

        let base = build("tx-a", ManifestMode::Send, 1024, 2048);
        // Any covered-field change must change the hash.
        assert_ne!(base, build("tx-b", ManifestMode::Send, 1024, 2048));
        assert_ne!(base, build("tx-a", ManifestMode::Sync, 1024, 2048));
        assert_ne!(base, build("tx-a", ManifestMode::Send, 2048, 2048));
        assert_ne!(base, build("tx-a", ManifestMode::Send, 1024, 4096));
    }

    #[test]
    fn file_count() {
        let mut builder = ManifestBuilder::new("tx", ManifestMode::Send, 1024);
        assert_eq!(builder.file_count(), 0);
        builder.add_file(FileEntry {
            path: PathBuf::from("f1"),
            size: 100,
            hash: None,
        });
        assert_eq!(builder.file_count(), 1);
    }
}
