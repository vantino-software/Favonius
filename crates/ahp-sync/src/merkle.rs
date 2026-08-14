// Favonius — high-performance file transfer over UDP
// Copyright (c) 2025-2026 Vantino SàRL
// SPDX-License-Identifier: Apache-2.0

//! Merkle tree for hierarchical integrity verification.

use crate::{RegionMap, SyncError};

/// A Merkle tree built from leaf hashes using BLAKE3.
///
/// Stored as levels: `levels[0]` = leaves, `levels[last]` = root.
#[derive(Debug, Clone)]
pub struct MerkleTree {
    levels: Vec<Vec<[u8; 32]>>,
}

/// Compute the parent hash from two children.
fn hash_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut combined = [0u8; 64];
    combined[..32].copy_from_slice(left);
    combined[32..].copy_from_slice(right);
    *blake3::hash(&combined).as_bytes()
}

impl MerkleTree {
    /// Build a Merkle tree from leaf hashes.
    ///
    /// If the number of leaves at any level is odd, the last leaf is duplicated.
    pub fn from_leaves(leaves: &[[u8; 32]]) -> Self {
        if leaves.is_empty() {
            return Self {
                levels: vec![vec![]],
            };
        }

        let mut levels = vec![leaves.to_vec()];
        let mut current = leaves.to_vec();

        while current.len() > 1 {
            // If odd, duplicate last.
            if current.len() % 2 != 0 {
                current.push(*current.last().unwrap());
            }
            let mut next_level = Vec::with_capacity(current.len() / 2);
            for pair in current.chunks(2) {
                next_level.push(hash_pair(&pair[0], &pair[1]));
            }
            levels.push(next_level.clone());
            current = next_level;
        }

        Self { levels }
    }

    /// Build a Merkle tree from a region map's hashes.
    pub fn from_region_map(map: &RegionMap) -> Self {
        Self::from_leaves(&map.hashes)
    }

    /// The root hash of the tree.
    pub fn root(&self) -> [u8; 32] {
        self.levels
            .last()
            .and_then(|l| l.first().copied())
            .unwrap_or([0u8; 32])
    }

    /// Number of leaves.
    pub fn leaf_count(&self) -> usize {
        self.levels.first().map(|l| l.len()).unwrap_or(0)
    }

    /// Depth of the tree (number of levels minus one).
    pub fn depth(&self) -> usize {
        self.levels.len().saturating_sub(1)
    }

    /// Generate a Merkle proof for the given leaf index.
    ///
    /// Returns a list of `(is_right_sibling, hash)` pairs from leaf to root.
    pub fn proof(&self, leaf_index: usize) -> Vec<(bool, [u8; 32])> {
        if self.leaf_count() <= 1 {
            return Vec::new();
        }

        let mut proof = Vec::new();
        let mut idx = leaf_index;

        for level in &self.levels[..self.levels.len() - 1] {
            let mut level_with_dup = level.clone();
            if level_with_dup.len() % 2 != 0 {
                level_with_dup.push(*level_with_dup.last().unwrap());
            }

            if idx % 2 == 0 {
                // Sibling is on the right.
                let sibling_idx = idx + 1;
                if sibling_idx < level_with_dup.len() {
                    proof.push((true, level_with_dup[sibling_idx]));
                }
            } else {
                // Sibling is on the left.
                proof.push((false, level_with_dup[idx - 1]));
            }
            idx /= 2;
        }

        proof
    }
}

impl MerkleTree {
    /// Get the hashes at a given level of the tree.
    /// Level 0 = leaves, level depth() = root.
    pub fn level(&self, level: usize) -> &[[u8; 32]] {
        self.levels.get(level).map(|l| l.as_slice()).unwrap_or(&[])
    }

    /// Compute which leaf indices differ between this tree and another.
    ///
    /// The result is symmetric-safe: a leaf is reported whenever its hash
    /// differs OR it exists in only one of the two trees. So when `other`
    /// is larger (file grew) every leaf past `self.leaf_count()` is a diff,
    /// and when `other` is smaller (file shrank) every leaf past
    /// `other.leaf_count()` is a diff — the caller (delta resume) can never
    /// silently skip a chunk that only one side has. Indices are returned
    /// in ascending order and may reach up to
    /// `max(self.leaf_count(), other.leaf_count()) - 1`.
    ///
    /// Uses top-down traversal: starts at the deeper tree's root level and
    /// only descends into subtrees whose hashes differ. Subtree hashes are
    /// only ever compared at the same level, where a node covers the same
    /// leaf range in both trees. O(D × log N + K) where D = number of
    /// differing subtrees and K = leaves present in only one tree.
    pub fn diff_leaves(&self, other: &MerkleTree) -> Vec<usize> {
        let self_leaves = self.leaf_count();
        let other_leaves = other.leaf_count();
        if self_leaves == 0 || other_leaves == 0 {
            return (0..self_leaves.max(other_leaves)).collect();
        }
        if self_leaves == other_leaves && self.root() == other.root() {
            return Vec::new(); // identical
        }

        // Node 0 at the deeper tree's root level covers the whole leaf
        // range of both trees; the recursion treats a subtree missing from
        // one tree as "all of the other tree's leaves in its range differ".
        let mut diffs = Vec::new();
        self.diff_recurse(other, self.depth().max(other.depth()), 0, &mut diffs);
        diffs
    }

    fn diff_recurse(
        &self,
        other: &MerkleTree,
        level: usize,
        node_idx: usize,
        diffs: &mut Vec<usize>,
    ) {
        let self_level = self.levels.get(level);
        let other_level = other.levels.get(level);

        let self_hash = self_level.and_then(|l| l.get(node_idx));
        let other_hash = other_level.and_then(|l| l.get(node_idx));

        if let (Some(a), Some(b)) = (self_hash, other_hash) {
            if a == b {
                return; // subtree matches
            }
        }

        if level == 0 {
            // Leaf level — present in only one tree, or hashes differ.
            if self_hash.is_some() || other_hash.is_some() {
                diffs.push(node_idx);
            }
            return;
        }

        // A tree that HAS this level but not this node has no leaves in
        // this subtree's range (level L has ceil(leaf_count / 2^L) nodes),
        // so every leaf of the other tree in the range is a diff. A tree
        // that lacks the level entirely is shallower than `level`; its
        // leaves may still overlap the range, so that case must descend.
        if self_level.is_some() && self_hash.is_none() {
            let start = node_idx << level;
            let end = (start + (1usize << level)).min(other.leaf_count());
            diffs.extend(start..end);
            return;
        }
        if other_level.is_some() && other_hash.is_none() {
            let start = node_idx << level;
            let end = (start + (1usize << level)).min(self.leaf_count());
            diffs.extend(start..end);
            return;
        }

        // Descend into both children.
        let left_child = node_idx * 2;
        let right_child = node_idx * 2 + 1;
        self.diff_recurse(other, level - 1, left_child, diffs);
        self.diff_recurse(other, level - 1, right_child, diffs);
    }

    /// Pick the best level for efficient diff exchange.
    /// Finds the LOWEST level that fits in a single UDP packet (~1400 bytes).
    /// Lower levels = more granularity = smaller subtree diffs.
    /// Max ~43 hashes (43 × 32 = 1376 bytes + 5 header + overhead ≈ 1430).
    /// Returns (level_index, node_count).
    pub fn strategic_level(&self) -> (usize, usize) {
        let max_hashes = 43;
        // Walk from leaves upward, find the FIRST level that fits.
        for (i, level) in self.levels.iter().enumerate() {
            if level.len() <= max_hashes && level.len() > 1 {
                return (i, level.len());
            }
        }
        // Fallback: root level.
        (self.depth(), 1)
    }

    /// Given differing node indices at a specific level, expand down to
    /// identify all differing leaf indices.
    ///
    /// `level` and `diff_nodes` may come from a remote peer (ResumeAck
    /// payload); out-of-range values yield an empty result instead of
    /// panicking on the `1 << level` shift or overflowing index arithmetic.
    pub fn expand_diffs_to_leaves(&self, level: usize, diff_nodes: &[usize]) -> Vec<usize> {
        if level == 0 {
            return diff_nodes.to_vec();
        }
        // A node at level L covers 2^L leaves. Reject levels that do not
        // exist in this tree or would overflow the shift.
        if level > self.depth() || level >= usize::BITS as usize {
            return Vec::new();
        }
        let mut leaves = Vec::new();
        let leaf_count = self.leaf_count();
        for &node_idx in diff_nodes {
            // Each node at level L covers 2^L leaves starting at node_idx * 2^L.
            let span = 1usize << level;
            let Some(start_leaf) = node_idx.checked_mul(span) else {
                continue;
            };
            let end_leaf = start_leaf.saturating_add(span).min(leaf_count);
            for li in start_leaf..end_leaf {
                leaves.push(li);
            }
        }
        leaves
    }

    /// Serialize the tree to bytes for persistent storage or network exchange.
    /// Format: [4-byte leaf_count LE] [4-byte num_levels LE] then each level's hashes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&(self.leaf_count() as u32).to_le_bytes());
        buf.extend_from_slice(&(self.levels.len() as u32).to_le_bytes());
        for level in &self.levels {
            buf.extend_from_slice(&(level.len() as u32).to_le_bytes());
            for hash in level {
                buf.extend_from_slice(hash);
            }
        }
        buf
    }

    /// Deserialize a tree from bytes.
    ///
    /// The input may come from a corrupt local cache file, so every length
    /// is validated before allocating: `num_levels` is hard-capped, each
    /// level's hash count is checked against the remaining bytes, and the
    /// buffer must be consumed exactly (trailing garbage is an error).
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        /// A tree over N leaves has at most log2(N) + 2 levels; 64 is a
        /// generous hard cap that keeps the up-front allocation bounded.
        const MAX_LEVELS: usize = 64;

        if data.len() < 8 {
            return None;
        }
        let leaf_count = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;
        let num_levels = u32::from_le_bytes([data[4], data[5], data[6], data[7]]) as usize;

        if num_levels == 0 || num_levels > MAX_LEVELS {
            return None;
        }

        let mut offset = 8;
        let mut levels = Vec::with_capacity(num_levels);
        for _ in 0..num_levels {
            if offset + 4 > data.len() { return None; }
            let count = u32::from_le_bytes([
                data[offset], data[offset+1], data[offset+2], data[offset+3]
            ]) as usize;
            offset += 4;
            // Validate against the remaining bytes BEFORE allocating.
            let byte_len = count.checked_mul(32)?;
            let end = offset.checked_add(byte_len)?;
            if end > data.len() { return None; }
            let mut hashes = Vec::with_capacity(count);
            for chunk in data[offset..end].chunks_exact(32) {
                let mut h = [0u8; 32];
                h.copy_from_slice(chunk);
                hashes.push(h);
            }
            offset = end;
            levels.push(hashes);
        }

        // Trailing bytes mean the buffer is corrupt or tampered with.
        if offset != data.len() {
            return None;
        }
        // The declared leaf count must match the first (leaf) level.
        if levels.first().map(|l| l.len()).unwrap_or(0) != leaf_count {
            return None;
        }
        Some(Self { levels })
    }
}

/// Build a Merkle tree from file data chunked at the given payload size,
/// validating the chunking parameters.
///
/// `payload_size` typically comes from a peer-supplied transfer manifest;
/// a zero value is rejected instead of panicking in `div_ceil`.
pub fn try_build_file_merkle(
    file_data: &[u8],
    payload_size: usize,
) -> Result<MerkleTree, SyncError> {
    if payload_size == 0 {
        return Err(SyncError::InvalidPayloadSize(payload_size));
    }
    let total_chunks = file_data.len().div_ceil(payload_size);
    let mut leaves = Vec::with_capacity(total_chunks);
    for ci in 0..total_chunks {
        let offset = ci * payload_size;
        let end = (offset + payload_size).min(file_data.len());
        leaves.push(*blake3::hash(&file_data[offset..end]).as_bytes());
    }
    Ok(MerkleTree::from_leaves(&leaves))
}

/// Build a Merkle tree from file data chunked at the given payload size.
///
/// Compatibility wrapper around [`try_build_file_merkle`]: a zero
/// `payload_size` yields an empty tree instead of panicking.
pub fn build_file_merkle(file_data: &[u8], payload_size: usize) -> MerkleTree {
    try_build_file_merkle(file_data, payload_size)
        .unwrap_or_else(|_| MerkleTree::from_leaves(&[]))
}

/// Incremental counterpart of [`try_build_file_merkle`]: file data is fed
/// through [`FileMerkleBuilder::update`] in arbitrary slices (they need not
/// align with payload boundaries) and [`FileMerkleBuilder::finish`] yields
/// exactly the tree the slice-based build produces over the concatenated
/// input. This lets callers hash a huge mapping through a bounded window
/// instead of holding the whole file slice live for one call.
#[derive(Debug)]
pub struct FileMerkleBuilder {
    payload_size: usize,
    leaves: Vec<[u8; 32]>,
    /// Buffered tail of a partial payload chunk (< payload_size bytes).
    partial: Vec<u8>,
}

impl FileMerkleBuilder {
    /// Start a builder for the given chunking. A zero `payload_size` is
    /// rejected with [`SyncError::InvalidPayloadSize`], as in
    /// [`try_build_file_merkle`].
    pub fn new(payload_size: usize) -> Result<Self, SyncError> {
        if payload_size == 0 {
            return Err(SyncError::InvalidPayloadSize(payload_size));
        }
        Ok(Self {
            payload_size,
            leaves: Vec::new(),
            partial: Vec::new(),
        })
    }

    /// Feed the next slice of file data.
    pub fn update(&mut self, mut data: &[u8]) {
        // Complete a partial chunk carried over from the previous call.
        if !self.partial.is_empty() {
            let take = (self.payload_size - self.partial.len()).min(data.len());
            self.partial.extend_from_slice(&data[..take]);
            data = &data[take..];
            if self.partial.len() == self.payload_size {
                self.leaves.push(*blake3::hash(&self.partial).as_bytes());
                self.partial.clear();
            }
        }
        // Hash full chunks straight out of the input (no copy).
        while data.len() >= self.payload_size {
            self.leaves
                .push(*blake3::hash(&data[..self.payload_size]).as_bytes());
            data = &data[self.payload_size..];
        }
        self.partial.extend_from_slice(data);
    }

    /// Finish the tree; the trailing partial chunk, if any, is the last leaf.
    pub fn finish(mut self) -> MerkleTree {
        if !self.partial.is_empty() {
            self.leaves.push(*blake3::hash(&self.partial).as_bytes());
        }
        MerkleTree::from_leaves(&self.leaves)
    }
}

/// Verify a Merkle proof against an expected root hash.
pub fn verify_proof(root: &[u8; 32], leaf: &[u8; 32], proof: &[(bool, [u8; 32])]) -> bool {
    let mut current = *leaf;
    for &(is_right, ref sibling) in proof {
        if is_right {
            current = hash_pair(&current, sibling);
        } else {
            current = hash_pair(sibling, &current);
        }
    }
    &current == root
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_leaf(byte: u8) -> [u8; 32] {
        *blake3::hash(&[byte]).as_bytes()
    }

    #[test]
    fn single_leaf() {
        let leaf = make_leaf(1);
        let tree = MerkleTree::from_leaves(&[leaf]);
        assert_eq!(tree.root(), leaf);
        assert_eq!(tree.leaf_count(), 1);
        assert_eq!(tree.depth(), 0);
    }

    #[test]
    fn two_leaves() {
        let a = make_leaf(1);
        let b = make_leaf(2);
        let tree = MerkleTree::from_leaves(&[a, b]);
        assert_eq!(tree.leaf_count(), 2);
        assert_eq!(tree.root(), hash_pair(&a, &b));
    }

    #[test]
    fn power_of_two() {
        let leaves: Vec<[u8; 32]> = (0..4).map(make_leaf).collect();
        let tree = MerkleTree::from_leaves(&leaves);
        assert_eq!(tree.leaf_count(), 4);
        assert_eq!(tree.depth(), 2);
    }

    #[test]
    fn non_power_of_two() {
        let leaves: Vec<[u8; 32]> = (0..5).map(make_leaf).collect();
        let tree = MerkleTree::from_leaves(&leaves);
        assert_eq!(tree.leaf_count(), 5);
        assert!(tree.depth() >= 2);
    }

    #[test]
    fn proof_verifies() {
        let leaves: Vec<[u8; 32]> = (0..8).map(make_leaf).collect();
        let tree = MerkleTree::from_leaves(&leaves);
        let root = tree.root();

        for i in 0..8 {
            let proof = tree.proof(i);
            assert!(
                verify_proof(&root, &leaves[i], &proof),
                "proof failed for leaf {i}"
            );
        }
    }

    #[test]
    fn tampered_proof_fails() {
        let leaves: Vec<[u8; 32]> = (0..4).map(make_leaf).collect();
        let tree = MerkleTree::from_leaves(&leaves);
        let root = tree.root();
        let proof = tree.proof(0);

        // Tamper with the leaf.
        let tampered_leaf = make_leaf(99);
        assert!(!verify_proof(&root, &tampered_leaf, &proof));
    }

    #[test]
    fn empty_tree() {
        let tree = MerkleTree::from_leaves(&[]);
        assert_eq!(tree.leaf_count(), 0);
        assert_eq!(tree.root(), [0u8; 32]);
    }

    #[test]
    fn diff_identical_trees() {
        let leaves: Vec<[u8; 32]> = (0..8).map(make_leaf).collect();
        let a = MerkleTree::from_leaves(&leaves);
        let b = MerkleTree::from_leaves(&leaves);
        assert!(a.diff_leaves(&b).is_empty());
    }

    #[test]
    fn diff_one_leaf_changed() {
        let leaves_a: Vec<[u8; 32]> = (0..8).map(make_leaf).collect();
        let mut leaves_b = leaves_a.clone();
        leaves_b[3] = make_leaf(99); // change leaf 3

        let a = MerkleTree::from_leaves(&leaves_a);
        let b = MerkleTree::from_leaves(&leaves_b);
        assert_eq!(a.diff_leaves(&b), vec![3]);
    }

    #[test]
    fn diff_multiple_leaves() {
        let leaves_a: Vec<[u8; 32]> = (0..16).map(make_leaf).collect();
        let mut leaves_b = leaves_a.clone();
        leaves_b[2] = make_leaf(100);
        leaves_b[7] = make_leaf(101);
        leaves_b[14] = make_leaf(102);

        let a = MerkleTree::from_leaves(&leaves_a);
        let b = MerkleTree::from_leaves(&leaves_b);
        let diffs = a.diff_leaves(&b);
        assert_eq!(diffs, vec![2, 7, 14]);
    }

    #[test]
    fn diff_all_different() {
        let a = MerkleTree::from_leaves(&(0..4).map(make_leaf).collect::<Vec<_>>());
        let b = MerkleTree::from_leaves(&(10..14).map(make_leaf).collect::<Vec<_>>());
        assert_eq!(a.diff_leaves(&b), vec![0, 1, 2, 3]);
    }

    #[test]
    fn diff_other_deeper_file_grew() {
        // Same first 4 leaves, other grew by 4: the new tail leaves must
        // all be reported (the old code silently skipped them).
        let leaves_a: Vec<[u8; 32]> = (0..4).map(make_leaf).collect();
        let leaves_b: Vec<[u8; 32]> = (0..8).map(make_leaf).collect();
        let a = MerkleTree::from_leaves(&leaves_a);
        let b = MerkleTree::from_leaves(&leaves_b);
        assert_eq!(a.diff_leaves(&b), vec![4, 5, 6, 7]);
    }

    #[test]
    fn diff_other_deeper_with_changed_prefix() {
        // Grew by 4 AND leaf 1 changed: changed prefix + all new leaves.
        let leaves_a: Vec<[u8; 32]> = (0..4).map(make_leaf).collect();
        let mut leaves_b: Vec<[u8; 32]> = (0..8).map(make_leaf).collect();
        leaves_b[1] = make_leaf(99);
        let a = MerkleTree::from_leaves(&leaves_a);
        let b = MerkleTree::from_leaves(&leaves_b);
        assert_eq!(a.diff_leaves(&b), vec![1, 4, 5, 6, 7]);
    }

    #[test]
    fn diff_other_shallower_file_shrank() {
        // Same first 4 leaves, other shrank: leaves present only in self
        // are reported (symmetric rule — never miss a one-sided leaf).
        let leaves_a: Vec<[u8; 32]> = (0..8).map(make_leaf).collect();
        let leaves_b: Vec<[u8; 32]> = (0..4).map(make_leaf).collect();
        let a = MerkleTree::from_leaves(&leaves_a);
        let b = MerkleTree::from_leaves(&leaves_b);
        assert_eq!(a.diff_leaves(&b), vec![4, 5, 6, 7]);
    }

    #[test]
    fn diff_same_depth_different_leaf_count() {
        // 3 vs 4 leaves: both depth 2, but leaf 3 exists only in other.
        let leaves_a: Vec<[u8; 32]> = (0..3).map(make_leaf).collect();
        let leaves_b: Vec<[u8; 32]> = (0..4).map(make_leaf).collect();
        let a = MerkleTree::from_leaves(&leaves_a);
        let b = MerkleTree::from_leaves(&leaves_b);
        assert_eq!(a.diff_leaves(&b), vec![3]);
        // And the mirror image.
        assert_eq!(b.diff_leaves(&a), vec![3]);
    }

    #[test]
    fn diff_wildly_different_depths() {
        // 1 leaf vs 16 sharing leaf 0: all of other's extra leaves differ.
        let one = MerkleTree::from_leaves(&[make_leaf(0)]);
        let many = MerkleTree::from_leaves(&(0..16).map(make_leaf).collect::<Vec<_>>());
        let expected: Vec<usize> = (1..16).collect();
        assert_eq!(one.diff_leaves(&many), expected);
        // Mirror: 32 vs 2 sharing the first 2 leaves.
        let big = MerkleTree::from_leaves(&(0..32).map(make_leaf).collect::<Vec<_>>());
        let small = MerkleTree::from_leaves(&(0..2).map(make_leaf).collect::<Vec<_>>());
        let expected: Vec<usize> = (2..32).collect();
        assert_eq!(big.diff_leaves(&small), expected);
    }

    #[test]
    fn diff_never_misses_one_sided_leaf() {
        // Property: for a spread of sizes sharing a common prefix, every
        // leaf present in only one tree must appear in the diff, and no
        // shared-prefix leaf may appear.
        for self_n in [1usize, 2, 3, 5, 8, 13] {
            for other_n in [1usize, 2, 3, 5, 8, 13] {
                let a = MerkleTree::from_leaves(
                    &(0..self_n as u8).map(make_leaf).collect::<Vec<_>>(),
                );
                let b = MerkleTree::from_leaves(
                    &(0..other_n as u8).map(make_leaf).collect::<Vec<_>>(),
                );
                let diffs = a.diff_leaves(&b);
                let common = self_n.min(other_n);
                let expected: Vec<usize> = (common..self_n.max(other_n)).collect();
                assert_eq!(
                    diffs, expected,
                    "self_n={self_n} other_n={other_n}"
                );
            }
        }
    }

    #[test]
    fn serialize_roundtrip() {
        let leaves: Vec<[u8; 32]> = (0..8).map(make_leaf).collect();
        let tree = MerkleTree::from_leaves(&leaves);
        let bytes = tree.to_bytes();
        let restored = MerkleTree::from_bytes(&bytes).unwrap();
        assert_eq!(tree.root(), restored.root());
        assert_eq!(tree.leaf_count(), restored.leaf_count());
    }

    #[test]
    fn build_file_merkle_works() {
        let data = vec![0xABu8; 4096];
        let tree = super::build_file_merkle(&data, 1024);
        assert_eq!(tree.leaf_count(), 4);
        assert_ne!(tree.root(), [0u8; 32]);
    }

    #[test]
    fn build_file_merkle_zero_payload_size_no_panic() {
        let data = vec![0xABu8; 4096];
        // Fallible entry point rejects payload_size == 0.
        let err = super::try_build_file_merkle(&data, 0).unwrap_err();
        assert!(matches!(err, SyncError::InvalidPayloadSize(0)));
        // Compatibility wrapper must not panic; yields an empty tree.
        let tree = super::build_file_merkle(&data, 0);
        assert_eq!(tree.leaf_count(), 0);
    }

    #[test]
    fn expand_diffs_to_leaves_rejects_huge_level() {
        let leaves: Vec<[u8; 32]> = (0..8).map(make_leaf).collect();
        let tree = MerkleTree::from_leaves(&leaves);
        // level >= 64 would panic on `1 << level`; level > depth is invalid.
        assert!(tree.expand_diffs_to_leaves(64, &[0]).is_empty());
        assert!(tree.expand_diffs_to_leaves(255, &[0]).is_empty());
        assert!(tree.expand_diffs_to_leaves(tree.depth() + 1, &[0]).is_empty());
        // Huge node indices must not overflow index arithmetic.
        assert!(tree.expand_diffs_to_leaves(1, &[usize::MAX]).is_empty());
        // A valid expansion still works.
        assert_eq!(tree.expand_diffs_to_leaves(1, &[0]), vec![0, 1]);
    }

    #[test]
    fn from_bytes_rejects_absurd_num_levels() {
        // num_levels = u32::MAX must fail fast, not allocate ~100 GB.
        let mut data = Vec::new();
        data.extend_from_slice(&1u32.to_le_bytes());
        data.extend_from_slice(&u32::MAX.to_le_bytes());
        assert!(MerkleTree::from_bytes(&data).is_none());

        // num_levels = 0 is invalid too.
        let mut data = Vec::new();
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());
        assert!(MerkleTree::from_bytes(&data).is_none());
    }

    #[test]
    fn from_bytes_rejects_oversized_hash_count() {
        // One level claiming u32::MAX hashes with no backing bytes.
        let mut data = Vec::new();
        data.extend_from_slice(&1u32.to_le_bytes()); // leaf_count
        data.extend_from_slice(&1u32.to_le_bytes()); // num_levels
        data.extend_from_slice(&u32::MAX.to_le_bytes()); // level hash count
        assert!(MerkleTree::from_bytes(&data).is_none());
    }

    #[test]
    fn from_bytes_rejects_trailing_garbage() {
        let leaves: Vec<[u8; 32]> = (0..4).map(make_leaf).collect();
        let tree = MerkleTree::from_leaves(&leaves);
        let mut bytes = tree.to_bytes();
        bytes.extend_from_slice(&[0xDE, 0xAD]);
        assert!(MerkleTree::from_bytes(&bytes).is_none());
    }

    #[test]
    fn from_bytes_rejects_leaf_count_mismatch() {
        let leaves: Vec<[u8; 32]> = (0..4).map(make_leaf).collect();
        let tree = MerkleTree::from_leaves(&leaves);
        let mut bytes = tree.to_bytes();
        // Lie about the leaf count in the header.
        bytes[0..4].copy_from_slice(&999u32.to_le_bytes());
        assert!(MerkleTree::from_bytes(&bytes).is_none());
    }

    #[test]
    fn from_bytes_empty_tree_roundtrip() {
        let tree = MerkleTree::from_leaves(&[]);
        let restored = MerkleTree::from_bytes(&tree.to_bytes()).unwrap();
        assert_eq!(restored.leaf_count(), 0);
        assert_eq!(restored.root(), tree.root());
    }

    /// Deterministic xorshift filler (no dev-dependency on a RNG crate).
    fn pseudo_random(len: usize, seed: u64) -> Vec<u8> {
        let mut state = seed.max(1);
        let mut out = Vec::with_capacity(len);
        while out.len() < len {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            out.extend_from_slice(&state.to_le_bytes());
        }
        out.truncate(len);
        out
    }

    #[test]
    fn streaming_builder_matches_slice_path() {
        // Sizes hitting empty, sub-chunk, exact-multiple, and ragged tails.
        let sizes = [0usize, 1, 100, 1023, 1024, 1025, 4096, 100_000];
        let payload_sizes = [1usize, 4, 1024, 1350];
        for &payload_size in &payload_sizes {
            for &size in &sizes {
                let data = pseudo_random(size, size as u64 ^ payload_size as u64);
                let expected = super::build_file_merkle(&data, payload_size);
                // Feed the builder in awkward splits: 1 byte, then a
                // near-chunk stride, then one final slice.
                let mut builder = super::FileMerkleBuilder::new(payload_size).unwrap();
                let stride = payload_size.saturating_sub(1).max(1);
                let mut off = 0usize;
                if !data.is_empty() {
                    builder.update(&data[..1]);
                    off = 1;
                }
                while off + stride < data.len() {
                    builder.update(&data[off..off + stride]);
                    off += stride;
                }
                builder.update(&data[off..]);
                let tree = builder.finish();
                assert_eq!(
                    tree.root(),
                    expected.root(),
                    "root mismatch: size={size} payload={payload_size}"
                );
                assert_eq!(tree.leaf_count(), expected.leaf_count());
                assert_eq!(tree.to_bytes(), expected.to_bytes());
            }
        }
    }

    #[test]
    fn streaming_builder_rejects_zero_payload_size() {
        let err = super::FileMerkleBuilder::new(0).unwrap_err();
        assert!(matches!(err, SyncError::InvalidPayloadSize(0)));
    }
}
