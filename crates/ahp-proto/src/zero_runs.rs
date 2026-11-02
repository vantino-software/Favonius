// Favonius — high-performance file transfer over UDP
// Copyright (c) 2025-2026 Vantino SàRL
// SPDX-License-Identifier: Apache-2.0

//! Zero runs: chunks a sparse file's holes make unnecessary to send.
//!
//! A hole in a sparse file reads as zeros and occupies no storage. Sending
//! it means reading, framing, pacing and acknowledging zeros, and on tmpfs
//! reading it through a mapping even allocates it at the source. So when the
//! daemon advertises [`crate::CAP_ZERO_RUNS`], the sender lists in the
//! MANIFEST the runs of chunks that lie *wholly* inside holes, `[first,
//! count]` in chunk units, and both ends mark them received before any DATA
//! flows. A chunk only partly inside a hole is sent as usual, zeros
//! included, so the bytes on the wire stay exactly the file's bytes.
//!
//! The MANIFEST is a single control datagram, so the list is bounded by the
//! space left in it: [`fit`] keeps the runs that cover the most chunks and
//! drops the rest, which are then sent as ordinary data. Dropping runs costs
//! bandwidth, never correctness.

/// A run of chunks: `[first_chunk, chunk_count]`.
pub type ZeroRun = [u64; 2];

/// The most runs a daemon accepts in one MANIFEST. Far above what fits in a
/// datagram; a bound on the work a malformed manifest can cause.
pub const MAX_ZERO_RUNS: usize = 4096;

/// The chunk runs wholly inside `holes`, byte ranges `(offset, len)` sorted
/// and non-overlapping, for a file of `file_size` bytes split into
/// `payload_size`-byte chunks (the last one possibly shorter).
pub fn runs_in_holes(holes: &[(u64, u64)], file_size: u64, payload_size: u64) -> Vec<ZeroRun> {
    let mut runs: Vec<ZeroRun> = Vec::new();
    if payload_size == 0 {
        return runs;
    }
    let total = file_size.div_ceil(payload_size);
    for &(off, len) in holes {
        let end = off.saturating_add(len).min(file_size);
        if end <= off {
            continue;
        }
        // First chunk starting at or after the hole's start.
        let first = off.div_ceil(payload_size);
        // Chunks whose end is within the hole: chunk c ends at
        // min((c+1)*ps, file_size). A hole reaching the end of the file
        // covers the short last chunk too.
        let last_exclusive = if end == file_size { total } else { end / payload_size };
        if last_exclusive > first {
            match runs.last_mut() {
                Some(r) if r[0] + r[1] == first => r[1] += last_exclusive - first,
                _ => runs.push([first, last_exclusive - first]),
            }
        }
    }
    runs
}

/// Keep the runs that cover the most chunks within `budget` bytes of JSON
/// (`[[a,b],[c,d]]`), returned in ascending order.
pub fn fit(runs: &[ZeroRun], budget: usize) -> Vec<ZeroRun> {
    let cost = |r: &ZeroRun| format!("[{},{}],", r[0], r[1]).len();
    let mut by_size: Vec<ZeroRun> = runs.to_vec();
    by_size.sort_by(|a, b| b[1].cmp(&a[1]).then(a[0].cmp(&b[0])));
    let mut kept = Vec::new();
    // Two bytes for the enclosing brackets.
    let mut used = 2usize;
    for r in by_size {
        if kept.len() >= MAX_ZERO_RUNS {
            break;
        }
        let c = cost(&r);
        if used + c <= budget {
            used += c;
            kept.push(r);
        }
    }
    kept.sort_by_key(|r| r[0]);
    kept
}

/// Check runs from a MANIFEST: ascending, non-empty, non-overlapping, inside
/// `total_chunks`, and no more than [`MAX_ZERO_RUNS`]. Returns how many
/// chunks they cover.
pub fn validate(runs: &[ZeroRun], total_chunks: u64) -> Result<u64, String> {
    if runs.len() > MAX_ZERO_RUNS {
        return Err(format!("{} zero runs exceed the limit of {MAX_ZERO_RUNS}", runs.len()));
    }
    let mut next_free = 0u64;
    let mut covered = 0u64;
    for r in runs {
        let [first, count] = *r;
        let end = first.checked_add(count).ok_or("zero run overflows")?;
        if count == 0 {
            return Err(format!("empty zero run at chunk {first}"));
        }
        if first < next_free {
            return Err(format!("zero run at chunk {first} is out of order or overlaps"));
        }
        if end > total_chunks {
            return Err(format!("zero run [{first},{count}] ends past chunk {total_chunks}"));
        }
        next_free = end;
        covered += count;
    }
    Ok(covered)
}

/// Byte ranges `(offset, len)` the runs cover, the last clipped to the file.
pub fn byte_ranges(runs: &[ZeroRun], file_size: u64, payload_size: u64) -> Vec<(u64, u64)> {
    runs.iter()
        .map(|&[first, count]| {
            let start = first.saturating_mul(payload_size).min(file_size);
            let end = first.saturating_add(count).saturating_mul(payload_size).min(file_size);
            (start, end - start)
        })
        .filter(|&(_, len)| len > 0)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_chunks_wholly_inside_a_hole_are_runs() {
        // 10 chunks of 100 bytes. Hole [150, 450): chunks 2 and 3 are inside
        // ([200,300) and [300,400)); 1 and 4 are only partly.
        assert_eq!(runs_in_holes(&[(150, 300)], 1000, 100), vec![[2, 2]]);
        // Aligned exactly.
        assert_eq!(runs_in_holes(&[(200, 200)], 1000, 100), vec![[2, 2]]);
        // Smaller than a chunk: nothing.
        assert!(runs_in_holes(&[(210, 50)], 1000, 100).is_empty());
    }

    #[test]
    fn a_hole_to_the_end_covers_the_short_last_chunk() {
        // 950 bytes: chunk 9 is [900, 950).
        assert_eq!(runs_in_holes(&[(800, 150)], 950, 100), vec![[8, 2]]);
        // A hole ending before the end does not cover the short chunk.
        assert_eq!(runs_in_holes(&[(800, 140)], 950, 100), vec![[8, 1]]);
    }

    #[test]
    fn adjacent_holes_merge_into_one_run() {
        assert_eq!(runs_in_holes(&[(0, 200), (200, 200)], 1000, 100), vec![[0, 4]]);
    }

    #[test]
    fn fitting_keeps_the_largest_runs_in_order() {
        let runs = vec![[0, 1], [10, 500], [600, 2], [1000, 300]];
        // Room for the brackets and two runs of this size.
        let kept = fit(&runs, 2 + "[10,500],".len() + "[1000,300],".len());
        assert_eq!(kept, vec![[10, 500], [1000, 300]]);
        assert!(fit(&runs, 1).is_empty());
    }

    #[test]
    fn validation_refuses_what_a_sender_cannot_mean() {
        assert_eq!(validate(&[[0, 2], [5, 3]], 10), Ok(5));
        assert!(validate(&[[5, 3], [0, 2]], 10).is_err(), "out of order");
        assert!(validate(&[[0, 3], [2, 2]], 10).is_err(), "overlap");
        assert!(validate(&[[8, 3]], 10).is_err(), "past the end");
        assert!(validate(&[[1, 0]], 10).is_err(), "empty");
        assert!(validate(&[[u64::MAX, 2]], 10).is_err(), "overflow");
        let many: Vec<ZeroRun> = (0..MAX_ZERO_RUNS as u64 + 1).map(|i| [i * 2, 1]).collect();
        assert!(validate(&many, u64::MAX).is_err(), "too many");
    }

    #[test]
    fn byte_ranges_clip_the_last_chunk() {
        assert_eq!(byte_ranges(&[[8, 2]], 950, 100), vec![(800, 150)]);
        assert_eq!(byte_ranges(&[[0, 1], [3, 2]], 1000, 100), vec![(0, 100), (300, 200)]);
    }
}
