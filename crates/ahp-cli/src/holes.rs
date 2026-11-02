// Favonius — high-performance file transfer over UDP
// Copyright (c) 2025-2026 Vantino SàRL
// SPDX-License-Identifier: Apache-2.0

//! Where a file's holes are, as the filesystem reports them.
//!
//! `SEEK_DATA`/`SEEK_HOLE` on Linux and macOS. A filesystem without hole support
//! reports the whole file as data, which is the correct answer for it, and
//! so does any error: holes are an optimisation, never a requirement.
//! Elsewhere the file is treated as all data.

/// The holes of `file`, `file_size` bytes long, as sorted non-overlapping
/// `(offset, len)` byte ranges. Empty when there are none or they cannot be
/// found.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub fn holes(file: &std::fs::File, file_size: u64) -> Vec<(u64, u64)> {
    use std::os::unix::io::AsRawFd;
    let fd = file.as_raw_fd();
    let seek = |off: u64, whence: libc::c_int| -> Option<u64> {
        // SAFETY: lseek on a file descriptor we hold open; it only moves the
        // file offset, which nothing else in this process relies on (reads
        // go through a mapping or pread).
        let r = unsafe { libc::lseek(fd, off as libc::off_t, whence) };
        (r >= 0).then_some(r as u64)
    };
    let mut out = Vec::new();
    let mut off = 0u64;
    while off < file_size {
        // The next hole at or after `off`; every file has one at its end.
        let Some(hole) = seek(off, libc::SEEK_HOLE) else { break };
        if hole >= file_size {
            break;
        }
        // The data after it, or the end of the file (ENXIO) if none.
        let data = seek(hole, libc::SEEK_DATA).unwrap_or(file_size).min(file_size);
        if data > hole {
            out.push((hole, data - hole));
        }
        if data <= off {
            break; // no progress: a filesystem misreporting; stop here
        }
        off = data;
    }
    out
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub fn holes(_file: &std::fs::File, _file_size: u64) -> Vec<(u64, u64)> {
    Vec::new()
}

/// Split `[start, end)` into segments that are wholly inside a hole or
/// wholly outside every hole, in order, as `(in_hole, seg_start, seg_end)`.
pub fn segments(holes: &[(u64, u64)], start: u64, end: u64) -> Vec<(bool, u64, u64)> {
    let mut out = Vec::new();
    let mut pos = start;
    // Holes are sorted; skip those wholly before the range.
    let first = holes.partition_point(|&(o, l)| o + l <= start);
    for &(o, l) in &holes[first..] {
        if pos >= end || o >= end {
            break;
        }
        let (hs, he) = (o.max(pos), (o + l).min(end));
        if hs > pos {
            out.push((false, pos, hs));
        }
        if he > hs {
            out.push((true, hs, he));
        }
        pos = pos.max(he);
    }
    if pos < end {
        out.push((false, pos, end));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn segments_alternate_and_cover_the_range() {
        let holes = [(100, 100), (300, 50)];
        assert_eq!(
            segments(&holes, 0, 400),
            vec![(false, 0, 100), (true, 100, 200), (false, 200, 300), (true, 300, 350), (false, 350, 400)]
        );
        assert_eq!(segments(&holes, 150, 320), vec![(true, 150, 200), (false, 200, 300), (true, 300, 320)]);
        assert_eq!(segments(&[], 0, 10), vec![(false, 0, 10)]);
    }

    /// A real sparse file: 1 MiB of data, a hole, one byte at the end.
    #[cfg(target_os = "linux")]
    #[test]
    fn the_filesystem_reports_a_files_holes() {
        use std::io::{Seek, SeekFrom, Write};
        let path = std::env::temp_dir().join(format!("favonius-holes-{:016x}", rand::random::<u64>()));
        let size = 32u64 << 20;
        {
            let mut f = std::fs::File::create(&path).unwrap();
            f.write_all(&vec![7u8; 1 << 20]).unwrap();
            f.seek(SeekFrom::Start(size - 1)).unwrap();
            f.write_all(b"x").unwrap();
        }
        let f = std::fs::File::open(&path).unwrap();
        let h = holes(&f, size);
        std::fs::remove_file(&path).ok();
        // Filesystems round to their block size; the hole is most of the file.
        let total: u64 = h.iter().map(|&(_, l)| l).sum();
        assert!(total > size - (2 << 20), "holes {h:?} cover {total} of {size}");
        assert!(h.iter().all(|&(o, l)| o >= 1 << 20 && o + l <= size));
    }
}
