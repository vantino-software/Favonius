// Favonius — high-performance file transfer over UDP
// Copyright (c) 2025-2026 Vantino SàRL
// SPDX-License-Identifier: Apache-2.0

//! Directory walking and glob filtering for multi-file transfers.
//!
//! Deliberately dependency-free: a recursive walk and a small glob matcher
//! are a few dozen lines each, and Favonius's dependency set is part of what
//! downstream users audit before embedding it.

use std::collections::HashSet;
use std::io;
use std::path::{Path, PathBuf};

/// One regular file discovered under a walk root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TreeEntry {
    /// Absolute (or walk-root-relative) path to open for reading.
    pub abs: PathBuf,
    /// Path relative to the walk root, always `/`-separated. This is the
    /// key both sides agree on, so it must not carry platform separators.
    pub rel: String,
    /// File size in bytes.
    pub size: u64,
    /// Modification time in whole seconds since the Unix epoch. Whole
    /// seconds because that is the resolution every filesystem and archive
    /// format agrees on; sub-second mtimes do not survive a round trip
    /// through FAT, tar, or S3 metadata.
    pub mtime: i64,
}

/// Filters applied to a walk. An empty include list matches everything;
/// exclude always wins over include.
#[derive(Debug, Default, Clone)]
pub struct Filters {
    pub include: Vec<String>,
    pub exclude: Vec<String>,
}

impl Filters {
    pub fn new(include: Option<&str>, exclude: Option<&str>) -> Self {
        Self {
            include: split_patterns(include),
            exclude: split_patterns(exclude),
        }
    }

    /// Whether a relative path survives the filters.
    pub fn accepts(&self, rel: &str) -> bool {
        if self.exclude.iter().any(|p| glob_match(p, rel)) {
            return false;
        }
        self.include.is_empty() || self.include.iter().any(|p| glob_match(p, rel))
    }
}

fn split_patterns(s: Option<&str>) -> Vec<String> {
    s.map(|s| {
        s.split(',')
            .map(str::trim)
            .filter(|p| !p.is_empty())
            .map(str::to_string)
            .collect()
    })
    .unwrap_or_default()
}

/// Recursively collect regular files under `root`, sorted by relative path.
///
/// Symlinked *files* are followed (the daemon accepts a symlink to a
/// regular file), but symlinked *directories* are not: a link pointing at
/// an ancestor turns the walk into an infinite one, and no amount of depth
/// limiting makes that safe to follow by default. Directories are also
/// deduplicated by canonical path so a bind mount or hardlinked directory
/// cannot produce the same cycle.
///
/// Returns entries sorted by `rel` so a transfer is reproducible and two
/// sides can diff two listings without sorting first.
pub fn walk(root: &Path, filters: &Filters) -> io::Result<Vec<TreeEntry>> {
    let mut out = Vec::new();
    let mut seen_dirs = HashSet::new();
    walk_inner(root, root, filters, &mut out, &mut seen_dirs)?;
    out.sort_by(|a, b| a.rel.cmp(&b.rel));
    Ok(out)
}

fn walk_inner(
    root: &Path,
    dir: &Path,
    filters: &Filters,
    out: &mut Vec<TreeEntry>,
    seen_dirs: &mut HashSet<PathBuf>,
) -> io::Result<()> {
    // Cycle guard: canonicalize each directory before descending.
    let canonical = dir.canonicalize()?;
    if !seen_dirs.insert(canonical) {
        return Ok(());
    }

    let mut children: Vec<_> = std::fs::read_dir(dir)?.collect::<Result<Vec<_>, _>>()?;
    children.sort_by_key(|e| e.file_name());

    for child in children {
        let path = child.path();
        // `symlink_metadata` does not traverse the link, so we can tell a
        // symlinked directory from a real one before deciding to descend.
        let link_meta = std::fs::symlink_metadata(&path)?;
        let is_symlink = link_meta.file_type().is_symlink();

        let meta = match std::fs::metadata(&path) {
            Ok(m) => m,
            // A dangling symlink is not an error for a walk — skip it.
            Err(_) if is_symlink => continue,
            Err(e) => return Err(e),
        };

        if meta.is_dir() {
            if is_symlink {
                continue; // never descend through a link (cycle risk)
            }
            walk_inner(root, &path, filters, out, seen_dirs)?;
        } else if meta.is_file() {
            let rel = relative_slash_path(root, &path);
            if !filters.accepts(&rel) {
                continue;
            }
            out.push(TreeEntry {
                abs: path,
                rel,
                size: meta.len(),
                mtime: mtime_secs(&meta),
            });
        }
        // Sockets, FIFOs and device nodes are silently skipped: they have
        // no transferable content.
    }
    Ok(())
}

/// Path of `path` relative to `root`, with `/` separators.
fn relative_slash_path(root: &Path, path: &Path) -> String {
    let rel = path.strip_prefix(root).unwrap_or(path);
    rel.components()
        .map(|c| c.as_os_str().to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join("/")
}

fn mtime_secs(meta: &std::fs::Metadata) -> i64 {
    meta.modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Join a destination base with a `/`-separated relative path.
///
/// Rejects anything that would escape the base — `..` components and
/// absolute relative paths. The daemon enforces its own `--dest-root`
/// confinement, but a sync client that can be talked into writing outside
/// the destination it was given is a bug on its own terms.
pub fn join_dest(base: &str, rel: &str) -> Option<String> {
    if rel.is_empty() {
        return None;
    }
    for part in rel.split('/') {
        if part.is_empty() || part == "." || part == ".." {
            return None;
        }
    }
    let trimmed = base.trim_end_matches('/');
    Some(format!("{trimmed}/{rel}"))
}

/// Glob matcher supporting `*` (within a path segment), `**` (across
/// segments), `?`, and character classes `[abc]` / `[a-z]` / `[!abc]`.
///
/// A pattern with no `/` is matched against the basename as well as the
/// full relative path, so `--include '*.bin'` does the obvious thing on a
/// nested tree rather than matching only top-level files.
pub fn glob_match(pattern: &str, text: &str) -> bool {
    if !pattern.contains('/') {
        let base = text.rsplit('/').next().unwrap_or(text);
        if glob_segment(pattern.as_bytes(), base.as_bytes()) {
            return true;
        }
    }
    glob_segment(pattern.as_bytes(), text.as_bytes())
}

/// A single parsed glob token.
#[derive(Debug, PartialEq, Eq)]
enum Tok {
    /// A literal byte.
    Lit(u8),
    /// `?` — any one byte except the separator.
    Any,
    /// `*` — any run of bytes not containing the separator.
    Star,
    /// `**` — any run of bytes, separators included.
    DoubleStar,
    /// `[...]` — `(negated, inclusive byte ranges)`.
    Class(bool, Vec<(u8, u8)>),
}

fn tokenize(pat: &[u8]) -> Vec<Tok> {
    let mut toks = Vec::with_capacity(pat.len());
    let mut i = 0;
    while i < pat.len() {
        match pat[i] {
            b'*' => {
                if pat.get(i + 1) == Some(&b'*') {
                    toks.push(Tok::DoubleStar);
                    i += 2;
                    // Collapse `***`+ down to `**`.
                    while pat.get(i) == Some(&b'*') {
                        i += 1;
                    }
                } else {
                    toks.push(Tok::Star);
                    i += 1;
                }
            }
            b'?' => {
                toks.push(Tok::Any);
                i += 1;
            }
            b'[' => match parse_class(pat, i) {
                Some((tok, next)) => {
                    toks.push(tok);
                    i = next;
                }
                // Unterminated class: treat the `[` as a literal so the
                // pattern still means something rather than silently
                // matching nothing.
                None => {
                    toks.push(Tok::Lit(b'['));
                    i += 1;
                }
            },
            c => {
                toks.push(Tok::Lit(c));
                i += 1;
            }
        }
    }
    toks
}

/// Parse a `[...]` class starting at `pat[i]`; returns the token and the
/// index just past the closing `]`.
fn parse_class(pat: &[u8], i: usize) -> Option<(Tok, usize)> {
    let mut j = i + 1;
    let negate = matches!(pat.get(j), Some(&b'!') | Some(&b'^'));
    if negate {
        j += 1;
    }
    let mut ranges = Vec::new();
    let mut first = true;
    while j < pat.len() {
        // A `]` in first position is a literal, not the terminator.
        if pat[j] == b']' && !first {
            return Some((Tok::Class(negate, ranges), j + 1));
        }
        first = false;
        if j + 2 < pat.len() && pat[j + 1] == b'-' && pat[j + 2] != b']' {
            ranges.push((pat[j], pat[j + 2]));
            j += 3;
        } else {
            ranges.push((pat[j], pat[j]));
            j += 1;
        }
    }
    None
}

/// Glob matcher over tokens, by dynamic programming.
///
/// A backtracking matcher is the usual choice, but it keeps only one `*`
/// resume point, which is wrong once `*` is forbidden from crossing `/`:
/// when an inner `*` runs into a separator and fails, the correct move is
/// to give an *outer* `**` another byte, and a single resume point has
/// already forgotten it. (`**/*.log` against `a/b/x.log` is the smallest
/// case.) The DP evaluates every (token, position) pair exactly once, so
/// it is both correct and O(tokens x bytes) — no backtracking blowup.
fn glob_segment(pat: &[u8], text: &[u8]) -> bool {
    glob_toks(&tokenize(pat), text)
}

fn glob_toks(toks: &[Tok], text: &[u8]) -> bool {
    let (n, m) = (toks.len(), text.len());

    // next[j] = toks[i+1..] matches text[j..]; cur[j] = toks[i..] matches.
    // Only the row for i+1 is ever needed, so two rows suffice.
    let mut next = vec![false; m + 1];
    next[m] = true; // empty pattern matches empty remainder
    let mut cur = vec![false; m + 1];

    for i in (0..n).rev() {
        // `**/` is also allowed to match zero directories, so that
        // `a/**/c` matches `a/c` and not just `a/b/c`.
        let skip_two = matches!(
            (&toks[i], toks.get(i + 1)),
            (Tok::DoubleStar, Some(Tok::Lit(b'/')))
        );

        for j in (0..=m).rev() {
            cur[j] = match &toks[i] {
                Tok::Star => next[j] || (j < m && text[j] != b'/' && cur[j + 1]),
                Tok::DoubleStar => next[j] || (j < m && cur[j + 1]),
                Tok::Any => j < m && text[j] != b'/' && next[j + 1],
                Tok::Lit(c) => j < m && text[j] == *c && next[j + 1],
                Tok::Class(negate, ranges) => {
                    j < m && {
                        let c = text[j];
                        let hit = ranges.iter().any(|&(lo, hi)| c >= lo && c <= hi);
                        // A class never matches the separator, matching
                        // the behaviour of `?` and `*`.
                        hit != *negate && c != b'/' && next[j + 1]
                    }
                }
            };
            // `toks[i+2..]` matching here means the `**/` matched nothing
            // at all. That row is no longer live, so consult it via a
            // direct sub-match; patterns carry few `**/`.
            if skip_two && !cur[j] && glob_toks(&toks[i + 2..], &text[j..]) {
                cur[j] = true;
            }
        }
        std::mem::swap(&mut cur, &mut next);
    }
    next[0]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn glob_star_stays_within_a_segment() {
        assert!(glob_match("*.bin", "a.bin"));
        assert!(glob_match("a/*.bin", "a/b.bin"));
        // A single star must not cross a separator.
        assert!(!glob_match("a/*.bin", "a/b/c.bin"));
        assert!(!glob_match("a/*", "a/b/c"));
    }

    #[test]
    fn glob_doublestar_crosses_segments() {
        assert!(glob_match("a/**/c.bin", "a/b/c.bin"));
        assert!(glob_match("a/**/c.bin", "a/b/x/y/c.bin"));
        // `**/` also matches zero directories.
        assert!(glob_match("a/**/c.bin", "a/c.bin"));
        assert!(glob_match("**/*.log", "deep/nested/x.log"));
        assert!(glob_match("src/**", "src/a/b/c.rs"));
    }

    #[test]
    fn bare_pattern_matches_basename_at_any_depth() {
        // The property that makes `--include '*.bin'` behave as expected.
        assert!(glob_match("*.bin", "deep/nested/file.bin"));
        assert!(!glob_match("*.bin", "deep/nested/file.txt"));
        // Once a pattern has a separator it is anchored to the full path.
        assert!(!glob_match("nested/*.bin", "deep/nested/file.bin"));
    }

    #[test]
    fn glob_question_and_classes() {
        assert!(glob_match("a?c", "abc"));
        assert!(!glob_match("a?c", "a/c"), "? must not match a separator");
        assert!(glob_match("[abc]x", "bx"));
        assert!(glob_match("[a-z]x", "qx"));
        assert!(!glob_match("[!abc]x", "bx"));
        assert!(glob_match("[!abc]x", "zx"));
        // Unterminated class must not match rather than panic.
        assert!(!glob_match("[abc", "a"));
    }

    #[test]
    fn glob_backtracking_terminates() {
        // Pathological pattern: must return, not hang or overflow.
        assert!(!glob_match(
            "*a*a*a*a*a*a*a*b",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        ));
        assert!(glob_match("*a*b", "xxaxxb"));
    }

    #[test]
    fn filters_exclude_beats_include() {
        let f = Filters::new(Some("*.bin,*.txt"), Some("secret*"));
        assert!(f.accepts("a.bin"));
        assert!(f.accepts("d/b.txt"));
        assert!(!f.accepts("secret.bin"), "exclude must win");
        assert!(!f.accepts("a.log"), "not in include list");

        // Empty include matches everything not excluded.
        let f = Filters::new(None, Some("*.tmp"));
        assert!(f.accepts("anything.rs"));
        assert!(!f.accepts("x.tmp"));
    }

    #[test]
    fn join_dest_rejects_escapes() {
        assert_eq!(join_dest("/dst", "a/b.bin").as_deref(), Some("/dst/a/b.bin"));
        assert_eq!(join_dest("/dst/", "a.bin").as_deref(), Some("/dst/a.bin"));
        // Anything that could climb out of the destination is refused.
        assert_eq!(join_dest("/dst", "../etc/passwd"), None);
        assert_eq!(join_dest("/dst", "a/../../b"), None);
        assert_eq!(join_dest("/dst", "/abs"), None);
        assert_eq!(join_dest("/dst", ""), None);
    }

    #[test]
    fn walk_finds_files_and_skips_symlinked_dirs() {
        let tmp = std::env::temp_dir().join(format!("favonius-walk-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(tmp.join("sub/deep")).unwrap();
        std::fs::write(tmp.join("a.bin"), b"a").unwrap();
        std::fs::write(tmp.join("sub/b.bin"), b"bb").unwrap();
        std::fs::write(tmp.join("sub/deep/c.txt"), b"ccc").unwrap();

        let all = walk(&tmp, &Filters::default()).unwrap();
        let rels: Vec<_> = all.iter().map(|e| e.rel.as_str()).collect();
        assert_eq!(rels, vec!["a.bin", "sub/b.bin", "sub/deep/c.txt"]);
        assert_eq!(all[2].size, 3);

        // A symlink pointing back at the root must not cause an infinite
        // walk; the entry count is unchanged.
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(&tmp, tmp.join("sub/loop")).unwrap();
            let again = walk(&tmp, &Filters::default()).unwrap();
            assert_eq!(again.len(), 3, "symlinked directory was followed");
        }

        let filtered = walk(&tmp, &Filters::new(Some("*.bin"), None)).unwrap();
        let rels: Vec<_> = filtered.iter().map(|e| e.rel.as_str()).collect();
        assert_eq!(rels, vec!["a.bin", "sub/b.bin"]);

        std::fs::remove_dir_all(&tmp).ok();
    }
}
