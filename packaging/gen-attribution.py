#!/usr/bin/env python3
# Favonius — high-performance file transfer over UDP
# Copyright (c) 2025-2026 Vantino SàRL
# SPDX-License-Identifier: Apache-2.0
"""Collect the licence notices that must ship with a release binary.

MIT, BSD, ISC and Unicode-3.0 all condition redistribution on reproducing
the copyright notice and licence text. A tarball containing only Favonius'
own LICENSE and NOTICE does not satisfy them, and THIRD-PARTY.md does not
either -- it lists licence *names*, not the texts the licences require.

This walks the dependency graph of the two shipped binaries for one target
and emits a single file with the full text of every dependency's licence.

Deliberately scoped narrower than THIRD-PARTY.md, which documents the whole
build graph. Only what is linked into a shipped binary carries an
attribution obligation, so dev-dependencies and build-only crates are
excluded here: `--filter-platform` drops crates for other targets and the
walk follows normal dependency edges only.

Usage:
    gen-attribution.py <target-triple> <output-path>
"""

import json
import subprocess
import sys
from pathlib import Path

# The binaries actually packaged by release.yml. Keep in sync with its
# `cargo build -p ...` line.
SHIPPED = ["ahp-cli", "ahp-daemon"]

LICENCE_GLOBS = ["LICENSE*", "LICENCE*", "COPYING*", "NOTICE*", "UNLICENSE*"]

# Crates known to be linked into the binaries whose licences carry a notice
# condition. Used as a positive control: if the walk stops finding these,
# it has broken and its silence must not be read as "nothing to attribute".
CONTROL = ["ring", "untrusted", "curve25519-dalek", "subtle"]


def die(msg):
    print(f"gen-attribution: {msg}", file=sys.stderr)
    raise SystemExit(1)


def main():
    if len(sys.argv) != 3:
        die(f"usage: {sys.argv[0]} <target-triple> <output-path>")
    target, out_path = sys.argv[1], Path(sys.argv[2])

    meta = json.loads(subprocess.run(
        ["cargo", "metadata", "--format-version", "1", "--locked",
         "--filter-platform", target],
        capture_output=True, text=True, check=True).stdout)

    packages = {p["id"]: p for p in meta["packages"]}
    nodes = {n["id"]: n for n in meta["resolve"]["nodes"]}
    by_name = {p["name"]: p["id"] for p in meta["packages"]}

    # Walk normal (non-dev, non-build) edges from each shipped binary.
    seen, stack = set(), []
    for name in SHIPPED:
        if name not in by_name:
            die(f"shipped crate {name!r} is not in the metadata -- "
                f"has release.yml changed without updating SHIPPED?")
        stack.append(by_name[name])

    while stack:
        pid = stack.pop()
        if pid in seen:
            continue
        seen.add(pid)
        for dep in nodes[pid]["deps"]:
            kinds = {k["kind"] for k in dep["dep_kinds"]}
            # kind None is a normal dependency; "dev"/"build" are not linked
            # into the shipped artefact.
            if None in kinds:
                stack.append(dep["pkg"])

    workspace = set(meta["workspace_members"])
    third_party = sorted(
        (packages[i] for i in seen if i not in workspace),
        key=lambda p: p["name"].lower())

    if not third_party:
        die("resolved zero third-party dependencies -- the walk is broken")

    missing_control = [c for c in CONTROL
                       if c not in {p["name"] for p in third_party}]
    if missing_control:
        die(f"control crates absent from the walk: {missing_control}. "
            f"Either the dependency graph changed or this script is broken; "
            f"do not ship until it is known which.")

    chunks, no_text = [], []
    for pkg in third_party:
        root = Path(pkg["manifest_path"]).parent
        files = sorted({f for g in LICENCE_GLOBS for f in root.glob(g)
                        if f.is_file()})
        header = (f"## {pkg['name']} {pkg['version']}\n\n"
                  f"Declared licence: `{pkg.get('license') or 'see text below'}`  \n"
                  f"Repository: {pkg.get('repository') or 'not declared'}\n")
        if not files:
            no_text.append(f"{pkg['name']} {pkg['version']}")
            chunks.append(header + "\nNo licence file is present in this "
                          "crate's published source; the declared licence "
                          "above governs.\n")
            continue
        body = "".join(
            f"\n<details><summary>{f.name}</summary>\n\n```\n"
            f"{f.read_text(encoding='utf-8', errors='replace').strip()}\n"
            f"```\n\n</details>\n"
            for f in files)
        chunks.append(header + body)

    out = [
        "# Third-party licence notices",
        "",
        f"Every crate linked into the `favonius` and `favonius-daemon` "
        f"binaries for `{target}`, with the full text of the licence its "
        f"author ships.",
        "",
        "Several of these licences (MIT, the BSD family, ISC, Unicode-3.0) "
        "require that this notice accompany a binary distribution. That is "
        "what this file is for. It is generated by "
        "`packaging/gen-attribution.py`; do not edit it by hand.",
        "",
        f"Favonius itself is Apache-2.0 -- see `LICENSE` and `NOTICE`. "
        f"{len(third_party)} third-party crates are listed below.",
        "",
    ]
    if no_text:
        out += [f"Crates shipping no licence file of their own "
                f"({len(no_text)}): {', '.join(no_text)}.", ""]
    out += ["---", ""] + chunks

    out_path.write_text("\n".join(out), encoding="utf-8")
    print(f"gen-attribution: {len(third_party)} crates -> {out_path} "
          f"({out_path.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
