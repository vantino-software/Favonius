# Security

## Reporting a vulnerability

Report privately to **security@vantino.ch**. Please do not open a public
issue for a vulnerability.

Include what you need to reproduce it: version or commit, the command lines
for both ends, and what you observed. We will acknowledge within five
working days.

## Status of this code

**Favonius has not been security audited.** The cryptography is assembled
from standard primitives — X25519, AES-256-GCM, HKDF, BLAKE3, Ed25519 —
through established Rust crates, but the *protocol composition* is our own:
the handshake, the key schedule, header protection, session tickets and the
0-RTT path have had no external review and no formal analysis.

The packet parsers have not been fuzzed.

Treat this as software to evaluate, not as a hardened component to put in
front of untrusted networks without your own assessment.

## What the defaults do and do not give you

| | Default | Notes |
|---|---|---|
| Encryption | **off** | `--encrypt` turns on AES-256-GCM with X25519 |
| Server authentication | **off** | Without `--server-key`, an encrypted handshake is anonymous DH — an active on-path attacker can man-in-the-middle it. Pin the daemon's key with `--server-key` (see `favonius-daemon keygen`). |
| Destination confinement | **required** | The daemon refuses to start without `--dest-root`. |
| HTTP control API | loopback | Binds `127.0.0.1:7800`; refuses a non-loopback address without `FAVONIUS_API_TOKEN`. |

**`--encrypt` alone gives you confidentiality against a passive observer,
not authentication.** For a meaningful guarantee against an active
attacker, pin the server key.

## Destination confinement

`--dest-root` confines every incoming transfer under one directory, and
destinations escaping it are rejected.

Earlier versions treated it as optional and merely warned when it was
absent. That was wrong: without it the daemon wrote to any absolute path a
sender asked for, with no authentication, so a peer able to reach the
control port could write `/etc/cron.d/…` and obtain remote code execution.
The daemon now exits rather than start that way. If you genuinely want a
daemon that accepts arbitrary sender-chosen paths, you must ask for it by
name with `--allow-any-dest`; do not expose such a daemon to a network you
do not control.

## Threat model, briefly

Favonius aims to protect a transfer's **confidentiality and integrity in
flight** when `--encrypt` is used, and to prevent a **remote sender from
choosing where files land** when `--dest-root` is set.

It does not attempt to: hide that a transfer is happening or how large it
is; resist traffic analysis (`--header-protect` masks connection and packet
numbers, it does not pad); protect against a compromised endpoint; or
authenticate *senders* to the daemon — any peer that can reach the control
port can transfer, so put the daemon behind network controls if that
matters.

0-RTT resumption trades a round trip for replay exposure. Tickets are
single-use via a replay cache with a fresh per-session server nonce, but
early data has weaker guarantees than a completed handshake by
construction. If that trade is not one you want, do not present a ticket.
