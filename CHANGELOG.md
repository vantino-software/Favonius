# Changelog

Notable changes to Favonius. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[Semantic Versioning](https://semver.org/).

While the major version is 0, the wire protocol and the CLI may both change
in a minor release. See [Stability](#stability).

## [0.1.0] — 2026-08-15

First public release.

**The project was called Hespera until this release.** It was renamed
before publication because IBM holds an incontestable US registration for
**ASPERA** covering exactly this software — "high speed data and file
transfer software; server software...; client software...; software
development kit" — and *Hespera* was close enough in sound and identical
in goods to be a real problem. Nothing was published under the old name;
there is no compatibility shim to write and no user to migrate. The
protocol name is unaffected: it was and remains **AHP**.

### Added

- **Per-stream data ports.** With `--data-port-range`, a transfer reserves
  a contiguous run of daemon ports and sends stream *i* to
  `base + min(i, count-1)`, so one transfer's streams drain N kernel
  receive queues instead of one. Streams past the end of the run share the
  last port. Negotiated in the HELLO_ACK capability bitfield — no new
  packet type, no flag day, and a daemon without the range behaves exactly
  as before. Measured on a 38 ms cloud path, both arms at `--streams 4`,
  ABBA-counterbalanced: **145.6 against 131.1 MiB/s, +11%**, and
  retransmits down from 1819 to 21 — it is primarily a loss fix.
  **Open the whole range in your firewall.**
- **UDP GRO on the receive path.** The kernel coalesces consecutive
  datagrams before the daemon sees them, the receive-side counterpart of
  the `UDP_SEGMENT` batching the sender has always used. +43% on loopback
  plaintext, +13.6% on a WAN pair at ~20% less CPU per byte.
  `FAVONIUS_UDP_GRO=0` restores the old path; kernels before 5.0 fall back
  automatically. These two figures have no published per-run file; they
  were measured during development and the CSVs were not kept.
- **Real parallel transfers.** `--max-concurrent` now means what it says
  when `--data-port-range` is set: the data socket is the admission token,
  and a sender that cannot be given one is declined and retries rather than
  being quietly placed on a shared socket.
- The sender reports observed loss and names a faster profile when a
  transfer retransmits more than 1% of its packets.

- **AHP transport** — UDP file transfer with split control (7801) and data
  (7802) planes; threaded receiver; GSO / `sendmmsg` / io_uring / AF_XDP
  send paths.
- **Six congestion-control profiles** (`--congestion`): `classic`,
  `model`, `cycle`, `fair`, `wifi`, `udt`, selected by the `auto` default
  from the probed link type — `classic` on WAN, loopback and unclassified
  paths, `model` on LAN. An explicit name overrides it; an unknown name is
  rejected rather than silently falling back.
- **Encryption** (`--encrypt`) — AES-256-GCM with X25519, key rotation at
  2^30 packets, header protection (`--header-protect`), 0-RTT session
  tickets with a replay cache, optional Ed25519 server authentication with
  client-side pinning (`--server-key`).
- **Compression** (`--compression`) — per-chunk zstd with a per-packet
  flag; incompressible chunks are sent raw.
- **Resume** (`--resume`) — BLAKE3 Merkle tree diff, cached per destination.
- **Directory transfer and stateless sync** — recursive trees, glob
  filters, `--dry-run`, and one-way / mirror / append-only modes.
- **IPv4 and IPv6**, with hostname resolution.
- **Observability** — a progress line every two seconds with rate and ETA;
  Prometheus metrics at `GET /metrics`.
- **`--adaptive`** — per-link parameter history, used only once a stored
  record has beaten the link-type defaults on that link. The explorer does
  not draw `fair`, which loses every cell measured
  except the unimpaired baseline, by 3.8x (metro) to 19.6x
  (congested-hi).
- **Benchmark harness** — shaped container pair, reproducible from this
  repository (`benchmarks/scripts/`).

### Security

- `favonius-daemon` **requires `--dest-root`** and refuses to start without
  it. For most of its private history it warned and continued, and in that
  state any peer able to reach the control port could write to any absolute
  path the daemon's user could write — including `/etc/cron.d/`, which is remote code
  execution. The unconfined behaviour now has to be requested by name with
  `--allow-any-dest`.
- The protocol version byte is validated. A peer speaking an unknown
  version is rejected as a version mismatch instead of being decoded as if
  it were version 1.
- The HTTP control API refuses to bind a non-loopback address without
  `FAVONIUS_API_TOKEN`.
- **DATA payloads longer than the negotiated chunk size are rejected**
  before they are copied. The 64 KiB receive buffer GRO needs removed a
  bound the kernel had been enforcing implicitly, and without an explicit
  check an oversized packet could overwrite neighbouring chunks of the
  destination file — reaching a fixed-size buffer ahead of the AEAD tag
  check on an encrypted transfer.

### Fixed

- **`model` could deadlock on a lossy path and never recover.** The
  model-based controller is BBR-style: ProbeRtt clamps the congestion
  window to 16 x MTU for 200 ms in every 10 s. The exit from that phase was
  evaluated only inside `on_ack_received`, so if everything in flight was
  lost while the window was clamped — one radio burst is enough — no ack
  arrived, the exit was never re-evaluated, and the window stayed clamped
  for the rest of the transfer. The sender crawled on timeout retransmits
  at **0.02 MiB/s** until the receiver abandoned it at 300 s. A hang, not a
  slowdown: waiting does not recover it.

  Reachable by the **default** configuration, because `--congestion auto`
  resolves to `model` on a LAN or wifi link. Measured on an 802.11ac path
  to a Raspberry Pi: one transfer in six. ProbeRtt is a timer, so its
  expiry is now checked from every callback that carries a clock —
  `on_ack_received`, `on_packet_lost` and `on_packet_sent`, the last being
  the only one still firing when a path has stopped delivering entirely.
  Ten consecutive runs after the fix: no stalls, mean 41.7 MiB/s.

  Found only because the real-hardware table was re-measured on a physical
  radio. Every emulated rig and every cloud pair in this repository ran
  `model` without incident.

- **A declined transfer was told nothing, and waited out a 2 s timeout.**
  The daemon takes a data socket as its admission token, and when the pool
  is empty it declined by `continue`-ing the accept loop — sending no reply
  at all. The protocol has a signal for exactly this (a HELLO_ACK carrying
  no data port, which the sender has always understood), and the daemon
  never sent it; the code reasoned that "the sender retries every 2 s",
  which it does only by waiting out its own HELLO_ACK timeout.

  Meanwhile the ports it was waiting for came back in milliseconds: the
  daemon must advertise a port-run length before it knows `num_streams`, so
  it reserves optimistically and returns the unused tail as soon as the
  MANIFEST arrives. The sender was asleep through all of it.

  Both decline paths now answer. Measured on loopback, four concurrent
  transfers against a ten-port pool: the worst sender went from **2.39 s to
  0.82 s**, and the 2 s step disappeared. The busy retry also backs off from
  25 ms rather than polling flat at 1 s, so a sender that is told to wait
  comes back promptly instead of a second later.

- **The path probe cost ten round trips instead of one.** It sent one
  probe, blocked on that probe's reply, then sent the next — so the phase
  before the first byte of every transfer cost `PROBE_COUNT` RTTs: about
  425 ms on a 38 ms path, measured at 440 ms against a delayed echo server.
  The probes are now sent and collected concurrently over the same socket,
  which costs the spacing plus one round trip — 87 ms measured on the same
  harness, a saving of ~350 ms per transfer that scales with RTT and is
  zero on loopback.

  Sending all the probes first and reading the replies afterwards is the
  obvious version of this fix and it is wrong: the echoes then queue in the
  socket buffer while the remaining probes go out, and every RTT sample is
  inflated by its own wait. That version measured `avg_rtt=28.12ms` on
  loopback where the true figure is 0.2 ms, which would have fed a bad
  initial window and a bad link classification into every transfer. The
  shipped fix keeps each sample timestamped on arrival.

- **The probe overstated RTT by 5.8x on a link that batches its
  deliveries.** Sending the probes concurrently is only correct if each
  echo is read when it lands. On an 802.11ac path the client coalesced
  downlink delivery: the receiver echoed every probe within 0.25 ms and
  they left 6 ms apart — confirmed by a capture at the receiver — while the
  sender read eight of them at one instant ~50 ms later. Differencing each
  against its own staggered send time produces a straight-line staircase
  descending by exactly one probe interval, which read as `avg_rtt=22.9ms,
  jitter=15.4ms` where ping alongside measured 3.9 ms and 2.1 ms. That
  inflates the estimated bandwidth-delay product and the initial window.

  Batching is not ours to prevent, and interleaving the receive with the
  sends does not avoid it — that was tried. Echoes sharing an arrival
  instant are now collapsed to the one that waited least, which is the only
  one carrying path delay. Measured after the fix: 3.3-5.2 ms against
  ping's 3.1-3.8 ms.

- **A probe over an idle link could report 100% loss on a path with none.**
  A radio that has been idle drops most of a burst while it renegotiates.
  Captured after a 3 s pause: of ten probes **one** arrived, its echo was
  lost returning, and the sender saw nothing — while the HELLO sent 265 ms
  later and everything after it went through untouched. The probe phase had
  landed entirely inside the wake-up window, and the resulting "unknown
  link, 100% loss" selects a 64 KB window for a transfer about to run at
  full rate. With a 3 s gap between transfers this happened in six runs out
  of eight; it is now zero in ten. The first burst is what warms the link,
  so the retry costs an extra burst only in the case that was already
  broken.

- **The link classifier trusted a jitter figure computed from one sample.**
  Collapsing a batched delivery routinely leaves two or three samples, and
  a single sample has zero variance by definition — which selects
  `LanEthernet` over `LanWifi`, or on an unluckily low sample `Loopback`
  over both. Observed: a lone 0.46 ms sample classifying an 802.11ac path
  as loopback. Below three samples the link is now classified on base RTT
  alone, taking the jitter-tolerant reading; assuming wifi on an ethernet
  link costs little, while the reverse tells the controller to read real
  jitter as congestion.

### Fixed during development

Nothing was released before this, so these are not regressions. They are
recorded because two of the three are the kind of bug worth knowing was
possible in a tool that writes files to a path a peer chose.

- `favonius sync` addressed the HTTP control API through `--daemon`
  (default loopback) while sending data to the host in the destination
  string. With a remote destination it therefore planned against the local
  filesystem, and in `--mode mirror --confirm-delete` deleted local files.
  The API host now follows the destination unless `--daemon` is given
  explicitly.
- `--bandwidth-limit` was accepted and silently ignored. It now errors; a
  cap that does not apply is worse than an absent flag.
- Prometheus metrics were never updated by the UDP data path, so
  `/metrics` reported zeros through any amount of traffic.

### Known limitations

- **A receiver whose disk is slower than the link is paced, not
  flow-controlled.** The receive path queues writeback early and waits when
  the backlog exceeds a limit, which fixed the worst of it: a Raspberry Pi
  writing to an SD card at 17.3 MiB/s over a 46 MiB/s link went from 21% of
  transfers failing outright to completing 6 of 6. What is still missing is
  true flow control — there is no WINDOW_UPDATE, so a receiver cannot tell a
  sender to slow down, only absorb and stall.
- **`--max-concurrent` needs `--data-port-range` to mean anything.**
  Without a range the daemon has one data socket and serves one transfer at
  a time; a second sender is queued and its stall detector may abort it.
- **Daemon-side rejections are not reported to the sender.** The protocol
  specifies ERROR packets and `ahp-proto` defines the codes, but the daemon
  does not send them, so a rejected transfer looks like a network timeout
  (`deadline has elapsed`).
- **The four shaped WAN scenarios are emulated** on a single containerised
  host. The cloud-pair and physical-hardware tables in the README are not,
  but the emulated numbers have never been reproduced on a physical NIC.
- **Most published benchmark tables predate the two startup fixes below**
  and have not been re-run; treat them as a floor. The one arm that *has*
  been re-measured is four concurrent transfers on the 38 ms cloud pair,
  ABBA-counterbalanced against the pre-fix binary in a single session:
  **282.7 -> 369.9 MiB/s, +30.8%**, winning all four paired rounds
  (`benchmarks/results/wan_startup_ab_2026-08-14.csv`). The pre-fix arm
  reproduces the previously published 277.4 to within 2%. Fitting the two published campaigns that differ only in
  transfer size (4 x 256 MiB in 4.86 s, 4 x 512 MiB in 7.41 s) gives about
  402 MiB/s steady-state behind a ~2.3 s fixed cost. The same fit on
  loopback gives ~30 ms, so nearly all of it is round-trip-dependent —
  around 60 RTTs, far more than a slow start to an 18 MB BDP should need.
  Steady-state is above four TCP flows on that path; the measured rate on a
  few hundred MiB is not. Not diagnosed further.
- **No security audit and no parser fuzzing.** See `SECURITY.md`.

## Stability

- **Wire protocol.** `PROTOCOL_VERSION` is 1. A 0.x release may change it;
  when it does, the change will be listed here and mismatched peers will be
  rejected with a version error rather than failing obscurely. There is no
  compatibility guarantee between 0.x releases yet.
- **CLI.** Flags may change in a 0.x minor release. Renamed values keep
  their old spelling as an alias where it costs nothing — `--congestion rl`
  still selects `cycle`.
- **Rust.** MSRV is 1.87, verified in CI. Raising it is a minor-version
  change.

[0.1.0]: https://github.com/vantino-software/Favonius/releases/tag/v0.1.0
