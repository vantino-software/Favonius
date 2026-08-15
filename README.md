# Favonius

High-performance file transfer over UDP with adaptive congestion control,
end-to-end encryption, compression, and resumable transfers.

**Which reader are you?** If you want to hack on congestion control or the
send path, [Contributing](#contributing) and `CONTRIBUTING.md` are the
place to start — the measurement discipline is written down and
disagreement with our own numbers is welcome. If you are evaluating this to
move files in production, read [SECURITY.md](SECURITY.md) first and expect
0.x churn: the wire protocol may change in a minor release.

## Features

- **Fast on impaired paths** — 1.1x to 1.9x the throughput of the best
  other UDP tool measured, matched one controller to one — more against
  kernel TCP on long or lossy paths; less on short clean ones. See
  UDP transfer tools on lossy, high-latency links; see
  [Performance](#performance) for the numbers and their caveats
- **Encrypted** — AES-256-GCM with X25519 key exchange, key rotation,
  header protection, 0-RTT resume (`--encrypt`); optional Ed25519 server
  authentication (`--server-key`)
- **Compressed** — per-chunk zstd with a per-packet flag
  (`--compression balanced`)
- **Resumable** — a Merkle tree diff skips unchanged chunks (`--resume`)
- **Directories and sync** — recursive tree transfer with glob filters;
  stateless one-way, mirror and append-only sync
- **IPv4 everywhere, IPv6 on Linux** — with hostname resolution
- **Adaptive** — six congestion-control profiles (`--congestion`), chosen
  from the probed link type by default (`auto`)

## Quick Start

**Try it on one machine first.** Two terminals, no network required:

```bash
cargo build --release
mkdir -p /tmp/fav-in && head -c 64M /dev/urandom > /tmp/big.bin

# terminal 1 — the receiver
./target/release/favonius-daemon \
  --protocol-listen 127.0.0.1:7801 --data-listen 127.0.0.1:7802 \
  --dest-root /tmp/fav-in

# terminal 2 — the sender
./target/release/favonius send /tmp/big.bin "127.0.0.1:7801:/tmp/fav-in/big.bin"
cmp /tmp/big.bin /tmp/fav-in/big.bin && echo "transferred and identical"
```

`--dest-root` is mandatory and the daemon refuses to start without it: it
is what stops a peer choosing an arbitrary absolute path to write to.

Across a network:

```bash
# Build
cargo build --release

# Start the daemon on the receiver
favonius-daemon --protocol-listen 0.0.0.0:7801 --data-listen 0.0.0.0:7802 \
               --dest-root /srv/incoming

# Send a file
favonius send myfile.tar.gz "receiver.example.com:7801:/srv/incoming/myfile.tar.gz"

# Encrypted and compressed
favonius send myfile.tar.gz "receiver.example.com:7801:/srv/incoming/f.tgz" \
  --encrypt --compression balanced

# Resume an interrupted transfer
favonius send myfile.tar.gz "receiver.example.com:7801:/srv/incoming/f.tgz" --resume

# A whole directory tree, filtered, with a dry run first
favonius send ./project "receiver.example.com:7801:/srv/incoming/project" \
  --include '*.rs,*.toml' --exclude 'target/**' --dry-run

# Sync a directory
favonius sync ./project "receiver.example.com:7801:/srv/incoming/project"
```

Destinations are `host:port:/path`. The host may be a name or a literal
IPv4 address; names are resolved and IPv4 is preferred where both are
offered.

IPv6 literals use bracket form (`[2001:db8::1]:7801:/path`) and are
**accepted on Linux only**. The Windows and macOS send backends do not
implement IPv6 yet and refuse it with an explanatory error rather than
failing later. The batched receive path also reports a V6 peer as
`0.0.0.0:0`, so IPv6 should be treated as Linux-only and lightly exercised
until there is an end-to-end test for it.

`fvn` is a shorter alias for the `favonius` client — a symlink to the same
binary, shipped in the release tarballs. Every example above works with
either name. See [packaging/](packaging/) to create it from a source build.

## Directory transfer and sync

`send` accepts a directory and transfers the tree recursively, one file per
transfer, preserving relative paths. `--include` / `--exclude` take
comma-separated globs supporting `*`, `**`, `?` and `[a-z]` classes; a
pattern without a `/` matches the basename at any depth, so `--include
'*.bin'` does what you expect on a nested tree. `--dry-run` lists what
would move and exits.

`sync` reconciles a local directory with a remote one. It is **stateless**:
no database, no catalog, no change history. The plan is recomputed on every
run by diffing the local tree against a listing of the destination, which
means a sync is always self-correcting and never depends on a previous run
having completed.

| Mode | Creates | Overwrites | Deletes |
|------|---------|-----------|---------|
| `one-way` (default) | yes | yes | no |
| `mirror` | yes | yes | yes (needs `--confirm-delete`) |
| `append-only` | yes | no | no |

**Change detection.** By default two files are considered identical when
their sizes match — the same semantics as `rsync --size-only`, and with the
same caveat: an edit that preserves a file's length is invisible. Pass
`--checksum` to compare BLAKE3 content hashes instead, which is exact at
the cost of reading every file on both sides. Modification time is
deliberately not used, because Favonius does not propagate mtime to the
destination and comparing it would mark every file as changed on every run.

**Requirements.** `sync` needs the daemon to be started with `--dest-root`,
which both confines and enables the filesystem endpoints it uses to list
and prune the destination. Without it the daemon refuses to expose them.

**Out of scope by design.** Bidirectional sync, conflict resolution,
snapshots and version-preserving modes all require remembering what
happened on a previous run. Favonius keeps no such state, so those modes are
rejected with an explanatory error rather than silently approximated.

## Monitoring a transfer

The sender prints a progress line to stderr every two seconds:

```
  [ 60.4%]  374.4 MiB/s  ETA     1s  | rtt min=0.1ms avg=1.8ms jitter=1.61ms | cwnd=1778KB | retx=0 loss_events=0
```

The daemon exports Prometheus metrics at `GET /metrics` on its HTTP port —
`favonius_bytes_transferred_total`, `favonius_packets_sent_total`,
`favonius_active_transfers`, and RTT histograms — updated by the UDP data
path itself.

## Architecture

```
Sender (favonius CLI)                    Receiver (favonius-daemon)
┌──────────────────────┐          ┌──────────────────────────┐
│  File → Chunks       │          │  Control port (7801)     │
│  ↓                   │  HELLO   │  ├─ HELLO/HELLO_ACK      │
│  Compress (optional) │ ───────► │  │  (DH or 0-RTT ticket) │
│  ↓                   │          │  ├─ MANIFEST exchange    │
│  Encrypt (optional)  │          │  ├─ KEY_UPDATE (rotate)  │
│  ↓                   │          │  └─ FINISH + ticket      │
│  Header protect (opt)│  DATA    │                          │
│  ↓                   │ ───────► │  Data port (7802)        │
│  CC + Pacing         │          │  ├─ Threaded receiver    │
│  ↓                   │          │  ├─ Unprotect header     │
│  GSO/sendmmsg batch  │  ACK     │  ├─ Decrypt → Decompress │
│                      │ ◄─────── │  └─ mmap write to disk   │
└──────────────────────┘          └──────────────────────────┘
```

## Encryption

End-to-end AES-256-GCM with ephemeral X25519 key exchange:

```bash
# Encrypted transfer
favonius send secret.tar.gz "host:7801:/path" --encrypt

# Encrypted + header protection (masks connection_id and packet_number)
favonius send secret.tar.gz "host:7801:/path" --encrypt --header-protect
```

- Key exchange embedded in HELLO/HELLO_ACK handshake
- Per-packet nonces derived from sequence numbers
- Zero-allocation in-place encrypt/decrypt on the hot path
- 0-13% throughput overhead (AES-NI accelerated)
- **Key rotation**: automatic at 2^30 packets via KEY_UPDATE (the per-key nonce space is 2^64 — a 64-bit sequence number XORed into the IV — so 2^30 is a conservative margin)
- **Header protection** (`--header-protect`): AES-128-ECB mask over connection_id + packet_number fields, preventing on-path traffic correlation (QUIC-inspired, RFC 9001 &sect;5.4)
- **0-RTT session resumption**: daemon issues encrypted session ticket after transfer; on reconnect, the client presents the ticket to skip the DH handshake entirely
- **Server authentication**: the daemon can sign each full handshake with an Ed25519 identity key (`favonius-daemon --identity`, generate via `favonius-daemon keygen`); the sender pins the public key with `--server-key` (64 hex chars or a file) and aborts on mismatch. Without a pin the encrypted handshake is anonymous (unauthenticated DH).

## Compression

Per-chunk zstd with adaptive per-packet flag:

```bash
favonius send logs.tar "host:7801:/path" --compression balanced
```

| Profile | zstd Level | Best for |
|---------|-----------|----------|
| `fast` | 1 | Binary data, high throughput |
| `balanced` | 3 | Text, general purpose |
| `streaming` | 6 | Logs, repetitive data |
| `none` | — | Already compressed (default) |

Incompressible chunks are sent uncompressed automatically (per-packet flag).
Compression and encryption can be combined: compress → encrypt → send.

## Resumable Transfers

Resume interrupted transfers or sync modified files:

```bash
favonius send largefile.bin "host:7801:/path" --resume
```

**The timings in this section have no published per-run file.** They were
measured during development on the loopback rig and the CSVs were not
kept; the chunk counts are structural and follow from the 1 MiB chunk
size. Treat the seconds as indicative, not as a benchmark result.

### How it works

1. Sender computes BLAKE3 Merkle tree of the source file
2. Daemon checks for cached Merkle tree at destination:
   - **Roots match** → instant skip (0 packets, <1s)
   - **Cached tree exists, roots differ** → exchange strategic-level hashes, identify differing subtrees
   - **No cache** → per-chunk hash comparison (first time), cache built for future
3. Only differing chunks are transferred
4. Post-transfer BLAKE3 whole-file verification

### Resume performance

| Scenario | Chunks sent | Time (256MB) |
|----------|------------|-------------|
| Full transfer | 198842 (100%) | 3.6s |
| Resume, identical file | 0 (0%) | 0.8s |
| Resume, 50% partial | 99421 (50%) | 1.1s |
| Resume, 1 chunk modified | 1 (0.0005%) | 0.1s |

## Daemon Configuration

```bash
favonius-daemon \
  --protocol-listen 0.0.0.0:7801 \  # Control port (HELLO, MANIFEST, FINISH)
  --data-listen 0.0.0.0:7802 \      # Data port (DATA, ACK)
  --max-concurrent 4 \               # Concurrent transfers (see the note below)
  --data-port-range 7803-7822 \      # Enables parallel transfers AND per-stream ports
  --max-file-size-mb 0 \             # Max file size (MB); 0 = unlimited
  --dest-root /srv/favonius \         # Confine transfer destinations under this directory
  --identity /etc/favonius/identity.key \  # Ed25519 identity key (see `favonius-daemon keygen`)
  --log-level info
```

`--dest-root` is **required**. Without it the daemon would write to any
absolute path a sender asks for, with no authentication — a peer that can
reach the control port could write `/etc/cron.d/…` and obtain remote code
execution. Earlier versions warned and continued; the daemon now refuses to
start, and the unconfined behaviour must be requested by name with
`--allow-any-dest`. With a root set, destinations escaping it are rejected
(verified: `--dest-root /srv/confined` accepts `/srv/confined/ok.bin` and
rejects `/srv/confined/../../root/ESCAPED.bin`).

**`--data-port-range` is what enables both parallel transfers and
per-stream data ports**, and without it `--max-concurrent` is only a queue
depth. Two transfers sharing one data socket would steal each other's
packets, so the daemon gives each transfer a socket of its own — and where
the pool allows, a *contiguous run* of them, so one transfer's streams land
on separate kernel receive queues instead of one.

Sizing it: a transfer may hold at most half the pool (a fairness cap), so
four ports is the minimum that splits at all, and roughly
`(concurrent transfers) x (streams per transfer)` is what you want. The
daemon logs the run length it can offer at startup and warns when the
range is too small to offer one. A sender arriving when every socket is
taken is declined and retries — it is never quietly put on a shared
socket.

**Open the whole range in your firewall**, or streams beyond the first
port are silently dropped and the transfer stalls. See Firewall Rules.

Measured contribution of the split, 38 ms cloud path, both arms at
`--streams 4` with `FAVONIUS_PER_STREAM_PORTS` flipped, ABBA-counterbalanced,
n=12 per arm: **145.6 MiB/s with the port run against 131.1 without —
+11%** ([plaintext](benchmarks/results/ab_per_stream_ports_plaintext_2026-08-12.csv);
the encrypted arm, n=8, gives 142.5 against 116.8, +22%).

**The throughput figure is the weaker half of the result.** Retransmits
over the same runs fall from a mean of **1819 to 21** — the split is
primarily a loss fix, and the bandwidth follows from not retransmitting.
How much bandwidth follows depends on how deep the receiver's single queue
already was; on a host with a large `net.core.rmem_max` there is less to
relieve.

The daemon's HTTP control API (default `127.0.0.1:7800`) requires
`Authorization: Bearer <token>` on every endpoint except `GET /health`
when `FAVONIUS_API_TOKEN` is set, and refuses to bind a non-loopback
address without a token.

The daemon uses memory-mapped I/O for file writes — no full-file heap
allocation, safe for multi-GB transfers on memory-constrained devices.

## Known limitation: a slow receiver disk

When the receiver's disk is slower than the link, the receive path queues
writeback early and waits for it once the not-yet-durable backlog passes a
bound, so the transfer runs at disk speed instead of failing. Before that
existed, dirty pages accumulated until the kernel's dirty throttle blocked
the receive loop outright, packets were dropped, and transfers died.

Measured on a Raspberry Pi 4 whose SD card writes at 17.3 MiB/s, over a link
good for 46 MiB/s — same hardware, same runs, only the destination changed:

| destination | throughput | retransmits | failed runs |
|---|---|---|---|
| SD card | 17.6 MiB/s | 9.6% | 5 of 24 (21%) |
| tmpfs | 34.7 MiB/s | 0.4% | 0 of 15 |

(Both rows predate the two send-path fixes that later took the tmpfs case
to 41.3 MiB/s. The comparison is unaffected — same runs, same hardware, only
the destination changed — but do not read 34.7 as the current tmpfs
number.)

This is not a historical curiosity. Re-measuring the hardware table on
2026-08-15 reproduced it by accident, because `hardware_bench.sh` defaults
`DEST_ROOT` to `/srv`, which on that Pi is the SD card: every arm returned
13-18 MiB/s at 10-24% retransmits, with 26,000-41,000 UDP receive-buffer
overflows per transfer, and it read convincingly as a 2.6x throughput
regression in the transport. It was the disk. If a Favonius number is
inexplicably low, check what the destination is mounted on before checking
anything else.

With writeback pacing, the same SD-card case completes **6 of 6** instead
of failing a fifth of the time. Throughput settles near the card's own
17 MiB/s, which is the honest ceiling.

Retransmits remain high in that state (~13%): the receiver still drops
packets while it waits rather than telling the sender to slow down. Proper
flow control — the protocol reserves a `WINDOW_UPDATE` packet type for it —
is not implemented yet.

## When a transfer fails with "deadline has elapsed"

The message means the sender got no response. It has two quite different
causes, and the daemon's log is what distinguishes them:

1. **The daemon never saw you** — a firewall dropped the UDP. See below.
2. **The daemon rejected the transfer and the sender was not told why.**
   The daemon logs the reason (`file size … exceeds limit`, a destination
   outside `--dest-root`, a transfer already in progress); the sender just
   times out. **Read the daemon's log before debugging the network.**

Cause 2 is a known gap rather than a subtlety: the protocol specifies ERROR
packets and `ahp-proto` defines the codes, but the daemon does not yet send
them, so a rejected transfer is indistinguishable from a blocked one at the
sender. Watch for it especially with `--max-file-size-mb`, which silently
rejects anything larger.

A **version mismatch is now reported as one**: the header decoder rejects
any protocol version it does not implement instead of decoding the packet
as if it were the current one.

## Firewall Rules

Favonius uses UDP for its data plane. If UFW (or another firewall) is
enabled, transfers will hang with "deadline has elapsed" unless UDP
responses can reach the sender.

```bash
# On the SENDER — allow inbound UDP on ephemeral ports (where responses arrive)
sudo ufw allow proto udp from any to any port 32768:65535

# On the RECEIVER — allow inbound Favonius traffic
sudo ufw allow 7800:7802/tcp    # HTTP API
sudo ufw allow 7801:7802/udp    # AHP control + data
sudo ufw allow 7803:7822/udp    # only if the daemon runs --data-port-range 7803-7822
```

**Note**: Source-IP rules (`ufw allow from <IP> ...`) do not work when
sender and receiver are on different subnets — the router NATs the
response packets, changing the source IP. Use the ephemeral port rule
on the sender side instead.

Without these rules, the daemon's HTTP API (port 7800/TCP) will respond
normally, but the UDP handshake (HELLO/HELLO_ACK on port 7801) and data
transfer (DATA/ACK on port 7802) will fail silently.

## ACK Modes

| Mode | Flag | Best for |
|------|------|----------|
| **bitmap** (default) | `--ack-mode bitmap` | General purpose, WiFi |
| **nack** | `--ack-mode nack` | Low-loss wired links |

NACK mode uses reorder-tolerant gap detection (32-packet threshold + 25ms
delay) to avoid false retransmits on WiFi.

## Congestion Control

Six profiles, selected with `--congestion`:

| profile | algorithm | use it when |
|---|---|---|
| `auto` | picks one of the below from the probed link type | **default** — `classic` on WAN, loopback and unclassified paths; `model` on LAN |
| `classic` | CUBIC-like, loss-based | what `auto` selects on a WAN path |
| `model` | BBR-like (Startup/Drain/ProbeBW/ProbeRtt) | high-bandwidth, low-loss paths |
| `cycle` | probe/drain/cruise gain cycle over a windowed-max delivery estimate | high random loss, no shared bottleneck |
| `fair` | Reno AIMD, deliberately conservative | shared links, where taking most of the bottleneck is wrong |
| `wifi` | rate probing tolerant of non-congestion loss | dedicated wireless LANs |
| `udt` | UDT4-style DAIMD | interoperability comparisons |

**The default is `auto`, which resolves to `classic` on any WAN path.**
That is deliberate, and it is not the fastest choice on every path. Which
profile is fastest depends on one thing — where the loss comes from — and
the split is clean. Measured in netem at 1 Gbit (MiB/s, n=5-8):

| path | loss source | `classic` | `cycle` | `model` |
|---|---|---|---|---|
| 25 ms, 0.5% | injected | 93.7 | 93.3 | **100.2** |
| 50 ms, 1% | injected | 80.3 | **87.5** | 84.7 |
| 150 ms, 2% | injected | 49.0 | **59.3** | 47.0 |
| 100 ms, 5% | injected | 55.1 | **68.9** | 63.3 |
| 25 ms, shallow queue | congestion | 100.8 | 96.3 | **101.9** |
| 50 ms, shallow queue | congestion | **95.5** | 85.0 | 86.2 |
| 150 ms, shallow queue | congestion | **70.8** | 59.3 | 54.9 |

The rate-based profiles win every path where loss is random, by 7-25%,
because they do not treat it as a congestion signal. Where the loss comes
from the queue they are themselves filling they lose the 50 ms and 150 ms
cells by 11-19% — but not all three: `model` takes the 25 ms cell by 1.1%,
which is inside the noise and is bolded in the table above. Note that
delay and queue depth covary in these three cells (0.80, 0.40 and 0.25 BDP
as RTT rises), so the sweep separates "congestion-induced loss" from
"random loss" cleanly and does *not* separate delay from queue depth.
`classic` is close to the mirror image.

**That table is Favonius against itself.** Against kernel TCP on the same
three congested cells — unshaped, queue at 1.0 BDP, 512 MiB, n=3, every
arm in one session
([source](benchmarks/results/netem_fair_v2-congfix_2026-08-15.csv)):

**One controller each** — this file has no multi-controller Favonius arm,
so this is the only matched comparison it supports:

| cell | Favonius `classic` | cubic | bbr |
|---|---|---|---|
| shallow queue, 25 ms | **292.9** | 120.0 | 97.3 |
| shallow queue, 50 ms | **248.6** | 60.6 | 49.0 |
| shallow queue, 150 ms | **123.1** | 22.8 | 15.8 |

Matched one-to-one, `classic` leads by **2.4x to 5.4x** against cubic and
3.0x to 7.8x against bbr, in all three cells, and the margin widens with
latency. That is the result.

For reference only, four TCP flows on the same cells reach 218.2 / 125.9 /
59.5 (cubic `-P4`) and 217.4 / 142.3 / 48.3 (bbr `-P4`). **Those are not a
comparison** — four controllers against one is not a matched arm, and this
file contains no four-controller Favonius arm to put beside them. They are
here so the numbers are not missing, not so a win can be claimed from
them, and that holds even though one Favonius controller happens to exceed
four TCP flows in all three cells.

`auto` resolves to `classic` on a WAN because congestion-induced loss is
what a shared link produces, and because a controller that ignores
congestion signals is not merely slower there, it is unfriendly to
everything else on the link.

**On a genuinely lossy path that costs about a fifth of the throughput.**
Measured on real hardware — a 38 ms cloud path with 1% injected loss,
n=3, one transfer:

| profile | MiB/s | cv |
|---|---|---|
| `model` | 106.5 | 29.3% |
| `cycle` | 106.2 | **1.2%** |
| `wifi` | 102.6 | 9.0% |
| `classic` (what `auto` picks) | 84.0 | 18.2% |
| `udt` | 5.3 | 1.1% |

If your path drops packets at random — satellite, a poor radio, a lossy
tunnel — `--congestion cycle` is worth measuring: same throughput as
`model` with a twentieth of the variance (cv 1.2% against 29.3%). The sender now says so itself when
a transfer retransmits more than 1% of its packets, because nothing else
told you.

`udt` collapsing to 5.3 is the same loss-based failure as kernel cubic,
which managed 4.5 MiB/s in that cell.

`--congestion cycle` was called `rl`, and `rl` still works as an alias. No
learned policy ships and none is planned: nine attempts — offline retrains,
five PPO seeds, and a contextual bandit over the cycle's own parameters
trained on the rig — all failed to beat the fixed cycle, the last of them
by a margin smaller than its own run-to-run spread. What runs is a
probe/drain/cruise gain cycle with an RTT-clocked ramp: a BBR-family
controller with no learning in it, which is what the new name says.

Algorithm details, constants and their justifications:
[crates/ahp-congestion/ALGORITHMS.md](crates/ahp-congestion/ALGORITHMS.md).

## Performance

**The short version, in three sentences.** The longer and lossier the path,
the better Favonius does: at 142 ms one Favonius controller moves 3.3x what a
single TCP (cubic) flow does, and under 1% loss four Favonius transfers beat
four BBR flows on every pair measured. On a short clean path it leads any
single flow but not four of them, and on a 4 ms LAN it is *slower* than
TCP — which is the expected result, since that is the condition TCP is best
at and the one Favonius's design buys nothing on. Every table below states
its rig, its n, and what it does not show; the per-run data is in
[benchmarks/results/](benchmarks/results/README.md).

**All throughput figures in this section are MiB/s** (bytes / 1048576 /
second), for every tool. The harnesses time every arm on one wall clock
and divide by the same constant — **iperf3 is timed, not self-reported** —
so the comparisons are like-for-like. Multiply by 1.049 for MB/s.

### On an emulated 100 Mbit link

Measured on a shaped container pair (`tc netem` for delay and loss over
`tbf` for the bottleneck), all traffic crossing the same qdisc. Paths are
one-way delay and uniform random loss. MiB/s.

**One session, one tree, every column.** Each tool was measured back to
back on the same container pair on 2026-08-14, so the columns are directly
comparable and there is no cross-session drift to argue about. Data:
[`netem_fair_v2-xtool_…csv`](benchmarks/results/netem_fair_v2-xtool_100mbit_q1.0_j0_2026-08-14.csv)
for every UDP tool, and
[`netem_fair_v2-tcpfix_…csv`](benchmarks/results/netem_fair_v2-tcpfix_100mbit_q1.0_j0_2026-08-14.csv)
plus [`-tcpfix2_…csv`](benchmarks/results/netem_fair_v2-tcpfix2_100mbit_q1.0_j0_2026-08-14.csv)
for the TCP arms, re-measured after the harness bug described below.

**100 Mbit link (ceiling 11.9 MiB/s), n=3:**

| path | Favonius | uftp | libudt | tsunami | QUIC | TCP ×4 | TCP ×1 |
|---|---|---|---|---|---|---|---|
| 25 ms / 0.5% | **10.64** | 8.02 | 5.01 | 2.85 | 2.37 | 5.19 | 1.38 |
| 50 ms / 1% | **10.20** | 6.39 | 3.43 | 1.47 | 0.79 | 1.84 | 0.00 |
| 150 ms / 2% | **8.37** | 3.51 | 1.84 | 0.00 | 0.00 | 0.00 | 0.00 |
| 100 ms / 5% | **8.36** | 4.47 | 0.31 | 0.27 | 0.00 | 0.00 | 0.00 |

**Read Favonius against TCP ×4, not TCP ×1.** Favonius runs four streams
by default, so four TCP flows is the like-for-like comparison and the
honest one: 2.1x on the mildest path, 5.5x at 50 ms/1%. The single-flow
column is included because it is what a naive `iperf3 -c` reports, not
because it is the fair fight.

**These four paths are the worst case for TCP, not a typical one**, and
that caveat belongs next to the column rather than at the end of the
section. They inject *uniform random* loss, the one condition where
loss-based congestion control is structurally worst — every drop is read
as congestion when nothing is congested. On the same four paths shaped at
1 Gbit, kernel cubic reaches 0.08-1.9% of the link
([calibration](benchmarks/results/tcp_calibration_1000mbit_2026-08-09.csv)).
On a shallow-queue path with congestion-induced loss instead, QUIC/cubic
is competitive with Favonius. Most of the margin above is a statement
about the loss model, not about congestion control in general.

**Zeros are failures, and the mean counts them as zero.** That penalises a
tool for not finishing, which is the intent, but a cell mixing successes
and timeouts is not the same quantity as one that completed three times —
so where they mix, it is written out here rather than left in the CSV:
libudt's 0.31 at 100 ms/5% is one run at 0.93 and two timeouts; tsunami's
0.27 there is one run at 0.80 and two timeouts. Every other non-zero cell
completed all three runs. Favonius and uftp complete every scenario; no
other tool does.

**Tsunami now appears, where before it was withheld.** Earlier revisions of
this table gave it no figure at all, on the grounds that a tool completing
*no* scenario — including the unimpaired baseline — was far likelier to
mean the harness drove it wrongly than that the tool had zero throughput.
That was the right call, and it was the harness: the fault was found and
fixed, and tsunami now completes the two shorter paths. Its runs still
exit non-zero even when the delivered file matches the source sha256, so
its numbers are reported on the strength of the checksum rather than the
exit status.

**A harness bug that inflated our own lead, recorded because the fix
changed published numbers.** The TCP arms verify delivery by comparing
iperf3's receiver-side byte total against the source size. With `-P 4`
each of the four streams closes with its own tail in flight, so the
receiver total lands 1-6% under the sender's on runs that completed
cleanly. A 2% tolerance scored six such runs BAD and recorded them as
0.00 MiB/s — indistinguishable, in the CSV, from a tool that stalled. It
zeroed two of three cross-country runs and all three transatlantic ones,
turning a real 5.19 into 1.68 and a real 1.84 into 0.00: a false zero in a
competitor's column, in our favour, on the arm added specifically to stop
comparing our four streams against TCP's one. The check now gates on the
sender total, which is what actually separates a completed run from a
truncated one, and treats the receiver figure as the loose bound it is —
TCP cannot silently lose bytes, so for TCP alone the transport is the
delivery guarantee that a sha256 provides for every other tool.

**The remaining caveat:** this comes from a single-host container rig and
has not been reproduced on physical NICs — the two sections below have.
**Why these tools, and not rsync or scp.** The set is uftp, UDT4, tsunami
and quinn — the open-source accelerated-transfer tools that, like this one,
move bulk data over UDP with their own congestion control. `rsync`, `scp`
and `rclone` are absent on purpose: they run over TCP, so **kernel TCP
measured directly by iperf3 is their upper bound**, and it is in every
table. rsync over ssh cannot beat raw cubic on the same path — it pays for
encryption and its delta algorithm on top. Testing the ceiling is a
stronger test than testing the tool, and it is the same ceiling for every
TCP-based mover.

**All Favonius arms in the competitor tables ran with
`--data-port-range 7803-7812`**, so the per-stream data ports and parallel
transfers described above are in these numbers, not absent from them
(`benchmarks/scripts/competitor_bench.sh`). The netem container rig and the
Raspberry Pi rig do **not** pass a port range, so their tables are without
the feature; that is stated where those tables appear.

**How each tool was invoked.** A comparison is only as good as its
configuration, so here is exactly what ran. All transfers move the same
128 MB file, with no compression and no encryption anywhere.

| tool | invocation |
|---|---|
| Favonius | `favonius send /data/test.bin $SRV:7801:/tmp/dst/recv.bin --congestion classic --compression none --streams 4` |
| uftp | `uftpd -d -D /tmp/dst -B 20971520` / `uftp -Y none -R -1 -B 20971520 -H $SRV /data/test.bin` |
| libudt | `sendfile 9000` / `recvfile $SRV 9000 /data/test.bin /tmp/dst/udt.bin` (the UDT4 reference apps) |
| QUIC | `quic-bench server --addr 0.0.0.0:4433` / `quic-bench client --addr $SRV:4433 --src … --dst …` (quinn) |

Favonius runs its **shipped default** (`classic`); no per-cell tuning was
applied to it. uftp gets no rate cap (`-R -1`) and a 20 MB buffer; libudt
and QUIC run their reference configurations.

**Versions were not pinned**, and that is a real limitation of this table:
the comparison binaries were built once into the benchmark image and the
image does not record what they were. Treat the competitor columns as
"these tools, configured this way, on this rig" rather than as a statement
about the projects. Pinning versions is on the list.

Reproduce the Favonius column (needs Docker; the harness builds its own
image from this repository on first run, which takes a few minutes):

```bash
RATE_MBIT=100 QUEUE_BDP=1.0 INSTANCE=repro \
ONLY_MODES="classic,model,rl" \
ONLY_SCENARIOS="cross-country,transatlantic,satellite,degraded,congested" \
TRANSFER_TIMEOUT=180 \
  ./benchmarks/scripts/bench_netem_fair_v2.sh --runs 3 --tools favonius
```

The other columns need uftp, libudt, tsunami and a QUIC client inside the
same image. Those are third-party binaries not redistributed here; build
them and drop them in `/opt/bench/bin` to fill the table in.


### On real WAN paths

Emulated results are cheap to produce and easy to flatter. These are two
cloud machines, `e2-standard-4` in `europe-west3` and `europe-north1`,
**38 ms**, every transfer's SHA-256 checked at the destination. To separate
instance variance from path variance, the clean table below is **three
independent machine pairs** on the same path in one session, n=3 per pair —
nine Favonius runs behind each Favonius number, three behind each iperf3 one.

| tool | controllers | sockets | MiB/s | spread across 3 rigs |
|---|---|---|---|---|
| **Favonius, 4 concurrent transfers** | 4 | 4 | **394.4** | 4.7% |
| iperf3 cubic `-P4` | 4 | 4 | 185.7 | 12.3% |
| iperf3 bbr `-P4` | 4 | 4 | 150.7 | 0.1% |
| **Favonius `--streams 4`** | 1 | 4 | **138.1** | 24.5% |
| **Favonius `--streams 1`** | 1 | 1 | **116.8** | 16.1% |
| libudt | 1 | 1 | 70.9 | 11.1% |
| iperf3 cubic `-P1` | 1 | 1 | 68.4 | 4.1% |
| iperf3 bbr `-P1` | 1 | 1 | 61.8 | 0.2% |
| uftp | 1 | 1 | 59.1 | 37.6% |
| tsunami | 1 | 1 | 56.8 | 0.2% |
| quinn (QUIC) | 1 | 1 | 23.7 | 1.5% |

**Read the first two columns before the third.** The only rows that may be
compared directly are rows with the same pair. `Favonius, 4 concurrent
transfers` is four separate transfers at `--streams 1` — four controllers
on four sockets — which is what `iperf3 -P4` is, so **394.4 against 185.7
is matched on both axes**, and Favonius takes it by 2.12x. It wins on each
rig independently: 2.11x, 2.02x, 2.26x. `--streams 4` is one controller on
four sockets and belongs beside nothing else in this table; it is here
because leaving it out would hide the socket-vs-controller distinction the
design turns on.

**Read it by controller count.** `iperf3 -P 4` is four congestion
controllers with four windows; `favonius --streams 4` is **one** controller
multiplexed across four sockets. Matched one-to-one Favonius leads — 116.8
against single-flow cubic's 68.4 and BBR's 61.8 — and one Favonius
controller across four sockets (138.1) is within 26% of *four* TCP
controllers (185.7), which is an efficiency observation rather than a win.
Against the best other UDP tool, libudt at 70.9, a single Favonius stream
is 1.65x.

**An earlier version of this table reported the opposite result** — 211.2
against cubic's 324.2, Favonius losing the matched four-versus-four
comparison by 35%. That was measured before the startup defects described
in [Known limitation](#known-limitation-a-slow-receiver-disk) and the
session notes below were found: a path probe that cost one round trip per
probe instead of one in total, and a declined transfer that received no
reply and waited out a 2 s timeout. Both are fixed, and this table is a
complete re-measurement on three fresh pairs. The old numbers are kept in
`benchmarks/results/` rather than deleted.

**Favonius is the least stable arm here and that is not yet explained.**
Its spread across the three rigs is 4.7-24.5% where BBR's is 0.1-0.2% and
cubic's 4.1-12.3%. The aggregate figure is the steady one; the single-
controller arms move most. uftp is worse still at 37.6%, so this is not
unique to us, but it is ours to explain and we cannot yet.

**The advantage grows with distance.** Frankfurt to Oregon, **142 ms**,
same binaries and harness:

Favonius arms are n=3 per distance, iperf3 arms n=1.

| arm | 38 ms | 142 ms | keeps |
|---|---|---|---|
| Favonius, 4 concurrent | 405.8 | 300.2 | **74%** |
| Favonius `--streams 1` | 121.6 | 89.5 | **74%** |
| iperf3 cubic `-P4` | 192.7 | 54.3 | 28% |
| iperf3 cubic `-P1` | 70.3 | 17.9 | 25% |

At 142 ms, matched one-to-one, a single Favonius controller is **5.0x**
single-flow cubic (89.5 against 17.9); matched four-to-four, four
concurrent transfers are **5.5x** four TCP flows (300.2 against 54.3).
TCP keeps 25-28% of its throughput over the longer path; Favonius keeps
74% on both arms. A window-based controller pays a round trip to detect
each loss and several more to re-grow toward an 18 MB bandwidth-delay
product.

Both columns are from the **same session on the same hosts** — the
previous version of this table drew its two columns from different
sessions, which is exactly the comparison a "keeps" ratio must not be
built on. The iperf3 arms are n=3 here; they were n=1 before.

**Under loss**, 1% injected on the sender's egress, four concurrent
transfers against four BBR flows, **six ABBA-counterbalanced rounds on one
host pair** — odd rounds run Favonius first, even rounds BBR first, so run
order cannot be mistaken for the effect. Both arms move the same aggregate,
4 x 512 MiB. (An earlier version of this section described these as three
*machine pairs*; its data file shows one path and six paired rounds. They
were rounds, and the description was wrong.)

**Four controllers on each side** — four concurrent Favonius transfers
against four BBR flows:

Every round is shown, because with six of them a summary row can hide the
one that matters. Both arms are four controllers.

| round | Favonius, 4 concurrent, `--congestion cycle` | iperf3 bbr `-P4` | ratio |
|---|---|---|---|
| 1 | 331.8 | 197.0 | 1.68x |
| 2 | 274.2 | 179.5 | **1.53x** |
| 3 | 291.8 | 179.2 | 1.63x |
| 4 | 414.7 | 197.0 | 2.11x |
| 5 | 347.4 | 197.0 | 1.76x |
| 6 | 382.9 | 197.0 | 1.94x |
| **mean** | **340.5** | **191.1** | **1.78x** |

Ratios are computed **within** a round, never by pairing one arm's worst
round against the other's best: those are different rounds and pairing them
would throw away the counterbalancing the design exists to provide.

**That result needs `--congestion cycle`, and the default loses this cell.**
An earlier single-pair run of the same scenario with the shipped default
(`auto`, which resolves to `classic` on a WAN) measured **157.3 against
BBR's 227.5** — Favonius 30% *behind*
([file](benchmarks/results/competitors_leaky_1pct_38ms_2026-08-13.csv)).
That is the injected-loss row of the profile table above doing what it
says: `classic` treats random loss as congestion and backs off. If your
path drops packets for reasons other than congestion, you have to say so.

Within the `cycle` arm, Favonius wins **every one of the six rounds**.
**Quote the floor, 1.53x, not the mean** — Favonius's own spread across
those rounds is 51% while BBR's is 10%, on the same hosts in the same hour,
and that sensitivity is still not explained. It is the same instability the
three-rig table shows, and re-measuring on fresh hosts did not remove it.
Kernel cubic collapses to 1% of its clean throughput in this cell; libudt
to 3%.

Caveats that belong with these numbers:

- **TCP is untuned** — stock Ubuntu, no `tcp_rmem` enlargement, no pacing
  qdisc. That is what a user gets by default, not what a tuned server does.
- The clean tables are **0% loss paths**; the loss cell is *uniform random*
  loss, which is the family rate-based controllers are good at. Neither
  says anything about congestion-induced loss on a shared link.
- **quinn is its example client and server**, which are demonstrations —
  single stream, no tuning. That number is not a verdict on QUIC.
- Numbers are not comparable across the tables above: transfer sizes and
  timing boundaries differ. Within each table every tool got the same
  clock on the same hosts in the same hour.
- **There are three published figures for "4 concurrent transfers" at
  38 ms, and they differ by transfer size, not by code.**

  | file | MiB/s | what was timed |
  |---|---|---|
  | `threerig_pair{1,2,3}_38ms` | **211.2** | 4 x 256 MiB, senders only (`competitor_bench.sh` sets `t0` after the daemon is listening and `t1` before the hash check) |
  | `competitors_crosscountry_38ms` | **258.9** | 4 x 512 MiB, senders only, single pair |
  | `wan_sockets_vs_controllers` | **277.4** | 4 x 512 MiB, senders only |

  `iperf3 cubic -P4` sits at 320-327 in all three — and the reason it does
  not move is that **iperf3 was run time-limited (`-t 15`, exactly 15.00 s
  every run) while Favonius moved a fixed number of bytes in 4.9 to 7.9 s.**
  A 15-second run amortises TCP's slow-start over 15 seconds; a 4.9-second
  transfer amortises Favonius's ramp over 4.9.

  That is most of the gap, and the shipped data lets you separate it. Two
  points, same code, same path family, different transfer sizes:

  | campaign | bytes | wall | rate |
  |---|---|---|---|
  | three-rig | 4 x 256 MiB | 4.86 s | 211.2 |
  | keep-rate | 4 x 512 MiB | 7.41 s | 277.4 |

  Solving those two for a fixed cost plus a steady rate gave **≈402 MiB/s
  steady-state with a ≈2.3 s fixed startup** — a steady-state *above*
  `cubic -P4`'s 320-327. It was a two-point fit with no degrees of freedom
  left over, offered at the time as an estimate rather than a law.

  **That prediction has since been tested directly and it held.** With the
  startup cost removed, four concurrent transfers measure **394.4 MiB/s**
  across three fresh machine pairs — against a predicted 402, an error of
  under 2%. The estimate is left here because a prediction that was
  published before it could be checked, and then checked, is worth more
  than one quietly replaced by the number it predicted.

  **So the gap is startup, not throughput — and two causes of it have since
  been fixed.** The path probe cost ten round trips instead of one (425 ms
  on this path, now 87 ms), and a transfer declined for want of a data
  socket was sent no reply at all, so it waited out a 2 s timeout while the
  sockets it wanted were handed back within milliseconds. On loopback, four
  concurrent transfers against a ten-port pool went from a 2.39 s worst
  sender to 0.82 s.

  **Both fixes have now been measured on the same 38 ms cloud pair**, with
  the pre-fix and post-fix binaries alternated ABBA inside one session so
  rig drift cannot be read as the effect of the change
  ([data](benchmarks/results/wan_startup_ab_2026-08-14.csv)). Four
  concurrent transfers, 512 MiB each, every destination hash-verified:

  | build | n | MiB/s | per-round |
  |---|---|---|---|
  | pre-fix | 4 | 282.7 | 287.1, 293.9, 278.1, 271.8 |
  | **post-fix** | 4 | **369.9** | 390.1, 335.5, 372.0, 381.8 |

  **+30.8%, and the post-fix build wins all four paired rounds** (+35.9%,
  +14.2%, +33.8%, +40.5%). The pre-fix arm reproduces the published 277.4
  at 282.7, within 2%, which is the check that the two sessions are
  comparable at all.

  **That took this cell past four TCP flows**, and the full re-measurement
  since has widened it: 394.4 against `iperf3 cubic -P4`'s 185.7 on three
  fresh pairs, a 2.12x lead where the pre-fix table showed a 35% deficit.

  **Most cross-tool tables have since been re-measured with the fixed
  build**, rather than corrected by estimate: the emulated 100 Mbit table,
  the three-rig 38 ms table, the 38/142 ms distance table, the congested-
  cell table and the under-loss table were all re-run from scratch, each
  with every tool measured in the same session. The estimates that used to
  live here are gone because the measurements replaced them.

  **One cross-tool table has not been re-run: the hardware LAN table
  below.** It needs two physical machines, a real radio and a real switch,
  and that rig is not available on demand. The probe fix is worth under 1%
  there — 0.04 s of a ~6 s transfer at 4 ms RTT — so the number is not
  materially wrong, but it is a pre-fix number and is labelled as one in
  its own section rather than only here.

  The **profile** tables (Favonius against Favonius, on 1 Gbit and under
  loss) were not re-run either, and do not need to be: every profile paid
  the same probe, so their ranking is unaffected by construction.

  **The direction of the old error is worth recording.** Every pre-fix
  cross-tool number understated Favonius and never the competitors — the
  probe ran only in our own client, `iperf3` was time-limited, and the other
  tools do not run it. An error that runs one way is a bias, not noise, and
  it is the reason these tables were re-measured rather than annotated.

Raw per-run data for all of the above, with an index of what each file is
and which claim it backs:
[benchmarks/results/](benchmarks/results/README.md).

### On real hardware

**No port range here** — `hardware_bench.sh` starts the daemon without
`--data-port-range`, so this table is single-data-socket throughout.

**This is the one cross-tool table still measured with the pre-fix build**,
because reproducing it needs two physical machines, a real radio and a real
switch rather than a cloud API. The startup fixes described above are worth
under 1% at this RTT — the path probe costs 0.04 s of a ~6 s transfer at
4 ms — so the figures are not materially wrong, but they are older than
every other table here and should be read as such.

The table above is emulated. This one is not: two physical machines, a
real radio and a real switch, 256 MB per transfer, n=6 and n=10,
integrity verified
on every run.

Path: laptop on 802.11ac → router → Raspberry Pi 4 (armv7, Raspbian 10) on
wired Ethernet. RTT 5.5 ms. TCP baseline measured over the same path, in
the same session, with a dependency-free python3 sink.

**The arms are matched on controllers and not on sockets, and the
asymmetry favours Favonius.** The TCP baseline is a single socket with a
single congestion controller; Favonius runs the default `--streams 4`,
which is still **one** controller but four sockets. Favonius loses anyway,
at 0.87x — so this is a conservative number, and the gap on a like-for-like
single socket would be wider, not narrower.

| | mean | cv | retx/run | vs TCP |
|---|---|---|---|---|
| TCP (baseline) | 47.3 MiB/s | — | — | 1.00x |
| Favonius `classic` | **41.3 MiB/s** | 8.6% | 2561 | **0.87x** |
| Favonius `cycle` | 38.9 MiB/s | 7.9% | 2407 | 0.82x |
| Favonius `model` | 38.6 MiB/s | 11.6% | 3316 | 0.82x |
| Favonius `auto` | 37.8 MiB/s | 11.8% | 2509 | 0.80x |

**All four profiles and the TCP baseline are from one session on one
build**, n=6 each, 24 transfers, every destination hash-verified
([data](benchmarks/results/hardware_2026-08-15.csv)). Earlier revisions of
this table quoted `classic` and `auto` from two different sessions and
omitted `model` and `cycle` entirely, because those two "were measured on
this path once and the runs were not kept". They are quoted now.

**Why `model` was missing, and what it cost.** Re-measuring it exposed a
deadlock. `model` is BBR-style: ProbeRtt clamps the window to 16 x MTU for
200 ms in every 10 s, and the exit from that phase was evaluated only when
an ack arrived. If a radio burst lost everything in flight inside those
200 ms, no ack ever came, the exit was never re-evaluated, and the window
stayed clamped for the rest of the transfer — the sender crawling on
timeout retransmits at **0.02 MiB/s** until the receiver gave up at 300 s.
One run in six. It is a hang, not a slowdown: waiting does not recover it.

That path was reachable by the **default** configuration, because `auto`
resolves to `model` on a LAN or wifi link. ProbeRtt is a timer, so its
expiry is now checked from every callback that carries a clock — including
`on_packet_sent`, the only one still firing when a path has stopped
delivering entirely. Ten consecutive `model` transfers on the same radio
after the fix: no stalls, mean 41.7 MiB/s.

It took a lossy physical path to find. Every emulated rig in this
repository, and every cloud pair, ran it without incident.

**Normalise by a baseline from the same session, always.** The radio on
this path has been measured between 31.8 and 46.3 MiB/s inside one hour,
so a Favonius number divided by yesterday's TCP number means nothing.
Across sessions the ratio has read between 0.84x and 0.90x; the 0.87x above
is one controlled measurement, not a stable constant.

**A destination on the wrong filesystem invalidates the whole table.** The
first attempt at this re-run wrote to `/srv` on the Pi, which is the SD
card: 16 MB/s of sustained write. Every arm returned 13-18 MiB/s with
10-20% retransmits, and the retransmits were not a network event at all —
the stalled writes back-pressured the receive thread until the UDP socket
buffer overflowed, 26,000-41,000 dropped datagrams per transfer. TCP was
unaffected because its baseline sink discards bytes and never touches
disk, so the comparison looked like a 2.6x Favonius regression that did not
exist. `hardware_bench.sh` defaults `DEST_ROOT` to `/srv/favonius-incoming`;
on a Pi that default measures the SD card. This table writes to `/dev/shm`.
The same effect, in its intended form, is the
[slow receiver disk](#known-limitation-a-slow-receiver-disk) section above.

**Favonius is slower than TCP here, and that is the expected result.** This
is a short, clean, low-loss LAN — the condition TCP is best at and the one
Favonius's design buys nothing on. The emulated table above is about long
lossy paths, where loss-based TCP collapses; nothing in this repository
claims an advantage on a 4 ms LAN. `classic` being both fastest and
steadiest here is consistent with it shipping as the default.

**Tuning note.** `--streams 1` is worth measuring on a low-RTT path. On
this one it is **38.0 MiB/s against 4 streams' 32.4** — +17.3%, paired
t = +4.08 at n=4 pairs, order counterbalanced. Multi-stream earns its keep
on high-BDP lossy paths, not on a 4 ms LAN.

Two corrections to what this note said before, both worth stating because
the old version was confidently wrong:

- The mechanism given previously — that 4 streams "fragments each pacing
  quantum" — **is not the cause.** The real defect was that `ACK_EVERY` was
  a per-stream packet count that nobody scaled, so at 4 streams the count
  trigger could never fire and feedback ran on a 15 ms timer instead of on
  data. That is fixed (`max(ACK_EVERY / n_streams, 16)`).
- Fixing it narrowed the gap from ~25% to ~17% but **did not close it**, so
  the earlier numbers (41.5 against 33.1) no longer apply and neither does
  the expectation that the gap would disappear. What remains is real and
  its cause is not established: 4 streams spends 26.4% of the send loop
  window-blocked against 1 stream's 17.6%, which is a symptom, not an
  explanation. Treat the remaining gap as measured but unexplained.

**One arm in the published LAN file looks alarming and should be
explained.** `lan_tcp_vs_favonius_2026-08-12_final.csv` contains a
`favonius-adaptive` arm at **7.7 MiB/s** against 35-45 for everything else.
That is `--adaptive` before it was fixed: it returned the best stored
record whenever any existed, which pinned every later transfer inside
whatever region the first few explored. It now requires a stored record to
have beaten the link-type defaults before it will use one, and measures
level with the default. The old rows are kept rather than deleted, because
a benchmark set that quietly drops its worst result is not evidence.

Reproduce with `benchmarks/scripts/hardware_bench.sh` (needs SSH to the
peer; measures its own TCP baseline first).


## Contributing

Bug reports, and measurements that disagree with ours, are the most useful
things right now — see [CONTRIBUTING.md](CONTRIBUTING.md) for how to build,
test and measure, and [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md). Security
issues go to [SECURITY.md](SECURITY.md), not the issue tracker.

Release notes and the stability policy are in
[CHANGELOG.md](CHANGELOG.md). **MSRV is 1.87**, held by CI.

## Why the crates are called `ahp-*`

**Favonius is the implementation; AHP is the protocol it speaks.** AHP —
the Adaptive High-speed Protocol — is the UDP wire protocol specified in
[docs/AHP_protocol_RFC.md](docs/AHP_protocol_RFC.md). The crates carry the
protocol name (`ahp-proto` is the wire format, `ahp-congestion` the
congestion control, `ahp-crypto` the handshake); the binaries carry the
product name — `favonius`, `favonius-daemon`, and `fvn`, which is a symlink
to the first rather than a build of its own. A second implementation of AHP
would not be called Favonius.

## Project Structure

```
crates/
  ahp-proto           wire format, codecs, packet types
  ahp-crypto          X25519, AES-256-GCM, HKDF, header protection, key rotation, tickets
  ahp-congestion      congestion-control profiles
  ahp-xdp             AF_XDP zero-copy transport
  ahp-platform-net    cross-platform UDP send (Linux GSO, Windows USO, macOS sendmsg)
  ahp-compression     per-chunk zstd
  ahp-sync            Merkle tree for resume verification
  ahp-cli             sender CLI (favonius)
  ahp-daemon          receiver daemon (favonius-daemon)
  ahp-api             HTTP REST API
  ahp-policy          adaptive parameter selection
  ahp-observability   logging and metrics
docs/                 protocol RFC, build guide, send-path optimisation
benchmarks/           reproducible benchmark harness
```

## Building

```bash
# Prerequisites: Rust 1.87+ (Linux for GSO/sendmmsg)
cargo build --release
cargo test --workspace

# Cross-compile for ARM
cross build --release --target armv7-unknown-linux-gnueabihf -p ahp-daemon
```

See [docs/BUILD.md](docs/BUILD.md) for Windows and macOS targets.

## Documentation

- [docs/AHP_protocol_RFC.md](docs/AHP_protocol_RFC.md) — the wire protocol
- [docs/BUILD.md](docs/BUILD.md) — native and cross-compilation
- [docs/OPTIMIZATION.md](docs/OPTIMIZATION.md) — send-path optimisation
- [crates/ahp-congestion/ALGORITHMS.md](crates/ahp-congestion/ALGORITHMS.md) — congestion control

## License

Dependency licences are listed in
[THIRD-PARTY.md](THIRD-PARTY.md), generated from `Cargo.lock` — 289
crates, all permissive, none copyleft.


Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).

Copyright (c) 2025-2026 Vantino SàRL.
