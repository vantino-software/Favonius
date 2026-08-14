# Benchmark results

**A note on the tool name.** These runs were executed by a binary called
`hespera`; the project was renamed to Favonius before its first public
release. The tool name has been updated in these files and in their
filenames so the index and the README agree. **No measurement was re-run
and no number was changed** — only the label.


Raw per-run data behind the numbers in the project README. Every row is one
transfer or one measurement interval; nothing here is a summary that cannot
be recomputed from the rows above it.

Three conventions worth knowing before reading any of it:

- **A transfer counts only if its bytes were verified.** The harnesses that
  produce these files hash the destination against the source and mark the
  run `ok` or `MISMATCH`. A tool that reports success having transferred
  nothing is a real failure mode and has happened here more than once, so
  timing without verification is not recorded as a result.
- **Numbers are comparable within a file, not across files.** Transfer
  size, timing boundaries (whether the clock includes daemon startup and
  verification) and harness differ between campaigns. Each file was
  produced in one session on one set of hosts.
- **Favonius's `--streams N` is one congestion controller** multiplexed
  across N sockets, not N flows. The counterpart to `iperf3 -P N` is N
  concurrent *transfers*. Files that compare against TCP state the
  controller count per row for this reason.

## Real WAN paths — the tables in the project README

Google Cloud `e2-standard-4` pairs, `europe-west3` ↔ `europe-north1`
(38 ms) unless stated.

| file | what it is |
|---|---|
| `threerig_pair{1,2,3}_38ms_2026-08-13.csv` | **Three independent machine pairs on the same path, one session, n=3 each** — the clean-path table. Separates instance variance from path variance; every tool lands within 0.4–9.2% across the three. |
| `transcontinental_2026-08-12.csv` | Frankfurt → Oregon, **142 ms**. The keep-rate column in the README comes from this against the 38 ms tables. |
| `loss_1pct_threerig_2026-08-13.csv` | 1% injected egress loss, four concurrent transfers vs four BBR flows, **ABBA-counterbalanced across three pairs**. The README quotes the worst pair (1.18x), not the 1.35x mean. |
| `loss_1pct_abba_38ms_2026-08-13.csv` | The same comparison on a single pair, which is what showed the result was pair-dependent. |
| `loss_1pct_profiles_38ms_2026-08-13.csv` | Congestion profiles under 1% loss: `model`/`cycle`/`wifi` beat `classic` by 22–27%. Source of the table in the README's Congestion Control section. |
| `competitors_crosscountry_38ms_2026-08-12.csv` | Favonius, tsunami, UDT4, quinn, uftp — one sender, one session, hash-verified. |
| `competitors_transcontinental_142ms_2026-08-12.csv` | The same tool set at 142 ms, same sender and hour. |
| `competitors_leaky_1pct_38ms_2026-08-13.csv` | The same tool set under 1% loss. Kernel cubic falls to 1% of its clean throughput here; UDT4 to 3%. |
| `competitors_wan_2026-08-12.csv` | An earlier competitor run on a single WAN pair, superseded by the three above but kept — it is what the later runs were checked against. |
| `competitors_2026-08-12.csv` | **Not a WAN file.** The 4 ms LAN rig (peer `192.168.0.155`), and every competitor row in it is `MISMATCH` — kept as the record of a run that did not produce usable competitor numbers. |
| `wan_matched_controllers_2026-08-12.csv` | Favonius against TCP at matched congestion-controller counts, the comparison that corrected an earlier "1.5x deficit" reading. |
| `wan_sockets_vs_controllers_2026-08-12.csv` | Sockets and controllers varied independently: `--streams 4` (1 controller, 4 sockets) against 4 concurrent transfers (4 controllers). |
| `wan_congestion_profiles_2026-08-12.csv` | Profiles on a clean WAN path, including the `fair` row that measured 7.4 MiB/s against classic's 125.8 and got that profile removed from the adaptive explorer. |

## Per-stream data ports

| file | what it is |
|---|---|
| `ab_per_stream_ports_plaintext_2026-08-12.csv` | A/B of the port split, plaintext, ABBA, one binary (`FAVONIUS_PER_STREAM_PORTS=0` flips the arm). |
| `ab_per_stream_ports_encrypted_2026-08-12.csv` | The same A/B with encryption and header protection. |
| `ab_stream_run_with_per_stream_ports_2026-08-12.csv` | `FAVONIUS_STREAM_RUN` 1 vs 32 with the split active — the coupling that stops per-packet round-robin collapsing every GSO batch to one datagram. |

## LAN and real hardware

| file | what it is |
|---|---|
| `hardware_2026-08-11.csv`, `hardware_2026-08-12.csv` | Laptop → Raspberry Pi 4 over 802.11ac with a same-session TCP baseline. `classic` at n=6 (08-11); `classic` and `auto` at n=10 each (08-12). No `model` or `cycle` runs were kept for this path. |
| `lan_tcp_vs_favonius_2026-08-12_final.csv` | Favonius against kernel TCP over the same radio at matched controller counts. |
| `competitors_lan_favonius_2026-08-12.csv` | Favonius arms on the Pi. The competitor arms are absent because the tools were not installed on that peer — a comparison that silently drops a tool is better than one that silently misconfigures it. |
| `streams_ab_lan_2026-08-11.csv` | Stream-count A/B on the LAN rig. |
| `ab_favonius_pace_debt_2026-08-11.csv` | Carried-pacing-debt A/B (`FAVONIUS_PACE_DEBT`), which is off by default because this file could not distinguish its effect from zero. |

## Emulated paths (`tc netem` over `tbf`, containers)

| file | what it is |
|---|---|
| `netem_tcp_vs_favonius_2026-08-12.csv` | Every congestion profile against kernel TCP across nine cells, unshaped (`rate_mbit=0`), queue 1.0 BDP. The file that showed `fair` losing every cell except the unimpaired baseline, by 3.8x (metro) to 19.6x (congested-hi). In the baseline cell it is third of six profiles (329.9, behind model 338.1 and wifi 330.7) and ahead of `rl` 322.4, `classic` 302.9 and `udt` 247.7. |
| `netem_1gbit_injected_loss_2026-08-10.csv` | The 1 Gbit table in the README's Congestion Control section — four uniformly-injected-loss cells, every profile, n=8. |
| `netem_1gbit_congested_2026-08-11.csv` | The three `congested-*` cells of that same table, where the loss comes from the queue the sender is filling rather than from netem. |
| `tcp_calibration_1000mbit_2026-08-09.csv` | Kernel TCP through the identical qdisc — the control that says whether a "% of link" figure is measured against the right ceiling. |
| `self_fairness_clean_100mbit_2026-08-11.csv` | Two Favonius transfers sharing one bottleneck: Jain index and efficiency. |
| `netem_fair_2026-04-05.csv`, `netem_fair_gso_2026-04-05.csv`, `netem_fair_iouring_2026-04-06.csv`, `netem_fair_2026-07-24.csv`, `netem_fair_v2_*.csv` | Cross-tool runs on the shaped container pair, including the send-path variants (GSO, io_uring). |
| `ab_ccfix_2026-08-02.csv`, `ab_ccfix_100mbit_2026-08-02.csv` | Before/after A/B of a congestion-control fix, one binary per arm. |
| `hardware_2026-08-14.csv` | **A void run, kept as the evidence for a harness defect.** Every throughput cell is empty and it reads as a total transfer failure; the transfers all succeeded. The client's own label had been corrected from `MB/s` to `MiB/s` — the divisor was always 1048576, only the label was wrong — and nine benchmark scripts parsed that literal string, so they matched nothing and wrote blanks. Superseded by `hardware_2026-08-15.csv`. Kept because "a parser keyed to a cosmetic label" is a failure worth being able to point at. |
| `hardware_2026-08-15.csv` | The real-hardware table: laptop on 802.11ac to a Raspberry Pi 4 on wired Ethernet, all four congestion profiles plus a TCP baseline in one session on one build, n=6 each, 24 transfers, every one hash-verified. Supersedes the 2026-08-11 and 2026-08-12 files, which quoted two profiles from two different sessions. **Destination is `/dev/shm`, not `/srv`** — the first attempt used the script's default, which on this Pi is the SD card at 16 MB/s, and measured the card rather than the network. |
| `netem_fair_v2-congfix_2026-08-15.csv` | The congested-cell table in the README's Congestion Control section — Favonius `classic` against cubic and bbr, one and four flows, on the three shallow-queue cells (25/50/150 ms), unshaped, 512 MiB, n=3, one session. Supersedes `netem_tcp_vs_favonius_2026-08-12.csv`, which was measured before the startup fixes **and** before the `-P4` verification bug was found — three of its cells recorded `0.0` for four-flow TCP, which the re-run shows were not zeros. |
| `wan_distance_38ms_2026-08-14.csv`, `wan_distance_142ms_2026-08-14.csv` | The 38 ms / 142 ms distance table. Favonius and iperf3 arms, n=3 each, **both distances in one session on one sender** — the previous version of that table drew its two columns from different sessions, which a "keeps" ratio must not be built on. |
| `wan_pairB_dist_38ms_2026-08-14.csv`, `wan_pairC_dist_38ms_2026-08-14.csv` | Pairs B and C of the three-rig 38 ms table, on independently created machine pairs. Together with the pair-A file above they are the "spread across 3 rigs" column. Run sequentially, never concurrently: two pairs transferring at once would contend on the same regional path and corrupt the variance figure the table exists to report. |
| `wan_competitors_38ms_2026-08-14.csv`, `wan_competitors_142ms_2026-08-14.csv`, `wan_pairB_competitors_38ms_2026-08-14.csv`, `wan_pairC_competitors_38ms_2026-08-14.csv` | libudt, tsunami, uftp and quinn against Favonius on the same pairs and in the same session. Note these are `competitor_bench.sh` output and report **MB/s**, not MiB/s; the README tables divide by 1.048576. |
| `loss_1pct_abba_38ms_2026-08-14.csv` | The under-loss table: 1% injected on the sender's egress, four concurrent Favonius transfers (`--congestion cycle`) against four BBR flows, six ABBA rounds on one pair, both arms moving 4 x 512 MiB. Supersedes the 2026-08-13 file, whose section described its rounds as "machine pairs". |
| `netem_fair_v2-xtool_100mbit_q1.0_j0_2026-08-14.csv` | The cross-tool table in the README's Performance section. Every UDP tool — Favonius, uftp, libudt, tsunami, quinn — measured back to back in one session on one tree, 4 paths x 3 runs, 84 rows. Supersedes the two-session arrangement it replaced. |
| `netem_fair_v2-xtool2_100mbit_q1.0_j0_2026-08-14.csv` | An independent repeat of the hardest row (100 ms / 5%) for uftp, tsunami and TCP, run separately. uftp came back at 4.31 MiB/s against 4.47 in the main run and 4.31 on 2026-08-03 — an unchanged binary reproducing itself within 4% across three sessions, which is the control that says the rig is not drifting under the tools. |
| `netem_fair_v2-tcpfix_100mbit_q1.0_j0_2026-08-14.csv`, `netem_fair_v2-tcpfix2_100mbit_q1.0_j0_2026-08-14.csv` | The TCP arms of that same table, re-measured after a verification bug was found in the harness. It compared iperf3's receiver-side byte total against the source size with a 2% tolerance; with `-P 4` each stream closes with its own tail in flight, so clean runs land 1-6% under and six were scored 0.00 MiB/s. The effect was to understate TCP ×4 — a real 5.19 recorded as 1.68, a real 1.84 as 0.00 — a false zero in a competitor's column, in our own favour. `tcpfix2` is the transatlantic ×4 cell alone, re-run after the bound was widened a second time. |
| `INVALID_netem_fair_v2_100mbit_q1.0_j0_2026-08-03.*` | **A void run, kept deliberately.** The `.README` beside it records what aborted and which cells cannot be certified. Discarded data is worth keeping when something else might otherwise cite it. |

## What is not here

The ~250 `netem_fair_v2-<tag>_*.csv` files from congestion-control
development are not published. They are single-experiment sweeps whose tags
(`cliff1.095`, `rz175`, `ucyc`) index an internal engineering log, and
without it they are not interpretable — publishing them would add volume
rather than evidence.

Four tagged files are the exception and are published, because the README
cites them: `-xtool` and `-xtool2` (the cross-tool table and an independent
repeat of its hardest row) and `-tcpfix` / `-tcpfix2` (the TCP arms). A
table's own evidence has to ship with it.

Rig addresses in these files are private-range (`10.x`, `192.168.x`)
addresses of machines that no longer exist.

## Baselines

`../baselines/main.tsv` is the rolling n=8 re-recording of the four shaped
100 Mbit cells for every profile — mean, mean retransmit rate, n, and
standard deviation — in that order, and the file is headerless. It is what the README's 100 Mbit table quotes, and what a
regression run is compared against. `crates/ahp-congestion/ALGORITHMS.md`
prints an earlier n=3 run of the same cells and says so.
