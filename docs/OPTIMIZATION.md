# Favonius Send-Path Optimization

This document describes how Favonius achieves high UDP send throughput on
each supported platform. The fundamental challenge is the same everywhere:
**per-packet syscall overhead caps single-thread UDP send at ~150-300 MB/s**.
Every supported platform exposes a different mechanism to amortize this
overhead, and Favonius uses the best one available on each.

## Table of contents

1. [Linux: GSO (the gold standard)](#linux-gso)
2. [Windows: USO (UDP Send Offload)](#windows-uso)
3. [Windows: RIO (Registered I/O)](#windows-rio)
4. [macOS: parallel sendmsg + dispatch queues](#macos)
5. [Performance ceiling comparison](#performance-ceiling)
6. [Cross-platform abstraction in `ahp-platform-net`](#abstraction)

---

## Linux: GSO — Generic Segmentation Offload {#linux-gso}

GSO (specifically **UDP GSO** here, also called UDP segmentation offload) is a
Linux kernel feature that lets userspace submit one large UDP buffer in a
single syscall, and the kernel (or the NIC, if hardware-capable) splits it
into multiple individual UDP datagrams at fixed segment boundaries. From the
application's point of view, you write one big packet; on the wire, the
receiver sees N separate UDP datagrams.

It's the single most important optimization in Favonius's send path — without
it, throughput drops by ~50% even on a fast link.

## The problem GSO solves

A naive UDP sender does:

```
loop:
  fill packet[i] in userspace
  sendto(socket, packet[i], len[i], dest)   # 1 syscall per packet
```

For 1500-byte packets at 1 Gbps you need ~83K sendto calls per second. Each
one:

1. Crosses the user→kernel boundary (TLB flush, mode switch, ~200ns)
2. Allocates a fresh `sk_buff` (skb) — the kernel's per-packet metadata structure
3. Walks the netfilter chains
4. Computes IP and UDP checksums (or marks them for offload)
5. Routes the packet
6. Hands it to the NIC TX queue

That's a lot of work per packet. Profiling shows the kernel spends most of
the CPU in `__alloc_skb` and `udp_send_skb`. At 10 Gbps the CPU literally
cannot keep up using the naive approach.

`sendmmsg(2)` helps a bit — it lets you submit N packets in one syscall —
but each packet still gets its own skb and goes through the full per-packet
processing pipeline. You save the syscall overhead but not the per-packet
kernel work.

## What GSO does differently

With GSO you submit **one giant buffer** containing N back-to-back packets
of fixed size, plus a control message (`UDP_SEGMENT` cmsg) telling the
kernel the segment size. The kernel sees this as a **single logical packet**
and runs all the per-packet work (skb alloc, routing, netfilter) **once**,
then splits it into N segments at the very last moment before handing off
to the NIC.

```c
ssize_t sendmsg(int fd, const struct msghdr *msg, int flags);

// msg->msg_iov points to one big buffer
// msg->msg_control contains a CMSG_LEVEL_UDP / UDP_SEGMENT entry
//   with the segment size (e.g., 1430 bytes = MTU - IP - UDP headers)
```

The buffer layout:

```
[packet 1: 1430 bytes][packet 2: 1430 bytes][packet 3: 1430 bytes]...[packet N]
                                                                              ↑
                                                                        last may be short
```

The kernel sees `total_length / segment_size` packets but only allocates
**one** skb (a "GSO skb") that references the original buffer. It walks
netfilter once. It routes once. It computes the checksums for the GSO skb.

Then, in the very last step before the NIC TX queue (`skb_segment`), the
kernel either:

- **Hardware offload** (if the NIC supports UDP_GSO_L4): hands the GSO skb
  to the NIC, which segments it in silicon. The CPU work is essentially zero.
- **Software offload**: the kernel itself splits the GSO skb into N regular
  skbs at segment boundaries. This is still much faster than N separate
  sends because the per-skb work was amortized.

## The actual numbers

Favonius's GSO call looks roughly like this in Rust (via nix):

```rust
let segment_size: u16 = 1430;
let cmsg = ControlMessage::UdpGsoSegments(&segment_size);
let iov = [IoSlice::new(&self.buf[..total_len])];

sendmsg(fd, &iov, &[cmsg], MsgFlags::empty(), Some(&dest))?;
```

`total_len` is up to **65,535 bytes** (the IP datagram size limit). At
1430 bytes per segment that's 45 packets per syscall — and the message
printed at startup confirms exactly that:

```
GSO: enabled (segment_size=1430, max_segments=45)
```

With 45 packets per syscall, the syscall rate at 1 Gbps drops from ~83K/s
to ~1.8K/s — a **45x reduction**. Even more importantly, the per-packet
skb alloc, netfilter walk, and checksum work is done once for 45 packets
instead of 45 times.

## Why segment_size = MTU - headers

The segment size is the **payload size on the wire**:

```
MTU - IP_header - UDP_header = 1500 - 20 - 8 = 1472
```

Favonius uses 1430 to leave headroom for the AHP header and to stay safely
under the path MTU.

If the segment size is wrong (larger than the path MTU), the resulting
packets get fragmented or dropped. So the sender must know the MTU before
enabling GSO. Favonius probes this during the initial network classification
phase.

## How it interacts with the rest of the stack

A few subtle points worth knowing:

1. **GSO requires a connected socket OR a single destination per call.**
   All segments in the GSO buffer go to the same address. You can't do
   scatter-gather across different destinations.

2. **The last segment can be short.** If the buffer is `5 * 1430 + 700`
   bytes, the kernel sends 5 full segments and a 700-byte final segment.
   Favonius tracks this via a `tail_len` field.

3. **The receiver sees individual UDP datagrams.** GSO is purely a sender-
   side optimization. The receiver gets N separate `recvfrom` events with
   N separate datagrams (or batches them via `recvmmsg`). There is no
   equivalent reassembly on the receive side — each segment travels the
   network independently.

4. **GSO requires Linux 4.18+** for UDP. Earlier kernels only had GSO for
   TCP. The probe in Favonius tries a small GSO send to detect support:

   ```rust
   fn probe_gso(fd: RawFd) -> bool {
       let segment: u16 = 1200;
       let data = [0u8; 0];
       let iov = [IoSlice::new(&data)];
       let cmsg = ControlMessage::UdpGsoSegments(&segment);
       sendmsg(fd, &iov, &[cmsg], MsgFlags::MSG_DONTWAIT, Some(&dest)).is_ok()
   }
   ```

5. **GSO and netem don't always play well.** When testing under `tc netem`,
   the kernel sometimes processes the GSO buffer as one logical "packet"
   for loss accounting, meaning a single random drop kills 45 datagrams.
   That's why netem benchmarks show different patterns than real lossy
   WAN links — netem applies loss to skbs, not bytes.

6. **GSO is orthogonal to checksum offload.** The NIC can still compute
   IP/UDP checksums for the segments after splitting. Favonius sets the
   checksum to 0 (legal for IPv4 UDP) and lets the NIC fill it in.

7. **What if a segment exceeds the path MTU?** The kernel emits an ICMP
   "fragmentation needed" message, which the sender can use to lower its
   segment size. Favonius doesn't currently handle PMTUD updates dynamically
   — it sticks with the segment size from the initial probe.

## Why GSO beat io_uring in our benchmarks

When we tested io_uring + sendmsg, we saw it was 60-82% slower under loss.
The reason is now obvious: io_uring submits N **independent** sendmsg SQEs
to the kernel, and each one goes through the full UDP send path. There's
no batching at the kernel level — io_uring just batches the **submission**
of independent operations. So you save the syscall overhead but you still
pay per-packet kernel work.

GSO collapses both layers into one:

- One syscall (like io_uring)
- One trip through the kernel's UDP send path (unlike io_uring)
- N segments emitted at the wire layer

This is why **GSO is unbeatable for UDP datagram batching from a single
socket**, and why the only way to go faster is AF_XDP — which bypasses
the kernel UDP stack entirely.

## When GSO doesn't help

A few situations where GSO is neutral or harmful:

- **Per-packet timing required** (e.g., precise pacing). GSO sends the
  whole batch in a burst — you can't space out individual segments.
  Favonius's `--pacing perpacket` mode disables GSO for this reason.

- **Variable packet sizes**. GSO requires a fixed segment size. Variable-
  size packets need to be padded or sent in separate GSO calls.

- **MSS smaller than expected**. If the kernel's auto-detected MSS is
  smaller than your segment size, the packets get fragmented at the IP
  layer, defeating the purpose.

- **Hardware that doesn't support UDP GSO**. Some older NICs only do TCP
  GSO. Software fallback still helps but the gain is smaller (~2-3x
  instead of 5-10x).

## TL;DR

GSO turns N `sendmmsg`-style packet sends into one `sendmsg` with a
`UDP_SEGMENT` cmsg. The kernel runs its per-packet work **once** for the
whole batch, then splits the buffer into N datagrams at the very last
moment. On Linux 4.18+ with a half-decent NIC you get ~45x fewer syscalls
and amortized kernel processing, which is why Favonius's default
`--pacing batch` mode uses GSO and why every other optimization we tried
(io_uring, zero-copy 2-iovec, AF_XDP integration) failed to beat it on
real workloads.

---

## Windows: USO — UDP Send Offload {#windows-uso}

Windows has a direct equivalent of Linux GSO, called **USO (UDP Send Offload)**.
Introduced in **Windows 10 version 2004 (Build 19041, May 2020)**, USO works
on the same principle: submit one large buffer with a segment-size hint,
and the kernel/NIC splits it into N datagrams at the wire layer.

### How it works

USO is enabled via a control message attached to `WSASendMsg`:

```c
// Build the WSAMSG with a UDP_SEND_MSG_SIZE control message.
WSAMSG msg = { 0 };
msg.name = (LPSOCKADDR)&dest;
msg.namelen = sizeof(dest);
msg.lpBuffers = &wsabuf;
msg.dwBufferCount = 1;

// Control buffer with the segment size.
char ctrl[WSA_CMSG_SPACE(sizeof(DWORD))];
msg.Control.buf = ctrl;
msg.Control.len = sizeof(ctrl);

WSACMSGHDR* cmsg = WSA_CMSG_FIRSTHDR(&msg);
cmsg->cmsg_level = IPPROTO_UDP;
cmsg->cmsg_type  = UDP_SEND_MSG_SIZE;
cmsg->cmsg_len   = WSA_CMSG_LEN(sizeof(DWORD));
*(DWORD*)WSA_CMSG_DATA(cmsg) = segment_size;  // e.g., 1430

DWORD bytes_sent;
WSASendMsg(sock, &msg, 0, &bytes_sent, NULL, NULL);
```

The application submits one buffer of `N * segment_size` bytes (plus optional
short tail). Windows segments it into N + 1 datagrams. Throughput matches
Linux GSO when the NIC driver supports the offload (most Intel, Realtek and
Mellanox drivers do). When the driver doesn't, the Windows kernel does
software segmentation — still much faster than per-packet sends.

### Caveats specific to Windows

- **OS version check at runtime**: USO requires Windows 10 build ≥ 19041.
  Use `RtlGetVersion` to check; falls back gracefully on older Windows.
- **VPN drivers**: some older third-party VPN clients silently break USO —
  packets either fail to segment or get dropped. Detect via `WSAEINVAL`
  return and fall back to per-packet `WSASendTo`.
- **Hyper-V virtual NICs**: USO support was added in a later patch.
  May need to test before enabling.
- **No `sendmmsg` equivalent**: Windows has no batched-multi-packet syscall.
  USO is the *only* way to amortize per-packet overhead on Windows; without
  it you're stuck with `WSASendTo` in a loop.

---

## Windows: RIO — Registered I/O {#windows-rio}

For ultra-high packet rates (>500K pps), Windows offers **RIO** (Registered
I/O), introduced in **Windows 8 / Windows Server 2012**. RIO is closer to
AF_XDP in spirit than to io_uring:

- Pre-register a memory region with the kernel (analogous to UMEM)
- Send packets via descriptors written to a ring buffer
- Completions arrive in another ring without syscalls
- Bypasses most of the Winsock layer

```c
// Register a buffer pool with the kernel
RIO_BUFFERID buf_id = rio.RIORegisterBuffer(buffer, buffer_size);

// Create request/completion queues
RIO_RQ rq = rio.RIOCreateRequestQueue(socket, ...);
RIO_CQ cq = rio.RIOCreateCompletionQueue(...);

// Submit sends — no syscall, just a write to the ring
rio.RIOSendEx(rq, &buf_descriptor, 1, NULL, &dest_addr, NULL, 0, 0, context);

// Harvest completions — no syscall
RIORESULT results[16];
ULONG n = rio.RIODequeueCompletion(cq, results, 16);
```

RIO is essentially "the io_uring of Windows" but it predates io_uring by
~7 years. It was originally designed for high-frequency trading and runs
the request/completion rings in shared memory between user and kernel.

**RIO + USO together** is the fastest path on Windows — RIO handles the
queue plumbing without syscalls, USO handles the segmentation at the wire
layer. Together they reach roughly Linux GSO performance and can saturate
10 GbE on a single thread.

### When to use RIO

- Sustained packet rates above ~500K pps
- Multi-tenant servers handling many UDP streams
- Latency-sensitive workloads where per-packet jitter matters

For typical Favonius workloads (single transfer, GbE link), **USO alone is
enough**. RIO becomes worthwhile only on dedicated 10G+ deployments. RIO is
on Favonius's roadmap as a Phase-2 follow-up after USO.

---

## macOS: parallel sendmsg + dispatch queues {#macos}

macOS is the most constrained of the three platforms. There is **no UDP
segmentation offload** equivalent at the BSD socket layer. Apple does not
expose any kernel API that lets userspace submit one buffer and get N
datagrams on the wire.

### What's available on macOS

| Mechanism | Useful for AHP send? | Notes |
|-----------|---------------------|-------|
| `sendto(2)` / `sendmsg(2)` | yes (baseline) | One syscall per packet |
| `writev(2)` (vectored I/O) | partially | Header + payload in one call, but still 1 packet per syscall |
| `sendmmsg(2)` | **not available** | macOS does not implement it |
| `sendfile(2)` | TCP only | Cannot be used for UDP |
| `kqueue(2)` | yes (event multiplexing) | Replaces epoll, doesn't help with batching |
| `dispatch_queue_t` (GCD) | yes (parallelism) | Can fan sends across CPU cores |
| BPF raw socket (`/dev/bpfN`) | only with elevated privileges | Direct packet injection like AF_XDP |
| Network Extension Framework | no (signed kext required) | Heavyweight, requires Apple Developer ID |

### The macOS strategy

Since per-packet syscall overhead is unavoidable, the only way to scale on
macOS is **parallelism**: dispatch sends across multiple cores via Grand
Central Dispatch (GCD), so the kernel can process them concurrently on
different cores.

```rust
// Pseudocode for the macOS backend
struct ParallelSendmsgBatchSender {
    sockets: Vec<UdpSocket>,        // One per worker thread (SO_REUSEPORT)
    workers: Vec<JoinHandle<()>>,
    tx: crossbeam_channel::Sender<Packet>,
}

// Each worker thread runs a tight sendto loop on its own socket.
// The OS routes packets across cores; bottleneck shifts from
// "one syscall path" to "N parallel syscall paths".
```

This typically gets you ~50-60% of Linux GSO throughput on the same hardware
— enough to saturate gigabit Ethernet and most home/SOHO uplinks. On 10 GbE,
expect ~700-800 MB/s peak.

### macOS-specific tuning that helps

Independent of the parallel-sendmsg approach, these tweaks measurably
improve macOS UDP performance:

- **`SO_NOSIGPIPE`**: required to prevent SIGPIPE on closed sockets (Linux
  uses `MSG_NOSIGNAL` instead).
- **Increase `SO_SNDBUF` / `SO_RCVBUF`**: macOS defaults are conservative
  (~256 KB). Bumping to 4-8 MB significantly reduces drops under burst.
- **`net.inet.udp.maxdgram` sysctl**: maximum UDP datagram size. Default
  is 9216 bytes, can be raised but rarely needed for AHP.
- **`net.inet.udp.recvspace` / `net.inet.udp.sendspace`**: kernel UDP
  socket buffer space defaults. Can be raised via `sysctl -w`.

### BPF raw socket path (advanced, not currently planned)

For Favonius workloads needing >1 GB/s on macOS, the only path is to
construct full Ethernet/IP/UDP frames in userspace and inject them via
`/dev/bpfN`. This is similar to our `ahp-xdp` packet builder but uses
the BSD BPF interface instead of Linux's AF_XDP. It requires:

- Root or BPF group membership
- Manually building L2/L3/L4 headers (the existing `ahp-xdp::packet`
  module is reusable here)
- Running outside the System Integrity Protection sandbox in some configs
- Apple Developer ID for binary distribution

Given the complexity and the fact that almost no real Favonius workload
needs >700 MB/s on macOS, this path is **not currently planned**.

---

## Performance ceiling comparison {#performance-ceiling}

Approximate single-thread UDP send throughput, 1430-byte payloads, no
encryption, no compression:

| Platform | Backend | Ceiling | Saturates | Status in Favonius |
|----------|---------|---------|-----------|-------------------|
| Linux | AF_XDP (raw, standalone) | ~3 GB/s | 25 GbE | Experimental |
| Linux | **GSO** (default) | 800-1200 MB/s | 10 GbE | **Production** |
| Windows 10 2004+ | RIO + USO | 800-1200 MB/s | 10 GbE | Roadmap |
| Windows 10 2004+ | **USO** | 700-1100 MB/s | 10 GbE | **In progress** |
| macOS (any) | parallel sendmsg | 400-700 MB/s | 5 GbE | **In progress** |
| Linux | sendmmsg (no GSO) | 200-300 MB/s | 2 GbE | Fallback only |
| Windows older | WSASendTo loop | 150-200 MB/s | 1 GbE | Fallback only |
| macOS (any) | sendto loop | 150-300 MB/s | 1-2 GbE | Fallback only |

**Bottom line**: With the right primitive enabled (Linux GSO, Windows USO),
Favonius reaches roughly the same throughput on Linux and Windows. macOS
trails by a factor of ~2 because Apple doesn't expose UDP segmentation.

---

## Cross-platform abstraction: `ahp-platform-net` crate {#abstraction}

Favonius's send-path implementations are isolated behind a `PacketBatchSender`
trait in the `ahp-platform-net` crate. The trait is platform-agnostic; each
OS gets its own implementation gated by `cfg(target_os = ...)`.

### The trait

```rust
pub trait PacketBatchSender: Send {
    /// Stage a single packet into the batch. The backend may copy or
    /// reference the data depending on its implementation.
    fn stage(&mut self, packet: &[u8]) -> Result<usize, SendError>;

    /// Flush all staged packets to the wire. Returns the count actually sent.
    fn flush(&mut self) -> Result<usize, SendError>;

    /// Whether the batch is at capacity and must be flushed before more
    /// packets can be staged.
    fn is_full(&self) -> bool;

    /// Number of packets currently staged but not yet flushed.
    fn pending(&self) -> usize;

    /// Capabilities of this backend (used by the AHP send loop to decide
    /// how aggressively to fill the batch).
    fn capabilities(&self) -> Capabilities;

    /// Backend identifier for logs and benchmarks.
    fn name(&self) -> &'static str;
}

pub struct Capabilities {
    pub max_batch_size: usize,
    pub supports_segmentation_offload: bool,
    pub supports_zero_copy: bool,
    pub typical_throughput_mbps: u32,
}
```

### Backend selection

The factory function `create_best_sender()` picks the best backend at
runtime, with platform-specific probing:

```rust
pub fn create_best_sender(
    socket: &UdpSocket,
    dest: SocketAddr,
    batch_capacity: usize,
    segment_size: usize,
) -> Box<dyn PacketBatchSender> {
    #[cfg(target_os = "linux")]
    {
        if linux::probe_gso(socket.as_raw_fd()) {
            return Box::new(linux::GsoBatchSender::new(socket, dest, batch_capacity, segment_size));
        }
        return Box::new(linux::SendmmsgBatchSender::new(socket, dest, batch_capacity));
    }

    #[cfg(target_os = "windows")]
    {
        if windows::probe_uso() {
            // UsoBatchSender::new returns None if enabling UDP_SEND_MSG_SIZE
            // fails — fall back to per-packet sends rather than emit the
            // staging buffer as one garbage datagram.
            if let Some(uso) = windows::UsoBatchSender::new(socket, dest, batch_capacity, segment_size) {
                return Box::new(uso);
            }
        }
        return Box::new(windows::SendtoLoopSender::new(socket, dest, batch_capacity));
    }

    #[cfg(target_os = "macos")]
    {
        return Box::new(macos::ParallelSendmsgBatchSender::new(socket, dest, batch_capacity));
    }
}
```

### What changes elsewhere in Favonius

Most of the AHP code is already platform-agnostic — the protocol codec,
congestion control, encryption, compression, the daemon receiver, and
anything that uses Tokio's `UdpSocket` work on all three platforms with no
changes. The only platform-specific bits live in `crates/ahp-cli/src/net_sender.rs`
where we currently use raw fds and `nix::sendmmsg`/`sendmsg` with cmsg. These
get refactored to call into `ahp-platform-net` instead.

The CC algorithms (RL, model, classic) are completely platform-agnostic —
they only see RTT, loss rate, and bytes-in-flight, none of which depend on
the kernel send path. **All the work done on the RL model carries over to
Windows and macOS for free.**
