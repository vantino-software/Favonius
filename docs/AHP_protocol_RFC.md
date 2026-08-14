# AHP: Adaptive High-speed Protocol

## Draft RFC Specification

### For secure, resumable, high-performance file transfer and partial-file synchronization over UDP

**Document status:** Draft
**Intended status:** Informational / Experimental
**Version:** `draft-ahp-00`
**Project:** Favonius
**Authors:** Project contributors
**Implementation language target:** Rust

---

# Abstract

AHP, the **Adaptive High-speed Protocol**, is a secure, UDP-based application-layer transport protocol for high-throughput bulk file transfer, resumable transfers, growing-file delivery, and partial-file synchronization across high-bandwidth, high-latency, and moderately lossy networks.

AHP separates the **control plane** from the **data plane**:

* **AHP-C** handles session establishment, capability negotiation, authentication, path probing, checkpoints, and control messages.
* **AHP-D** carries encrypted data packets, acknowledgements, retransmission signals, and pacing hints.
* **AHP-S** handles synchronization metadata, region maps, delta updates, and conflict signaling.
* **AHP-R** defines relay, rendezvous, and fallback behavior.

AHP is designed for:

* high-speed file transfer over WAN
* robust recovery after interruption
* adaptive congestion control
* efficient partial retransmission
* real-time transmission of changed file regions
* secure transport using modern cryptography

---

# 1. Conventions and Terminology

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHALL NOT**, **SHOULD**, **SHOULD NOT**, **RECOMMENDED**, **MAY**, and **OPTIONAL** are to be interpreted as described in RFC 2119 and RFC 8174.

## 1.1 Terms

**Endpoint**
A sender, receiver, relay, or peer participating in AHP.

**Session**
A secure association between two endpoints.

**Stream**
A logical sub-channel within a session.

**Transfer**
A file or fileset movement operation.

**Chunk**
A unit of file segmentation for transport, verification, checkpointing, and resume.

**Region**
A finer-grained file segment used in synchronization and partial-file repair.

**Checkpoint**
A persisted transfer progress structure allowing resume.

**Manifest**
A metadata object describing files, sizes, hashes, chunk maps, and attributes.

**Watermark**
The highest stable byte offset known for a growing file.

**Goodput**
Verified payload bytes delivered to the application per unit time.

---

# 2. Goals and Non-Goals

## 2.1 Goals

AHP is intended to:

1. maximize throughput on long fat networks
2. avoid TCP head-of-line collapse for bulk transfer
3. remain usable on lossy and variable-latency paths
4. support resumable transfer at chunk and region granularity
5. support file synchronization by transmitting only changed parts
6. support encrypted transport with forward secrecy
7. support growing files and early consumption
8. permit policy-driven fairness and bandwidth shaping
9. enable clean implementation in safe systems languages such as Rust

## 2.2 Non-Goals

AHP is not intended to:

1. replace a general-purpose filesystem protocol
2. provide arbitrary message-oriented application transport
3. guarantee perfect fairness against every competing flow class
4. require kernel modifications
5. depend on proprietary middleboxes

---

# 3. Protocol Architecture

AHP is divided into four sub-protocol families.

## 3.1 AHP-C: Control Plane

AHP-C defines:

* discovery
* handshake
* authentication
* capability negotiation
* path probing
* manifest negotiation
* checkpoint exchange
* termination
* error signaling

## 3.2 AHP-D: Data Plane

AHP-D defines:

* data framing
* packet numbering
* ACK and NACK signaling
* retransmission logic
* flow control
* pacing
* congestion feedback
* chunk delivery state

## 3.3 AHP-S: Sync Plane

AHP-S defines:

* chunk maps
* region maps
* rolling-signature metadata
* delta announcements
* conflict events
* live update metadata
* file-part repair

## 3.4 AHP-R: Relay and Rendezvous

AHP-R defines:

* endpoint coordination
* NAT traversal hints
* relay use
* fallback mode signaling
* relay-assisted session establishment

---

# 4. Transport Substrate

AHP uses UDP as its underlying transport.

Each session consists of:

* one control association
* one or more data streams
* optional sync streams
* optional relay and keepalive flows

AHP implementations:

* MUST support IPv4 and IPv6 where available
* SHOULD support path MTU adaptation
* SHOULD support UDP socket buffer tuning
* MAY multiplex multiple sessions on a single UDP socket

---

# 5. Security Model

AHP protects:

* confidentiality of payloads
* integrity of packets
* authenticity of peers or servers
* resistance to replay
* secure session resumption
* tamper detection for transfer metadata

AHP does not by itself protect against:

* compromised endpoints
* malicious storage targets after decryption
* application-layer exfiltration by authorized parties

---

# 6. Session Overview

An AHP session progresses through these phases:

1. **DISCOVERY**
2. **HELLO**
3. **CAPABILITY NEGOTIATION**
4. **AUTHENTICATION**
5. **PATH PROBE**
6. **MANIFEST / CHECKPOINT EXCHANGE**
7. **TRANSFER or SYNC**
8. **VERIFY**
9. **FINISH**
10. **TEARDOWN**

A session MAY skip discovery when endpoints are already configured.

---

# 7. Packet Framing

All AHP packets begin with a fixed common header.

## 7.1 Common Header

| Field          |    Size | Description                               |
| -------------- | ------: | ----------------------------------------- |
| Version        |  1 byte | Protocol version                          |
| Packet Type    |  1 byte | AHP packet type                           |
| Flags          | 2 bytes | Bit flags                                 |
| Header Length  | 2 bytes | Bytes of full header including extensions |
| Connection ID  | 8 bytes | Logical session identifier                |
| Stream ID      | 4 bytes | Logical stream                            |
| Packet Number  | 8 bytes | Monotonic per stream or packet space      |
| Timestamp      | 8 bytes | Sender timestamp in microseconds          |
| Payload Length | 4 bytes | Length of encrypted payload               |
| Header CRC     | 4 bytes | CRC32C over header                        |

Total fixed header size: **42 bytes**

Header extensions MAY follow.

Multi-byte integers MUST be network byte order.

## 7.2 Flags

Initial flags:

|   Bit | Name               | Meaning                                |
| ----: | ------------------ | -------------------------------------- |
|     0 | ACK_ELICITING      | Packet should provoke ACK feedback     |
|     1 | RETRANSMIT         | Packet contains retransmitted content  |
|     2 | PROBE              | Packet used for path probing           |
|     3 | FINAL              | Final packet in logical stream segment |
|     4 | COMPRESSED         | Payload compressed                     |
|     5 | ENCRYPTED          | Payload encrypted                      |
|     6 | FEC                | Packet contains FEC data               |
|     7 | CHECKPOINT_RELATED | Packet relates to resume/checkpoint    |
|     8 | LIVE_FILE          | Packet belongs to growing file         |
|     9 | DELTA              | Packet belongs to sync delta           |
| 10-15 | Reserved           | MUST be zero unless negotiated         |

---

# 8. Header Extensions

AHP uses typed header extensions.

Each extension:

| Field      |     Size |
| ---------- | -------: |
| Ext Type   |  2 bytes |
| Ext Length |  2 bytes |
| Ext Value  | variable |

Unknown extensions with the high-order “critical” bit set MUST cause a protocol error unless negotiated.

Suggested extensions:

* Path ID
* Key Phase
* ACK Delay Hint
* Compression Profile ID
* Chunk ID
* Region ID
* File ID
* Watermark Offset
* Relay Path Tag

---

# 9. Packet Types

## 9.1 Control Packet Types

| Type Code | Name           |
| --------: | -------------- |
|      0x01 | HELLO          |
|      0x02 | HELLO_ACK      |
|      0x03 | CAPS           |
|      0x04 | AUTH           |
|      0x05 | AUTH_ACK       |
|      0x06 | PATH_PROBE     |
|      0x07 | PATH_PROBE_ACK |
|      0x08 | MANIFEST       |
|      0x09 | CHECKPOINT     |
|      0x0A | RESUME_REQ     |
|      0x0B | RESUME_ACK     |
|      0x0C | FINISH         |
|      0x0D | ERROR          |
|      0x0E | KEEPALIVE      |
|      0x0F | KEY_UPDATE     |

## 9.2 Data Packet Types

| Type Code | Name          |
| --------: | ------------- |
|      0x20 | DATA          |
|      0x21 | ACK_BITMAP    |
|      0x22 | NACK_RANGE    |
|      0x23 | RATE_HINT     |
|      0x24 | WINDOW_UPDATE |
|      0x25 | CHUNK_COMMIT  |
|      0x26 | CHUNK_REPAIR  |

## 9.3 Sync Packet Types

| Type Code | Name          |
| --------: | ------------- |
|      0x40 | SYNC_ANNOUNCE |
|      0x41 | REGION_MAP    |
|      0x42 | DELTA_MAP     |
|      0x43 | CONFLICT      |
|      0x44 | WATERMARK     |
|      0x45 | LIVE_COMMIT   |

## 9.4 Relay Packet Types

| Type Code | Name            |
| --------: | --------------- |
|      0x60 | RENDEZVOUS      |
|      0x61 | RELAY_ASSIGN    |
|      0x62 | RELAY_FORWARD   |
|      0x63 | RELAY_HEARTBEAT |

---

# 10. TLV Encoding

Most control payloads use TLV fields.

## 10.1 TLV Structure

| Field  |     Size |
| ------ | -------: |
| Type   |  2 bytes |
| Length |  2 bytes |
| Value  | variable |

TLVs MAY appear in any order unless a packet type specifies otherwise.

Unknown non-critical TLVs MUST be ignored.

Unknown critical TLVs MUST cause an `ERROR_UNSUPPORTED_TLV`.

## 10.2 Standard TLVs

| TLV Type | Name                           |
| -------: | ------------------------------ |
|   0x0001 | Endpoint Name                  |
|   0x0002 | Protocol Version List          |
|   0x0003 | Supported Cipher Suites        |
|   0x0004 | Supported Compression Profiles |
|   0x0005 | Congestion Control Profiles    |
|   0x0006 | Max UDP Payload                |
|   0x0007 | Max Streams                    |
|   0x0008 | Authentication Method          |
|   0x0009 | Token                          |
|   0x000A | Nonce                          |
|   0x000B | Public Key                     |
|   0x000C | Signature                      |
|   0x000D | Manifest Hash                  |
|   0x000E | Checkpoint ID                  |
|   0x000F | Chunk Size                     |
|   0x0010 | Region Size                    |
|   0x0011 | File ID                        |
|   0x0012 | File Path                      |
|   0x0013 | File Size                      |
|   0x0014 | Watermark Offset               |
|   0x0015 | Timestamp                      |
|   0x0016 | Error Code                     |
|   0x0017 | Error Detail                   |
|   0x0018 | Resume Ticket                  |
|   0x0019 | Path Token                     |
|   0x001A | Fairness Profile               |
|   0x001B | Feature Bitmap                 |

---

# 11. Session Establishment

## 11.1 HELLO

The initiator sends `HELLO` containing:

* supported protocol versions
* random nonce
* supported cipher suites
* supported compression profiles
* supported congestion control profiles
* max streams
* max UDP payload
* optional token or identity hints

## 11.2 HELLO_ACK

The responder replies with:

* negotiated crypto mode (1 byte, first byte of the payload):
  * `0x00` plaintext
  * `0x01` full X25519 handshake — followed by the responder's 32-byte public key and 16-byte nonce; when the responder has an Ed25519 identity it additionally appends its 32-byte identity public key and a 64-byte Ed25519 signature over the handshake transcript (see §12.2)
  * `0x02` 0-RTT resume — a fresh 16-byte server nonce, mixed into the resumed key derivation
* data port (2 bytes, big-endian, last two bytes of the payload); a bare
  "busy" acknowledgement MAY carry only the mode byte
* selected version
* responder nonce
* selected core features
* selected cipher suite
* selected compression profile
* selected congestion profile
* optional path token

The crypto-mode byte makes the negotiated mode explicit so the initiator can
detect a mismatch — e.g. the responder rejected a resume ticket (normal after
a responder restart, since ticket keys are per-instance) and fell back to
plaintext. On mismatch the initiator MUST abort the transfer (evicting the
stale ticket so the next attempt performs a full handshake); it MUST NOT
stream data in a mode the responder did not select.

## 11.3 CAPS

Both sides exchange `CAPS` to finalize parameters such as:

* maximum concurrent streams
* chunk size policy
* checkpoint capabilities
* delta sync capability
* live file capability
* relay capability
* fallback transport capability

After `CAPS`, peers enter authentication.

---

# 12. Authentication

AHP MUST support at least one server-authenticated handshake. It SHOULD support mutual authentication.

## 12.1 Authentication Modes

Negotiated modes MAY include:

* `ANON_TOKEN`
* `PSK`
* `X25519_EPHEMERAL + SIGNATURE`
* `MTLS_GATEWAY_ASSISTED`
* `JWT_TOKEN_BOUND`

## 12.2 Recommended Baseline

The baseline secure mode is:

* ephemeral X25519 key exchange
* Ed25519 signature for endpoint authentication
* HKDF-SHA-256 key derivation
* AES-256-GCM for packet protection

Implementation note (Favonius): rather than separate `AUTH`/`AUTH_ACK`
packets, the responder piggybacks authentication on `HELLO_ACK` (mode
`0x01`): it appends its Ed25519 identity public key and a signature over the
transcript `"AHP-HANDSHAKE-SIG-v1" || server DH pubkey || client DH pubkey ||
len(server nonce) || server nonce || len(client nonce) || client nonce`
(see `ahp_crypto::signatures`). A pinning initiator MUST verify both the
presented identity against its pin and the signature before deriving session
keys, and MUST abort on any failure (§12.4). Resumed (0-RTT) sessions inherit
authentication from the ticket-issuing handshake; the identity is not
re-verified on resume (ticket keys are per-instance, so a responder restart
fails safe: the ticket is rejected and the initiator aborts on the mode
mismatch, forcing a full authenticated handshake).

## 12.3 AUTH Packet

`AUTH` includes:

* endpoint public key or certificate reference
* authentication token if applicable
* transcript hash
* endpoint signature over transcript
* optional resume ticket

## 12.4 AUTH_ACK

`AUTH_ACK` confirms:

* authenticated identity
* authorization result
* session key phase
* accepted resume privileges

Failure MUST terminate the session with `ERROR_AUTH_FAILED`.

---

# 13. Key Schedule

## 13.1 Inputs

The session key schedule is derived from:

* initiator nonce
* responder nonce
* ECDH shared secret
* transcript hash
* optional PSK or ticket secret

## 13.2 Derived Secrets

AHP derives:

* control plane encryption key
* data plane encryption key
* sync plane encryption key
* header protection key if used
* rekey secret
* resume secret

## 13.3 Rekey

Endpoints SHOULD rekey:

* after configurable byte thresholds
* after configurable time thresholds
* when key compromise suspicion exists

`KEY_UPDATE` announces new key phase.

Packets with unknown key phases MAY be buffered briefly and then rejected.

---

# 14. Encryption and Integrity

## 14.1 Mandatory Cipher Suite

Initial mandatory-to-implement suite:

* `X25519`
* `HKDF-SHA-256`
* `AES-256-GCM`
* `Ed25519`

## 14.2 Optional Cipher Suites

Optional:

* `X25519 + ChaCha20-Poly1305 + Ed25519`
* `P-256 + AES-256-GCM + ECDSA-P256`

## 14.3 Nonce Construction

Per-packet nonces MUST be unique within a key phase.

Recommended construction:

`nonce = session_nonce_prefix XOR packet_number`

If stream-scoped packet spaces are used, the construction MUST include stream identifier or derive per-stream subkeys.

## 14.4 Associated Data

Authenticated associated data MUST include:

* fixed header
* header extensions
* key phase
* stream ID
* connection ID

---

# 15. Path Probing and MTU Selection

## 15.1 Probe Phase

After authentication, endpoints SHOULD perform path probing.

Goals:

* estimate RTT
* estimate reordering
* estimate loss
* determine safe datagram payload
* seed congestion control

## 15.2 Probe Packets

`PATH_PROBE` and `PATH_PROBE_ACK` include:

* probe ID
* sent timestamp
* payload size
* path token if used

## 15.3 MTU Rules

Implementations:

* MUST avoid IP fragmentation where possible
* SHOULD begin conservatively
* SHOULD increase payload size gradually
* MUST fall back on probe loss or ICMP evidence where available

A default safe encrypted UDP payload of about 1200 bytes is RECOMMENDED for initial establishment, with larger payloads negotiated later.

---

# 16. Stream Model

A session consists of logical streams identified by `Stream ID`.

## 16.1 Stream Classes

| Stream Class | Purpose               |
| ------------ | --------------------- |
| 0            | Control               |
| 1            | Manifest              |
| 2+           | Data streams          |
| high range   | Sync streams          |
| reserved     | Relay and diagnostics |

## 16.2 Ordering Rules

AHP does not require global in-order delivery across streams.

Within a stream:

* packet numbering MUST be monotonic
* delivery MAY be out of order internally
* chunk assembly MUST respect chunk boundaries and integrity rules

## 16.3 Parallelism

Endpoints MAY send different files or chunks across multiple streams.

Implementations SHOULD permit dynamic stream assignment based on:

* file size
* priority
* disk readiness
* loss/retransmit pressure
* fairness profile

---

# 17. Manifest Exchange

Before data transfer, peers exchange a `MANIFEST`.

## 17.1 Manifest Content

A manifest includes:

* transfer ID
* transfer mode: bulk, sync, live
* file list
* per-file metadata
* file IDs
* file sizes
* chunking policy
* optional region map root hash
* permissions/timestamps if enabled
* overall manifest hash
* optional signature

## 17.2 File Metadata

Per file, the sender SHOULD include:

* logical path
* file type
* file size
* modified time
* whole-file hash if available
* chunk size
* chunk count
* chunk hash list or root hash
* sparse file metadata if applicable
* appendable/live flag if applicable

## 17.3 Manifest Compression

Large manifests SHOULD be compressed.

---

# 18. Chunking

## 18.1 Chunk Definition

A chunk is the primary transport and checkpoint unit.

Chunks SHOULD be large enough to reduce protocol overhead but small enough to allow fine resume granularity.

Recommended initial sizes:

* 1 MiB on moderate-speed links
* 4 MiB on faster links
* adaptive scaling up to 16 MiB for very high-speed links

## 18.2 Region Definition

A region is a smaller subunit within a chunk for sync or repair operations.

Recommended region sizes:

* 64 KiB
* 128 KiB
* 256 KiB

## 18.3 Chunk Identifiers

Each chunk is identified by:

* File ID
* Chunk Index

Each region is identified by:

* File ID
* Chunk Index
* Region Index

---

# 19. Data Transfer Semantics

## 19.1 DATA Payload

Each `DATA` packet payload MUST identify:

* File ID
* Chunk Index
* Byte Offset within chunk
* Payload bytes
* optional region marker
* optional compression marker if payload-local

## 19.2 Chunk Assembly

The receiver:

1. places packet payload into reassembly buffer
2. tracks received ranges
3. identifies missing ranges
4. verifies chunk integrity when complete
5. commits chunk to storage
6. updates checkpoint state

## 19.3 Commit Rules

A chunk MUST NOT be reported as complete until:

* all bytes are present
* integrity check passes
* storage commit policy succeeds

---

# 20. Acknowledgement Model

AHP uses explicit receiver feedback.

## 20.1 ACK_BITMAP

`ACK_BITMAP` acknowledges a base packet number and a bitmap of following packet numbers.

Fields:

* Stream ID
* Base Packet Number
* Bitmap Length
* Bitmap Data
* Highest Contiguous Packet
* ACK Delay

## 20.2 NACK_RANGE

`NACK_RANGE` reports missing packet ranges.

Fields:

* Stream ID
* Range Count
* Missing Ranges

## 20.3 ACK Frequency

Receivers SHOULD ACK frequently enough to support timely recovery but SHOULD avoid excessive control traffic.

ACK frequency MAY be adapted based on:

* sending rate
* packet loss
* RTT
* reordering depth
* fairness mode

---

# 21. Retransmission

## 21.1 Trigger Conditions

Retransmission MAY be triggered by:

* NACK receipt
* ACK gap heuristics
* timeout
* chunk completion stall
* finish-time repair sweep

## 21.2 Retransmission Priority

Priority SHOULD be:

1. packets blocking chunk completion
2. packets needed for live/growing file consumer progress
3. older missing packets
4. lower-priority outstanding packets

## 21.3 Retransmission Timing

Implementations SHOULD avoid naive timeout-only retransmission.

They SHOULD use:

* NACK-driven fast repair
* RTT-adaptive timers
* limited speculative retransmission in persistent uncertainty

---

# 22. Congestion Control

AHP uses pluggable congestion control.

## 22.1 Required Properties

Any congestion algorithm used in AHP MUST:

* react to persistent loss
* react to increasing queue delay
* support paced transmission
* expose current send rate
* avoid uncontrolled bursts

## 22.2 Standard Profiles

### AHP-Classic

Hybrid delay and rate-based.

### AHP-Model

Bandwidth/RTT model-based.

### AHP-Fair

Conservative mode intended for mixed-use networks.

## 22.3 Sender Inputs

Senders SHOULD consider:

* RTT estimate
* one-way delay estimate if clocks allow
* loss rate
* delivery rate
* ACK arrival pattern
* receiver flow control
* disk I/O backlog
* CPU contention

## 22.4 Pacing

AHP senders MUST pace packets.

Burst size SHOULD be limited based on:

* path RTT
* MTU
* pacing quantum
* retransmission pressure
* fairness policy

---

# 23. Flow Control

AHP has receiver-advertised flow control separate from congestion control.

## 23.1 Receiver Window

Receiver indicates available reassembly/storage capacity via `WINDOW_UPDATE`.

The sender MUST respect the lower of:

* congestion-allowed inflight
* receiver-advertised window

## 23.2 Window Dimensions

Receivers MAY express window in:

* bytes
* chunks
* regions

The negotiated mode MUST be explicit.

---

# 24. Checkpoint and Resume

Checkpoint restart is a first-class feature.

## 24.1 Checkpoint State

Checkpoint state SHOULD include:

* transfer ID
* manifest hash
* per-file completion state
* per-chunk verified completion
* partial chunk range maps
* encryption key phase compatibility info
* last stable watermarks for live files
* chunk hashes or roots
* transfer mode
* last session timestamp

## 24.2 CHECKPOINT Packet

A `CHECKPOINT` packet MAY carry:

* checkpoint ID
* manifest hash
* file completion summaries
* live watermark state
* resume ticket reference

## 24.3 Resume Procedure

A resume proceeds as follows:

1. endpoint reconnects
2. `RESUME_REQ` includes transfer ID, checkpoint ID, manifest hash, and resume ticket
3. peer validates authorization and checkpoint compatibility
4. peer replies `RESUME_ACK` with accepted checkpoint scope
5. sender resumes missing chunk and region ranges only

## 24.4 Resume Compatibility

Resume MUST fail if:

* transfer identity mismatches
* manifest incompatibility is severe
* authorization no longer permits access
* checkpoint integrity fails

Resume MAY degrade to partial restart if:

* manifest differs only on non-transferred files
* live file watermark advanced
* chunking policy remains compatible

---

# 25. Growing Files

AHP supports files that are actively being written while transfer is in progress.

## 25.1 Live File Rules

A live file transfer MUST include:

* appendable flag
* current stable watermark
* final-close indication when writing ends

## 25.2 WATERMARK Packet

`WATERMARK` carries:

* File ID
* stable offset
* optional estimated finality state
* generation counter

## 25.3 Receiver Behavior

Receiver MAY expose received bytes up to the last verified stable watermark.

Receiver MUST NOT treat a live file as complete until `LIVE_COMMIT` or final manifest closure is received.

---

# 26. Synchronization

AHP-S defines synchronization and delta transfer.

## 26.1 Sync Modes

* one-way sync
* two-way sync
* fan-out sync
* append-only sync
* live collaborative file update with conflict-safe rules

## 26.2 Change Detection

This RFC does not mandate one algorithm, but endpoints SHOULD support:

* fixed chunk comparison
* content-defined chunking for delta mode
* region hashing
* rolling signatures
* reconcile scans

## 26.3 DELTA_MAP

A `DELTA_MAP` identifies changed regions.

Fields include:

* File ID
* base version identifier
* region size
* changed region count
* changed ranges
* optional hash list

## 26.4 REGION_MAP

`REGION_MAP` MAY carry:

* Merkle subtree hashes
* region fingerprints
* sparse file extents
* invalidated ranges
* append ranges

## 26.5 Conflict Signaling

In two-way sync, conflicting edits MUST generate `CONFLICT` unless a different conflict policy was explicitly negotiated.

Conflict policies MAY include:

* safe-copy
* last-writer-wins
* append-merge
* application-defined external resolver

---

# 27. Integrity Verification

## 27.1 Chunk Integrity

Every completed chunk MUST be verified using a negotiated hash.

Recommended default:

* BLAKE3 for internal chunk hashing
* SHA-256 MAY be used for interoperability-oriented external manifests

## 27.2 Whole-File Integrity

Whole-file integrity SHOULD be verified at transfer completion when available.

## 27.3 Manifest Integrity

Manifest integrity MUST be protected by:

* authenticated transport
* manifest hash
* optional manifest signature

---

# 28. Compression

Compression is negotiated per session and may vary per file or chunk group.

## 28.1 Profiles

Standard initial profiles:

* `NONE`
* `ZSTD_FAST`
* `ZSTD_BALANCED`
* `ZSTD_STREAMING`

## 28.2 Compression Rules

Senders SHOULD avoid compressing:

* already compressed media
* encrypted containers
* random/high-entropy files

Senders MAY decide based on:

* sample entropy
* MIME/type hints
* user policy
* CPU availability
* bandwidth pressure

## 28.3 Signaling

Compression use MUST be signaled either:

* in packet flags plus profile ID
* or in stream/chunk metadata

---

# 29. Error Handling

## 29.1 ERROR Packet

An `ERROR` packet includes:

* error code
* severity
* offending stream if any
* optional packet number
* optional descriptive string
* retryability flag

## 29.2 Standard Error Codes

|   Code | Name                        |
| -----: | --------------------------- |
| 0x0001 | ERROR_UNSUPPORTED_VERSION   |
| 0x0002 | ERROR_UNSUPPORTED_FEATURE   |
| 0x0003 | ERROR_AUTH_FAILED           |
| 0x0004 | ERROR_PERMISSION_DENIED     |
| 0x0005 | ERROR_BAD_MANIFEST          |
| 0x0006 | ERROR_CHECKPOINT_INVALID    |
| 0x0007 | ERROR_PACKET_DECRYPT_FAILED |
| 0x0008 | ERROR_FLOW_CONTROL          |
| 0x0009 | ERROR_PROTOCOL_VIOLATION    |
| 0x000A | ERROR_PATH_FAILURE          |
| 0x000B | ERROR_STORAGE_FAILURE       |
| 0x000C | ERROR_CONFLICT              |
| 0x000D | ERROR_RELAY_UNAVAILABLE     |

## 29.3 Error Behavior

Critical protocol errors MUST terminate the affected session.

Recoverable transfer errors MAY terminate only the affected stream or transfer unit.

---

# 30. Keepalive and Idle Timeout

## 30.1 KEEPALIVE

Endpoints MAY send `KEEPALIVE` during idle periods.

A keepalive SHOULD include:

* connection ID
* last observed packet number
* current key phase
* optional RTT echo

## 30.2 Idle Timeout

Endpoints MUST negotiate idle timeout.

If no traffic or keepalive is seen within timeout, the session MAY be declared dead.

Receivers SHOULD allow longer idle windows during checkpointed pause mode.

---

# 31. Relay and Rendezvous

AHP-R provides mechanisms for indirect connectivity.

## 31.1 RENDEZVOUS

Used to coordinate peer addresses, tokens, and expected path identifiers.

## 31.2 RELAY_ASSIGN

A relay may assign:

* relay session ID
* relay path
* relay token
* expiration
* bandwidth class

## 31.3 RELAY_FORWARD

Relay-forwarded packets MUST preserve end-to-end encryption semantics where possible.

Relays SHOULD avoid decrypting data-plane payloads.

---

# 32. Version Negotiation

## 32.1 Version Rules

Peers advertise supported versions in `HELLO`.

If no compatible version exists, the responder MUST send `ERROR_UNSUPPORTED_VERSION`.

## 32.2 Minor Evolution

New TLVs, packet types, and profiles MAY be added without changing major version if forward-compatibility rules are respected.

Critical wire-format changes MUST require version increment.

---

# 33. State Machines

## 33.1 Session State Machine

```text
IDLE
  -> DISCOVERING
  -> HELLO_SENT
  -> HELLO_CONFIRMED
  -> CAPS_NEGOTIATING
  -> AUTHENTICATING
  -> PATH_PROBING
  -> READY
  -> TRANSFERRING / SYNCING / LIVE
  -> VERIFYING
  -> FINISHING
  -> CLOSED
```

On fatal error:

```text
ANY_ACTIVE_STATE -> ERROR -> CLOSED
```

## 33.2 Transfer State Machine

```text
NEW
 -> MANIFESTED
 -> QUEUED
 -> ACTIVE
 -> PARTIAL
 -> PAUSED
 -> RESUMING
 -> COMPLETE
 -> VERIFIED
 -> FAILED
 -> ABORTED
```

## 33.3 Chunk State Machine

```text
EMPTY
 -> PARTIAL
 -> COMPLETE_UNVERIFIED
 -> VERIFIED
 -> COMMITTED
```

If integrity fails:

```text
COMPLETE_UNVERIFIED -> REPAIR_PENDING
```

---

# 34. Recommended Defaults

Initial recommended defaults:

| Parameter                   | Default                                   |
| --------------------------- | ----------------------------------------- |
| Initial safe UDP payload    | 1200 bytes                                |
| Initial chunk size          | 1 MiB                                     |
| Initial region size         | 128 KiB                                   |
| Initial ACK interval        | 1 to 4 packets or short timer             |
| Initial idle timeout        | 30 s                                      |
| Rekey threshold             | configurable, e.g. per many GiB or 1 hour |
| Initial congestion profile  | AHP-Classic                               |
| Initial compression profile | auto                                      |
| Initial fairness            | balanced                                  |

These are deployment defaults, not wire requirements.

---

# 35. Wire Examples

## 35.1 Simplified HELLO Flow

```text
Initiator -> HELLO
  versions=[1]
  ciphers=[X25519_AES256GCM_ED25519]
  compression=[NONE,ZSTD_FAST,ZSTD_BALANCED]
  cc=[CLASSIC,MODEL,FAIR]
  nonce=Ni

Responder -> HELLO_ACK
  version=1
  cipher=X25519_AES256GCM_ED25519
  compression=ZSTD_BALANCED
  cc=CLASSIC
  nonce=Nr
```

## 35.2 Resume Flow

```text
Client -> RESUME_REQ
  transfer_id=T123
  checkpoint_id=C77
  manifest_hash=abc...
  ticket=...

Server -> RESUME_ACK
  accepted_checkpoint=C77
  missing_chunks=[file3:10-14, file8:0, file8:9]
  live_watermark[file12]=8388608
```

---

# 36. Implementation Guidance for Rust

## 36.1 Recommended Crate Split

The split used by the reference implementation:

* `ahp-proto` — wire format, codecs, packet types
* `ahp-crypto` — handshake, AEAD, header protection, key rotation, tickets
* `ahp-congestion` — congestion-control profiles
* `ahp-sync` — Merkle tree for resume verification
* `ahp-compression` — per-chunk compression
* `ahp-platform-net` — platform send-path abstraction
* `ahp-xdp` — optional kernel-bypass transport
* `ahp-policy` — adaptive parameter selection
* `ahp-observability` — logging and metrics
* `ahp-cli` — sender
* `ahp-daemon` — receiver
* `ahp-api` — HTTP control surface

An earlier revision of this section also recommended `ahp-control`,
`ahp-data`, `ahp-relay`, `ahp-checkpoint` and `ahp-storage`. Those were
implemented and then removed: nothing in the production path called them.
The functions they were meant to hold live in `ahp-cli` and `ahp-daemon`
instead, because the control and data planes are two sockets in one
process rather than two components. Implementers are free to split
differently; the protocol does not depend on it.

## 36.2 Packet Codec Guidance

Implementations SHOULD:

* use zero-copy decoding where safe
* isolate packet parsing from transport logic
* fuzz all parsers
* validate lengths before allocation
* avoid panics on malformed input

## 36.3 Async Model

A practical model is:

* one session actor
* one pacing scheduler
* N stream workers
* one checkpoint journal task
* one receive demux task
* bounded channels between components

---

# 37. IANA-Style Considerations

If later formalized, AHP would likely require registries for:

* packet types
* TLV types
* cipher suites
* compression profiles
* congestion-control profiles
* error codes
* feature bits

For now, these registries are project-maintained.

---

# 38. Security Considerations

Implementers MUST pay attention to:

* nonce reuse prevention
* replay windows
* amplification limits before authentication
* CPU exhaustion from bogus control packets
* memory exhaustion from pathological manifests
* path spoofing during probe phase
* ticket theft and resume abuse
* chunk hash collision assumptions
* key rotation and secure storage of identities
* metadata leakage through logs

Before authentication, responders MUST limit amplification. A responder SHOULD avoid sending significantly more bytes than it received from an unvalidated source.

Resume tickets SHOULD be short-lived and audience-bound.

Sensitive file paths SHOULD be redactable in logs.

---

# 39. Privacy Considerations

Even with encrypted payloads, metadata may reveal:

* endpoint addresses
* transfer timing
* packet sizes
* approximate transfer volume
* number of files

Implementations SHOULD consider:

* optional path redaction
* padded control messages
* configurable filename minimization in manifests
* access-controlled audit logs

---

# 40. Interoperability Considerations

AHP does not assume interoperability with proprietary accelerated transfer protocols.

Interoperability within AHP requires:

* identical packet framing rules
* compatible cipher suite support
* agreed chunk and manifest semantics
* version-compatible checkpoint format
* aligned sync conflict semantics

To preserve interoperability, implementations SHOULD:

* publish supported profile sets
* avoid undocumented private TLVs in community wire mode
* provide conformance tests

---

# 41. Conformance Levels

## 41.1 AHP Core

A conforming AHP Core implementation MUST support:

* HELLO / HELLO_ACK
* CAPS
* AUTH / AUTH_ACK
* DATA
* ACK_BITMAP
* CHECKPOINT
* FINISH
* ERROR
* AES-256-GCM baseline suite
* chunk-level transfer and resume

## 41.2 AHP Sync

A conforming AHP Sync implementation MUST additionally support:

* DELTA_MAP
* REGION_MAP
* CONFLICT
* region-level transfer semantics

## 41.3 AHP Live

A conforming AHP Live implementation MUST additionally support:

* WATERMARK
* LIVE_COMMIT
* appendable file semantics

---

# 42. Open Questions for `draft-ahp-01`

These are the most important areas to settle next:

1. **Packet number space**

   * per-stream vs per-session

2. **ACK encoding**

   * bitmap only vs bitmap + ranges hybrid

3. **Manifest format**

   * compact binary only vs JSON/CBOR gateway representation

4. **Chunk hash algorithm policy**

   * BLAKE3 internal baseline, SHA-256 external optional

5. **Path probing**

   * fully custom or partially QUIC-inspired logic

6. **Control-plane transport**

   * raw AHP-C over UDP only, or optional QUIC-assisted mode outside the core RFC

7. **FEC**

   * mandatory none in v1, optional extension later

8. **Multipath**

   * extension phase or v2

---

# 43. Minimal Compliance Test Matrix

Any reference implementation should test at least:

* authenticated session establishment
* failed authentication rejection
* MTU adaptation
* 1-file bulk transfer
* directory transfer
* interrupted transfer resume
* corrupted packet rejection
* retransmission under 1% loss
* sync changed-region transfer
* live/growing file watermark updates
* key update mid-transfer
* relay-assisted transfer
* downgrade protection on version/cipher negotiation

---

# 44. Example Appendix: Binary Layout Sketches

## 44.1 ACK_BITMAP Payload Sketch

| Field               |     Size |
| ------------------- | -------: |
| Acked Stream ID     |        4 |
| Base Packet Number  |        8 |
| Highest Contiguous  |        8 |
| Ack Delay Micros    |        4 |
| Bitmap Length Bytes |        2 |
| Bitmap              | variable |

## 44.2 DATA Payload Sketch

| Field               |     Size |
| ------------------- | -------: |
| File ID             |        8 |
| Chunk Index         |        8 |
| Chunk Offset        |        4 |
| Logical Data Length |        2 |
| Payload Bytes       | variable |

## 44.3 WATERMARK Payload Sketch

| Field            | Size |
| ---------------- | ---: |
| File ID          |    8 |
| Stable Watermark |    8 |
| Generation       |    4 |
| Flags            |    2 |

---

# 45. Summary

AHP defines an original, high-performance, secure UDP-based transport suitable for:

* WAN-optimized file transfer
* resumable transfers
* partial-file repair
* growing file delivery
* real-time synchronization of changed file parts

Its center of gravity is simple:

* secure session
* adaptive rate control
* chunk-based transfer
* region-aware sync
* first-class checkpointing

That gives the protocol a sturdy spine instead of a bag of unrelated tricks.

