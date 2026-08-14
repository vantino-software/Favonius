// Favonius — high-performance file transfer over UDP
// Copyright (c) 2025-2026 Vantino SàRL
// SPDX-License-Identifier: Apache-2.0

//! macOS backend: parallel sendmsg with worker threads.
//!
//! macOS has no UDP segmentation offload (no GSO/USO equivalent at the
//! BSD socket layer). The only way to scale UDP send throughput on macOS
//! is to parallelize across multiple worker threads, each running a tight
//! sendto loop. The kernel processes them concurrently across CPU cores.

mod parallel_sendmsg;
mod recvmsg;

pub use parallel_sendmsg::ParallelSendmsgBatchSender;
pub use recvmsg::RecvmsgReceiver;
