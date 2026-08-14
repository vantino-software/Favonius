// Favonius — high-performance file transfer over UDP
// Copyright (c) 2025-2026 Vantino SàRL
// SPDX-License-Identifier: Apache-2.0

pub mod net_receiver;

use ahp_api::AppState;
use tokio::net::TcpListener;

/// Start the API server on the given listener. Returns when the server shuts
/// down. Delegates to [`ahp_api::serve`], which refuses a non-loopback bind
/// without a bearer token.
pub async fn start_server(listener: TcpListener, state: AppState) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    ahp_api::serve(listener, state).await
}
