// Favonius — high-performance file transfer over UDP
// Copyright (c) 2025-2026 Vantino SàRL
// SPDX-License-Identifier: Apache-2.0

//! Tests for the API hardening: bearer auth, same-path rejection, and
//! mutex-poisoning recovery.

use ahp_api::{api_router, AppState};
use reqwest::Client;

/// Spawn an API server with the given state on a random port.
async fn spawn_server(state: AppState) -> String {
    let app = api_router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let base_url = format!("http://{}", addr);
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    base_url
}

#[tokio::test]
async fn bearer_token_required_when_configured() {
    let state = AppState::new(4).with_token("s3cret");
    let base_url = spawn_server(state).await;
    let client = Client::new();

    // No header -> 401
    let resp = client
        .get(format!("{}/transfers", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);

    // Wrong token -> 401
    let resp = client
        .get(format!("{}/transfers", base_url))
        .bearer_auth("wrong")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);

    // Correct token -> 200
    let resp = client
        .get(format!("{}/transfers", base_url))
        .bearer_auth("s3cret")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // /metrics is protected too.
    let resp = client
        .get(format!("{}/metrics", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);

    // /health stays open for liveness probes.
    let resp = client
        .get(format!("{}/health", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn no_token_configured_allows_requests() {
    // Warn-and-allow mode for loopback-only deployments.
    let state = AppState::new(4).with_token("");
    assert!(state.auth_token().is_none());
    let base_url = spawn_server(state).await;
    let client = Client::new();

    let resp = client
        .get(format!("{}/transfers", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn same_source_and_destination_rejected() {
    let state = AppState::new(4).with_token("");
    let base_url = spawn_server(state).await;
    let client = Client::new();

    let dir = std::env::temp_dir().join(format!("ahp_api_samepath_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("data.bin");
    std::fs::write(&file, b"precious data").unwrap();
    let path = file.to_string_lossy().to_string();

    // source == destination must be rejected, not truncated.
    let resp = client
        .post(format!("{}/transfers", base_url))
        .json(&serde_json::json!({"source": path, "destination": path}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
    assert_eq!(std::fs::read(&file).unwrap(), b"precious data");

    // Same file spelled differently (`.`) is still the same file.
    let dotted = format!("{}/./data.bin", dir.to_string_lossy());
    let resp = client
        .post(format!("{}/transfers", base_url))
        .json(&serde_json::json!({"source": path, "destination": dotted}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);

    // Destination inside the source directory is rejected.
    let inside = dir.join("nested").join("copy.bin").to_string_lossy().to_string();
    let resp = client
        .post(format!("{}/transfers", base_url))
        .json(&serde_json::json!({
            "source": dir.to_string_lossy(),
            "destination": inside,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);

    // Distinct paths are accepted.
    let other = dir.join("other.bin").to_string_lossy().to_string();
    let resp = client
        .post(format!("{}/transfers", base_url))
        .json(&serde_json::json!({"source": path, "destination": other}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn poisoned_engine_mutex_does_not_wedge_server() {
    let state = AppState::new(4).with_token("");

    // Poison the engine mutex: a panic while holding the guard.
    let engine = state.engine.clone();
    let handle = std::thread::spawn(move || {
        let _guard = engine.lock().unwrap();
        panic!("simulated handler panic");
    });
    let _ = handle.join();
    assert!(state.engine.lock().is_err(), "mutex should be poisoned");

    let base_url = spawn_server(state).await;
    let client = Client::new();

    // Handlers recover from poisoning instead of panicking forever.
    let resp = client
        .get(format!("{}/transfers", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let transfers: Vec<ahp_api::TransferResponse> = resp.json().await.unwrap();
    assert!(transfers.is_empty());
}
