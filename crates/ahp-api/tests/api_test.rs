// Favonius — high-performance file transfer over UDP
// Copyright (c) 2025-2026 Vantino SàRL
// SPDX-License-Identifier: Apache-2.0

use ahp_api::{AppState, CreateTransferRequest, TransferResponse};
use reqwest::Client;

/// Spawn an API server on a random port and return the base URL.
async fn spawn_server() -> String {
    let state = AppState::new(10);
    let app = ahp_api::api_router(state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let base_url = format!("http://{}", addr);

    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    base_url
}

/// Spawn a server with shared state so we can reuse it across requests.
async fn spawn_server_with_state(state: AppState) -> String {
    let app = ahp_api::api_router(state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let base_url = format!("http://{}", addr);

    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    base_url
}

#[tokio::test]
async fn test_health_check() {
    let base_url = spawn_server().await;
    let client = Client::new();

    let resp = client
        .get(format!("{}/health", base_url))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "ok");

    println!("test_health_check: PASSED");
}

#[tokio::test]
async fn test_create_and_list_transfers() {
    let state = AppState::new(10);
    let base_url = spawn_server_with_state(state).await;
    let client = Client::new();

    // Create a transfer
    let create_req = CreateTransferRequest {
        source: "/data/source".to_string(),
        destination: "/data/dest".to_string(),
        compression: Some(true),
        encryption: Some(false),
    };

    let resp = client
        .post(format!("{}/transfers", base_url))
        .json(&serde_json::json!({
            "source": create_req.source,
            "destination": create_req.destination,
            "compression": create_req.compression,
            "encryption": create_req.encryption,
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 201, "Expected 201 Created");

    let created: TransferResponse = resp.json().await.unwrap();
    assert!(!created.id.is_empty(), "Expected non-empty UUID");
    assert_eq!(created.state, "New");
    assert_eq!(created.source, "/data/source");
    assert_eq!(created.destination, "/data/dest");
    println!("Created transfer with id: {}", created.id);

    // List transfers
    let resp = client
        .get(format!("{}/transfers", base_url))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);

    let transfers: Vec<TransferResponse> = resp.json().await.unwrap();
    assert_eq!(transfers.len(), 1, "Expected exactly 1 transfer");
    assert_eq!(transfers[0].id, created.id);

    println!("test_create_and_list_transfers: PASSED");
}

#[tokio::test]
async fn test_get_transfer() {
    let state = AppState::new(10);
    let base_url = spawn_server_with_state(state).await;
    let client = Client::new();

    // Create a transfer first
    let resp = client
        .post(format!("{}/transfers", base_url))
        .json(&serde_json::json!({
            "source": "/tmp/src",
            "destination": "/tmp/dst",
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 201);
    let created: TransferResponse = resp.json().await.unwrap();

    // Get the transfer by ID
    let resp = client
        .get(format!("{}/transfers/{}", base_url, created.id))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);

    let fetched: TransferResponse = resp.json().await.unwrap();
    assert_eq!(fetched.id, created.id);
    assert_eq!(fetched.source, "/tmp/src");
    assert_eq!(fetched.destination, "/tmp/dst");
    // Background task may have already failed (source doesn't exist).
    assert!(
        fetched.state == "New" || fetched.state == "Active" || fetched.state == "Failed",
        "Unexpected state: {}",
        fetched.state,
    );

    println!("test_get_transfer: PASSED");
}

#[tokio::test]
async fn test_get_nonexistent_transfer() {
    let base_url = spawn_server().await;
    let client = Client::new();

    let resp = client
        .get(format!("{}/transfers/nonexistent-id-12345", base_url))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 404, "Expected 404 for nonexistent transfer");

    println!("test_get_nonexistent_transfer: PASSED");
}

#[tokio::test]
async fn test_resume_transfer() {
    let state = AppState::new(10);
    let base_url = spawn_server_with_state(state).await;
    let client = Client::new();

    // Create a transfer
    let resp = client
        .post(format!("{}/transfers", base_url))
        .json(&serde_json::json!({
            "source": "/mnt/a",
            "destination": "/mnt/b",
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 201);
    let created: TransferResponse = resp.json().await.unwrap();
    assert_eq!(created.state, "New");

    // Resume the transfer
    let resp = client
        .post(format!("{}/transfers/{}/resume", base_url, created.id))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);

    let resumed: TransferResponse = resp.json().await.unwrap();
    assert_eq!(resumed.id, created.id);
    assert_eq!(resumed.state, "Resuming", "Expected state to be Resuming after resume");

    // Verify the state via GET (background task may race with resume).
    let resp = client
        .get(format!("{}/transfers/{}", base_url, created.id))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let fetched: TransferResponse = resp.json().await.unwrap();
    assert!(
        fetched.state == "Resuming" || fetched.state == "Failed",
        "Expected Resuming or Failed, got {}",
        fetched.state,
    );

    println!("test_resume_transfer: PASSED");
}

#[tokio::test]
async fn test_resume_nonexistent_transfer() {
    let base_url = spawn_server().await;
    let client = Client::new();

    let resp = client
        .post(format!("{}/transfers/does-not-exist/resume", base_url))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 404, "Expected 404 for resuming nonexistent transfer");

    println!("test_resume_nonexistent_transfer: PASSED");
}

#[tokio::test]
async fn test_full_workflow() {
    let state = AppState::new(10);
    let base_url = spawn_server_with_state(state).await;
    let client = Client::new();

    // Create three transfers
    let mut ids = Vec::new();
    for i in 0..3 {
        let resp = client
            .post(format!("{}/transfers", base_url))
            .json(&serde_json::json!({
                "source": format!("/data/source_{}", i),
                "destination": format!("/data/dest_{}", i),
            }))
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), 201);
        let created: TransferResponse = resp.json().await.unwrap();
        assert_eq!(created.state, "New");
        println!("Created transfer {}: {}", i, created.id);
        ids.push(created.id);
    }

    // List all transfers and verify count
    let resp = client
        .get(format!("{}/transfers", base_url))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let transfers: Vec<TransferResponse> = resp.json().await.unwrap();
    assert_eq!(transfers.len(), 3, "Expected 3 transfers");

    // Get each transfer individually
    for (i, id) in ids.iter().enumerate() {
        let resp = client
            .get(format!("{}/transfers/{}", base_url, id))
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), 200);
        let t: TransferResponse = resp.json().await.unwrap();
        assert_eq!(t.id, *id);
        assert_eq!(t.source, format!("/data/source_{}", i));
        assert_eq!(t.destination, format!("/data/dest_{}", i));
        // Background task may have already failed (source doesn't exist).
        assert!(
            t.state == "New" || t.state == "Active" || t.state == "Failed",
            "Transfer {} unexpected state: {}",
            i, t.state,
        );
    }

    // Resume the second transfer
    let resp = client
        .post(format!("{}/transfers/{}/resume", base_url, ids[1]))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let resumed: TransferResponse = resp.json().await.unwrap();
    assert_eq!(resumed.state, "Resuming");

    // Verify states: second is Resuming, others may be New/Active/Failed.
    for (i, id) in ids.iter().enumerate() {
        let resp = client
            .get(format!("{}/transfers/{}", base_url, id))
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), 200);
        let t: TransferResponse = resp.json().await.unwrap();

        if i == 1 {
            assert_eq!(
                t.state, "Resuming",
                "Transfer 1 expected Resuming, got {}",
                t.state
            );
        } else {
            assert!(
                t.state == "New" || t.state == "Active" || t.state == "Failed",
                "Transfer {} unexpected state: {}",
                i, t.state,
            );
        }
    }

    // Health check still works
    let resp = client
        .get(format!("{}/health", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    println!("test_full_workflow: PASSED");
}
