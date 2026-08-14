// Favonius — high-performance file transfer over UDP
// Copyright (c) 2025-2026 Vantino SàRL
// SPDX-License-Identifier: Apache-2.0

use ahp_api::AppState;
use ahp_cli::FavoniusClient;
use tokio::net::TcpListener;

/// Spawn a daemon on a random port and return the address.
async fn spawn_daemon() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let state = AppState::new(64);
    tokio::spawn(async move {
        ahp_daemon::start_server(listener, state).await.unwrap();
    });
    // Give the server a moment to start
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    addr
}

/// Spawn a token-protected daemon on a random port.
async fn spawn_protected_daemon(token: &str) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let state = AppState::new(64).with_token(token);
    tokio::spawn(async move {
        ahp_daemon::start_server(listener, state).await.unwrap();
    });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    addr
}

#[tokio::test]
async fn test_cli_bearer_token_auth() {
    let addr = spawn_protected_daemon("test-secret").await;

    // Health stays unauthenticated.
    let anon = FavoniusClient::new(&addr);
    anon.health().await.unwrap();

    // Protected routes reject a token-less client.
    let err = anon.create_transfer("/data/a", "/data/b", None, None).await;
    assert!(err.is_err(), "request without token must be rejected");
    let err = anon.list_transfers().await;
    assert!(err.is_err(), "list without token must be rejected");

    // Wrong token: rejected.
    let wrong = FavoniusClient::new(&addr).with_token("wrong-secret");
    assert!(wrong.list_transfers().await.is_err());

    // Correct token: works.
    let client = FavoniusClient::new(&addr).with_token("test-secret");
    let resp = client
        .create_transfer("/data/file.bin", "node2:/data/file.bin", None, None)
        .await
        .unwrap();
    assert!(!resp.id.is_empty());
    assert_eq!(client.list_transfers().await.unwrap().len(), 1);
}

#[tokio::test]
async fn test_cli_send_and_status() {
    let addr = spawn_daemon().await;
    let client = FavoniusClient::new(&addr);

    // Health check
    client.health().await.unwrap();
    println!("Health check: OK");

    // Send a file
    let resp = client.create_transfer("/data/bigfile.tar", "remote:/backup/bigfile.tar", Some(true), Some(true)).await.unwrap();
    assert!(!resp.id.is_empty());
    assert_eq!(resp.state, "New");
    assert_eq!(resp.source, "/data/bigfile.tar");
    println!("Created transfer: {}", resp.id);

    // Check status (background task may have already failed since source doesn't exist).
    let status = client.get_transfer(&resp.id).await.unwrap();
    assert_eq!(status.id, resp.id);
    assert!(
        status.state == "New" || status.state == "Active" || status.state == "Failed",
        "Unexpected state: {}",
        status.state,
    );
    println!("Status check: {}", status.state);

    // List all
    let all = client.list_transfers().await.unwrap();
    assert_eq!(all.len(), 1);
    assert_eq!(all[0].id, resp.id);
    println!("List transfers: {} found", all.len());
}

#[tokio::test]
async fn test_cli_multiple_transfers_and_resume() {
    let addr = spawn_daemon().await;
    let client = FavoniusClient::new(&addr);

    // Create multiple transfers
    let t1 = client.create_transfer("/data/file1.bin", "node2:/data/file1.bin", None, None).await.unwrap();
    let t2 = client.create_transfer("/data/file2.bin", "node2:/data/file2.bin", None, None).await.unwrap();
    let t3 = client.create_transfer("/data/file3.bin", "node2:/data/file3.bin", None, None).await.unwrap();
    println!("Created 3 transfers: {}, {}, {}", t1.id, t2.id, t3.id);

    // List should show all 3
    let all = client.list_transfers().await.unwrap();
    assert_eq!(all.len(), 3);
    println!("Listed {} transfers", all.len());

    // Resume one
    let resumed = client.resume_transfer(&t2.id).await.unwrap();
    assert_eq!(resumed.state, "Resuming");
    println!("Resumed transfer {}: state={}", t2.id, resumed.state);

    // Verify the resumed state persists
    let check = client.get_transfer(&t2.id).await.unwrap();
    assert_eq!(check.state, "Resuming");

    // Others may have failed (source files don't exist).
    let check1 = client.get_transfer(&t1.id).await.unwrap();
    assert!(
        check1.state == "New" || check1.state == "Active" || check1.state == "Failed",
        "Unexpected state for t1: {}",
        check1.state,
    );
    println!("Other transfers: t1.state={}", check1.state);
}

#[tokio::test]
async fn test_cli_not_found() {
    let addr = spawn_daemon().await;
    let client = FavoniusClient::new(&addr);

    // Get non-existent transfer
    let err = client.get_transfer("non-existent-id").await;
    assert!(err.is_err());
    println!("Get non-existent: correctly returned error");

    // Resume non-existent transfer
    let err = client.resume_transfer("non-existent-id").await;
    assert!(err.is_err());
    println!("Resume non-existent: correctly returned error");
}

#[tokio::test]
async fn test_cli_full_workflow() {
    let _ = tracing_subscriber::fmt().with_env_filter("info").with_test_writer().try_init();

    let addr = spawn_daemon().await;
    let client = FavoniusClient::new(&addr);

    println!("=== Full CLI Workflow Test ===");
    println!("Daemon running at {}", addr);

    // 1. Health check
    client.health().await.unwrap();
    println!("[1/6] Health check: PASSED");

    // 2. Send a file
    let send = client.create_transfer(
        "/media/project/rushes.mxf",
        "edit-bay:/media/incoming/rushes.mxf",
        Some(true),
        Some(true),
    ).await.unwrap();
    println!("[2/6] Send created: {} (state={})", send.id, send.state);

    // 3. Check its status
    let status = client.get_transfer(&send.id).await.unwrap();
    assert_eq!(status.source, "/media/project/rushes.mxf");
    assert_eq!(status.destination, "edit-bay:/media/incoming/rushes.mxf");
    println!("[3/6] Status: source={} dest={}", status.source, status.destination);

    // 4. Create a sync job
    let sync = client.create_transfer(
        "/home/user/documents",
        "nas:/backup/documents",
        Some(true),
        Some(true),
    ).await.unwrap();
    println!("[4/6] Sync created: {} (state={})", sync.id, sync.state);

    // 5. List all - should be 2
    let all = client.list_transfers().await.unwrap();
    assert_eq!(all.len(), 2);
    println!("[5/6] Listed {} transfers", all.len());

    // 6. Resume the first transfer
    let resumed = client.resume_transfer(&send.id).await.unwrap();
    assert_eq!(resumed.state, "Resuming");
    println!("[6/6] Resumed {}: state={}", resumed.id, resumed.state);

    println!("=== All CLI workflow steps PASSED ===");
}
