// Favonius — high-performance file transfer over UDP
// Copyright (c) 2025-2026 Vantino SàRL
// SPDX-License-Identifier: Apache-2.0

pub mod fs_tree;
pub mod sync_plan;
pub mod net_probe;
pub mod preflight;
pub mod tcp_sender;
pub mod net_sender;
pub mod udt_transport;

use ahp_api::{CreateTransferRequest, TransferResponse};
use reqwest::Client;

/// CLI client for communicating with the Favonius daemon REST API.
pub struct FavoniusClient {
    base_url: String,
    client: Client,
    auth_token: Option<String>,
}

impl FavoniusClient {
    pub fn new(daemon_addr: &str) -> Self {
        // Attach the bearer token when the daemon is token-protected; the
        // same environment variable configures the daemon side.
        let auth_token = std::env::var(ahp_api::API_TOKEN_ENV)
            .ok()
            .filter(|t| !t.is_empty());
        Self {
            base_url: format!("http://{}", daemon_addr),
            // Bounded, because `sync` now addresses the destination host
            // rather than always loopback: an unreachable or firewalled
            // receiver used to hang the CLI indefinitely with no output.
            // Fail in 15 s with the connection error instead.
            client: Client::builder()
                .connect_timeout(std::time::Duration::from_secs(10))
                .timeout(std::time::Duration::from_secs(15))
                .build()
                .unwrap_or_else(|_| Client::new()),
            auth_token,
        }
    }

    /// Override the bearer token (primarily for tests).
    pub fn with_token(mut self, token: impl Into<String>) -> Self {
        let token = token.into();
        self.auth_token = if token.is_empty() { None } else { Some(token) };
        self
    }

    /// Attach `Authorization: Bearer <token>` when a token is configured.
    fn authed(&self, req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match &self.auth_token {
            Some(token) => req.bearer_auth(token),
            None => req,
        }
    }

    /// POST /transfers - create a new transfer
    pub async fn create_transfer(
        &self,
        source: &str,
        destination: &str,
        compression: Option<bool>,
        encryption: Option<bool>,
    ) -> Result<TransferResponse, CliError> {
        let req = CreateTransferRequest {
            source: source.to_string(),
            destination: destination.to_string(),
            compression,
            encryption,
        };
        let resp = self.authed(self.client
            .post(format!("{}/transfers", self.base_url))
            .json(&req))
            .send()
            .await
            .map_err(|e| CliError::Connection(e.to_string()))?;

        if !resp.status().is_success() {
            return Err(CliError::Api(format!("HTTP {}", resp.status())));
        }

        resp.json::<TransferResponse>().await
            .map_err(|e| CliError::Parse(e.to_string()))
    }

    /// GET /transfers - list all transfers
    pub async fn list_transfers(&self) -> Result<Vec<TransferResponse>, CliError> {
        let resp = self.authed(self.client
            .get(format!("{}/transfers", self.base_url)))
            .send()
            .await
            .map_err(|e| CliError::Connection(e.to_string()))?;

        if !resp.status().is_success() {
            return Err(CliError::Api(format!("HTTP {}", resp.status())));
        }

        resp.json::<Vec<TransferResponse>>().await
            .map_err(|e| CliError::Parse(e.to_string()))
    }

    /// GET /transfers/:id - get a specific transfer
    pub async fn get_transfer(&self, id: &str) -> Result<TransferResponse, CliError> {
        let resp = self.authed(self.client
            .get(format!("{}/transfers/{}", self.base_url, id)))
            .send()
            .await
            .map_err(|e| CliError::Connection(e.to_string()))?;

        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Err(CliError::NotFound(id.to_string()));
        }
        if !resp.status().is_success() {
            return Err(CliError::Api(format!("HTTP {}", resp.status())));
        }

        resp.json::<TransferResponse>().await
            .map_err(|e| CliError::Parse(e.to_string()))
    }

    /// POST /transfers/:id/resume - resume an interrupted transfer
    pub async fn resume_transfer(&self, id: &str) -> Result<TransferResponse, CliError> {
        let resp = self.authed(self.client
            .post(format!("{}/transfers/{}/resume", self.base_url, id)))
            .send()
            .await
            .map_err(|e| CliError::Connection(e.to_string()))?;

        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Err(CliError::NotFound(id.to_string()));
        }
        if !resp.status().is_success() {
            return Err(CliError::Api(format!("HTTP {}", resp.status())));
        }

        resp.json::<TransferResponse>().await
            .map_err(|e| CliError::Parse(e.to_string()))
    }

    /// GET /fs/list - list regular files under a destination directory.
    ///
    /// Used by `sync` to diff the destination without keeping any state of
    /// its own. Requires the daemon to run with `--dest-root`; a 404 means
    /// the endpoint is disabled, which is reported as such rather than as
    /// "the directory is empty" — the difference decides whether a mirror
    /// would delete everything.
    pub async fn fs_list(&self, path: &str, hash: bool) -> Result<Vec<ahp_api::FsEntry>, CliError> {
        let resp = self.authed(self.client
            .get(format!("{}/fs/list", self.base_url))
            .query(&[("path", path), ("hash", if hash { "true" } else { "false" })]))
            .send()
            .await
            .map_err(|e| CliError::Connection(e.to_string()))?;

        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Err(CliError::Api(
                "daemon has no --dest-root configured, so it cannot list the \
                 destination (required for sync)".to_string(),
            ));
        }
        if !resp.status().is_success() {
            return Err(CliError::Api(format!("HTTP {}", resp.status())));
        }
        resp.json::<ahp_api::FsListResponse>().await
            .map(|r| r.entries)
            .map_err(|e| CliError::Parse(e.to_string()))
    }

    /// DELETE /fs/entry - remove one regular file under the destination root.
    pub async fn fs_delete(&self, path: &str) -> Result<(), CliError> {
        let resp = self.authed(self.client
            .delete(format!("{}/fs/entry", self.base_url))
            .query(&[("path", path)]))
            .send()
            .await
            .map_err(|e| CliError::Connection(e.to_string()))?;

        // Already gone is the desired end state, not an error.
        if resp.status().is_success() || resp.status() == reqwest::StatusCode::NOT_FOUND {
            Ok(())
        } else {
            Err(CliError::Api(format!("HTTP {}", resp.status())))
        }
    }

    /// GET /health - check daemon health
    pub async fn health(&self) -> Result<(), CliError> {
        let resp = self.authed(self.client
            .get(format!("{}/health", self.base_url)))
            .send()
            .await
            .map_err(|e| CliError::Connection(e.to_string()))?;

        if resp.status().is_success() {
            Ok(())
        } else {
            Err(CliError::Api(format!("daemon unhealthy: HTTP {}", resp.status())))
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum CliError {
    #[error("connection failed: {0}")]
    Connection(String),
    #[error("API error: {0}")]
    Api(String),
    #[error("transfer not found: {0}")]
    NotFound(String),
    #[error("failed to parse response: {0}")]
    Parse(String),
    #[error("{0}")]
    Config(String),
}
