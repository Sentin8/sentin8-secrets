// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Secrets
// SPDX-License-Identifier: Apache-2.0

//! Secrets service configuration loaded from environment variables.

use std::env;

use sentin8::auth::client::{Client as AuthClient, ClientOptions};

/// Configuration for secrets.
pub struct SecretsConfig {
    /// The port.
    pub port: u16,
    /// Auth JWKS URL for token verification.
    /// The sentin8 auth JWKS URL.
    pub sentin8_auth_jwks_url: String,
    /// Auth issuer for token verification.
    /// The sentin8 auth issuer.
    pub sentin8_auth_issuer: String,
    /// Shared Auth client - constructed once so the discovery and JWKS
    /// caches are reused across every request (5-minute TTL each).
    /// The auth client.
    pub auth_client: AuthClient,
    /// Database URL.
    /// The database URL.
    pub database_url: String,
    /// Bus base URL for event publication (inbox-first).
    /// The sentin8 bus URL.
    pub sentin8_bus_url: String,
    /// Bus stream family for Secrets events (default `"secrets"`).
    /// The stream family.
    pub stream_family: String,
    /// Master key for AES-256-GCM envelope encryption.
    /// Loaded at boot; held zeroized. NEVER logged, persisted or returned.
    /// The master key.
    pub master_key: sentin8::crypto::MasterKey,
    /// Version prune window in days (design - versions older than the
    /// current one are pruned after this window). 0 disables pruning.
    /// The prune days.
    pub prune_days: i64,
    /// Dev mode: when true, a missing master key generates an ephemeral key
    /// with a loud warning (values unreadable after restart).
    /// The dev mode.
    pub dev_mode: bool,
}

impl std::fmt::Debug for SecretsConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The master key is opaque (zeroized bytes) - the debug shape only
        // reports whether it is loaded, never its material.
        f.debug_struct("SecretsConfig")
            .field("port", &self.port)
            .field("master_key_loaded", &true)
            .field("prune_days", &self.prune_days)
            .field("dev_mode", &self.dev_mode)
            .finish()
    }
}

impl Clone for SecretsConfig {
    fn clone(&self) -> Self {
        // MasterKey is Clone; the rest derive it.
        Self {
            port: self.port,
            sentin8_auth_jwks_url: self.sentin8_auth_jwks_url.clone(),
            sentin8_auth_issuer: self.sentin8_auth_issuer.clone(),
            auth_client: self.auth_client.clone(),
            database_url: self.database_url.clone(),
            sentin8_bus_url: self.sentin8_bus_url.clone(),
            stream_family: self.stream_family.clone(),
            master_key: self.master_key.clone(),
            prune_days: self.prune_days,
            dev_mode: self.dev_mode,
        }
    }
}

impl SecretsConfig {
    /// Handle from env.
    pub fn from_env() -> Self {
        let cfg = sentin8::config::Sentin8Config::from_env();
        let sentin8_auth_issuer =
            env::var("SENTIN8_AUTH_ISSUER").unwrap_or_else(|_| cfg.sentin8_auth_issuer());

        // Master key - fail-closed when absent outside dev mode.
        let master_key = match sentin8::crypto::MasterKey::from_base64(
            &env::var("SENTIN8_SECRETS_MASTER_KEY").unwrap_or_default(),
        ) {
            Ok(Some(k)) => k,
            Ok(None) => {
                if env::var("SENTIN8_DEV").map(|v| v == "1").unwrap_or(false)
                    || env::var("SENTIN8_SECRETS_DEV_MODE")
                        .map(|v| v == "1")
                        .unwrap_or(false)
                {
                    tracing::warn!(
                        "SENTIN8_SECRETS_MASTER_KEY not set - generated EPHEMERAL dev master key \
                         (all stored secrets become unreadable after restart; set the env var for persistence)"
                    );
                    sentin8::crypto::MasterKey::from_bytes(&{
                        let mut k = [0u8; 32];
                        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut k);
                        k
                    })
                    .expect("32-byte key is valid")
                } else {
                    panic!(
                        "SENTIN8_SECRETS_MASTER_KEY must be set (base64-encoded 32 bytes) - \
                         Sentin8:Secrets refuses to start without a master key (fail-closed, design §10)"
                    );
                }
            }
            Err(e) => panic!("SENTIN8_SECRETS_MASTER_KEY invalid: {e}"),
        };

        Self {
            port: env::var("SENTIN8_SECRETS_PORT")
                .expect("SENTIN8_SECRETS_PORT must be set by captain")
                .parse()
                .expect("SENTIN8_SECRETS_PORT must be a valid u16"),
            sentin8_auth_jwks_url: env::var("SENTIN8_AUTH_JWKS_URL")
                .unwrap_or_else(|_| cfg.sentin8_auth_jwks_url()),
            sentin8_auth_issuer: sentin8_auth_issuer.clone(),
            auth_client: AuthClient::new(ClientOptions {
                base_url: sentin8_auth_issuer,
                ..Default::default()
            }),
            database_url: env::var("SENTIN8_SECRETS_DATABASE_URL").unwrap_or_else(|_| {
                env::var("DATABASE_URL").unwrap_or_else(|_| {
                    sentin8::config::Sentin8Config::default_database_url().to_string()
                })
            }),
            sentin8_bus_url: env::var("SENTIN8_BUS_URL").unwrap_or_else(|_| cfg.sentin8_bus_url()),
            stream_family: env::var("SENTIN8_SECRETS_STREAM_FAMILY")
                .unwrap_or_else(|_| "secrets".into()),
            master_key,
            prune_days: env::var("SENTIN8_SECRETS_PRUNE_DAYS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(7),
            dev_mode: env::var("SENTIN8_DEV").map(|v| v == "1").unwrap_or(false),
        }
    }
}
