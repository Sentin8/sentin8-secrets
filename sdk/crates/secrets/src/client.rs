// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Secrets
// SPDX-License-Identifier: Apache-2.0

//! Sentin8:Secrets HTTP client (`sentin8::secrets::client`).
//!
//! Resolves secret references against the Sentin8:Secrets service
//! (`POST /v1/secrets/resolve`) with an M2M bearer token. Static-token and
//! dynamic-token-source construction mirror the storage-client pattern.


use crate::{SecretError, SecretValue};

#[derive(Clone)]
/// Sentin8:Secrets HTTP client — **certificate-presenting** on the
/// platform path (auth DESIGN §4.3f): every call presents the
/// workload's Acme-issued client certificate in the TLS handshake.
/// No bearer token exists on this path.
pub struct SecretsClient {
    base_url: String,
    http: reqwest::Client,
}

/// Body of `POST /v1/secrets/resolve`.
#[derive(Debug, serde::Serialize)]
struct ResolveBody<'a> {
    r#ref: &'a str,
}

/// Body of `PUT /v1/secrets/{name}` (the machine write path — same endpoint
/// the dash/admin UI uses; M2M `sentin8:secrets:secret:write`).
#[derive(Debug, serde::Serialize)]
struct UpsertBody<'a> {
    value: &'a str,
    #[serde(default)]
    description: &'a str,
}

/// Response of `POST /v1/secrets/resolve`.
#[derive(Debug, serde::Deserialize)]
struct ResolveResponse {
    #[allow(dead_code)]
    name: String,
    value: String,
    #[allow(dead_code)]
    version: i32,
}

impl SecretsClient {
    /// Build a certificate-presenting SecretsClient. The transport
    /// presents `cert_path`/`key_path` (the workload's Acme-issued
    /// identity) on every call and trusts only `ca_cert_path`.
    ///
    /// # Errors
    /// Returns a `SecretError::Backend`-formatted [`String`] when the
    /// mTLS transport cannot be built from the identity paths.
    pub fn with_workload_identity(
        base_url: impl Into<String>,
        ca_cert_path: &str,
        cert_path: &str,
        key_path: &str,
    ) -> Result<Self, String> {
        let mtls =
            sentin8_middleware::mtls::MtlsConfig::new(ca_cert_path, cert_path, key_path);
        Ok(Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            http: sentin8_middleware::mtls::build_mtls_client(&mtls)?,
        })
    }

    /// Resolve a secret reference URI (`secrets://<name>`) to its value.
    /// The plaintext is wrapped in a zeroize-on-drop `SecretValue` and
    /// never logged.
    pub async fn resolve(&self, reference: &str) -> Result<SecretValue, SecretError> {
        let url = format!("{}/v1/secrets/resolve", self.base_url);
        let resp = self
            .http
            .post(&url)
            .json(&ResolveBody { r#ref: reference })
            .send()
            .await
            .map_err(|e| SecretError::Backend(format!("secrets resolve: {e}")))?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Err(SecretError::NotFound(reference.to_string()));
        }
        if !resp.status().is_success() {
            return Err(SecretError::Backend(format!(
                "secrets resolve status {}",
                resp.status()
            )));
        }
        let body: ResolveResponse = resp
            .json()
            .await
            .map_err(|e| SecretError::Backend(format!("secrets resolve decode: {e}")))?;
        Ok(SecretValue::new(body.value.into_bytes()))
    }

    /// Store a secret value (`PUT /v1/secrets/{name}` — upsert + version
    /// bump). The machine write path for the DCR-credential scheme: consumers
    /// are crates that need to persist credential material by reference
    /// instead of touching the owner's tables.
    pub async fn put(&self, name: &str, value: &str, description: &str) -> Result<(), SecretError> {
        let url = format!("{}/v1/secrets/{}", self.base_url, name);
        let resp = self
            .http
            .put(&url)
            .json(&UpsertBody { value, description })
            .send()
            .await
            .map_err(|e| SecretError::Backend(format!("secrets put: {e}")))?;
        if !resp.status().is_success() {
            return Err(SecretError::Backend(format!(
                "secrets put status {}",
                resp.status()
            )));
        }
        Ok(())
    }
}
