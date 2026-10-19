// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Secrets
// SPDX-License-Identifier: Apache-2.0

//! # sentin8-secrets
//!
//! Secret reference model and resolver interface for Sentin8 services.
//!
//! Secret References Only: sensitive material is stored by reference,
//! never as plaintext in application tables. Forbidden in ordinary tables:
//! provider tokens, OAuth client secrets, webhook signing secrets, private
//! keys, PAN, PIN, CVV, clear payment credentials.
//!
//! Services store a [`SecretRef`] in their DB tables and use a
//! [`SecretResolver`] to retrieve the actual secret value at runtime from a
//! backing secret store (HashiCorp Vault, AWS Secrets Manager, or a local
//! encrypted file for development).

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

pub mod client;

/// A reference to a secret stored in an external secret manager.
///
/// Stored as a string column in DB tables (e.g. `webhook_secret_ref`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretRef {
    /// The secret manager backend (e.g. "vault", "aws-sm", "local-file").
    pub backend: String,
    /// The opaque path/key identifying the secret in the backend.
    pub path: String,
}

impl SecretRef {
    pub fn new(backend: impl Into<String>, path: impl Into<String>) -> Self {
        Self {
            backend: backend.into(),
            path: path.into(),
        }
    }

    /// Render as a `backend://path` URI string for storage in DB text columns.
    pub fn to_uri(&self) -> String {
        format!("{}://{}", self.backend, self.path)
    }

    /// Parse a `backend://path` URI string back into a `SecretRef`.
    pub fn parse(uri: &str) -> Result<Self, SecretError> {
        let (backend, path) = uri
            .split_once("://")
            .ok_or_else(|| SecretError::InvalidRef(format!("missing '://' in {uri:?}")))?;
        if backend.is_empty() || path.is_empty() {
            return Err(SecretError::InvalidRef(uri.to_string()));
        }
        Ok(Self {
            backend: backend.to_string(),
            path: path.to_string(),
        })
    }
}

/// The resolved secret value (plaintext bytes). Held only in memory.
/// Bytes are zeroized when dropped to minimize exposure.
#[derive(Debug, Clone)]
pub struct SecretValue {
    inner: Vec<u8>,
}

impl SecretValue {
    pub fn new(inner: Vec<u8>) -> Self {
        Self { inner }
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.inner
    }
    pub fn into_string(self) -> Result<String, SecretError> {
        // We can't destructure `self` (Drop), so zeroize a clone of the
        // bytes and let the original's Drop handle the rest.
        let bytes = self.inner.clone();
        String::from_utf8(bytes).map_err(|e| SecretError::InvalidUtf8(e.to_string()))
    }
}

/// Zeroize the secret bytes when dropped to minimize exposure in memory.
impl Drop for SecretValue {
    fn drop(&mut self) {
        for b in self.inner.iter_mut() {
            *b = 0;
        }
    }
}

/// Trait for resolving a [`SecretRef`] into a [`SecretValue`].
#[async_trait]
pub trait SecretResolver: Send + Sync {
    async fn resolve(&self, reference: &SecretRef) -> Result<SecretValue, SecretError>;
}

#[derive(Debug, thiserror::Error)]
pub enum SecretError {
    #[error("invalid secret reference: {0}")]
    InvalidRef(String),
    #[error("secret not found: {0}")]
    NotFound(String),
    #[error("invalid UTF-8 in secret value: {0}")]
    InvalidUtf8(String),
    #[error("secret backend error: {0}")]
    Backend(String),
}

// ── Resolver backends ───────────────────────────────────────────────────

/// `env://` backend - resolves against environment variables
/// (`SENTIN8_SECRETS_<SCREAMING_PATH>`). Dev-bootstrap backend.
pub struct EnvResolver;

#[async_trait]
impl SecretResolver for EnvResolver {
    async fn resolve(&self, reference: &SecretRef) -> Result<SecretValue, SecretError> {
        let env_key = format!(
            "SENTIN8_SECRETS_{}",
            reference.path.to_uppercase().replace(['-', '.', '/'], "_")
        );
        std::env::var(&env_key)
            .map(|v| SecretValue::new(v.into_bytes()))
            .map_err(|_| SecretError::NotFound(env_key))
    }
}

/// `file://` backend - reads the raw file at the reference path (relative
/// paths resolve against `SENTIN8_SECRETS_DIR`, defaulting to
/// `/etc/sentin8/secrets` - the dir captain propagates).
pub struct FileResolver {
    root: std::path::PathBuf,
}

impl FileResolver {
    pub fn from_env_dir() -> Self {
        let root =
            std::env::var("SENTIN8_SECRETS_DIR").unwrap_or_else(|_| "/etc/sentin8/secrets".into());
        Self {
            root: std::path::PathBuf::from(root),
        }
    }
}

#[async_trait]
impl SecretResolver for FileResolver {
    async fn resolve(&self, reference: &SecretRef) -> Result<SecretValue, SecretError> {
        // Path traversal guard - refuse absolute paths and ParentDir
        // components (the storage adapter's `safe_path` pattern).
        if reference.path.starts_with('/')
            || std::path::Path::new(&reference.path).components().any(|c| {
                matches!(
                    c,
                    std::path::Component::ParentDir | std::path::Component::RootDir
                )
            })
        {
            return Err(SecretError::InvalidRef(reference.path.clone()));
        }
        let path = self.root.join(&reference.path);
        std::fs::read(&path)
            .map(SecretValue::new)
            .map_err(|e| SecretError::Backend(format!("read {}: {e}", path.display())))
    }
}

/// `secrets://` backend - resolves via the Sentin8:Secrets HTTP resolve
/// endpoint (`POST /v1/secrets/resolve`). auth DESIGN §4.3f:
/// the standard platform path is **certificate-presenting** - the caller's
/// Acme-issued client certificate authenticates at the TLS handshake; no
/// bearer token exists on this path.
pub struct ServiceResolver {
    client: crate::client::SecretsClient,
}

impl ServiceResolver {
    /// Build the cert-presenting resolver for a workload identity (the
    /// standard platform path).
    ///
    /// # Errors
    /// Returns the mTLS transport build error when the identity paths
    /// cannot be loaded.
    pub fn with_workload_identity(
        base_url: impl Into<String>,
        ca_cert_path: &str,
        cert_path: &str,
        key_path: &str,
    ) -> Result<Self, String> {
        Ok(Self {
            client: crate::client::SecretsClient::with_workload_identity(
                base_url,
                ca_cert_path,
                cert_path,
                key_path,
            )?,
        })
    }
}

#[async_trait]
impl SecretResolver for ServiceResolver {
    async fn resolve(&self, reference: &SecretRef) -> Result<SecretValue, SecretError> {
        self.client.resolve(&reference.to_uri()).await
    }
}

/// Resolve a `backend://path` URI through the standard backend chain:
/// `secrets://` → ServiceResolver, `env://` → EnvResolver,
/// `file://` → FileResolver. Unknown backends error.
pub async fn resolve_credential(credential_ref: &str) -> Result<SecretValue, SecretError> {
    let reference = SecretRef::parse(credential_ref)?;
    match reference.backend.as_str() {
        "secrets" | "service" | "sentin8-secrets" => {
            // the platform path presents the calling workload's
            // certificate - resolved from the shared m2m identity helpers.
            // A missing identity surfaces as a Backend error (fail-closed;
            // the caller diagnoses provisioning, never a silent fallback).
            let base = std::env::var("SENTIN8_SECRETS_URL")
                .unwrap_or_else(|_| "https://secrets.ops.sys.localhost.local".into());
            let ca = sentin8_m2m::platform_ca_path();
            let workload = std::env::var("SENTIN8_SECRETS_WORKLOAD")
                .ok()
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| "cli".into());
            let issuer = std::env::var("SENTIN8_AUTH_ISSUER")
                .unwrap_or_else(|_| "https://auth.ops.sys.sentin8.local".into());
            let cert = sentin8_m2m::ensure_workload_certificate(&issuer, &workload, &ca)
                .await
                .map_err(|e| SecretError::Backend(format!("secrets identity: {e}")))?;
            let resolver = ServiceResolver::with_workload_identity(
                base,
                &cert.ca_cert_path,
                &cert.cert_path,
                &cert.key_path,
            )
            .map_err(|e| SecretError::Backend(format!("secrets client: {e}")))?;
            resolver.resolve(&reference).await
        }
        "env" => EnvResolver.resolve(&reference).await,
        "file" => FileResolver::from_env_dir().resolve(&reference).await,
        other => Err(SecretError::Backend(format!(
            "unsupported secret backend: {other}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn env_resolver_resolves_and_errors() {
        // SAFETY(test): single-threaded test process; writing a test-owned key.
        std::env::set_var("SENTIN8_SECRETS_TEST_KEY", "abc");
        let r = EnvResolver
            .resolve(&SecretRef::new("env", "test-key"))
            .await
            .unwrap();
        assert_eq!(r.as_bytes(), b"abc");
        assert!(EnvResolver
            .resolve(&SecretRef::new("env", "nope-missing"))
            .await
            .is_err());
    }

    #[test]
    fn secret_ref_round_trip() {
        let r = SecretRef::new("vault", "sentin8/auth/signing-key");
        let uri = r.to_uri();
        assert_eq!(uri, "vault://sentin8/auth/signing-key");
        let parsed = SecretRef::parse(&uri).unwrap();
        assert_eq!(parsed, r);
    }

    #[test]
    fn secret_ref_rejects_invalid() {
        assert!(SecretRef::parse("no-scheme").is_err());
        assert!(SecretRef::parse("://path").is_err());
        assert!(SecretRef::parse("backend://").is_err());
    }

    #[test]
    fn secret_value_into_string() {
        let v = SecretValue::new(b"super-secret-token".to_vec());
        assert_eq!(v.into_string().unwrap(), "super-secret-token");
    }

    #[tokio::test]
    async fn file_resolver_traversal_guard() {
        let resolver = FileResolver {
            root: std::path::PathBuf::from("/tmp"),
        };
        let err = resolver
            .resolve(&SecretRef::new("file", "../../etc/passwd"))
            .await
            .unwrap_err();
        assert!(matches!(err, SecretError::InvalidRef(_)));
    }
}
