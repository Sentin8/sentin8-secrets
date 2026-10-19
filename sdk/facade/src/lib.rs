//! sentin8-secrets-sdk - per-service SDK mini-facade (SDD §3.1).
//!
//! Re-exports the Sentin8:Secrets SDK crate. No logic, no features
//! (SDD-4b). Consumers import as `use sentin8_secrets_sdk::secrets::…`.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

/// The secrets crate - `SecretRef`, `SecretResolver`, `SecretValue`, and
/// the HTTP resolve client (re-export).
pub mod secrets {
    pub use sentin8_secrets::*;
}
