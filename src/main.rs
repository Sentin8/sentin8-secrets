// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Secrets
// SPDX-License-Identifier: Apache-2.0

//! Sentin8:Secrets - tenant secret management service.
//!
//! Stores tenant secret material encrypted at rest (AES-256-GCM envelopes
//! via `sentin8-crypto`), serves it by reference, versions + rotates it,
//! and audit-logs every reveal (M2M resolve + human reveal).
//! Design: .
//!
//! Boot runs on the platform `sentin8-shell` crate (design
//! ): registration
//! flag, PQ provider, config, capped pool, PG18 check, state binding, OpenAPI
//! merge, middleware stack and PQ-TLS listener are owned by the shell. This
//! binary supplies only its registration data, state and routes.

mod admin_ui;
mod auth;
mod config;
mod handlers;
mod openapi;
mod policy;
mod registration;
mod server;

use utoipa::OpenApi;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    sentin8::shell::serve(
        sentin8::shell::Sentin8Shell::new("sentin8:secrets", "SENTIN8_SECRETS")
            .with_registration(registration::print)
            .with_state(server::build_state)
            .with_own_health()
            .with_router(|router, _state| server::routes(router))
            .with_openapi(openapi::SecretsOpenApi::openapi()),
    )
    .await
}
