// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Secrets
// SPDX-License-Identifier: Apache-2.0

//! Axum server setup for Sentin8:Secrets.

use std::sync::Arc;

use axum::routing::{get, post, put};

use crate::handlers::{self, AppState};

/// Build state.
pub async fn build_state(
    core: sentin8::shell::ServiceCore,
) -> anyhow::Result<crate::handlers::AppState> {
    let config = crate::config::SecretsConfig::from_env();
    // ── Sentin8:Policy (- shell-owned boot): consume the
    // engine the shell booted in step 8 - no second engine, consumer, or
    // DCR registration here.
    let policy_engine = core.admin.policy.clone();

    let state = AppState {
        master_key: Arc::new(config.master_key.clone()),
        config: Arc::new(config.clone()),
        pool: core.pool.clone(),
        policy: policy_engine.clone(),
        admin: sentin8::shield::admin::SharedAdminState {
            service: "sentin8:secrets".to_string(),
            pool: core.pool.clone(),
            policy: policy_engine.clone(),
            auth_client: Arc::new(config.auth_client.clone()),
        },
    };

    Ok(state)
}

/// Add this service's routes onto the shell-provided router. The shell
/// owns the boot sequence, state binding, OpenAPI merge and the standard
/// middleware stack; this adds ONLY routes (including the service's own
/// `/v1/health` - custom payload).
/// Handle routes.
pub fn routes(
    router: axum::Router<crate::handlers::AppState>,
) -> axum::Router<crate::handlers::AppState> {
    router
        .route("/v1/health", get(handlers::health_handler))
        // ── Secret CRUD (env-scoped; env from token, never from path) ──────
        .route(
            "/v1/secrets/{name}",
            put(handlers::put_secret)
                .get(handlers::get_secret)
                .delete(handlers::delete_secret),
        )
        .route("/v1/secrets", get(handlers::list_secrets))
        .route("/v1/secrets/{name}/rotate", post(handlers::rotate_secret))
        .route("/v1/secrets/{name}/history", get(handlers::secret_history))
        .route("/v1/secrets/{name}/reveal", get(handlers::reveal_secret))
        .route("/v1/secrets/{name}/reads", get(handlers::secret_reads))
        .route("/v1/secrets/resolve", post(handlers::resolve_secret))
        // Cron proxy-back target (secrets DESIGN §10 - expiry scan).
        .route(
            "/v1/internal/schedules/run",
            post(handlers::internal_schedules_run),
        )
        // ── Maintenance ──────
        .route(
            "/v1/secrets/maintenance/prune",
            post(handlers::maintenance_prune),
        )
        .route(
            "/v1/secrets/maintenance/re-encrypt",
            post(handlers::maintenance_re_encrypt),
        )
        // ── Admin UI (RFW) ─────────────────────────────────────────────────
        .route("/v1/admin/ui/{*page}", get(crate::admin_ui::get_admin_ui))
        .route("/v1/admin/{resource}", get(crate::admin_ui::get_admin_data))
        .route(
            "/v1/admin/secrets",
            post(crate::admin_ui::admin_put_secret).get(crate::admin_ui::get_admin_data_secrets),
        )
        .route(
            "/v1/admin/secrets/{name}/disable",
            post(crate::admin_ui::admin_disable_secret),
        )
        .route(
            "/v1/admin/secrets/{name}/reveal",
            post(crate::admin_ui::admin_reveal_secret),
        )
        .route(
            "/v1/admin/secrets/rotate",
            post(crate::admin_ui::admin_rotate_secret),
        )
        // ── Sentin8:Policy admin API ( - shared implementation,
        // one surface per service; handlers are generic over this AppState).
        .route(
            "/v1/admin/policy-sets",
            get(sentin8::shield::admin::list_policy_sets::<handlers::AppState>),
        )
        .route(
            "/v1/admin/policy-sets/{name}",
            get(sentin8::shield::admin::get_policy_set::<handlers::AppState>)
                .put(sentin8::shield::admin::put_policy_set::<handlers::AppState>)
                .delete(sentin8::shield::admin::delete_policy_set::<handlers::AppState>),
        )
        .route(
            "/v1/admin/policy-sets/{name}/test",
            post(sentin8::shield::admin::test_policy_set::<handlers::AppState>),
        )
        .route(
            "/v1/admin/policy-sets/enforce",
            post(sentin8::shield::admin::admin_enforce_policy_set::<handlers::AppState>),
        )
        .route(
            "/v1/admin/policy-sets/shadow",
            post(sentin8::shield::admin::admin_shadow_policy_set::<handlers::AppState>),
        )
        .route(
            "/v1/admin/policy-sets/disable",
            post(sentin8::shield::admin::admin_disable_policy_set::<handlers::AppState>),
        )
        .route(
            "/v1/admin/relations",
            get(sentin8::shield::admin::list_relations::<handlers::AppState>)
                .put(sentin8::shield::admin::put_relation::<handlers::AppState>)
                .delete(sentin8::shield::admin::delete_relation::<handlers::AppState>),
        )
        .route(
            "/v1/admin/relations/check",
            get(sentin8::shield::admin::check_relation::<handlers::AppState>),
        )
        .route(
            "/v1/admin/attributes",
            get(sentin8::shield::admin::list_attributes::<handlers::AppState>)
                .put(sentin8::shield::admin::put_attribute::<handlers::AppState>)
                .delete(sentin8::shield::admin::delete_attribute::<handlers::AppState>),
        )
}

/// Shared policy-admin surface accessor - the shared
/// handlers extract this service's admin state via [`HasPolicyAdmin`].
impl sentin8::shield::admin::HasPolicyAdmin for AppState {
    fn policy_admin(&self) -> &sentin8::shield::admin::SharedAdminState {
        &self.admin
    }
}
