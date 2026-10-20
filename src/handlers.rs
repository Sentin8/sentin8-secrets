// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Secrets
// SPDX-License-Identifier: Apache-2.0

//! HTTP handlers for Sentin8:Secrets.
//!
//! All tenant context is resolved from the auth token's `env_id` claim
//! (globally unique) - never from URL path segments. Plaintext secret
//! values exist ONLY inside request/response handling (zeroize-on-drop
//! `SecretValue`); the metadata surface never serializes values, and every
//! reveal (M2M resolve or human reveal) writes a `reads` audit row.

use std::sync::Arc;

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use utoipa::ToSchema;

use crate::config::SecretsConfig;

#[derive(Clone)]
/// app state.
pub struct AppState {
    /// The config.
    pub config: Arc<SecretsConfig>,
    /// DB connection pool for the secrets tables + outbox.
    /// The pool.
    pub pool: sqlx::PgPool,
    /// Master key for envelope encryption (zeroized on drop).
    /// The master key.
    pub master_key: Arc<sentin8::crypto::MasterKey>,
    /// Shield engine ( - ): the only access gate.
    /// The policy.
    pub policy: Arc<crate::policy::Engine>,
    /// Shared Sentin8:Policy admin surface ( - one
    /// implementation for every service; mounted in server::routes).
    /// The admin.
    pub admin: sentin8::shield::admin::SharedAdminState,
}

// Step 5 is the ONLY access gate (.16): the scope helpers kept as
// trivial `Ok()` so call sites and signatures stay stable - the enforced
// Shield scope-mirror set decides, keyed on the same action ids the call
// sites evaluate.
fn require_read_scope(_a: &crate::auth::AuthContext) -> Result<(), (StatusCode, String)> {
    Ok(())
}
fn require_write_scope(_a: &crate::auth::AuthContext) -> Result<(), (StatusCode, String)> {
    Ok(())
}
fn require_admin_scope(_a: &crate::auth::AuthContext) -> Result<(), (StatusCode, String)> {
    Ok(())
}

// ── Row mapping ─────────────────────────────────────────────────────────

/// A fetched `secrets` row. The plaintext is NEVER part of this type -
/// `value_cipher` is the v2 envelope; the metadata projection never
/// serializes it.
#[derive(sqlx::FromRow, Clone)]
/// The secretrow type.
pub struct SecretRow {
    id: uuid::Uuid,
    name: String,
    description: String,
    value_cipher: Vec<u8>,
    key_version: i32,
    version: i32,
    status: String,
    created_by: String,
    env_id: uuid::Uuid,
    created_at: chrono::DateTime<chrono::Utc>,
    updated_at: chrono::DateTime<chrono::Utc>,
    expires_at: Option<chrono::DateTime<chrono::Utc>>,
}

impl SecretRow {
    /// Metadata projection - NEVER includes the value.
    /// Handle metadata.
    pub fn metadata(&self) -> serde_json::Value {
        serde_json::json!({
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "version": self.version,
            "key_version": self.key_version,
            "status": self.status,
            "created_by": self.created_by,
            "env_id": self.env_id,
            "created_at": self.created_at.to_rfc3339(),
            "updated_at": self.updated_at.to_rfc3339(),
            "expires_at": self
                .expires_at
                .map(|e| e.to_rfc3339())
                .unwrap_or_default(),
            "ref": format!("secrets://{}", self.name),
        })
    }
}

async fn fetch_by_name(
    pool: &sqlx::PgPool,
    env_id: uuid::Uuid,
    name: &str,
) -> Result<Option<SecretRow>, (StatusCode, String)> {
    let mut tx = begin_tenant_tx(pool, env_id).await?;
    let row = sqlx::query_as::<_, SecretRow>(
        "SELECT id, name, description, value_cipher, key_version, version, status, created_by, env_id, created_at, updated_at, expires_at
         FROM secrets WHERE env_id = $1 AND name = $2",
    )
    .bind(env_id)
    .bind(name)
    .fetch_optional(&mut *tx)
    .await
    .map_err(db_err)?;
    tx.commit().await.map_err(db_err)?;
    Ok(row)
}

fn db_err(e: sqlx::Error) -> (StatusCode, String) {
    (StatusCode::INTERNAL_SERVER_ERROR, format!("db error: {e}"))
}

/// Begin an explicit transaction with the tenant RLS context set on the
/// same connection (secrets DESIGN §5). The context is
/// transaction-local (`set_config(..., true)`), so every query that must
/// see tenant rows runs inside the returned transaction - a context set on
/// an autocommit connection evaporates at statement commit.
pub(crate) async fn begin_tenant_tx(
    pool: &sqlx::PgPool,
    env_id: uuid::Uuid,
) -> Result<sqlx::Transaction<'static, sqlx::Postgres>, (StatusCode, String)> {
    let mut tx = pool.begin().await.map_err(db_err)?;
    sqlx::query("SELECT sentin8_set_tenant_context($1)")
        .bind(env_id)
        .execute(&mut *tx)
        .await
        .map_err(db_err)?;
    Ok(tx)
}

/// Validate a secret name: non-empty, no whitespace, printable ASCII path
/// segments (letters, digits, dash, underscore, slash). Refuses traversal.
/// Shared with the admin-UI handlers (public wrapper below).
fn validate_name(name: &str) -> Result<(), (StatusCode, String)> {
    if name.is_empty() || name.len() > 256 {
        return Err((StatusCode::BAD_REQUEST, "invalid secret name length".into()));
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '/')
    {
        return Err((
            StatusCode::BAD_REQUEST,
            "invalid secret name: use [a-zA-Z0-9/_-] only".into(),
        ));
    }
    if name.split('/').any(|seg| seg.is_empty()) {
        return Err((
            StatusCode::BAD_REQUEST,
            "invalid secret name: empty segment".into(),
        ));
    }
    Ok(())
}

/// Public wrapper for admin_ui handlers ( name validation).
/// Validate name admin.
pub fn validate_name_admin(name: &str) -> Result<(), (StatusCode, String)> {
    validate_name(name)
}

// ── Event emission (inbox-first - design ) ─────────────────────────

/// Emit a secrets event through the shared outbox helper. Metadata-only
/// payloads - values NEVER in event payloads. Best-effort: a failed event
/// is logged, never fails the domain operation. Every row carries the
/// publisher's bearer token and subject (bus design ).
async fn emit_event(
    pool: &sqlx::PgPool,
    env_id: uuid::Uuid,
    event_type: &str,
    payload: serde_json::Value,
    stream_family: &str,
    publisher_token: Option<String>,
    publisher_subject: Option<&str>,
) {
    let mut conn = match pool.acquire().await {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(error = %e, event_type = %event_type, "secrets: failed to acquire connection for outbox event");
            return;
        }
    };
    let _ = sqlx::query("SELECT sentin8_set_tenant_context($1)")
        .bind(env_id)
        .execute(&mut *conn)
        .await;
    if let Err(e) = sentin8::bus::outbox::insert_outbox_row_with_publisher(
        &mut *conn,
        env_id,
        stream_family,
        event_type,
        &payload,
        publisher_token.as_deref(),
        publisher_subject,
    )
    .await
    {
        tracing::warn!(error = %e, event_type = %event_type, "secrets: failed to emit outbox event");
    }
}

// ── Upsert ──────────────────────────────────────────────────────────────

/// `PUT /v1/secrets/{name}` - upsert + new version.
#[derive(Debug, serde::Deserialize, ToSchema)]
/// Request body for upsertsecret.
pub struct UpsertSecretRequest {
    /// Plaintext secret value (encrypted server-side, never stored as sent).
    /// The value.
    pub value: String,
    #[serde(default)]
    /// The description.
    pub description: String,
    #[serde(default)]
    /// Optional expiry - a Cron schedule emits `sentin8:secrets:secret:expiring`
    /// T-14d before it (secrets README §7).
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[utoipa::path(
    put,
    operation_id = "secret.upsert",
    path = "/v1/secrets/{name}",
    params(("name" = String, Path, description = "Secret name path (e.g. stripe/api_key)")),
    request_body = UpsertSecretRequest,
    responses(
        (status = 200, description = "Secret stored (metadata returned)"),
        (status = 400, description = "Invalid name"),
        (status = 403, description = "Missing secrets scope"),
    ),
    security(("sentin8:secrets:secret:write" = [])),
    tag = "secrets",
)]
/// Handle PUT secret.
pub async fn put_secret(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(name): Path<String>,
    axum::Json(req): axum::Json<UpsertSecretRequest>,
) -> Result<Response, (StatusCode, String)> {
    let a = crate::auth::verify_token(&state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:secrets:secret:write"),
    )
    .await?;
    require_write_scope(&a)?;
    validate_name(&name)?;
    let env_id = a.env_id();

    // Encrypt server-side - plaintext exists only in this request scope.
    let envelope =
        sentin8::crypto::seal_raw(&state.master_key, req.value.as_bytes()).map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("encrypt failed: {e}"),
            )
        })?;

    // Upsert with version bump - one tenant transaction carries the row
    // and its version-history row (context is transaction-local; secrets
    // DESIGN §5).
    let mut tx = begin_tenant_tx(&state.pool, env_id).await?;
    let row = sqlx::query_as::<_, SecretRow>(
        r#"INSERT INTO secrets (name, description, value_cipher, key_version, version, status, created_by, env_id, expires_at)
           VALUES ($1, $2, $3, 1, 1, 'active', $4, $5, $6)
           ON CONFLICT (env_id, name) DO UPDATE
             SET description = EXCLUDED.description,
                 value_cipher = EXCLUDED.value_cipher,
                 key_version = 1,
                 version = secrets.version + 1,
                 status = 'active',
                 expires_at = EXCLUDED.expires_at,
                 updated_at = now()
         RETURNING id, name, description, value_cipher, key_version, version, status, created_by, env_id, created_at, updated_at"#,
    )
    .bind(&name)
    .bind(&req.description)
    .bind(req.expires_at)
    .bind(&envelope)
    .bind(a.sub())
    .bind(env_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(db_err)?;

    // Version history row (same logical change, same transaction).
    let _ = sqlx::query(
        "INSERT INTO versions (secret_id, version, value_cipher, key_version, created_by, env_id)
         VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT (secret_id, version) DO NOTHING",
    )
    .bind(row.id)
    .bind(row.version)
    .bind(&envelope)
    .bind(row.key_version)
    .bind(a.sub())
    .bind(env_id)
    .execute(&mut *tx)
    .await
    .map_err(db_err)?;
    tx.commit().await.map_err(db_err)?;

    let created = row.version == 1;
    let event_type = if created {
        "sentin8:secrets:secret:created"
    } else {
        "sentin8:secrets:secret:updated"
    };
    let mut payload = serde_json::json!({
        "secret_id": row.id,
        "name": row.name,
        "version": row.version,
    });
    if !created {
        payload["previous_version"] = serde_json::json!(row.version - 1);
    }
    emit_event(
        &state.pool,
        env_id,
        event_type,
        payload,
        &state.config.stream_family,
        crate::auth::raw_bearer_token(&headers),
        Some(a.sub()),
    )
    .await;

    // Metadata only - the envelope never leaves this function.
    Ok(axum::Json(row.metadata()).into_response())
}

// ── Metadata reads ──────────────────────────────────────────────────────

#[derive(Debug, serde::Deserialize, utoipa::ToSchema, utoipa::IntoParams)]
/// The listsecretsquery type.
pub struct ListSecretsQuery {
    #[serde(default)]
    /// The status.
    pub status: Option<String>,
}

/// `GET /v1/secrets` - list metadata (names, versions, status - NEVER values).
#[utoipa::path(
    get,
    operation_id = "secret.list",
    path = "/v1/secrets",
    params(ListSecretsQuery),
    responses(
        (status = 200, description = "Secret metadata list"),
        (status = 403, description = "Missing secrets scope"),
    ),
    security(("sentin8:secrets:secret:read" = [])),
    tag = "secrets",
)]
/// List secrets.
pub async fn list_secrets(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::extract::Query(q): axum::extract::Query<ListSecretsQuery>,
) -> Result<axum::Json<serde_json::Value>, (StatusCode, String)> {
    let a = crate::auth::verify_token(&state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:secrets:secret:read"),
    )
    .await?;
    require_read_scope(&a)?;
    let env_id = a.env_id();

    let status_filter = q.status.as_deref().unwrap_or("active");
    let all = status_filter == "all";
    let mut tx = begin_tenant_tx(&state.pool, env_id).await?;
    let rows: Vec<SecretRow> = if all {
        sqlx::query_as(
            "SELECT id, name, description, value_cipher, key_version, version, status, created_by, env_id, created_at, updated_at, expires_at
             FROM secrets WHERE env_id = $1 ORDER BY name",
        )
        .bind(env_id)
        .fetch_all(&mut *tx)
        .await
    } else {
        sqlx::query_as(
            "SELECT id, name, description, value_cipher, key_version, version, status, created_by, env_id, created_at, updated_at, expires_at
             FROM secrets WHERE env_id = $1 AND status = $2 ORDER BY name",
        )
        .bind(env_id)
        .bind(status_filter)
        .fetch_all(&mut *tx)
        .await
    }
    .map_err(db_err)?;
    tx.commit().await.map_err(db_err)?;

    let items: Vec<serde_json::Value> = rows.iter().map(|r| r.metadata()).collect();
    Ok(axum::Json(serde_json::json!({ "secrets": items })))
}

/// `GET /v1/secrets/{name}` - metadata for one secret (no value).
#[utoipa::path(
    get,
    operation_id = "secret.get",
    path = "/v1/secrets/{name}",
    params(("name" = String, Path, description = "Secret name path")),
    responses(
        (status = 200, description = "Secret metadata"),
        (status = 404, description = "Secret not found"),
        (status = 403, description = "Missing secrets scope"),
    ),
    security(("sentin8:secrets:secret:read" = [])),
    tag = "secrets",
)]
/// Fetch secret.
pub async fn get_secret(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(name): Path<String>,
) -> Result<axum::Json<serde_json::Value>, (StatusCode, String)> {
    let a = crate::auth::verify_token(&state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:secrets:secret:read"),
    )
    .await?;
    require_read_scope(&a)?;
    let env_id = a.env_id();
    let row = fetch_by_name(&state.pool, env_id, &name)
        .await?
        .ok_or((StatusCode::NOT_FOUND, format!("secret {name:?} not found")))?;
    Ok(axum::Json(row.metadata()))
}

// ── Rotation + history + lifecycle ──────────────────────────────────────

/// `POST /v1/secrets/{name}/rotate` - new version from body value; the old
/// version is retained until the prune window.
#[utoipa::path(
    post,
    operation_id = "secret.rotate",
    path = "/v1/secrets/{name}/rotate",
    params(("name" = String, Path, description = "Secret name path")),
    request_body = UpsertSecretRequest,
    responses(
        (status = 200, description = "Secret rotated (metadata returned)"),
        (status = 404, description = "Secret not found"),
        (status = 403, description = "Missing secrets scope"),
    ),
    security(("sentin8:secrets:secret:write" = [])),
    tag = "secrets",
)]
/// Rotate secret.
pub async fn rotate_secret(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(name): Path<String>,
    axum::Json(req): axum::Json<UpsertSecretRequest>,
) -> Result<axum::Json<serde_json::Value>, (StatusCode, String)> {
    let a = crate::auth::verify_token(&state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:secrets:secret:write"),
    )
    .await?;
    require_write_scope(&a)?;
    let env_id = a.env_id();

    let existing = fetch_by_name(&state.pool, env_id, &name)
        .await?
        .ok_or((StatusCode::NOT_FOUND, format!("secret {name:?} not found")))?;

    let envelope =
        sentin8::crypto::seal_raw(&state.master_key, req.value.as_bytes()).map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("encrypt failed: {e}"),
            )
        })?;
    let new_version = existing.version + 1;

    // Rotation + version-history row in one tenant transaction (secrets
    // DESIGN §5 - context is transaction-local).
    let mut tx = begin_tenant_tx(&state.pool, env_id).await?;
    let updated = sqlx::query_as::<_, SecretRow>(
        "UPDATE secrets SET value_cipher = $3, key_version = $4, version = $5, status = 'active', updated_at = now()
         WHERE env_id = $1 AND name = $2
         RETURNING id, name, description, value_cipher, key_version, version, status, created_by, env_id, created_at, updated_at",
    )
    .bind(env_id)
    .bind(&name)
    .bind(&envelope)
    .bind(1) // current master-key epoch
    .bind(new_version)
    .fetch_one(&mut *tx)
    .await
    .map_err(db_err)?;

    let _ = sqlx::query(
        "INSERT INTO versions (secret_id, version, value_cipher, key_version, created_by, env_id)
         VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT (secret_id, version) DO NOTHING",
    )
    .bind(updated.id)
    .bind(new_version)
    .bind(&envelope)
    .bind(1)
    .bind(a.sub())
    .bind(env_id)
    .execute(&mut *tx)
    .await
    .map_err(db_err)?;
    tx.commit().await.map_err(db_err)?;

    emit_event(
        &state.pool,
        env_id,
        "sentin8:secrets:secret:rotated",
        serde_json::json!({
            "secret_id": updated.id,
            "name": updated.name,
            "version": new_version,
            "previous_version": existing.version,
        }),
        &state.config.stream_family,
        crate::auth::raw_bearer_token(&headers),
        Some(a.sub()),
    )
    .await;

    Ok(axum::Json(updated.metadata()))
}

/// `GET /v1/secrets/{name}/history` - version metadata list (no values).
#[utoipa::path(
    get,
    operation_id = "secret.history",
    path = "/v1/secrets/{name}/history",
    params(("name" = String, Path, description = "Secret name path")),
    responses(
        (status = 200, description = "Version metadata list"),
        (status = 404, description = "Secret not found"),
        (status = 403, description = "Missing secrets scope"),
    ),
    security(("sentin8:secrets:secret:read" = [])),
    tag = "secrets",
)]
/// Handle secret history.
pub async fn secret_history(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(name): Path<String>,
) -> Result<axum::Json<serde_json::Value>, (StatusCode, String)> {
    let a = crate::auth::verify_token(&state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:secrets:secret:read"),
    )
    .await?;
    require_read_scope(&a)?;
    let env_id = a.env_id();
    let row = fetch_by_name(&state.pool, env_id, &name)
        .await?
        .ok_or((StatusCode::NOT_FOUND, format!("secret {name:?} not found")))?;

    #[derive(sqlx::FromRow)]
    struct VersionRec {
        version: i32,
        key_version: i32,
        created_by: String,
        created_at: chrono::DateTime<chrono::Utc>,
    }
    let mut tx = begin_tenant_tx(&state.pool, env_id).await?;
    let versions = sqlx::query_as::<_, VersionRec>(
        "SELECT version, key_version, created_by, created_at FROM versions
         WHERE secret_id = $1 AND env_id = $2 ORDER BY version DESC",
    )
    .bind(row.id)
    .bind(env_id)
    .fetch_all(&mut *tx)
    .await
    .map_err(db_err)?;
    tx.commit().await.map_err(db_err)?;

    let items: Vec<serde_json::Value> = versions
        .iter()
        .map(|v| {
            serde_json::json!({
                "version": v.version,
                "key_version": v.key_version,
                "created_by": v.created_by,
                "created_at": v.created_at.to_rfc3339(),
                "current": v.version == row.version,
            })
        })
        .collect();
    Ok(axum::Json(
        serde_json::json!({ "name": row.name, "versions": items }),
    ))
}

/// `DELETE /v1/secrets/{name}` - soft-disable (status → disabled). Hard
/// delete is not exposed (values are purge-able via version prune only).
#[utoipa::path(
    delete,
    operation_id = "secret.delete",
    path = "/v1/secrets/{name}",
    params(("name" = String, Path, description = "Secret name path")),
    responses(
        (status = 200, description = "Secret disabled"),
        (status = 404, description = "Secret not found"),
        (status = 403, description = "Missing secrets scope"),
    ),
    security(("sentin8:secrets:secret:admin" = [])),
    tag = "secrets",
)]
/// Delete secret.
pub async fn delete_secret(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(name): Path<String>,
) -> Result<axum::Json<serde_json::Value>, (StatusCode, String)> {
    let a = crate::auth::verify_token(&state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:secrets:secret:admin"),
    )
    .await?;
    require_admin_scope(&a)?;
    let env_id = a.env_id();

    let mut tx = begin_tenant_tx(&state.pool, env_id).await?;
    let row = sqlx::query_as::<_, SecretRow>(
        "UPDATE secrets SET status = 'disabled', updated_at = now()
         WHERE env_id = $1 AND name = $2
         RETURNING id, name, description, value_cipher, key_version, version, status, created_by, env_id, created_at, updated_at",
    )
    .bind(env_id)
    .bind(&name)
    .fetch_optional(&mut *tx)
    .await
    .map_err(db_err)?
    .ok_or((StatusCode::NOT_FOUND, format!("secret {name:?} not found")))?;
    tx.commit().await.map_err(db_err)?;

    emit_event(
        &state.pool,
        env_id,
        "sentin8:secrets:secret:disabled",
        serde_json::json!({ "secret_id": row.id, "name": row.name }),
        &state.config.stream_family,
        crate::auth::raw_bearer_token(&headers),
        Some(a.sub()),
    )
    .await;

    Ok(axum::Json(row.metadata()))
}

// ── Reveal (human, admin-gated, audit-logged) ───────────────────────────

/// `GET /v1/secrets/{name}/reveal` - return the value. Admin scope; every
/// call writes a `reads` audit row.
#[utoipa::path(
    get,
    operation_id = "secret.reveal",
    path = "/v1/secrets/{name}/reveal",
    params(("name" = String, Path, description = "Secret name path")),
    responses(
        (status = 200, description = "Revealed value (audit-logged)"),
        (status = 404, description = "Secret not found or disabled"),
        (status = 403, description = "Missing secrets admin scope"),
    ),
    security(("sentin8:secrets:secret:admin" = [])),
    tag = "secrets",
)]
/// Handle reveal secret.
pub async fn reveal_secret(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(name): Path<String>,
) -> Result<axum::Json<serde_json::Value>, (StatusCode, String)> {
    let a = crate::auth::verify_token(&state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:secrets:secret:admin"),
    )
    .await?;
    require_admin_scope(&a)?;
    let (value, meta) = resolve_internal(
        &state,
        a.env_id(),
        &name,
        a.sub(),
        "sentin8:secrets",
        "user",
    )
    .await?;
    let _ = value; // human response is the value string
    Ok(axum::Json(meta))
}

// ── Machine resolution (M2M, audit-logged) ──────────────────────────────

/// `POST /v1/secrets/resolve` - machine resolution. Body:
/// `{"ref": "secrets://<name>"}` → `{"value": ..., "version": ...}`.
/// Standard consumption path for services; audit row per call.
#[derive(Debug, serde::Deserialize, ToSchema)]
/// Request body for resolve.
pub struct ResolveRequest {
    /// Secret reference URI (`secrets://<name>`; a bare name is accepted).
    pub r#ref: String,
}

#[derive(Debug, serde::Serialize, ToSchema)]
/// Response payload for resolve.
pub struct ResolveResponse {
    /// The name.
    pub name: String,
    /// The value.
    pub value: String,
    /// The version.
    pub version: i32,
}

#[utoipa::path(
    post,
    operation_id = "secret.resolve",
    path = "/v1/secrets/resolve",
    request_body = ResolveRequest,
    responses(
        (status = 200, description = "Resolved value (audit-logged)"),
        (status = 400, description = "Invalid reference"),
        (status = 404, description = "Secret not found or disabled"),
        (status = 403, description = "Missing secrets scope"),
    ),
    security(("sentin8:secrets:secret:read" = [])),
    tag = "secrets",
)]
/// Resolve secret.
pub async fn resolve_secret(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::Json(req): axum::Json<ResolveRequest>,
) -> Result<axum::Json<ResolveResponse>, (StatusCode, String)> {
    let a = crate::auth::verify_token(&state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:secrets:secret:read"),
    )
    .await?;
    require_read_scope(&a)?;

    // Accept `secrets://<name>`, `sentin8-secrets://<name>` and bare names.
    let name = req
        .r#ref
        .strip_prefix("secrets://")
        .or_else(|| req.r#ref.strip_prefix("sentin8-secrets://"))
        .unwrap_or(&req.r#ref)
        .to_string();
    validate_name(&name)?;
    let env_id = a.env_id();

    let (value, meta) =
        resolve_internal(&state, env_id, &name, a.sub(), "sentin8:secrets", "m2m").await?;

    Ok(axum::Json(ResolveResponse {
        name: meta["name"].as_str().unwrap_or(&name).to_string(),
        value,
        version: meta["version"].as_i64().unwrap_or(0) as i32,
    }))
}

/// Internal resolve: fetch → check status → decrypt → audit row. The
/// plaintext lives only inside this function scope (zeroized via
/// `SecretValue` drop). Audit-before-response (secrets DESIGN §5): the
/// `reads` row is INSERTed inside the SAME tenant transaction as the
/// value SELECT - an audit failure aborts the read (500), the value is
/// never returned unaudited.
async fn resolve_internal(
    state: &AppState,
    env_id: uuid::Uuid,
    name: &str,
    reader_subject: &str,
    reader_service: &str,
    reader_type: &str,
) -> Result<(String, serde_json::Value), (StatusCode, String)> {
    let mut tx = begin_tenant_tx(&state.pool, env_id).await?;
    let row = sqlx::query_as::<_, SecretRow>(
        "SELECT id, name, description, value_cipher, key_version, version, status, created_by, env_id, created_at, updated_at, expires_at
         FROM secrets WHERE env_id = $1 AND name = $2",
    )
    .bind(env_id)
    .bind(name)
    .fetch_optional(&mut *tx)
    .await
    .map_err(db_err)?
    .ok_or((StatusCode::NOT_FOUND, format!("secret {name:?} not found")))?;
    if row.status != "active" {
        // Disabled secrets refuse to resolve.
        return Err((
            StatusCode::NOT_FOUND,
            format!("secret {name:?} is disabled"),
        ));
    }
    let plain = sentin8::crypto::open(&state.master_key, &row.value_cipher).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("decrypt failed: {e}"),
        )
    })?;
    let value = sentin8_secrets_sdk::secrets::SecretValue::new(plain)
        .into_string()
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("secret decode: {e}"),
            )
        })?;

    // Audit INSIDE the same transaction as the value read - a failed
    // INSERT rolls the whole read back (audit-before-response).
    sqlx::query(
        "INSERT INTO reads (secret_id, version, reader_subject, reader_service, reader_type, env_id)
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(row.id)
    .bind(row.version)
    .bind(reader_subject)
    .bind(reader_service)
    .bind(reader_type)
    .bind(env_id)
    .execute(&mut *tx)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, secret_id = %row.id, "secrets: reveal audit INSERT FAILED - read denied (audit-before-response)");
        (StatusCode::INTERNAL_SERVER_ERROR, "audit failure".to_string())
    })?;
    tx.commit().await.map_err(db_err)?;

    let meta = serde_json::json!({
        "name": row.name,
        "version": row.version,
    });
    Ok((value, meta))
}

// ── Reveal audit trail (admin) ──────────────────────────────────────────

/// `GET /v1/secrets/{name}/reads` - reveal audit trail (admin).
#[utoipa::path(
    get,
    operation_id = "secret.reads",
    path = "/v1/secrets/{name}/reads",
    params(("name" = String, Path, description = "Secret name path")),
    responses(
        (status = 200, description = "Reveal audit rows"),
        (status = 404, description = "Secret not found"),
        (status = 403, description = "Missing secrets admin scope"),
    ),
    security(("sentin8:secrets:secret:admin" = [])),
    tag = "secrets",
)]
/// Handle secret reads.
pub async fn secret_reads(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(name): Path<String>,
) -> Result<axum::Json<serde_json::Value>, (StatusCode, String)> {
    let a = crate::auth::verify_token(&state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:secrets:secret:admin"),
    )
    .await?;
    require_admin_scope(&a)?;
    let env_id = a.env_id();
    let row = fetch_by_name(&state.pool, env_id, &name)
        .await?
        .ok_or((StatusCode::NOT_FOUND, format!("secret {name:?} not found")))?;

    #[derive(sqlx::FromRow)]
    struct ReadRec {
        version: i32,
        reader_subject: String,
        reader_service: String,
        reader_type: String,
        created_at: chrono::DateTime<chrono::Utc>,
    }
    let mut tx = begin_tenant_tx(&state.pool, env_id).await?;
    let reads = sqlx::query_as::<_, ReadRec>(
        "SELECT version, reader_subject, reader_service, reader_type, created_at
         FROM reads WHERE secret_id = $1 AND env_id = $2 ORDER BY created_at DESC LIMIT 100",
    )
    .bind(row.id)
    .bind(env_id)
    .fetch_all(&mut *tx)
    .await
    .map_err(db_err)?;
    tx.commit().await.map_err(db_err)?;

    let items: Vec<serde_json::Value> = reads
        .iter()
        .map(|r| {
            serde_json::json!({
                "version": r.version,
                "reader_subject": r.reader_subject,
                "reader_service": r.reader_service,
                "reader_type": r.reader_type,
                "read_at": r.created_at.to_rfc3339(),
            })
        })
        .collect();
    Ok(axum::Json(
        serde_json::json!({ "name": row.name, "reads": items }),
    ))
}

/// `GET /v1/health` - custom payload (shell supplies the standard one too).
#[utoipa::path(
    get,
    operation_id = "secrets.health",
    path = "/v1/health",
    responses((status = 200, description = "Service healthy")),
    tag = "secrets",
)]
/// Handle health handler.
pub async fn health_handler() -> impl IntoResponse {
    let mut payload = serde_json::json!({
        "status": "ok",
        "service": "sentin8:secrets",
        "version": sentin8::build_info::id(),
        "build": sentin8::build_info::build_hash(),
    });
    if let Some(n) = sentin8::middleware::traffic_counter::process_active_connections() {
        payload["active_connections"] = serde_json::json!(n);
    }
    axum::Json(payload)
}

// ── Maintenance: version prune + master-key re-encrypt ──

/// `POST /v1/secrets/maintenance/prune` - delete versions older than the
/// current one past the retention window (default 7d; `SENTIN8_SECRETS_PRUNE_DAYS`).
/// Idempotent; safe to call from Sentin8:Cron (proxy-back). The reveal-audit
/// table is NEVER pruned (security-relevant history).
#[utoipa::path(
    post,
    operation_id = "secrets.maintenance.prune",
    path = "/v1/secrets/maintenance/prune",
    responses(
        (status = 200, description = "Prune summary"),
        (status = 403, description = "Missing secrets admin scope"),
    ),
    security(("sentin8:secrets:secret:admin" = [])),
    tag = "secrets",
)]
/// Handle maintenance prune.
pub async fn maintenance_prune(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Result<axum::Json<serde_json::Value>, (StatusCode, String)> {
    let a = crate::auth::verify_token(&state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:secrets:secret:admin"),
    )
    .await?;
    require_admin_scope(&a)?;

    let prune_days = state.config.prune_days;
    if prune_days <= 0 {
        return Ok(axum::Json(
            serde_json::json!({ "pruned": 0, "disabled": true }),
        ));
    }

    // Delete non-current versions whose created_at is older than the window.
    // Pruning runs within the caller's env (context set via the tenant
    // transaction - consistent with every other handler); a full-fleet
    // sweep calls this per env via the scheduled cron proxy-back.
    let mut tx = begin_tenant_tx(&state.pool, a.env_id()).await?;
    let result = sqlx::query(
        "DELETE FROM versions v
         USING secrets s
         WHERE v.secret_id = s.id
           AND v.env_id = s.env_id
           AND s.env_id = $1
           AND v.version < s.version
           AND v.created_at < now() - make_interval(days => $2)",
    )
    .bind(a.env_id())
    .bind(prune_days)
    .execute(&mut *tx)
    .await
    .map_err(db_err)?;
    tx.commit().await.map_err(db_err)?;

    Ok(axum::Json(serde_json::json!({
        "pruned": result.rows_affected(),
        "prune_days": prune_days,
        "env_id": a.env_id(),
    })))
}

/// `POST /v1/secrets/maintenance/re-encrypt` - re-encrypt rows whose
/// `key_version` is below the current master-key epoch (design
/// rotation lever). Read old / write new per row; idempotent + resumable
/// (rows keep their old `key_version` until successfully re-written).
#[derive(Debug, serde::Deserialize, ToSchema)]
/// Request body for reencrypt.
pub struct ReEncryptRequest {
    /// The PREVIOUS master key (base64-32) used to open `key_version < current` rows.
    /// The previous master key.
    pub previous_master_key: String,
    /// New epoch to stamp on re-encrypted rows (defaults to 1).
    #[serde(default)]
    /// The new key version.
    pub new_key_version: Option<i32>,
}

#[utoipa::path(
    post,
    operation_id = "secrets.maintenance.re-encrypt",
    path = "/v1/secrets/maintenance/re-encrypt",
    request_body = ReEncryptRequest,
    responses(
        (status = 200, description = "Re-encrypt summary"),
        (status = 400, description = "Invalid previous key"),
        (status = 403, description = "Missing secrets admin scope"),
    ),
    security(("sentin8:secrets:secret:admin" = [])),
    tag = "secrets",
)]
/// Handle maintenance re encrypt.
pub async fn maintenance_re_encrypt(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::Json(req): axum::Json<ReEncryptRequest>,
) -> Result<axum::Json<serde_json::Value>, (StatusCode, String)> {
    let a = crate::auth::verify_token(&state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:secrets:secret:admin"),
    )
    .await?;
    require_admin_scope(&a)?;

    let old_key = sentin8::crypto::MasterKey::from_base64(&req.previous_master_key)
        .map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                format!("invalid previous key: {e}"),
            )
        })?
        .ok_or((StatusCode::BAD_REQUEST, "previous key is empty".to_string()))?;
    let new_epoch = req.new_key_version.unwrap_or(1).max(1);

    // Rows in the caller's env with an old epoch. Kept in the caller's env
    // (same RLS consistency as prune); a full-fleet sweep calls this per env.
    #[derive(sqlx::FromRow)]
    struct Rec {
        id: uuid::Uuid,
        value_cipher: Vec<u8>,
    }
    let mut tx = begin_tenant_tx(&state.pool, a.env_id()).await?;
    let rows: Vec<Rec> = sqlx::query_as(
        "SELECT id, value_cipher FROM secrets WHERE env_id = $1 AND key_version < $2",
    )
    .bind(a.env_id())
    .bind(new_epoch)
    .fetch_all(&mut *tx)
    .await
    .map_err(db_err)?;

    let mut ok = 0u64;
    let mut failed = 0u64;
    for r in &rows {
        // Decrypt with the OLD key, re-seal with the CURRENT one.
        let plain = match sentin8::crypto::open(&old_key, &r.value_cipher) {
            Ok(p) => p,
            Err(e) => {
                failed += 1;
                tracing::error!(secret_id = %r.id, error = %e, "re-encrypt: decrypt with previous key FAILED");
                continue;
            }
        };
        let envelope = match sentin8::crypto::seal_raw(&state.master_key, &plain) {
            Ok(s) => s,
            Err(e) => {
                failed += 1;
                tracing::error!(secret_id = %r.id, error = %e, "re-encrypt: seal with current key FAILED");
                continue;
            }
        };
        // Update the main row + its current version-history row (same tenant
        // transaction; rows keep their old key_version until re-written -
        // idempotent + resumable).
        match sqlx::query(
            "UPDATE secrets SET value_cipher = $3, key_version = $4, updated_at = now()
             WHERE id = $1 AND env_id = $2",
        )
        .bind(r.id)
        .bind(a.env_id())
        .bind(&envelope)
        .bind(new_epoch)
        .execute(&mut *tx)
        .await
        {
            Ok(_) => ok += 1,
            Err(e) => {
                failed += 1;
                tracing::error!(secret_id = %r.id, error = %e, "re-encrypt: row update FAILED");
                continue;
            }
        }
        let _ = sqlx::query(
            "UPDATE versions SET value_cipher = $3, key_version = $4
             WHERE secret_id = $1 AND env_id = $2
               AND version = (SELECT version FROM secrets WHERE id = $1 AND env_id = $2)",
        )
        .bind(r.id)
        .bind(a.env_id())
        .bind(&envelope)
        .bind(new_epoch)
        .execute(&mut *tx)
        .await;
    }
    tx.commit().await.map_err(db_err)?;

    Ok(axum::Json(serde_json::json!({
        "scanned": rows.len(),
        "reencrypted": ok,
        "failed": failed,
        "new_key_version": new_epoch,
        "env_id": a.env_id(),
    })))
}

// ── Cron proxy-back (secrets DESIGN §10) ────────────────────────────────

/// `POST /v1/internal/schedules/run` - Sentin8:Cron proxy-back target.
/// Maintenance sweeps that must not depend on a user request:
/// (a) `expiry-scan` - emits `sentin8:secrets:secret:expiring` for every
/// secret whose `expires_at` lands within the next 14 days (secrets
/// README §7), (b) `version-prune` - drops prunable non-current versions
/// using the service's own prune window (SECRETS-2, secrets DESIGN §10:
/// the schedule is declared at boot next to `expiry-scan`). Authenticated
/// by the cron ticker's M2M token (verified like any other principal
/// under Shield).

/// The cron proxy-back request (`schedule_type` + the env to sweep).
#[derive(Debug, serde::Deserialize, utoipa::ToSchema)]
pub struct ScheduleRunRequest {
    /// The schedule type that fired (`expiry-scan`/`version-prune`).
    #[serde(default)]
    pub schedule_type: String,
    /// The env the sweep runs for.
    pub env_id: uuid::Uuid,
}

/// The `POST /v1/internal/schedules/run` reply (the per-type maintenance
/// result: the version-prune count, or the expiring notifications
/// emitted).
#[derive(Debug, serde::Serialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub struct ScheduleRunResponse {
    /// The schedule that ran.
    pub schedule_type: String,
    /// Version rows pruned (prune run).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pruned: Option<u64>,
    /// Expiring-secret notifications emitted (expiry run).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expiring: Option<usize>,
    /// Expiry-disable flag (expiry run).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disabled: Option<bool>,
    /// Always `completed`.
    pub status: String,
}

#[utoipa::path(
    post,
    operation_id = "secrets.internal.schedules.run",
    path = "/v1/internal/schedules/run",
    request_body = ScheduleRunRequest,
    responses((status = 200, description = "Maintenance run completed", body = ScheduleRunResponse)),
    tag = "secrets",
)]
/// Run the declared maintenance schedule for the cron's env.
pub async fn internal_schedules_run(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::Json(body): axum::Json<ScheduleRunRequest>,
) -> Result<axum::Json<ScheduleRunResponse>, (StatusCode, String)> {
    let a = crate::auth::verify_token(&state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:secrets:secret:admin"),
    )
    .await?;
    require_admin_scope(&a)?;
    let schedule_type = if body.schedule_type.is_empty() {
        "unknown".to_string()
    } else {
        body.schedule_type.clone()
    };

    // The cron row carries a single env; run the sweep for that env.
    let env_id = body.env_id;

    // (b) version-prune (SECRETS-2): drop prunable non-current versions for
    // the schedule's env - the same predicate the admin endpoint runs, but
    // driven by Cron so the window holds without a user request. The prune
    // window disabled (`prune_days <= 0`) is a no-op, reported as disabled.
    if schedule_type == "version-prune" {
        let prune_days = state.config.prune_days;
        if prune_days <= 0 {
            return Ok(axum::Json(ScheduleRunResponse {
                schedule_type: schedule_type.clone(),
                pruned: Some(0),
                expiring: None,
                disabled: Some(true),
                status: "completed".to_string(),
            }));
        }
        let mut tx = begin_tenant_tx(&state.pool, env_id).await?;
        let result = sqlx::query(
            "DELETE FROM versions v
             USING secrets s
             WHERE v.secret_id = s.id
               AND v.env_id = s.env_id
               AND s.env_id = $1
               AND v.version < s.version
               AND v.created_at < now() - make_interval(days => $2)",
        )
        .bind(env_id)
        .bind(prune_days)
        .execute(&mut *tx)
        .await
        .map_err(db_err)?;
        tx.commit().await.map_err(db_err)?;
        tracing::info!(env_id = %env_id, pruned = result.rows_affected(), "secrets cron version-prune run");
        return Ok(axum::Json(ScheduleRunResponse {
            schedule_type: schedule_type.clone(),
            pruned: Some(result.rows_affected()),
            expiring: None,
            disabled: None,
            status: "completed".to_string(),
        }));
    }

    let mut emitted = 0usize;
    let mut tx = begin_tenant_tx(&state.pool, env_id).await?;
    let expiring: Vec<(uuid::Uuid, String)> = sqlx::query_as(
        "SELECT id, name FROM secrets
          WHERE env_id = $1 AND status = 'active'
            AND expires_at IS NOT NULL
            AND expires_at <= now() + interval '14 days'
          LIMIT 100",
    )
    .bind(env_id)
    .fetch_all(&mut *tx)
    .await
    .map_err(db_err)?;
    for (id, name) in &expiring {
        // Outbox emit inside the same tx; a single failure skips the row
        // (at-least-once on the next scan).
        let payload = serde_json::json!({
            "secret_id": id, "name": name, "env_id": env_id,
        });
        if sentin8::bus::outbox::insert_outbox_row(
            &mut *tx,
            env_id,
            "secrets",
            "sentin8:secrets:secret:expiring",
            &payload,
        )
        .await
        .is_ok()
        {
            emitted += 1;
        }
    }
    tx.commit().await.map_err(db_err)?;
    tracing::info!(env_id = %env_id, emitted, "secrets cron maintenance run");
    Ok(axum::Json(ScheduleRunResponse {
        schedule_type,
        pruned: None,
        expiring: Some(emitted),
        disabled: None,
        status: "completed".to_string(),
    }))
}
