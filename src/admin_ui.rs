// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Secrets
// SPDX-License-Identifier: Apache-2.0

//! Sentin8:Secrets Admin UI handlers — RFW definitions.
//! Served from `GET /v1/admin/ui/{page}`, rendered by Sentin8:Dash at runtime.

use crate::handlers::AppState;
use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use sentin8::rfw::page::*;
use sentin8::rfw::response::AdminUiResponse;
use sentin8::rfw::widget::*;
use serde::Deserialize;

/// Resolve the effective env_id for admin operations.
/// Priority: target_env_id query param (BFF proxy) > x-sentin8-env-id header (TLS) > token env_id.
#[derive(Deserialize, Default)]
/// The targetenvquery type.
pub struct TargetEnvQuery {
    #[serde(default)]
    target_env_id: Option<String>,
}

/// Resolve the effective env and authorize it ( — cross-env access is
/// validated at the authorization layer): if the resolved env differs from
/// the token env, the caller must be a platform/env admin. Otherwise 403.
fn resolve_env_id(
    headers: &HeaderMap,
    query: &TargetEnvQuery,
    a: &crate::auth::AuthContext,
) -> Result<String, (StatusCode, String)> {
    let requested = query
        .target_env_id
        .as_deref()
        .and_then(|s| uuid::Uuid::parse_str(s).ok())
        .or_else(|| {
            headers
                .get("x-sentin8-env-id")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| uuid::Uuid::parse_str(s).ok())
        });
    let token_env = a.env_id();
    match requested {
        Some(env) if env != token_env => {
            if a.has_scope("sentin8:sys:admin")
                || a.has_scope("sentin8:sys:env:admin")
                || a.has_scope("sentin8:sys:org:admin")
            {
                Ok(env.to_string())
            } else {
                Err((
                    StatusCode::FORBIDDEN,
                    "caller has no role in the target environment".into(),
                ))
            }
        }
        _ => Ok(token_env.to_string()),
    }
}

const READ_SCOPES: &[&str] = &[
    "sentin8:secrets:secret:read",
    "sentin8:secrets:secret:write",
    "sentin8:secrets:secret:admin",
    "sentin8:sys:admin",
    "sentin8:sys:org:admin",
    "sentin8:sys:env:admin",
];
const WRITE_SCOPES: &[&str] = &[
    "sentin8:secrets:secret:write",
    "sentin8:secrets:secret:admin",
    "sentin8:sys:admin",
    "sentin8:sys:org:admin",
    "sentin8:sys:env:admin",
];

/// Fetch admin ui.
pub async fn get_admin_ui(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(page): Path<String>,
    Query(q): Query<TargetEnvQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let a = crate::auth::verify_token(&state.config, &headers).await?;
    a.require_any_scope(READ_SCOPES)?;
    let _ = resolve_env_id(&headers, &q, &a)?;
    let def = match page.as_str() {
        "overview" => AdminPage::new("Secrets Overview")
            .widget(card(
                "Secret Management",
                "Tenant secrets are encrypted at rest (AES-256-GCM envelopes), versioned on every write, and every reveal is audit-logged. Values are masked by default — use the Reveal row action for an explicit, logged reveal.",
            ))
            .build(),
        "secrets" => AdminPage::new("Secrets")
            .action(link("Add Secret", "secrets/new"))
            .widget(table_with_actions(
                vec![
                    col_s("name", "Name", true),
                    col_s("version", "Version", true),
                    col_s("status", "Status", true),
                    col_s("updated_at", "Updated", true),
                ],
                "/secrets",
                vec![
                    row_action("History", "secrets/{name}/history"),
                    row_action_post("Reveal", "secrets/{name}/reveal"),
                    row_action("Rotate", "secrets/{name}/rotate"),
                    row_action_post("Disable", "secrets/{name}/disable"),
                ],
            ))
            .build(),
        "secrets/new" => AdminPage::new("Add Secret")
            .widget(RemoteWidget::Form(WidgetForm {
                fields: vec![
                    WidgetFormField {
                        key: "name".into(),
                        label: "Secret Name".into(),
                        field_type: FormFieldType::Text,
                        required: true,
                        placeholder: Some("e.g. stripe/api_key".into()),
                        default_value: None,
                        options: None,
                        validation: None,
                        width: None,
                        help_text: Some(
                            "Path segments of letters, digits, dash, underscore, slash.".into(),
                        ),
                        visible_if: None,
                    },
                    WidgetFormField {
                        key: "value".into(),
                        label: "Secret Value".into(),
                        field_type: FormFieldType::Password,
                        required: true,
                        placeholder: None,
                        default_value: None,
                        options: None,
                        validation: None,
                        width: None,
                        help_text: Some(
                            "Encrypted at rest before storage. Never shown again without an explicit, audit-logged reveal.".into(),
                        ),
                        visible_if: None,
                    },
                    WidgetFormField {
                        key: "description".into(),
                        label: "Description".into(),
                        field_type: FormFieldType::Text,
                        required: false,
                        placeholder: None,
                        default_value: None,
                        options: None,
                        validation: None,
                        width: None,
                        help_text: None,
                        visible_if: None,
                    },
                ],
                submit_endpoint: "/v1/admin/secrets".into(),
                submit_label: "Store Secret".into(),
                cancel_label: "Cancel".into(),
                method: FormMethod::Post,
            }))
            .build(),
        _p if page.starts_with("secrets/") && page.ends_with("/history") => {
            let name = page
                .strip_prefix("secrets/")
                .unwrap_or("")
                .strip_suffix("/history")
                .unwrap_or("");
            AdminPage::new(format!("History: {name}"))
                .widget(table(vec![
                    col_s("version", "Version", true),
                    col_s("key_version", "Key Epoch", true),
                    col_s("created_by", "Created By", true),
                    col_s("created_at", "Created", true),
                    col_s("current", "Current", true),
                ], "/secrets/history?name={name}"))
                .build()
        }
        p if page.starts_with("secrets/") && page.ends_with("/reads") => {
            let name = p
                .strip_prefix("secrets/")
                .unwrap_or("")
                .strip_suffix("/reads")
                .unwrap_or("");
            AdminPage::new(format!("Reveal Audit: {name}"))
                .widget(table(vec![
                    col_s("version", "Version", true),
                    col_s("reader_subject", "Reader", true),
                    col_s("reader_service", "Service", true),
                    col_s("reader_type", "Type", true),
                    col_s("read_at", "At", true),
                ], "/secrets/reads?name={name}"))
                .build()
        }
        "secrets/rotate" => AdminPage::new("Rotate Secret")
            .widget(RemoteWidget::Form(WidgetForm {
                fields: vec![
                    WidgetFormField {
                        key: "name".into(),
                        label: "Secret Name".into(),
                        field_type: FormFieldType::Hidden,
                        required: true,
                        placeholder: None,
                        default_value: None,
                        options: None,
                        validation: None,
                        width: None,
                        help_text: None,
                        visible_if: None,
                    },
                    WidgetFormField {
                        key: "value".into(),
                        label: "New Secret Value".into(),
                        field_type: FormFieldType::Password,
                        required: true,
                        placeholder: None,
                        default_value: None,
                        options: None,
                        validation: None,
                        width: None,
                        help_text: Some("The previous version is retained until the prune window.".into()),
                        visible_if: None,
                    },
                ],
                submit_endpoint: "/v1/admin/secrets/rotate".into(),
                submit_label: "Rotate".into(),
                cancel_label: "Cancel".into(),
                method: FormMethod::Post,
            }))
            .build(),
        "settings" => AdminPage::new("Secrets Settings")
            .widget(card(
                "Configuration",
                "Master key epoch, prune window, and stream family are configured via environment variables on the Secrets service (SENTIN8_SECRETS_*). Master-key rotation: set the new SENTIN8_SECRETS_MASTER_KEY, restart, then POST /v1/secrets/maintenance/re-encrypt with the previous key.",
            ))
            .build(),
        p if sentin8::rfw::policy_page("sentin8:secrets", p).is_some() => sentin8::rfw
            ::policy_page("sentin8:secrets", p)
            .expect("policy_page checked in guard")
            .build(),
        _ => {
            return Err((StatusCode::NOT_FOUND, format!("Unknown admin UI page: {page}")));
        }
    };
    Ok(Json(
        serde_json::to_value(AdminUiResponse::page(def)).unwrap(),
    ))
}

/// `GET /v1/admin/{resource}` — returns a JSON array of admin data rows.
/// Fetch admin data.
pub async fn get_admin_data(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<TargetEnvQuery>,
    Query(name_q): Query<NameQuery>,
    Path(resource): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    admin_data(state, headers, q, name_q, resource).await
}

/// GET alias for `/v1/admin/secrets` — the POST-only literal on the same
/// path shadows the `/v1/admin/{resource}` catch-all for GET requests
/// (axum returns 405 instead of falling through), so the data read must be
/// registered explicitly, mirroring the db service pattern.
pub async fn get_admin_data_secrets(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<TargetEnvQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    admin_data(
        state,
        headers,
        q,
        NameQuery::default(),
        "secrets".to_string(),
    )
    .await
}

async fn admin_data(
    state: AppState,
    headers: HeaderMap,
    q: TargetEnvQuery,
    name_q: NameQuery,
    resource: String,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let a = crate::auth::verify_token(&state.config, &headers).await?;
    a.require_any_scope(READ_SCOPES)?;
    let env_id = resolve_env_id(&headers, &q, &a)?;
    let env_uuid = uuid::Uuid::parse_str(&env_id)
        .map_err(|_| (StatusCode::BAD_REQUEST, "invalid env id".into()))?;
    // Tenant RLS context is transaction-local; every query below runs on the
    // same explicit transaction (secrets DESIGN §5).
    let mut tx = crate::handlers::begin_tenant_tx(&state.pool, env_uuid).await?;
    let rows: Vec<serde_json::Value> = match resource.as_str() {
        "secrets" => {
            let recs: Vec<(
                uuid::Uuid,
                String,
                i32,
                String,
                chrono::DateTime<chrono::Utc>,
            )> = sqlx::query_as(
                "SELECT id, name, version, status, updated_at FROM secrets
                     WHERE env_id = $1 ORDER BY name",
            )
            .bind(env_uuid)
            .fetch_all(&mut *tx)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("db error: {e}")))?;
            recs.iter()
                .map(|(id, name, version, status, updated_at)| {
                    serde_json::json!({
                        "id": id,
                        "name": name,
                        "version": version,
                        "status": status,
                        "updated_at": updated_at.to_rfc3339(),
                    })
                })
                .collect()
        }
        "secrets/history" => {
            let name = name_q
                .name
                .clone()
                .ok_or((StatusCode::BAD_REQUEST, "missing ?name= param".into()))?;
            let recs: Vec<(i32, i32, String, chrono::DateTime<chrono::Utc>)> = sqlx::query_as(
                "SELECT v.version, v.key_version, v.created_by, v.created_at
                 FROM versions v JOIN secrets s ON s.id = v.secret_id
                 WHERE s.env_id = $1 AND s.name = $2 ORDER BY v.version DESC",
            )
            .bind(env_uuid)
            .fetch_all(&mut *tx)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("db error: {e}")))?;
            let current: Option<i32> =
                sqlx::query_scalar("SELECT version FROM secrets WHERE env_id = $1 AND name = $2")
                    .bind(env_uuid)
                    .bind(&name)
                    .fetch_optional(&mut *tx)
                    .await
                    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("db error: {e}")))?;
            recs.iter()
                .map(|(version, key_version, created_by, created_at)| {
                    serde_json::json!({
                        "version": version,
                        "key_version": key_version,
                        "created_by": created_by,
                        "created_at": created_at.to_rfc3339(),
                        "current": Some(version) == current.as_ref(),
                    })
                })
                .collect()
        }
        "secrets/reads" => {
            let name = name_q
                .name
                .clone()
                .ok_or((StatusCode::BAD_REQUEST, "missing ?name= param".into()))?;
            let recs: Vec<(i32, String, String, String, chrono::DateTime<chrono::Utc>)> =
                sqlx::query_as(
                    "SELECT r.version, r.reader_subject, r.reader_service, r.reader_type, r.created_at
                     FROM reads r JOIN secrets s ON s.id = r.secret_id
                     WHERE s.env_id = $1 AND s.name = $2
                     ORDER BY r.created_at DESC LIMIT 100",
                )
                .bind(env_uuid)
                .bind(&name)
                .fetch_all(&mut *tx)
                .await
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("db error: {e}")))?;
            recs.iter()
                .map(
                    |(version, reader_subject, reader_service, reader_type, read_at)| {
                        serde_json::json!({
                            "version": version,
                            "reader_subject": reader_subject,
                            "reader_service": reader_service,
                            "reader_type": reader_type,
                            "read_at": read_at.to_rfc3339(),
                        })
                    },
                )
                .collect()
        }
        _ => vec![],
    };
    tx.commit()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("db error: {e}")))?;
    tracing::info!(resource = %resource, env = %env_uuid, rows = rows.len(), "admin data read");
    Ok(Json(serde_json::Value::Array(rows)))
}

/// `POST /v1/admin/secrets` — store a secret from the admin form. Returns
/// an RFW redirect to the secrets list. The value is encrypted server-side
/// exactly like the public API (`put_secret`).
#[derive(Deserialize)]
/// Request body for adminupsert.
pub struct AdminUpsertRequest {
    /// The name.
    pub name: String,
    /// The value.
    pub value: String,
    #[serde(default)]
    /// The description.
    pub description: Option<String>,
    #[serde(default)]
    /// Optional expiry — emits `sentin8:secrets:secret:expiring` T-14d
    /// before it via the cron schedule (secrets README §7).
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Handle admin put secret.
pub async fn admin_put_secret(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<TargetEnvQuery>,
    Json(req): Json<AdminUpsertRequest>,
) -> Result<Json<AdminUiResponse>, (StatusCode, String)> {
    let a = crate::auth::verify_token(&state.config, &headers).await?;
    a.require_any_scope(WRITE_SCOPES)?;
    let env_id = resolve_env_id(&headers, &q, &a)?;
    let env_uuid = uuid::Uuid::parse_str(&env_id)
        .map_err(|_| (StatusCode::BAD_REQUEST, "invalid env id".into()))?;
    crate::handlers::validate_name_admin(&req.name)?;

    let envelope =
        sentin8::crypto::seal_raw(&state.master_key, req.value.as_bytes()).map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("encrypt failed: {e}"),
            )
        })?;

    // The RLS context is transaction-local — the INSERT and its versions row
    // must share one tenant transaction (secrets DESIGN §5).
    let mut tx = crate::handlers::begin_tenant_tx(&state.pool, env_uuid).await?;
    let row = sqlx::query_as::<_, (uuid::Uuid, i32)>(
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
         RETURNING id, version"#,
    )
    .bind(&req.name)
    .bind(req.description.as_deref().unwrap_or(""))
    .bind(&envelope)
    .bind(a.sub())
    .bind(env_uuid)
    .bind(req.expires_at)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("db error: {e}")))?;

    let _ = sqlx::query(
        "INSERT INTO versions (secret_id, version, value_cipher, key_version, created_by, env_id)
         VALUES ($1, $2, $3, 1, $4, $5) ON CONFLICT (secret_id, version) DO NOTHING",
    )
    .bind(row.0)
    .bind(row.1)
    .bind(&envelope)
    .bind(a.sub())
    .bind(env_uuid)
    .execute(&mut *tx)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("db error: {e}")))?;
    tx.commit()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("db error: {e}")))?;

    sentin8::audit::AuditEvent::builder()
        .service("secrets")
        .action(sentin8::audit::AuditAction::Create)
        .resource("secret", &req.name)
        .actor(a.sub(), "org_staff")
        .tenant(uuid::Uuid::nil(), env_uuid)
        .message("secret stored via admin UI")
        .details(serde_json::json!({ "name": req.name, "version": row.1 }))
        .build();
    tracing::info!(
        name = %req.name,
        version = row.1,
        env_id = %env_uuid,
        actor = %a.sub(),
        "secret stored via admin UI"
    );

    Ok(Json(AdminUiResponse::redirect("secrets")))
}

/// `POST /v1/admin/secrets/{name}/disable` — soft-disable (admin).
#[derive(Deserialize)]
/// Request body for adminrotate.
pub struct AdminRotateRequest {
    /// The name.
    pub name: String,
    /// The value.
    pub value: String,
}

/// Handle admin disable secret.
pub async fn admin_disable_secret(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<TargetEnvQuery>,
    Path(name): Path<String>,
) -> Result<Json<AdminUiResponse>, (StatusCode, String)> {
    let a = crate::auth::verify_token(&state.config, &headers).await?;
    a.require_any_scope(WRITE_SCOPES)?;
    let env_id = resolve_env_id(&headers, &q, &a)?;
    let env_uuid = uuid::Uuid::parse_str(&env_id)
        .map_err(|_| (StatusCode::BAD_REQUEST, "invalid env id".into()))?;

    let mut tx = crate::handlers::begin_tenant_tx(&state.pool, env_uuid).await?;
    let updated = sqlx::query_scalar::<_, i32>(
        "UPDATE secrets SET status = 'disabled', updated_at = now()
         WHERE env_id = $1 AND name = $2 RETURNING version",
    )
    .bind(env_uuid)
    .bind(&name)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("db error: {e}")))?;
    tx.commit()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("db error: {e}")))?;

    if updated.is_none() {
        return Err((StatusCode::NOT_FOUND, format!("secret {name:?} not found")));
    }

    // Domain event (outbox) carries the audit context for store/disable
    // actions; reveals additionally write a `reads` row.
    tracing::info!(name = %name, env_id = %env_uuid, "secret disabled via admin UI");

    Ok(Json(AdminUiResponse::redirect("secrets")))
}

/// `POST /v1/admin/secrets/{name}/reveal` — explicit reveal action. Every
/// call writes a `reads` audit row; the value is returned once and
/// never cached by the UI.
/// Handle admin reveal secret.
pub async fn admin_reveal_secret(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<TargetEnvQuery>,
    Path(name): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let a = crate::auth::verify_token(&state.config, &headers).await?;
    // Reveal requires the admin scope — read scopes are not enough.
    a.require_any_scope(&[
        "sentin8:secrets:secret:admin",
        "sentin8:sys:admin",
        "sentin8:sys:org:admin",
        "sentin8:sys:env:admin",
    ])?;
    let env_id = resolve_env_id(&headers, &q, &a)?;
    let env_uuid = uuid::Uuid::parse_str(&env_id)
        .map_err(|_| (StatusCode::BAD_REQUEST, "invalid env id".into()))?;

    crate::handlers::validate_name_admin(&name)?;

    #[derive(sqlx::FromRow)]
    struct Row {
        id: uuid::Uuid,
        value_cipher: Vec<u8>,
        version: i32,
        status: String,
    }
    let mut tx = crate::handlers::begin_tenant_tx(&state.pool, env_uuid).await?;
    let row = sqlx::query_as::<_, Row>(
        "SELECT id, value_cipher, version, status FROM secrets WHERE env_id = $1 AND name = $2",
    )
    .bind(env_uuid)
    .bind(&name)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("db error: {e}")))?
    .ok_or((StatusCode::NOT_FOUND, format!("secret {name:?} not found")))?;

    if row.status != "active" {
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

    // Audit row — every reveal is recorded.
    sqlx::query(
        "INSERT INTO reads (secret_id, version, reader_subject, reader_service, reader_type, env_id)
         VALUES ($1, $2, $3, $4, 'user', $5)",
    )
    .bind(row.id)
    .bind(row.version)
    .bind(a.sub())
    .bind("sentin8:secrets")
    .bind(env_uuid)
    .execute(&mut *tx)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("db error: {e}")))?;
    tx.commit()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("db error: {e}")))?;

    tracing::info!(
        name = %name,
        version = row.version,
        reader = %a.sub(),
        env_id = %env_uuid,
        "secret revealed via admin UI (audit row written)"
    );

    Ok(Json(serde_json::json!({
        "name": name,
        "version": row.version,
        "value": value,
    })))
}

/// `POST /v1/admin/secrets/rotate` — rotate from the admin form. The
/// previous version is retained until the prune window.
/// Handle admin rotate secret.
pub async fn admin_rotate_secret(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<TargetEnvQuery>,
    Json(req): Json<AdminRotateRequest>,
) -> Result<Json<AdminUiResponse>, (StatusCode, String)> {
    let a = crate::auth::verify_token(&state.config, &headers).await?;
    a.require_any_scope(WRITE_SCOPES)?;
    let env_id = resolve_env_id(&headers, &q, &a)?;
    let env_uuid = uuid::Uuid::parse_str(&env_id)
        .map_err(|_| (StatusCode::BAD_REQUEST, "invalid env id".into()))?;

    #[derive(sqlx::FromRow)]
    struct Row {
        id: uuid::Uuid,
        version: i32,
    }
    let mut tx = crate::handlers::begin_tenant_tx(&state.pool, env_uuid).await?;
    let existing =
        sqlx::query_as::<_, Row>("SELECT id, version FROM secrets WHERE env_id = $1 AND name = $2")
            .bind(env_uuid)
            .bind(&req.name)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("db error: {e}")))?
            .ok_or((
                StatusCode::NOT_FOUND,
                format!("secret {:?} not found", req.name),
            ))?;

    let envelope =
        sentin8::crypto::seal_raw(&state.master_key, req.value.as_bytes()).map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("encrypt failed: {e}"),
            )
        })?;
    let new_version = existing.version + 1;

    sqlx::query(
        "UPDATE secrets SET value_cipher = $3, key_version = 1, version = $4, status = 'active', updated_at = now()
         WHERE id = $1 AND env_id = $2",
    )
    .bind(existing.id)
    .bind(env_uuid)
    .bind(&envelope)
    .bind(new_version)
    .execute(&mut *tx)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("db error: {e}")))?;

    let _ = sqlx::query(
        "INSERT INTO versions (secret_id, version, value_cipher, key_version, created_by, env_id)
         VALUES ($1, $2, $3, 1, $4, $5) ON CONFLICT (secret_id, version) DO NOTHING",
    )
    .bind(existing.id)
    .bind(new_version)
    .bind(&envelope)
    .bind(a.sub())
    .bind(env_uuid)
    .execute(&mut *tx)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("db error: {e}")))?;
    tx.commit()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("db error: {e}")))?;

    tracing::info!(name = %req.name, version = new_version, env_id = %env_uuid, actor = %a.sub(), "secret rotated via admin UI");

    Ok(Json(AdminUiResponse::redirect("secrets")))
}

// ── Small RFW constructors (shared shape with storage admin_ui) ─────────

/// Optional `?name=` query param for history/reads data endpoints.
#[derive(Deserialize, Default)]
/// The namequery type.
pub struct NameQuery {
    #[serde(default)]
    /// The name.
    pub name: Option<String>,
}

fn col_s(key: &str, label: &str, sortable: bool) -> WidgetDataTableColumn {
    WidgetDataTableColumn {
        key: key.into(),
        label: label.into(),
        sortable,
        width: None,
        format: None,
    }
}
fn table_with_actions(
    columns: Vec<WidgetDataTableColumn>,
    endpoint: &str,
    row_actions: Vec<WidgetButton>,
) -> RemoteWidget {
    RemoteWidget::DataTable(WidgetDataTable {
        columns,
        data_endpoint: endpoint.into(),
        sortable: true,
        filterable: true,
        page_size: 20,
        empty_message: Some("No secrets stored yet.".into()),
        row_link: None,
        row_actions,
    })
}
fn table(columns: Vec<WidgetDataTableColumn>, endpoint: &str) -> RemoteWidget {
    RemoteWidget::DataTable(WidgetDataTable {
        columns,
        data_endpoint: endpoint.into(),
        sortable: true,
        filterable: true,
        page_size: 20,
        empty_message: Some("No data.".into()),
        row_link: None,
        row_actions: vec![],
    })
}
fn row_action(label: &str, route: &str) -> WidgetButton {
    WidgetButton {
        label: label.into(),
        button_type: ButtonType::Link,
        route: Some(route.into()),
        endpoint: None,
        icon: None,
    }
}
fn row_action_post(label: &str, endpoint: &str) -> WidgetButton {
    WidgetButton {
        label: label.into(),
        button_type: ButtonType::Primary,
        route: None,
        endpoint: Some(endpoint.into()),
        icon: None,
    }
}
fn card(title: &str, body: &str) -> RemoteWidget {
    RemoteWidget::Card(WidgetCard {
        title: Some(title.into()),
        subtitle: None,
        children: vec![RemoteWidget::Text(WidgetText {
            text: body.into(),
            text_type: WidgetTextType::Body,
            align: TextAlign::Left,
            max_lines: None,
        })],
        actions: vec![],
    })
}
fn link(label: &str, route: &str) -> AdminUiAction {
    AdminUiAction {
        label: label.into(),
        action_type: AdminUiActionType::Link,
        route: Some(route.into()),
        endpoint: None,
        icon: Some("0xe145".into()),
    }
}
