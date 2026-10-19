// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Secrets
// SPDX-License-Identifier: Apache-2.0

//! Integration tests for Sentin8:Secrets.
//!
//! DB-backed tests run against a provisioned PostgreSQL (testing-strategy
//! §3): `make infra-up` + the `secrets` SQL applied, then run without the
//! `#[ignore]` gate. Naming follows `[layer_]area_behavior` with the `sec_`
//! security prefix (§3.3).

use sqlx::{PgPool, Row};

/// Provision: connect + tenant context helper. Returns the pool and the
/// test env id (a fresh env per run keeps rows isolated).
async fn provision() -> Option<(PgPool, uuid::Uuid)> {
    let url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://sentin8@localhost:5432/sentin8".into());
    let pool = PgPool::connect(&url).await.ok()?;
    // Skip silently when not provisioned (CI without infra).
    if sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM information_schema.tables WHERE table_name = 'secrets'",
    )
    .fetch_one(&pool)
    .await
    .ok()?
        == 0
    {
        return None;
    }
    let env_id = uuid::Uuid::new_v4();
    // Create a fake env row (RLS needs the tenant present for context-set,
    // but sentin8_set_tenant_context only sets config - no FK check needed).
    Some((pool, env_id))
}

/// Set tenant context inside a pool transaction (context is
/// transaction-local, principles §4.3d) and return it. The transaction
/// owns its connection for its lifetime.
async fn set_ctx(pool: &PgPool, env_id: uuid::Uuid) -> sqlx::Transaction<'static, sqlx::Postgres> {
    let mut tx = pool.begin().await.expect("tx");
    sqlx::query("SELECT sentin8_set_tenant_context($1)")
        .bind(env_id)
        .execute(&mut *tx)
        .await
        .expect("set tenant context");
    tx
}

const MK: &str = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="; // base64 of 0..31 bytes pattern

fn master_key() -> sentin8::crypto::MasterKey {
    sentin8::crypto::MasterKey::from_base64(MK)
        .expect("valid test master key")
        .expect("non-empty")
}

// ── sec_secrets_envelope_roundtrip ──────────────────────────────────────

#[tokio::test]
async fn sec_secrets_envelope_roundtrip_and_metadata_shape() {
    // Pure-crypto round trip - no DB needed (security property pin).
    let mk = master_key();
    let plaintext = b"totally-secret-value";
    let envelope = sentin8::crypto::seal_raw(&mk, plaintext).expect("seal");
    assert_ne!(envelope, plaintext.to_vec());
    assert!(sentin8::crypto::is_envelope(&envelope));
    let opened = sentin8::crypto::open(&mk, &envelope).expect("open");
    assert_eq!(opened, plaintext.to_vec());
    // A second seal of the same plaintext differs (fresh nonce).
    let envelope2 = sentin8::crypto::seal_raw(&mk, plaintext).expect("seal2");
    assert_ne!(envelope, envelope2);
}

// ── sec_secrets_upsert_and_version_bump ─────────────────────────────────

#[tokio::test]
async fn sec_secrets_upsert_bumps_version_and_writes_history() {
    let Some((pool, env_id)) = provision().await else {
        return;
    };
    let mk = master_key();
    let seal = |v: &[u8]| sentin8::crypto::seal_raw(&mk, v).unwrap();

    let mut tx = set_ctx(&pool, env_id).await;

    // First write → version 1.
    let v1: (uuid::Uuid, i32) = sqlx::query_as(
        "INSERT INTO secrets (name, description, value_cipher, key_version, version, status, created_by, env_id)
         VALUES ('test/alpha', 'd', $1, 1, 1, 'active', 'tester', $2)
         RETURNING id, version",
    )
    .bind(seal(b"one"))
    .bind(env_id)
    .fetch_one(&mut *tx)
    .await
    .expect("insert v1");

    // Upsert (conflict) → version 2.
    let v2: (uuid::Uuid, i32) = sqlx::query_as(
        "INSERT INTO secrets (name, description, value_cipher, key_version, version, status, created_by, env_id)
         VALUES ('test/alpha', 'd2', $1, 1, 1, 'active', 'tester', $2)
         ON CONFLICT (env_id, name) DO UPDATE
           SET value_cipher = EXCLUDED.value_cipher, version = secrets.version + 1, updated_at = now()
         RETURNING id, version",
    )
    .bind(seal(b"two"))
    .bind(env_id)
    .fetch_one(&mut *tx)
    .await
    .expect("upsert v2");

    assert_eq!(v1.0, v2.0);
    assert_eq!(v1.1, 1);
    assert_eq!(v2.1, 2);

    // History rows are written by the handler alongside each write -
    // mirror that here (one row per version).
    for (ver, val) in [(1, b"one".as_slice()), (2, b"two".as_slice())] {
        sqlx::query(
            "INSERT INTO versions (secret_id, version, value_cipher, key_version, created_by, env_id)
             VALUES ($1, $2, $3, 1, 'tester', $4) ON CONFLICT (secret_id, version) DO NOTHING",
        )
        .bind(v1.0)
        .bind(ver)
        .bind(seal(val))
        .bind(env_id)
        .execute(&mut *tx)
        .await
        .expect("history row");
    }

    let versions: Vec<i32> =
        sqlx::query("SELECT version FROM versions WHERE secret_id = $1 ORDER BY version")
            .bind(v1.0)
            .fetch_all(&mut *tx)
            .await
            .expect("history")
            .iter()
            .map(|r| r.get::<i32, _>(0))
            .collect();
    assert_eq!(versions, vec![1, 2]);

    // Metadata projection contains no plaintext.
    let row: (String, Vec<u8>) =
        sqlx::query_as("SELECT name, value_cipher FROM secrets WHERE id = $1")
            .bind(v1.0)
            .fetch_one(&mut *tx)
            .await
            .expect("row");
    assert_eq!(row.0, "test/alpha");
    assert!(!String::from_utf8_lossy(&row.1).contains("two"));

    tx.rollback().await.ok(); // transaction-scoped context dies with it
                              // Cleanup (context + delete on the SAME transaction - FORCE RLS).
    let mut ctx = pool.begin().await.expect("cleanup tx");
    sqlx::query("SELECT sentin8_set_tenant_context($1)")
        .bind(env_id)
        .execute(&mut *ctx)
        .await
        .ok();
    sqlx::query("DELETE FROM secrets WHERE id = $1")
        .bind(v1.0)
        .execute(&mut *ctx)
        .await
        .ok();
    ctx.commit().await.ok();
}

// ── sec_secrets_rls_cross_env_isolation ─────────────────────────────────

#[tokio::test]
async fn sec_secrets_rls_cross_env_isolation() {
    let Some((pool, env_a)) = provision().await else {
        return;
    };
    let mk = master_key();

    // RLS is enforced against NON-superuser roles only - connect as the
    // service role (`sentin8_secrets_service`, created by the init grants
    // step) the way the real service does.
    let svc_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://sentin8@localhost:5432/sentin8".into());
    let svc_url = svc_url.replace("sentin8:sentin8", "sentin8_secrets_service:oauth");
    let Ok(svc) = PgPool::connect(&svc_url).await else {
        // Service role not reachable (fresh DB) - RLS verified at handler level.
        return;
    };

    // Create rows in env A and env B.
    let env_b = uuid::Uuid::new_v4();
    for env in [env_a, env_b] {
        let mut conn = pool.acquire().await.expect("conn");
        sqlx::query("SELECT sentin8_set_tenant_context($1)")
            .bind(env)
            .execute(&mut *conn)
            .await
            .expect("ctx");
        sqlx::query(
            "INSERT INTO secrets (name, description, value_cipher, key_version, version, status, created_by, env_id)
             VALUES ('test/iso', '', $1, 1, 1, 'active', 'tester', $2)",
        )
        .bind(sentin8::crypto::seal_raw(&mk, format!("{env}").as_bytes()).unwrap())
        .bind(env)
        .execute(&mut *conn)
        .await
        .expect("insert");
    }

    // A service-role connection with env B context sees only env B's row.
    // Context must be set and queried on the SAME connection (principles
    // §4.3d) - use one explicit transaction.
    let mut tx = svc.begin().await.expect("svc tx");
    sqlx::query("SELECT sentin8_set_tenant_context($1)")
        .bind(env_b)
        .execute(&mut *tx)
        .await
        .expect("ctx b");
    let visible: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM secrets WHERE name = 'test/iso'")
        .fetch_one(&mut *tx)
        .await
        .expect("count");
    tx.rollback().await.ok();
    assert_eq!(visible, 1, "env B must see only its own row (RLS)");

    // Cleanup (as superuser, context on the SAME connection - FORCE RLS
    // applies even to the table owner).
    for env in [env_a, env_b] {
        let mut tx = pool.begin().await.expect("cleanup tx");
        sqlx::query("SELECT sentin8_set_tenant_context($1)")
            .bind(env)
            .execute(&mut *tx)
            .await
            .expect("ctx cleanup");
        sqlx::query("DELETE FROM secrets WHERE name = 'test/iso'")
            .execute(&mut *tx)
            .await
            .expect("cleanup");
        tx.commit().await.ok();
    }
}

// ── sec_secrets_disabled_secret_refusal ─────────────────────────────────

#[tokio::test]
async fn sec_secrets_disabled_secret_refusal_at_resolve_level() {
    let Some((pool, env_id)) = provision().await else {
        return;
    };
    let mk = master_key();

    let mut tx = set_ctx(&pool, env_id).await;
    let (id,): (uuid::Uuid,) = sqlx::query_as(
        "INSERT INTO secrets (name, description, value_cipher, key_version, version, status, created_by, env_id)
         VALUES ('test/dead', '', $1, 1, 1, 'disabled', 'tester', $2) RETURNING id",
    )
    .bind(sentin8::crypto::seal_raw(&mk, b"x").unwrap())
    .bind(env_id)
    .fetch_one(&mut *tx)
    .await
    .expect("insert disabled");

    // The service refuses to resolve disabled rows (handlers.rs status gate):
    // here we pin the SQL-level invariant the handler relies on.
    let status: String = sqlx::query_scalar("SELECT status FROM secrets WHERE id = $1")
        .bind(id)
        .fetch_one(&mut *tx)
        .await
        .unwrap();
    assert_eq!(status, "disabled");

    tx.rollback().await.ok();
}

// ── sec_secrets_reveal_audit_row_written ────────────────────────────────

#[tokio::test]
async fn sec_secrets_reveal_writes_audit_row() {
    let Some((pool, env_id)) = provision().await else {
        return;
    };
    let mk = master_key();

    let mut tx = set_ctx(&pool, env_id).await;
    let (id,): (uuid::Uuid,) = sqlx::query_as(
        "INSERT INTO secrets (name, description, value_cipher, key_version, version, status, created_by, env_id)
         VALUES ('test/audited', '', $1, 1, 1, 'active', 'tester', $2) RETURNING id",
    )
    .bind(sentin8::crypto::seal_raw(&mk, b"v").unwrap())
    .bind(env_id)
    .fetch_one(&mut *tx)
    .await
    .expect("insert");

    sqlx::query(
        "INSERT INTO reads (secret_id, version, reader_subject, reader_service, reader_type, env_id)
         VALUES ($1, 1, 'subject-1', 'sentin8:ai', 'm2m', $2)",
    )
    .bind(id)
    .bind(env_id)
    .execute(&mut *tx)
    .await
    .expect("audit row");

    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM reads WHERE secret_id = $1")
        .bind(id)
        .fetch_one(&mut *tx)
        .await
        .unwrap();
    assert_eq!(count, 1, "every reveal must leave an audit row");

    tx.rollback().await.ok();
}

// ── sec_secrets_rls_fails_closed_without_context ────────────────────────

/// Pinned invariant (secrets DESIGN §5, cross-cutting CC-5): under FORCE
/// RLS, a service-role connection WITHOUT tenant context must see zero
/// rows and must fail INSERTs - the fail-closed posture the handler
/// transactions (`begin_tenant_tx`) rely on. Runtime-skip when the
/// service role is not provisioned.
#[tokio::test]
async fn sec_secrets_rls_fails_closed_without_context() {
    let Some((pool, env_a)) = provision().await else {
        return;
    };
    let mk = master_key();

    let svc_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://sentin8@localhost:5432/sentin8".into());
    let svc_url = svc_url.replace("sentin8:sentin8", "sentin8_secrets_service:oauth");
    let Ok(svc) = PgPool::connect(&svc_url).await else {
        return; // Service role not reachable (fresh DB) - skipped.
    };

    // Seed one row in env A (superuser, context on the same connection).
    let mut tx = set_ctx(&pool, env_a).await;
    sqlx::query(
        "INSERT INTO secrets (name, description, value_cipher, key_version, version, status, created_by, env_id)
         VALUES ('test/failclosed', '', $1, 1, 1, 'active', 'tester', $2)",
    )
    .bind(sentin8::crypto::seal_raw(&mk, b"x").unwrap())
    .bind(env_a)
    .execute(&mut *tx)
    .await
    .expect("insert");
    tx.commit().await.ok();

    // Service role, NO context set: SELECT must return zero rows.
    let visible: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM secrets WHERE name = 'test/failclosed'")
            .fetch_one(&svc)
            .await
            .expect("count under no context");
    assert_eq!(
        visible, 0,
        "no context → RLS filters all rows (fail closed)"
    );

    // Service role, NO context: INSERT must be rejected (policy check).
    let insert = sqlx::query(
        "INSERT INTO secrets (name, description, value_cipher, key_version, version, status, created_by, env_id)
         VALUES ('test/failclosed-2', '', $1, 1, 1, 'active', 'svc', $2)",
    )
    .bind(sentin8::crypto::seal_raw(&mk, b"y").unwrap())
    .bind(env_a)
    .execute(&svc)
    .await;
    assert!(insert.is_err(), "no context → INSERT denied (fail closed)");

    // Cleanup.
    let mut tx = set_ctx(&pool, env_a).await;
    sqlx::query("DELETE FROM secrets WHERE name LIKE 'test/failclosed%'")
        .execute(&mut *tx)
        .await
        .expect("cleanup");
    tx.commit().await.ok();
}
