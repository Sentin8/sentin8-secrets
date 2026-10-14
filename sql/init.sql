-- SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
-- SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
-- SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Secrets
-- SPDX-License-Identifier: Apache-2.0

-- Sentin8:Secrets — tenant secret management service.
-- Design: sentin8/design/sentin8-sentin8-secrets-technical-design.md §4.2.
--
-- Secret material is stored ONLY as `v2:` AES-256-GCM envelopes
-- (sentin8-crypto). Plaintext values never touch application tables, the
-- API metadata surface, event payloads, or logs. Every reveal (M2M resolve
-- or human reveal) writes an audit row here.

CREATE SCHEMA IF NOT EXISTS secrets;

-- ── Core secret table (design §4.2) ───────────────────────────────────────

CREATE TABLE IF NOT EXISTS secrets.secrets (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            TEXT NOT NULL,                    -- e.g. 'stripe/api_key'
    description     TEXT NOT NULL DEFAULT '',
    value_cipher    BYTEA NOT NULL,                   -- v2: envelope (sentin8-crypto)
    key_version     INTEGER NOT NULL DEFAULT 1,       -- master-key epoch (re-encrypt lever)
    version         INTEGER NOT NULL DEFAULT 1,       -- secret version (rotation counter)
    status          TEXT NOT NULL DEFAULT 'active'
                    CHECK (status IN ('active', 'disabled')),
    expires_at      TIMESTAMPTZ,                   -- nullable; T-14d expiring event (secrets README §7)
    created_by      TEXT NOT NULL,
    env_id          UUID NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (env_id, name)
);

CREATE INDEX IF NOT EXISTS idx_secrets_env ON secrets.secrets (env_id);
CREATE INDEX IF NOT EXISTS idx_secrets_env_name ON secrets.secrets (env_id, name);

-- Version history — append-only, enables rotation + rollback (§4.2).
CREATE TABLE IF NOT EXISTS secrets.versions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    secret_id       UUID NOT NULL REFERENCES secrets.secrets(id) ON DELETE CASCADE,
    version         INTEGER NOT NULL,
    value_cipher    BYTEA NOT NULL,
    key_version     INTEGER NOT NULL,
    created_by      TEXT NOT NULL,
    env_id          UUID NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (secret_id, version)
);

CREATE INDEX IF NOT EXISTS idx_secrets_versions_secret ON secrets.versions (secret_id, version DESC);

-- Reveal audit — who read which version, when. Append-only, NEVER pruned
-- (security-relevant history, design §4.2).
CREATE TABLE IF NOT EXISTS secrets.reads (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    secret_id       UUID NOT NULL REFERENCES secrets.secrets(id) ON DELETE CASCADE,
    version         INTEGER NOT NULL,
    reader_subject  TEXT NOT NULL,                    -- user subject or M2M client id
    reader_service  TEXT NOT NULL,                    -- e.g. 'sentin8:ai'
    reader_type     TEXT NOT NULL CHECK (reader_type IN ('user', 'm2m')),
    env_id          UUID NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_secrets_reads_secret ON secrets.reads (secret_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_secrets_reads_env ON secrets.reads (env_id);

-- ── Row-Level Security (mandatory hardening — principles §4.3d) ───────────

ALTER TABLE secrets.secrets ENABLE ROW LEVEL SECURITY;
ALTER TABLE secrets.secrets FORCE ROW LEVEL SECURITY;
ALTER TABLE secrets.versions ENABLE ROW LEVEL SECURITY;
ALTER TABLE secrets.versions FORCE ROW LEVEL SECURITY;
ALTER TABLE secrets.reads ENABLE ROW LEVEL SECURITY;
ALTER TABLE secrets.reads FORCE ROW LEVEL SECURITY;

-- Standard tenant match policy on every secrets table (isolation only —
-- never business logic; db-design §7.0 binding rule).
DROP POLICY IF EXISTS secrets_select ON secrets.secrets;
CREATE POLICY secrets_select ON secrets.secrets
    FOR SELECT USING (sentin8_current_env_id() = env_id);
DROP POLICY IF EXISTS secrets_insert ON secrets.secrets;
CREATE POLICY secrets_insert ON secrets.secrets
    FOR INSERT WITH CHECK (sentin8_current_env_id() = env_id);
DROP POLICY IF EXISTS secrets_update ON secrets.secrets;
CREATE POLICY secrets_update ON secrets.secrets
    FOR UPDATE USING (sentin8_current_env_id() = env_id);
DROP POLICY IF EXISTS secrets_delete ON secrets.secrets;
CREATE POLICY secrets_delete ON secrets.secrets
    FOR DELETE USING (sentin8_current_env_id() = env_id);

DROP POLICY IF EXISTS secrets_versions_select ON secrets.versions;
CREATE POLICY secrets_versions_select ON secrets.versions
    FOR SELECT USING (sentin8_current_env_id() = env_id);
DROP POLICY IF EXISTS secrets_versions_insert ON secrets.versions;
CREATE POLICY secrets_versions_insert ON secrets.versions
    FOR INSERT WITH CHECK (sentin8_current_env_id() = env_id);
DROP POLICY IF EXISTS secrets_versions_delete ON secrets.versions;
CREATE POLICY secrets_versions_delete ON secrets.versions
    FOR DELETE USING (sentin8_current_env_id() = env_id);

DROP POLICY IF EXISTS secrets_reads_select ON secrets.reads;
CREATE POLICY secrets_reads_select ON secrets.reads
    FOR SELECT USING (sentin8_current_env_id() = env_id);
DROP POLICY IF EXISTS secrets_reads_insert ON secrets.reads;
CREATE POLICY secrets_reads_insert ON secrets.reads
    FOR INSERT WITH CHECK (sentin8_current_env_id() = env_id);

-- ── Grants ─────────────────────────────────────────────────────────────────

GRANT SELECT, INSERT, UPDATE, DELETE ON
    secrets.secrets, secrets.versions, secrets.reads
    TO sentin8_secrets_service;


-- ── Local outbox (DBX, architecture-principles §6.7) ─────────────────────
-- Producer path: secrets.outbox rows commit in the SAME transaction as the
-- domain change; a post-commit relay pushes them to Bus POST /v1/produce.
-- Generated from sentin8-outbox::outbox_table_sql("secrets").
CREATE TABLE IF NOT EXISTS secrets.outbox (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id          UUID NOT NULL,
    event_type      TEXT NOT NULL,
    stream_family   TEXT NOT NULL,
    payload         JSONB NOT NULL,
    publisher_id_token  TEXT,
    publisher_subject   TEXT,
    relayed         BOOLEAN NOT NULL DEFAULT false,
    relayed_at      TIMESTAMPTZ,
    relay_attempts  INT NOT NULL DEFAULT 0,
    next_retry_at   TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_secrets_outbox_unrelayed
    ON secrets.outbox (created_at) WHERE relayed = false;
ALTER TABLE secrets.outbox ENABLE ROW LEVEL SECURITY;
ALTER TABLE secrets.outbox FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS outbox_select ON secrets.outbox;
CREATE POLICY outbox_select ON secrets.outbox FOR SELECT
    USING (sentin8_context_initialized() AND env_id = sentin8_current_env_id());
DROP POLICY IF EXISTS outbox_insert ON secrets.outbox;
CREATE POLICY outbox_insert ON secrets.outbox FOR INSERT
    WITH CHECK (sentin8_context_initialized() AND env_id = sentin8_current_env_id());
DROP POLICY IF EXISTS outbox_update ON secrets.outbox;
CREATE POLICY outbox_update ON secrets.outbox FOR UPDATE
    USING (sentin8_context_initialized() AND env_id = sentin8_current_env_id());
CREATE OR REPLACE FUNCTION secrets.secrets_notify_outbox() RETURNS TRIGGER
LANGUAGE plpgsql AS $fn$
BEGIN
    PERFORM pg_notify('secrets_outbox_changed', '');
    RETURN NEW;
END;
$fn$;
DROP TRIGGER IF EXISTS outbox_notify_trigger ON secrets.outbox;
CREATE TRIGGER outbox_notify_trigger
    AFTER INSERT ON secrets.outbox
    FOR EACH ROW
    EXECUTE FUNCTION secrets.secrets_notify_outbox();


-- ── Local audit journal (DBX §6.8) ────────────────────────────────────────
-- Spill journal for the canonical audit push: rows written same-tx as the
-- domain change, pushed to Sys POST /v1/audit (sentin8:sys:audit:write), then
-- marked pushed. A Sys outage never drops audit. Generated from
-- sentin8-audit::audit_journal_sql("secrets").
CREATE TABLE IF NOT EXISTS secrets.audit_journal (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id          UUID NOT NULL,
    action          TEXT NOT NULL,
    target_resource_type TEXT,
    target_resource_id    TEXT,
    actor_user_id   TEXT,
    actor_subject_type TEXT,
    severity        TEXT NOT NULL DEFAULT 'info',
    correlation_id  TEXT,
    before_state    JSONB,
    after_state     JSONB,
    details         JSONB,
    pushed          BOOLEAN NOT NULL DEFAULT false,
    pushed_at       TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_secrets_audit_journal_unpushed
    ON secrets.audit_journal (created_at) WHERE pushed = false;
ALTER TABLE secrets.audit_journal ENABLE ROW LEVEL SECURITY;
ALTER TABLE secrets.audit_journal FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS audit_journal_dml ON secrets.audit_journal;
CREATE POLICY audit_journal_dml ON secrets.audit_journal
    USING (sentin8_context_initialized() AND env_id = sentin8_current_env_id())
    WITH CHECK (sentin8_context_initialized() AND env_id = sentin8_current_env_id());


-- ── Schema grants (service-owned — the 2026-10-03 ownership pass) ─────
-- This service's own schema: USAGE for its role (platform.sql no longer
-- seeds per-service USAGE; the service declares it here).
GRANT USAGE ON SCHEMA secrets TO sentin8_secrets_service;
GRANT SELECT, INSERT, UPDATE, DELETE ON secrets.outbox TO sentin8_secrets_service;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA secrets TO sentin8_secrets_service;
GRANT SELECT, INSERT, UPDATE, DELETE ON secrets.audit_journal TO sentin8_secrets_service;
