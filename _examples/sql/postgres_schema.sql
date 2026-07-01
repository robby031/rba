-- Skema database PostgreSQL untuk library RBA.
--
-- 1. auth_events       - riwayat autentikasi
-- 2. sessions          - state sesi aktif
-- 3. subject_profiles  - baseline perilaku pengguna
-- 4. policy_bundles    - aturan kebijakan

CREATE TABLE IF NOT EXISTS auth_events (
    event_id       TEXT PRIMARY KEY,
    tenant_id      TEXT NOT NULL,
    subject_id     TEXT NOT NULL,
    session_id     TEXT,
    action         TEXT NOT NULL,        -- login, token_refresh, api_access, change_password, add_device
    occurred_at    TIMESTAMPTZ NOT NULL,
    ip_address     TEXT,
    user_agent     TEXT,
    geo_country    TEXT,                 -- ISO 3166-1 alpha-2
    asn            TEXT,
    device_id_hash TEXT,
    risk_score     DOUBLE PRECISION,
    risk_level     TEXT,                 -- low, medium, high
    decision       TEXT,                 -- allow, challenge, deny, restrict
    reasons        TEXT[]                -- array of reason codes
);

CREATE INDEX idx_auth_events_subject ON auth_events (tenant_id, subject_id, occurred_at DESC);
CREATE INDEX idx_auth_events_session ON auth_events (session_id);

CREATE TABLE IF NOT EXISTS sessions (
    session_id      TEXT PRIMARY KEY,
    tenant_id       TEXT NOT NULL,
    subject_id      TEXT NOT NULL,
    authenticated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    current_acr     TEXT NOT NULL DEFAULT 'low',
    current_amr     TEXT[] NOT NULL DEFAULT '{}',
    risk_locked     BOOLEAN NOT NULL DEFAULT FALSE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at      TIMESTAMPTZ NOT NULL,
    last_accessed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_sessions_subject ON sessions (tenant_id, subject_id);

CREATE TABLE IF NOT EXISTS subject_profiles (
    tenant_id              TEXT NOT NULL,
    subject_id             TEXT NOT NULL,
    last_seen_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    known_countries        TEXT[] NOT NULL DEFAULT '{}',
    known_asn              TEXT[] NOT NULL DEFAULT '{}',
    known_device_id_hashes TEXT[] NOT NULL DEFAULT '{}',
    preferred_challenge    TEXT,         -- webauthn, totp, push, sms
    min_required_acr_by_risk JSONB,     -- {"medium": "phr", "high": "phrh"}
    updated_at             TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, subject_id)
);

CREATE TABLE IF NOT EXISTS policy_bundles (
    id          SERIAL PRIMARY KEY,
    tenant_id   TEXT NOT NULL,
    version     TEXT NOT NULL,
    rules       JSONB NOT NULL,          -- Array of PolicyRule
    is_active   BOOLEAN NOT NULL DEFAULT FALSE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, version)
);

CREATE INDEX idx_policy_bundles_active ON policy_bundles (tenant_id) WHERE is_active = TRUE;
