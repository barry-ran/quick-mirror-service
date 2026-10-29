CREATE TABLE IF NOT EXISTS qm_bootstrap_intents (
    service_scope uuid NOT NULL,
    key_hash bytea NOT NULL CHECK (octet_length(key_hash) = 32),
    request_hash bytea NOT NULL CHECK (octet_length(request_hash) = 32),
    upstream_key text NOT NULL,
    replay_domain text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    expires_at timestamptz NOT NULL DEFAULT clock_timestamp() + interval '24 hours',
    PRIMARY KEY (service_scope, key_hash)
);
CREATE INDEX IF NOT EXISTS qm_bootstrap_intents_expiry ON qm_bootstrap_intents(expires_at);
