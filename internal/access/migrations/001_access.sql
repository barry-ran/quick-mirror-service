CREATE TABLE IF NOT EXISTS qm_access_tokens (
    service_scope uuid NOT NULL,
    token_hash bytea NOT NULL CHECK (octet_length(token_hash)=32),
    device_uuid uuid NOT NULL,
    tenant_uuid uuid NOT NULL,
    application_uuid uuid NOT NULL,
    role text NOT NULL CHECK (role IN ('pc','mobile')),
    expires_at timestamptz NOT NULL,
    credential_nonce bytea NOT NULL CHECK (octet_length(credential_nonce)=12),
    credential_ciphertext bytea NOT NULL CHECK (octet_length(credential_ciphertext) BETWEEN 17 AND 528),
    PRIMARY KEY(service_scope,token_hash)
);
CREATE INDEX IF NOT EXISTS qm_access_tokens_expiry ON qm_access_tokens(expires_at);

-- 不随 token 清理删除；跨本数据库所有 service_scope 累计同 key 的 GCM 使用量。
CREATE TABLE IF NOT EXISTS qm_access_key_usage (
    key_hash bytea PRIMARY KEY CHECK (octet_length(key_hash)=32),
    encryptions bigint NOT NULL CHECK (encryptions BETWEEN 1 AND 4294967296)
);
