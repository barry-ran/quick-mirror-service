CREATE TABLE IF NOT EXISTS qm_installations (
 service_scope uuid NOT NULL, device_id uuid NOT NULL, application_id uuid NOT NULL,
 role text NOT NULL CHECK(role IN ('pc','mobile')), created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(service_scope,device_id)
);
CREATE TABLE IF NOT EXISTS qm_binding_codes (
 service_scope uuid NOT NULL, code text NOT NULL CHECK(code ~ '^[0-9]{6}$'),
 owner_device_id uuid NOT NULL, current boolean NOT NULL DEFAULT true,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(), retired_at timestamptz,
 PRIMARY KEY(service_scope,code),
 FOREIGN KEY(service_scope,owner_device_id) REFERENCES qm_installations(service_scope,device_id)
);
CREATE UNIQUE INDEX IF NOT EXISTS qm_one_current_code ON qm_binding_codes(service_scope,owner_device_id) WHERE current;
CREATE TABLE IF NOT EXISTS qm_bindings (
 service_scope uuid NOT NULL, binding_id uuid NOT NULL, pc_id uuid NOT NULL, mobile_id uuid NOT NULL,
 revision bigint NOT NULL DEFAULT 1 CHECK(revision>0), active boolean NOT NULL DEFAULT true,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(), revoked_at timestamptz,
 PRIMARY KEY(service_scope,binding_id),
 FOREIGN KEY(service_scope,pc_id) REFERENCES qm_installations(service_scope,device_id),
 FOREIGN KEY(service_scope,mobile_id) REFERENCES qm_installations(service_scope,device_id),
 CHECK(pc_id<>mobile_id)
);
CREATE UNIQUE INDEX IF NOT EXISTS qm_mobile_one_binding ON qm_bindings(service_scope,mobile_id) WHERE active;
CREATE TABLE IF NOT EXISTS qm_binding_receipts (
 service_scope uuid NOT NULL, actor_id uuid NOT NULL, operation text NOT NULL, request_key text NOT NULL,
 request_hash bytea NOT NULL, result jsonb, expires_at timestamptz NOT NULL DEFAULT clock_timestamp()+interval '24 hours',
 PRIMARY KEY(service_scope,actor_id,operation,request_key)
);
CREATE INDEX IF NOT EXISTS qm_binding_receipts_expiry ON qm_binding_receipts(service_scope,expires_at) WHERE result IS NOT NULL;
-- Receipt keys remain tombstones after result expiry: never execute an expired key again.
CREATE TABLE IF NOT EXISTS qm_binding_close_tasks (
 service_scope uuid NOT NULL, binding_id uuid NOT NULL, pc_id uuid NOT NULL, mobile_id uuid NOT NULL,
 binding_revision bigint NOT NULL, created_at timestamptz NOT NULL DEFAULT clock_timestamp(), completed_at timestamptz,
 PRIMARY KEY(service_scope,binding_id),
 FOREIGN KEY(service_scope,binding_id) REFERENCES qm_bindings(service_scope,binding_id)
);

-- Fair bounded recovery: a permanently draining task must not starve later tasks.
ALTER TABLE qm_binding_close_tasks ADD COLUMN IF NOT EXISTS last_checked_at timestamptz;
CREATE INDEX IF NOT EXISTS qm_binding_close_pending ON qm_binding_close_tasks(service_scope,last_checked_at,binding_id) WHERE completed_at IS NULL;
