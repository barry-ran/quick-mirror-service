CREATE TABLE IF NOT EXISTS qm_control_slots (
 service_scope uuid NOT NULL, target_uuid uuid NOT NULL,
 generation bigint NOT NULL DEFAULT 0 CHECK(generation>=0),
 active_intent uuid,
 PRIMARY KEY(service_scope,target_uuid)
);
CREATE TABLE IF NOT EXISTS qm_control_intents (
 service_scope uuid NOT NULL, id uuid NOT NULL, target_uuid uuid NOT NULL, owner_uuid uuid NOT NULL,
 runtime_boot uuid NOT NULL, runtime_hash bytea NOT NULL,
 generation bigint NOT NULL CHECK(generation>0), revision bigint NOT NULL DEFAULT 1 CHECK(revision>0),
 state text NOT NULL CHECK(state IN ('reserving','active','draining','released','failed')),
 outcome text NOT NULL CHECK(outcome IN ('pending','confirmed','unknown')),
 grant_id uuid, session_id uuid, drain_token uuid, close_reason text,
 create_key uuid NOT NULL, revoke_key uuid NOT NULL, replay_domain text NOT NULL,
 dispatched boolean NOT NULL DEFAULT false, revoked boolean NOT NULL DEFAULT false,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(), terminal_at timestamptz,
 PRIMARY KEY(service_scope,id), UNIQUE(service_scope,target_uuid,generation)
);
CREATE TABLE IF NOT EXISTS qm_control_commands (
 service_scope uuid NOT NULL, principal_uuid uuid NOT NULL, operation text NOT NULL,
 command_id uuid NOT NULL, request_hash bytea NOT NULL, intent_id uuid NOT NULL,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(service_scope,principal_uuid,operation,command_id)
);
CREATE INDEX IF NOT EXISTS qm_control_recovery ON qm_control_intents(service_scope,state);
-- command摘要不自动清理；终态24h后查询返回UNKNOWN。保留的业务历史不含凭证/请求正文。
