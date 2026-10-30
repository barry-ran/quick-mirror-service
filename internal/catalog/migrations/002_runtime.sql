ALTER TABLE qm_device_catalog ADD COLUMN IF NOT EXISTS runtime_proof_hash bytea;
ALTER TABLE qm_device_catalog ADD COLUMN IF NOT EXISTS status_payload_hash bytea;
