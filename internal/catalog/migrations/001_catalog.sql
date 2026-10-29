CREATE TABLE IF NOT EXISTS qm_device_catalog (
    service_scope uuid NOT NULL,
    device_uuid uuid NOT NULL,
    application_id uuid NOT NULL,
    app_version text NOT NULL CHECK (octet_length(app_version) <= 128),
    boot_id uuid,
    status_seq bigint NOT NULL DEFAULT 0 CHECK (status_seq >= 0),
    permissions jsonb NOT NULL DEFAULT '{}',
    capabilities jsonb NOT NULL DEFAULT '{}',
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (service_scope, device_uuid)
);

CREATE TABLE IF NOT EXISTS qm_device_boots (
    service_scope uuid NOT NULL,
    device_uuid uuid NOT NULL,
    boot_id uuid NOT NULL,
    PRIMARY KEY (service_scope, device_uuid, boot_id),
    FOREIGN KEY (service_scope, device_uuid)
        REFERENCES qm_device_catalog (service_scope, device_uuid)
);
