CREATE TABLE IF NOT EXISTS instance_recovery_bootstraps (
  instance_id TEXT PRIMARY KEY REFERENCES client_instances(id) ON DELETE CASCADE,
  allow_plaintext BOOLEAN NOT NULL DEFAULT TRUE,
  instance_key TEXT,
  configured_by_device_id TEXT NOT NULL REFERENCES devices(id),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CHECK (
    (allow_plaintext = TRUE AND instance_key IS NULL)
    OR (allow_plaintext = FALSE AND instance_key IS NOT NULL AND length(btrim(instance_key)) > 0)
  )
);

CREATE INDEX IF NOT EXISTS idx_instance_recovery_bootstraps_configured_by
  ON instance_recovery_bootstraps (configured_by_device_id);
