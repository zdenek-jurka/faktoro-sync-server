CREATE TABLE IF NOT EXISTS client_instances (
  id TEXT PRIMARY KEY,
  recovery_email TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_seen_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS devices (
  id TEXT PRIMARY KEY,
  instance_id TEXT NOT NULL REFERENCES client_instances(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  pairing_token_hash TEXT NOT NULL,
  recovery_email TEXT NOT NULL,
  recovery_token_hash TEXT,
  is_registered BOOLEAN NOT NULL DEFAULT FALSE,
  auth_token TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  registered_at TIMESTAMPTZ,
  last_seen_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_devices_pairing_hash ON devices(pairing_token_hash);
CREATE INDEX IF NOT EXISTS idx_devices_instance_id ON devices(instance_id);

CREATE TABLE IF NOT EXISTS sync_snapshots_shared (
  instance_id TEXT PRIMARY KEY REFERENCES client_instances(id) ON DELETE CASCADE,
  snapshot JSONB NOT NULL,
  version BIGINT NOT NULL DEFAULT 1,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS online_records_shared (
  instance_id TEXT NOT NULL REFERENCES client_instances(id) ON DELETE CASCADE,
  table_name TEXT NOT NULL,
  record_id TEXT NOT NULL,
  raw JSONB NOT NULL DEFAULT '{}'::jsonb,
  first_seen_at BIGINT NOT NULL,
  last_modified_at BIGINT NOT NULL,
  is_deleted BOOLEAN NOT NULL DEFAULT FALSE,
  PRIMARY KEY (instance_id, table_name, record_id)
);

CREATE INDEX IF NOT EXISTS idx_online_records_shared_instance_table_modified
  ON online_records_shared (instance_id, table_name, last_modified_at);

CREATE INDEX IF NOT EXISTS idx_online_records_shared_instance_modified
  ON online_records_shared (instance_id, last_modified_at);

CREATE TABLE IF NOT EXISTS device_public_keys (
  device_id TEXT PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
  instance_id TEXT NOT NULL REFERENCES client_instances(id) ON DELETE CASCADE,
  key_id TEXT NOT NULL,
  algorithm TEXT NOT NULL,
  public_key TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_device_public_keys_instance_id
  ON device_public_keys (instance_id);

CREATE TABLE IF NOT EXISTS instance_key_envelopes (
  instance_id TEXT NOT NULL REFERENCES client_instances(id) ON DELETE CASCADE,
  target_device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  key_id TEXT NOT NULL,
  algorithm TEXT NOT NULL,
  envelope TEXT NOT NULL,
  wrapped_by_device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (instance_id, target_device_id, key_id)
);

CREATE INDEX IF NOT EXISTS idx_instance_key_envelopes_target_device
  ON instance_key_envelopes (target_device_id, updated_at);

CREATE TABLE IF NOT EXISTS instance_sync_events (
  event_id BIGSERIAL PRIMARY KEY,
  instance_id TEXT NOT NULL REFERENCES client_instances(id) ON DELETE CASCADE,
  source_device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  event_type TEXT NOT NULL,
  created_at_ms BIGINT NOT NULL,
  payload JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_instance_sync_events_instance_created
  ON instance_sync_events (instance_id, created_at_ms);
