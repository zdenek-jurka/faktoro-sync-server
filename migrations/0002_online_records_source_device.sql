ALTER TABLE online_records_shared
  ADD COLUMN IF NOT EXISTS source_device_id TEXT REFERENCES devices(id) ON DELETE CASCADE;

CREATE INDEX IF NOT EXISTS idx_online_records_shared_instance_modified_source
  ON online_records_shared (instance_id, last_modified_at, source_device_id);
