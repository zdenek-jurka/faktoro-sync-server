ALTER TABLE online_records_shared
  DROP CONSTRAINT IF EXISTS online_records_shared_source_device_id_fkey;

ALTER TABLE online_records_shared
  ADD CONSTRAINT online_records_shared_source_device_id_fkey
  FOREIGN KEY (source_device_id)
  REFERENCES devices(id)
  ON DELETE SET NULL;
