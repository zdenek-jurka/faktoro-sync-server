CREATE EXTENSION IF NOT EXISTS pgcrypto;

UPDATE devices
SET auth_token = encode(digest(auth_token, 'sha256'), 'hex')
WHERE auth_token IS NOT NULL;
