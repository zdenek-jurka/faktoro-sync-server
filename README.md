# Faktoro Sync Server (Rust)

This service provides:
- always-available bootstrap payload for app pairing
- app-driven device pairing flow (server bootstrap payload -> app init -> app registration)
- required recovery email during app pairing init
- recovery payload delivery by email (for device loss recovery)
- support for multiple client instances on one server
- support for multiple devices per client instance
- online incremental sync endpoints for WatermelonDB
- near-real-time sync trigger events via WebSocket (with polling fallback on client)
- shared sync event bus across server instances via PostgreSQL `LISTEN/NOTIFY`
- full snapshot backup/restore endpoints
- encrypted sync payload contract (`_enc_*` envelopes) with optional plaintext fallback
- PostgreSQL storage

## Run With Docker

```bash
cd faktoro-server
cp .env.example .env
docker compose up --build
```

The server is available at `http://localhost:8080`.

`docker-compose.yml` uses defaults for all key variables, so if a key is missing in `.env`, the default value is used.

Before production deployment, configure SMTP variables (`SMTP_HOST`, `SMTP_PORT`, `SMTP_SECURITY`, `SMTP_USERNAME`, `SMTP_PASSWORD`, `SMTP_FROM`) and set `PUBLIC_BASE_URL` for correct bootstrap links behind reverse proxy.

SMTP security modes:
- `SMTP_SECURITY=starttls` (typical for port `587`)
- `SMTP_SECURITY=tls` (SMTPS, typical for port `465`)
- `SMTP_SECURITY=plain` (no TLS, useful for local MailHog/Mailpit)

If you see `received corrupt message of type InvalidContentType`, SMTP TLS mode/port is mismatched.

## TLS / SSL Termination

The sync server does not handle TLS/SSL termination by itself.
For production deployment, put it behind a reverse proxy/router that terminates HTTPS
(for example Traefik, Nginx, or Caddy) and forwards traffic to the container over HTTP.

Recommended setup:
- expose HTTPS only on the reverse proxy/router
- keep the sync server internal on private Docker network
- set `PUBLIC_BASE_URL` to your public `https://...` URL

For local development, you can override PostgreSQL storage mount via `POSTGRES_DATA_VOLUME`:
- default named volume: `POSTGRES_DATA_VOLUME=postgres_data`
- host bind mount (easy delete): `POSTGRES_DATA_VOLUME=./local/postgres-data`

When using bind mount, wiping DB is just:
```bash
rm -rf ./local/postgres-data
```

## Database Migrations

- The server runs pending migrations automatically at startup (`sqlx::migrate!`).
- DB migration version is logged before and after startup migrations.
- Current schema is defined by:
  - `migrations/0001_init.sql`
  - `migrations/0002_online_records_source_device.sql`

## Device Pairing Flow (App-driven)

1. App fetches the **server bootstrap payload** from `GET /api/pair/bootstrap`.
2. App calls `/api/pairing/init` with recovery email + device name (+ optional existing instance ID).
3. App calls `/api/devices/register-from-scan` with returned payload.
4. App stores `auth_token` and starts online sync.

Optional helper endpoint:
- `GET /api/pair/qr?payload=...` returns QR code PNG for any payload string.

## E2E Key Scaffolding

Server now includes key-management scaffolding for end-to-end encrypted sync:
- device public key registration/retrieval
- encrypted instance key envelope upload/retrieval

Server stores key envelopes as opaque blobs and cannot decrypt business data.

Transport behavior:
- `/api/sync/online/push` accepts encrypted record envelopes (`id`, `_enc_v`, `_enc_alg`, `_enc_iv`, `_enc_ct`)
- `/api/sync/push` accepts encrypted snapshot envelopes (`_enc_snapshot_*`)
- plaintext payloads are also accepted as explicit insecure fallback (for clients without Secure Crypto API)

## API

OpenAPI specification is available in `openapi.yaml`.
Published endpoints:
- `GET /openapi.yaml` (raw OpenAPI YAML)
- `GET /docs` (interactive API docs UI from `static/docs/index.html`)

OpenAPI descriptions are currently maintained in English only.

- `GET /`
- `GET /health`
- `GET /docs`
- `GET /openapi.yaml`
- `GET /api/pair/bootstrap`
- `GET /api/pair/qr?payload=...`
- `POST /api/pairing/init`
- `POST /api/devices/register-from-scan`
- `POST /api/devices/recover-from-code`
- `POST /api/devices/forget-registration`
- `GET /api/devices?device_id=...&auth_token=...`
- `POST /api/devices/remove`
- `POST /api/crypto/device-public-key`
- `GET /api/crypto/device-public-key?device_id=...&auth_token=...&target_device_id=...`
- `POST /api/crypto/instance-key-envelope`
- `GET /api/crypto/instance-key-envelope?device_id=...&auth_token=...&key_id=...`
- `POST /api/sync/online/pull`
- `POST /api/sync/online/push`
- `POST /api/sync/events/pull`
- `GET /api/sync/events/ws?device_id=...&auth_token=...`
- `POST /api/sync/push`
- `POST /api/sync/pull`

`POST /api/devices/register-from-scan` accepts optional `device_public_key`:
```json
{
  "raw_code": "{...pairing payload...}",
  "device_public_key": {
    "key_id": "ik-v1",
    "algorithm": "x25519",
    "public_key": "base64..."
  }
}
```
