# PDNS API Proxy

A Flask 3.x API proxy that sits between customer software and a [PowerDNS Authoritative Server](https://www.powerdns.com/auth.html). Customers authenticate with scoped API keys and can only access the DNS zones that belong to their PowerDNS-Admin **account**.

The proxy exposes the **same URL structure as the PowerDNS REST API** (`/api/v1/servers/<server_id>/zones/…`), so existing clients (PowerDNS-Admin, Terraform, custom scripts) can point at the proxy without changing their code. Zones outside the key's account are filtered out or rejected with 403.

The proxy shares the existing PowerDNS-Admin MySQL database and adds three custom tables (`api_keys`, `api_key_ip_allowlist`, `audit_logs`).

## Features

- **Drop-in PowerDNS API replacement** — same URL structure as the real PDNS API; clients need no changes
- **API key authentication** — keys are stored only as SHA-256 hashes; the full key is shown exactly once at creation time
- **Account-based zone isolation** — each key is bound to a PowerDNS-Admin account; requests to zones outside that account are rejected with 403
- **IP allowlist** — each key can be restricted to one or more IP addresses or CIDR ranges; an empty allowlist blocks all access
- **Audit log** — every proxied request is written to the `audit_logs` table
- **Role-aware UI** — HTML panel at `/` shared by all users; Administrators see all keys and can delete them, regular users only see and manage keys for their own accounts
- **Admin REST API** — JSON endpoints at `/admin/api-keys/` for programmatic key management (Administrator only)
- **Shared login** — all PowerDNS-Admin users log in at `/login` with optional TOTP 2FA

## Architecture

```
Client ──[X-API-Key]──► proxy.py (before_request auth)
                              │
                    AuthService + AuditService
                              │
                         ProxyService ──► PowerDNS API
                              │
                           MySQL (PowerDNS-Admin DB)
```

**Request flow:**
1. `before_request` validates `X-API-Key` via `AuthService.validate_api_key()` — checks hash, `is_active`, and IP allowlist.
2. Zone list endpoints filter the PDNS response to only include zones linked to the key's account.
3. Zone-specific endpoints check whether the requested zone belongs to the key's account before forwarding.
4. `ProxyService.forward_request()` forwards the request to the PowerDNS API with the internal API key.
5. `AuditService.log()` writes the result to `audit_logs`.

## Requirements

- Python 3.10+
- [PowerDNS-Admin](https://github.com/PowerDNS-Admin/PowerDNS-Admin) — the proxy shares its MySQL database and user/account tables
- MySQL (shared with PowerDNS-Admin)
- PowerDNS Authoritative Server with HTTP API enabled

## Installation

```bash
git clone <repo-url>
cd pdns-api-proxy

python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

cp .env.example .env
# Edit .env with your values (see Environment Variables below)
```

### Database migrations

Migrations live in `migrations/` as paired `NNN_description.up.sql` / `NNN_description.down.sql` files. The `migrate.py` script tracks applied migrations in a `schema_migrations` table (auto-created on first run).

```bash
# Show applied / pending migrations
python migrate.py status

# Apply all pending migrations
python migrate.py up

# Roll back the last applied migration
python migrate.py down
```

## Running

```bash
# Development
source venv/bin/activate
python run.py          # starts Flask dev server on http://127.0.0.1:5000

# Production (gunicorn example)
gunicorn -w 4 "app:create_app()"
```

## Production deployment with Docker + Caddy (Let's Encrypt)

The included `docker-compose.yml` runs the proxy behind [Caddy](https://caddyserver.com/), which automatically obtains and renews a Let's Encrypt TLS certificate.

### Prerequisites

- A server reachable from the internet with ports **80** and **443** open.
- A DNS A-record pointing your domain (e.g. `proxy.example.com`) to that server's IP address.
- Docker and Docker Compose installed on the server.

### Steps

**1. Clone the repo and copy the env file**

```bash
git clone <repo-url>
cd pdns-api-proxy
cp .env.example .env
```

**2. Fill in `.env`**

```dotenv
DATABASE_URL=mysql+pymysql://pdnsadmin:password@db-host:3306/powerdnsadmin
PDNS_API_URL=http://pdns-host:8081
PDNS_API_KEY=your-pdns-api-key
SECRET_KEY=a-long-random-string   # generate with: python3 -c "import secrets; print(secrets.token_hex(32))"
DOMAIN=proxy.example.com          # the public domain Caddy will request a certificate for
```

`PROXY_COUNT` is hardcoded to `1` in `docker-compose.yml` (Caddy is the single trusted proxy).

**3. Run database migrations**

```bash
# Either directly with Python (if you have a local venv):
source venv/bin/activate
python migrate.py up

# Or via the container (migrations run against DATABASE_URL from .env):
docker compose run --rm pdns-api-proxy python migrate.py up
```

**4. Start the stack**

```bash
docker compose up -d
```

Caddy immediately requests a certificate from Let's Encrypt via the ACME HTTP-01 challenge (uses port 80). After a few seconds the proxy is available at `https://proxy.example.com`.

**5. Verify**

```bash
curl https://proxy.example.com/ping
# → {"status": "ok"}
```

### Certificate renewal

Caddy renews certificates automatically in the background. Certificates and ACME account data are stored in the `caddy_data` Docker volume — do not delete that volume.

### Updates

```bash
git pull
docker compose build
docker compose up -d
```

## Environment Variables

| Variable | Description | Example |
|---|---|---|
| `DATABASE_URL` | SQLAlchemy connection string | `mysql+pymysql://user:pass@localhost:3306/powerdnsadmin` |
| `PDNS_API_URL` | PowerDNS API base URL | `http://127.0.0.1:8081` |
| `PDNS_API_KEY` | PowerDNS internal API key | `changeme` |
| `SECRET_KEY` | Flask session secret | (random string) |
| `PROXY_COUNT` | Number of trusted reverse proxies in front of this app (used for `X-Forwarded-For`). Set to `0` if the app is exposed directly without a proxy. Default: `1` | `1` |
| `DOMAIN` | Public hostname used by Caddy to obtain a Let's Encrypt certificate (Docker production only) | `proxy.example.com` |

## API Reference

All proxy endpoints require the `X-API-Key` header with a valid key (`pda_live_<32 hex chars>`).

The proxy mirrors the PowerDNS REST API URL structure. Zone IDs are zone names with a trailing dot (e.g. `example.com.`), exactly as PDNS uses them.

### Servers

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/v1/servers` | List servers (proxied from PDNS) |
| `GET` | `/api/v1/servers/<server_id>` | Server info (proxied from PDNS) |
| `GET` | `/api/v1/servers/<server_id>/config` | **Blocked** — admin only |
| `GET` | `/api/v1/servers/<server_id>/statistics` | **Blocked** — admin only |

### Zones

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/v1/servers/<server_id>/zones` | List zones (filtered to account's zones) |
| `POST` | `/api/v1/servers/<server_id>/zones` | **Blocked** — manage zones via PowerDNS-Admin |
| `GET` | `/api/v1/servers/<server_id>/zones/<zone_id>` | Zone details incl. RRsets |
| `PUT` | `/api/v1/servers/<server_id>/zones/<zone_id>` | Replace zone |
| `PATCH` | `/api/v1/servers/<server_id>/zones/<zone_id>` | Update zone RRsets |
| `DELETE` | `/api/v1/servers/<server_id>/zones/<zone_id>` | **Blocked** — manage zones via PowerDNS-Admin |

### Zone sub-resources

Zone sub-resources are proxied with the same access control applied to the parent zone. The proxy enforces an **allowlist**: only `rrsets` and `export` are forwarded. Any other sub-resource (`notify`, `rectify`, `metadata`, `cryptokeys`, and anything PDNS may add in the future) returns 403:

| Method | Path | Description |
|---|---|---|
| `*` | `/api/v1/servers/<server_id>/zones/<zone_id>/rrsets` | Manage RRsets (allowed) |
| `GET` | `/api/v1/servers/<server_id>/zones/<zone_id>/export` | Export zone (allowed) |
| `*` | anything else | **Blocked** — admin only |

Path components are validated per segment; `.`, `..`, and empty segments are rejected with 400.

### Health

| Method | Path | Description |
|---|---|---|
| `GET` | `/ping` | Liveness — returns `200 {"status":"ok"}` as long as the process is running. Never touches the database or PDNS. |
| `GET` | `/health` | Readiness — verifies the database (`SELECT 1`) and the PDNS API (`GET /api/v1/servers/localhost`, 2s timeout). Returns `200 {"status":"healthy"}` when both are OK, `503 {"status":"unhealthy"}` otherwise. Per-check details are written to the application log, not the response body, to avoid leaking which backend is down to unauthenticated callers. Results are cached for 5 seconds per worker, and each client IP is limited to 30 requests per minute (429 on overflow). |

Use `/ping` for container liveness probes; use `/health` for load-balancer readiness checks. Both endpoints are safe to expose publicly.

### Example requests

```bash
KEY="pda_live_abcdef1234567890abcdef1234567890"

# List zones (same as PDNS API)
curl -H "X-API-Key: $KEY" \
     http://localhost:5000/api/v1/servers/localhost/zones

# Get zone with RRsets
curl -H "X-API-Key: $KEY" \
     http://localhost:5000/api/v1/servers/localhost/zones/example.com.

# Update a record (PDNS RRsets format)
curl -X PATCH \
     -H "X-API-Key: $KEY" \
     -H "Content-Type: application/json" \
     -d '{
       "rrsets": [{
         "name": "www.example.com.",
         "type": "A",
         "ttl": 300,
         "changetype": "REPLACE",
         "records": [{"content": "1.2.3.4", "disabled": false}]
       }]
     }' \
     http://localhost:5000/api/v1/servers/localhost/zones/example.com.

# Send NOTIFY
curl -X PUT \
     -H "X-API-Key: $KEY" \
     http://localhost:5000/api/v1/servers/localhost/zones/example.com./notify
```

### Error responses

| Status | Meaning |
|---|---|
| `401` | Missing, invalid, or revoked API key; IP not on allowlist |
| `403` | Zone does not belong to this key's account; or blocked endpoint (zone creation/deletion, config, statistics, cryptokeys, metadata, notify, rectify) |
| `502` | PowerDNS API unreachable or timed out |

## Web UI

Available at `/` for all PowerDNS-Admin users. Login at `/login`. The interface adapts based on role:

| Feature | Regular user | Administrator |
|---|---|---|
| View keys | Own accounts only | All accounts |
| Create keys | Own accounts only | Any account |
| Revoke / activate | Own keys only | Any key |
| Delete keys | — | Yes |
| Audit log | Own keys only | Any key |
| IP allowlist management | Own keys only | Any key |

Users are assigned to accounts via the `account_user` table in PowerDNS-Admin.

## Admin REST API

The admin REST API (`/admin/api-keys/*`) requires an active Flask-Login session with the **Administrator** role (same session as the admin UI). Log in at `/login` first.

| Method | Path | Description |
|---|---|---|
| `GET` | `/admin/api-keys` | List all keys |
| `POST` | `/admin/api-keys` | Create a key |
| `GET` | `/admin/api-keys/<id>` | Get key details + IP allowlist |
| `PUT` | `/admin/api-keys/<id>` | Update description / active state |
| `DELETE` | `/admin/api-keys/<id>` | Delete a key |
| `POST` | `/admin/api-keys/<id>/ips` | Add IP to allowlist |
| `DELETE` | `/admin/api-keys/<id>/ips/<ip_id>` | Remove IP from allowlist |
| `GET` | `/admin/api-keys/<id>/audit` | Paginated audit log |

### Create key via REST API

Requires an active admin session cookie (log in at `/login` first):

```bash
# Log in and save the session cookie
curl -c cookies.txt -X POST http://localhost:5000/login \
     -d "username=admin&password=secret&csrf_token=<token>"

# Create a key using the session cookie
curl -b cookies.txt -X POST http://localhost:5000/admin/api-keys \
     -H "Content-Type: application/json" \
     -d '{
       "account_id": 1,
       "description": "Customer A automation",
       "ip_allowlist": [
         {"ip_address": "203.0.113.10", "cidr_mask": 32},
         {"ip_address": "10.0.0.0", "cidr_mask": 8}
       ]
     }'
```

Response (the `api_key` field is shown **once only**):

```json
{
  "id": 5,
  "api_key": "pda_live_abcdef1234567890abcdef1234567890",
  "key_prefix": "pda_live_abcd",
  "description": "Customer A automation"
}
```

## IP Allowlist Behaviour

- An **empty** allowlist means **no access** — all requests from that key are blocked.
- Add at least one entry to allow requests. Use `0.0.0.0/0` to allow all IPs.
- Bare IP addresses (e.g. `192.168.1.10`) are stored as `/32` (IPv4) or `/128` (IPv6) automatically.
- CIDR notation is supported: `10.0.0.0/8` allows the entire `10.0.0.0/8` range.
- Client IP is determined by Werkzeug's `ProxyFix` middleware based on the `PROXY_COUNT` setting. Set `PROXY_COUNT=0` if the app is exposed directly without a reverse proxy; set it to the number of trusted proxies otherwise. This prevents IP spoofing via a forged `X-Forwarded-For` header.

## Database Schema

Three custom tables are added to the PowerDNS-Admin database:

| Table | Purpose |
|---|---|
| `api_keys` | API key hashes, metadata, account binding |
| `api_key_ip_allowlist` | Per-key IP/CIDR allowlist entries |
| `audit_logs` | Request audit trail |

`account_id` in `api_keys` deliberately has no foreign key so migrations are independent of the PowerDNS-Admin schema version.

## Running Tests

```bash
pytest                              # all tests
pytest tests/test_auth_service.py  # single file
pytest tests/test_auth_service.py::TestAuthService::test_validate_valid_key  # single test
```

Tests use SQLite in-memory via a `TestConfig` class. The integration test (`tests/integration_test.py`) is a standalone script for end-to-end testing against a live environment — run it with `python tests/integration_test.py`.

## Adding Migrations

1. Never edit a committed migration file.
2. Add a new numbered pair: `migrations/002_description.up.sql` + `migrations/002_description.down.sql`.
3. Every `.up.sql` must have a corresponding `.down.sql` rollback.

## License

MIT — see [LICENSE](LICENSE).
