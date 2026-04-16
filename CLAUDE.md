# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Is

Flask 3.x API proxy that sits between customer software and PowerDNS Authoritative Server. Customers authenticate with API keys and can only access the DNS zones that belong to their PowerDNS-Admin **account**. The app shares the PowerDNS-Admin MySQL database and adds three custom tables (`api_keys`, `api_key_ip_allowlist`, `audit_logs`).

## Development Commands

```bash
# Setup
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env  # then fill in values

# Run dev server
python run.py

# Run all tests
pytest

# Run a single test file
pytest tests/test_auth_service.py

# Run a single test
pytest tests/test_auth_service.py::TestAuthService::test_validate_valid_key
```

## Starting the Application

```bash
# Development
source venv/bin/activate
python run.py          # starts Flask dev server on http://127.0.0.1:5000

# Production (gunicorn example)
gunicorn -w 4 "app:create_app()"
```

## Database Migrations

Migrations live in `migrations/` as paired `NNN_description.up.sql` / `NNN_description.down.sql` files.
The `migrate.py` script tracks applied migrations in a `schema_migrations` table (auto-created on first run).

```bash
# Show applied / pending migrations
python migrate.py status

# Apply all pending migrations
python migrate.py up

# Roll back the last applied migration
python migrate.py down

# Roll back the last N applied migrations
python migrate.py down N
```

**Rules for adding migrations:**
- Never edit a committed migration file — always add a new numbered file (`002_`, `003_`, …).
- Every `.up.sql` must have a corresponding `.down.sql` rollback.
- `account_id` in `api_keys` is intentionally stored without a FK so the migration is independent of the PowerDNS-Admin schema version.

## Environment Variables

| Variable | Description |
|---|---|
| `DATABASE_URL` | `mysql+pymysql://user:pass@host:3306/powerdnsadmin` |
| `PDNS_API_URL` | PowerDNS API base URL (default: `http://127.0.0.1:8081`) |
| `PDNS_API_KEY` | PowerDNS API key |
| `SECRET_KEY` | Flask session secret |
| `PROXY_COUNT` | Number of trusted reverse proxies in front of the app (default: `1`). Controls `X-Forwarded-For` trust via Werkzeug `ProxyFix`. Set to `0` if exposed directly. |

Tests use SQLite in-memory via a `TestConfig` class passed to `create_app()`.

## Architecture

```
Client → [X-API-Key header] → proxy.py (before_request auth) → ProxyService → PowerDNS API
                                     ↓
                              AuthService + AuditService → MySQL
```

**Request flow for proxy endpoints:**
1. `proxy.py:before_request` validates the `X-API-Key` header via `AuthService.validate_api_key()` — checks hash, `is_active`, and IP allowlist. Stores `g.api_key` and `g.client_ip`.
2. Route handlers decorated with `@require_domain_access("zone_id")` (`proxy_decorators.py`) check whether the requested zone belongs to the key's `account_id` via `PdnsDomain.account_id` before forwarding.
3. `ProxyService.forward_request()` forwards to PDNS API with the internal API key.
4. `AuditService.log()` writes to `audit_logs` table after each proxied request.

**Two separate interfaces:**
- `routes/admin.py` — JSON REST API (`/admin/api-keys/*`), protected by `admin_required` (Administrator role only)
- `routes/admin_ui.py` — HTML UI (`/`, `/keys/*`), shared by all logged-in users; role-aware scoping via `_get_accessible_accounts()` and `_check_key_access()`
- `routes/auth.py` — Login/logout/2FA at `/login` for all users

**Database models:**
- `app/models/api_key.py` — `ApiKey`, `ApiKeyIpAllowlist` (custom tables)
- `app/models/audit_log.py` — `AuditLog` (custom table)
- `app/models/pdns_admin.py` — Read-only models for existing PowerDNS-Admin tables: `PdnsUser` (table: `user`), `PdnsRole` (table: `role`), `PdnsAccount` (table: `account`), `PdnsDomain` (table: `domain`), `PdnsAccountUser` (table: `account_user`)

## Key Design Decisions

- **API keys** are stored only as SHA-256 hashes (`ApiKey.hash_key()`). The full key is shown exactly once at creation time (via flash message in UI, or JSON response in REST API).
- **Key format:** `pda_live_<32 hex chars>`. Display prefix: `pda_live_<first 4 chars>` (13 chars total stored in `key_prefix`).
- **Account-based domain access:** Each API key has an `account_id` referencing a PowerDNS-Admin `account`. Domain access is checked by querying `PdnsDomain.account_id` — no separate allowlist table. `AuthService.check_domain_access(account_id, domain_id)` and `AuthService.get_allowed_domains(account_id)` implement this.
- **IP allowlist:** Empty list means **no access** (all requests blocked). CIDR is supported (`cidr_mask` column, NULL = exact match). Logic is in `app/utils/ip_utils.py`.
- **Domain filtering:** `GET /api/v1/zones` filters the PDNS response client-side using `get_allowed_domains()`. All other zone/record endpoints use `check_domain_access()` inline.
- **Blocked proxy endpoints:** Zone creation (`POST /zones`) and deletion (`DELETE /zones/<id>`) always return 403. Server config and statistics endpoints always return 403. Zone sub-resources `cryptokeys`, `metadata`, `notify`, and `rectify` always return 403 — customers may only use `rrsets` and `export`.
- **Client IP:** Resolved by Werkzeug `ProxyFix` (configured via `PROXY_COUNT`) and read from `request.remote_addr`. Do not manually parse `X-Forwarded-For`.
- **Auth:** All PowerDNS-Admin users log in at `/admin/login` and land on the same `/admin/` dashboard. 2FA (TOTP via `pyotp`) is supported for all users.
- **Role-aware scoping:** Administrators see and manage all keys across all accounts. Regular users only see keys for their own accounts (via `account_user` table), cannot delete keys, and cannot select accounts outside their own when creating a key. The `_get_accessible_accounts()` and `_check_key_access()` helpers in `admin_ui.py` enforce this.
- **Admin UI auth:** Uses `PdnsUser` from PowerDNS-Admin's `user` table. Password is bcrypt. Delete and the JSON API (`/admin/api-keys/`) are Administrator-only.
- **CSRF:** Session-based token generated by `_csrf_token()` helpers, checked on all POST forms in the admin UI.

## What's Not Yet Implemented

- Docker setup (`Dockerfile`, `docker-compose.yml`) is planned but not yet implemented.
