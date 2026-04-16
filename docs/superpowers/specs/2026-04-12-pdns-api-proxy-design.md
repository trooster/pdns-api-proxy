# PDNS API Proxy - Design Document

**Datum:** 2026-04-12  
**Status:** Concept  
**Framework:** Flask (bestaand patroon van ssl-checker project)

---

## 1. Overview

Een standalone Flask webapp die als API proxy fungeert voor PowerDNS Authoritative Server. De app stelt klanten in staat om via API hun toegewezen domeinen te beheren, en ondersteunt SSL certificate aanvragen via DNS-01 challenge validatie.

### Use Cases

1. **Klant DNS-beheer** - Klanten kunnen via eigen software hun domeinen beheren (records toevoegen/wijzigen/verwijderen)
2. **SSL via DNS-validatie** - Automated SSL certificate aanvragen via Let's Encrypt/Sectigo ACME protocol met DNS-01 challenge

### Architectuur

```
┌─────────────────┐       ┌──────────────────┐       ┌─────────────────────┐
│  Klant Software │──────▶│  PDNS API Proxy  │──────▶│ PowerDNS Authoritative│
│  (SSL tool etc) │◀──────│  (Flask app)     │◀──────│  Server (intern)     │
└─────────────────┘       └──────────────────┘       └─────────────────────┘
                                  │
                                  ▼
                          ┌──────────────────┐
                          │  MySQL Database  │
                          │  (PowerDNS-Admin)│
                          │  + api_keys      │
                          │  + audit_logs    │
                          └──────────────────┘
```

---

## 2. Database Schema

### 2.1 Nieuwe Tabellen (in PowerDNS-Admin MySQL database)

**`api_keys`**

| Kolom | Type | Nullable | Beschrijving |
|-------|------|----------|--------------|
| id | INT AUTO_INCREMENT | Nee | Primary key |
| key_hash | VARCHAR(64) | Nee | SHA-256 hash van API key |
| key_prefix | VARCHAR(12) | Nee | Display prefix (bijv. `pda_live_ab12`) |
| description | VARCHAR(255) | Ja | Beschrijving/naam voor de key |
| pdns_user_id | INT | Nee | FK naar `users`.`id` |
| is_active | TINYINT(1) | Nee | Default 1 |
| created_at | DATETIME | Nee | |
| created_by | INT | Nee | FK naar `users`.`id` (admin) |

**`api_key_domain_allowlist`**

| Kolom | Type | Nullable | Beschrijving |
|-------|------|----------|--------------|
| id | INT AUTO_INCREMENT | Nee | Primary key |
| api_key_id | INT | Nee | FK naar `api_keys`.`id` |
| domain_id | INT | Nee | PowerDNS `domains`.`id` |

**`api_key_ip_allowlist`**

| Kolom | Type | Nullable | Beschrijving |
|-------|------|----------|--------------|
| id | INT AUTO_INCREMENT | Nee | Primary key |
| api_key_id | INT | Nee | FK naar `api_keys`.`id` |
| ip_address | VARCHAR(45) | Nee | IPv4 of IPv6 adres |
| cidr_mask | INT | Ja | Subnet mask (NULL = exacte match) |

**`audit_logs`**

| Kolom | Type | Nullable | Beschrijving |
|-------|------|----------|--------------|
| id | BIGINT AUTO_INCREMENT | Nee | Primary key |
| api_key_id | INT | Nee | FK naar `api_keys`.`id` |
| method | VARCHAR(10) | Nee | HTTP method (GET, POST, etc.) |
| path | VARCHAR(500) | Nee | Request path |
| request_body | TEXT | Ja | POST/PUT body (optioneel) |
| response_status | INT | Nee | HTTP response code |
| client_ip | VARCHAR(45) | Nee | Client IP adres |
| user_agent | VARCHAR(255) | Ja | User agent string |
| timestamp | DATETIME | Nee | |

### 2.2 Bestaande Tabellen (PowerDNS-Admin)

Relevante tabellen voor JOINs:

- `users` - PowerDNS-Admin gebruikers
- `domains` - PowerDNS domeinen (domain_id, name)
- `zones` - PowerDNS-Admin koppeling tussen users en domains

---

## 3. API Endpoints

### 3.1 Proxy Endpoints (voor klanten)

**Base URL:** `/api/v1`

| Method | Path | Beschrijving |
|--------|------|--------------|
| GET | /zones | Lijst van toegestane zones |
| GET | /zones/{zone_id} | Zone details |
| PATCH | /zones/{zone_id} | Zone wijzigen (TTL, SOA, etc.) |
| GET | /zones/{zone_id}/records | Alle records in zone |
| POST | /zones/{zone_id}/records | Record toevoegen |
| GET | /zones/{zone_id}/records/{record_id} | Specifiek record |
| PATCH | /zones/{zone_id}/records/{record_id} | Record wijzigen |
| DELETE | /zones/{zone_id}/records/{record_id} | Record verwijderen |

**Authenticatie:** `X-API-Key` header verplicht

### 3.2 Admin Endpoints (voor beheerder)

**Base URL:** `/admin`

| Method | Path | Beschrijving |
|--------|------|--------------|
| GET | /api-keys | Lijst van alle API keys |
| POST | /api-keys | Nieuwe API key aanmaken |
| GET | /api-keys/{id} | Key details bekijken |
| PUT | /api-keys/{id} | Key updaten (description, is_active) |
| DELETE | /api-keys/{id} | Key verwijderen |
| GET | /api-keys/{id}/audit | Audit log voor specifieke key |
| POST | /api-keys/{id}/domains | Domein toevoegen aan allowlist |
| DELETE | /api-keys/{id}/domains/{domain_id} | Domein verwijderen uit allowlist |
| POST | /api-keys/{id}/ips | IP toevoegen aan allowlist |
| DELETE | /api-keys/{id}/ips/{ip_id} | IP verwijderen uit allowlist |

**Authenticatie:** Session-based (dezelfde als PowerDNS-Admin admin account)

### 3.3 Health Endpoints

| Method | Path | Beschrijving |
|--------|------|--------------|
| GET | /health | Server health check |
| GET | /ping | Simple ping (voor monitoring) |

---

## 4. Authenticatie & Authorisatie Flow

### 4.1 API Key Validatie

```
1. Client stuurt request met X-API-Key header
2. Server berekent SHA-256 hash van key
3. Server zoekt key_hash in api_keys tabel
4. Als niet gevonden → 401 Unauthorized
5. Als key.is_active = 0 → 401 Unauthorized (revoked)
6. Server checkt IP tegen api_key_ip_allowlist
   - Als geen entries → alle IPs toegestaan
   - Als entries → client_ip moet matchen
   - Matchen met CIDR support indien cidr_mask is gezet
7. Als IP niet toegestaan → 403 Forbidden
8. Request wordt geproxied naar PDNS API
```

### 4.2 Domain Access Control

Bij elke proxy request:
```
1. Haal domain_id uit request path
2. Check of api_key_id + domain_id bestaat in api_key_domain_allowlist
3. Als niet → 403 Access denied
4. Als wel → forward request naar PDNS API
```

### 4.3 API Key Format

- **Format:** `pda_live_<32 karakter random string>`
- **Opslag:** Alleen SHA-256 hash in database
- **Display:** `pda_live_<eerste 4 karakters>` voor identificatie

---

## 5. Project Structuur

```
pdns-api-proxy/
├── app/
│   ├── __init__.py              # Flask app factory
│   ├── config.py                 # Configuration class
│   ├── extensions.py             # Flask extensions (SQLAlchemy, etc)
│   ├── models/
│   │   ├── __init__.py
│   │   ├── api_key.py            # API key model
│   │   ├── audit_log.py          # Audit log model
│   │   └── pdns_models.py        # PDNS-Admin user/zone models
│   ├── services/
│   │   ├── __init__.py
│   │   ├── auth_service.py       # API key validatie
│   │   ├── proxy_service.py      # PDNS API proxy logic
│   │   └── audit_service.py      # Audit logging
│   ├── routes/
│   │   ├── __init__.py
│   │   ├── proxy.py              # Klant proxy endpoints
│   │   ├── admin.py              # Admin panel endpoints
│   │   └── health.py             # Health/ping endpoints
│   └── utils/
│       ├── __init__.py
│       └── ip_utils.py           # IP allowlist checking met CIDR
├── migrations/
│   └── 001_create_api_tables.sql # Database migration
├── tests/
│   ├── __init__.py
│   ├── test_auth_service.py
│   ├── test_proxy_service.py
│   └── test_ip_utils.py
├── .env.example
├── requirements.txt
├── run.py                        # Entry point
├── Dockerfile
├── docker-compose.yml
└── CLAUDE.md
```

---

## 6. Configuration

### Environment Variables

| Variabele | Beschrijving | Voorbeeld |
|-----------|--------------|-----------|
| DATABASE_URL | MySQL connection string | `mysql+pymysql://user:pass@host:3306/powerdnsadmin` |
| PDNS_API_URL | PowerDNS API base URL | `http://127.0.0.1:8081` |
| PDNS_API_KEY | PowerDNS API key | `secret-pdns-api-key` |
| SECRET_KEY | Flask secret key | `your-secret-key-here` |

---

## 7. Error Responses

| HTTP Code | Situatic | Response Body |
|-----------|----------|---------------|
| 401 | Geen X-API-Key header | `{"error": "API key required"}` |
| 401 | Invalid API key | `{"error": "Invalid API key"}` |
| 401 | API key revoked | `{"error": "API key has been revoked"}` |
| 403 | IP not allowed | `{"error": "IP address not allowed for this API key"}` |
| 403 | Domain not allowed | `{"error": "Access denied to this domain"}` |
| 404 | Zone/record not found | `{"error": "Zone/record not found"}` |
| 502 | PDNS API timeout | `{"error": "Upstream DNS server unavailable"}` |
| 502 | PDNS API error | `{"error": "Upstream error", "details": "..."}` |

---

## 8. Security Requirements

1. **API Key opslag:** Alleen SHA-256 hash, nooit plaintext
2. **HTTPS only:** In productie moet de app alleen over HTTPS bereikbaar zijn
3. **IP allowlisting:** CIDR notation support voor subnetten (bijv. `192.168.1.0/24`)
4. **Domain filtering:** Klanten kunnen ALLEEN hun toegewezen domeinen benaderen
5. **Audit logging:** Alle requests worden gelogd met full request/response context
6. **Admin panel:** Afgeschermd met session-based auth

---

## 9. Afhankelijkheden

```
Flask>=3.0.0
Flask-SQLAlchemy>=3.1.0
Flask-Login>=0.6.0
PyMySQL>=1.1.0
requests>=2.31.0
python-dotenv>=1.0.0
ipaddress (stdlib)
hashlib (stdlib)
```

---

## 10. Implementatie Volgorde

1. **Database migration** - Nieuwe tabellen aanmaken
2. **Models** - SQLAlchemy modellen voor nieuwe tabellen
3. **Auth service** - API key validatie + IP checking
4. **Proxy service** - PDNS API forwarding met domain filtering
5. **Proxy routes** - Klant-facing endpoints
6. **Admin routes** - Admin panel voor key management
7. **Audit logging** - Middleware voor request logging
8. **Tests** - Unit tests voor auth en proxy logica
9. **Docker** - Dockerfile en docker-compose

---

## 11. Taken (kleinschalig, lage context per taak)

Elke taak is klein genoeg om in een sessie met beperkte context af te ronden. Tests worden per taak meegeschreven in plaats van als aparte milestone.

| # | Taak | Scope | Tests |
|---|------|-------|-------|
| 1 | Flask app skeleton + config + health endpoints | App factory, config, extensions, health/ping routes | Health endpoint tests |
| 2 | Database migration SQL | `migrations/001_create_api_tables.sql` | - |
| 3 | SQLAlchemy models | `api_key`, `api_key_domain_allowlist`, `api_key_ip_allowlist`, `audit_log`, PDNS-Admin read-only models | Model tests |
| 4 | Auth service | API key validatie + IP allowlist checking met CIDR | Auth + IP utils tests |
| 5 | Proxy service | PDNS API forwarding + domain filtering logica | Proxy service tests |
| 6 | Proxy routes: zones | GET /zones, GET /zones/{id}, PATCH /zones/{id} | Zone route tests |
| 7 | Proxy routes: records | GET/POST/PATCH/DELETE /zones/{id}/records[/{rid}] | Record route tests |
| 8 | Admin routes: API key CRUD | GET/POST/PUT/DELETE /api-keys, GET /api-keys/{id}/audit | Admin key tests |
| 9 | Admin routes: allowlists | POST/DELETE /api-keys/{id}/domains, POST/DELETE /api-keys/{id}/ips | Allowlist tests |
| 10 | Audit logging middleware | Middleware die alle requests logt | Audit middleware tests |
| 11 | Docker | Dockerfile + docker-compose.yml | - |

- [ ] **T1:** Flask app skeleton + config + health endpoints
- [ ] **T2:** Database migration SQL
- [ ] **T3:** SQLAlchemy models
- [ ] **T4:** Auth service (API key validatie + IP allowlisting)
- [ ] **T5:** Proxy service (PDNS API forwarding + domain filtering)
- [ ] **T6:** Proxy routes: zones (3 endpoints)
- [ ] **T7:** Proxy routes: records (4 endpoints)
- [ ] **T8:** Admin routes: API key CRUD (5 endpoints)
- [ ] **T9:** Admin routes: allowlists (4 endpoints)
- [ ] **T10:** Audit logging middleware
- [ ] **T11:** Docker deployment
