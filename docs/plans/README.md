# PDNS API Proxy - Implementation Plans

**Volgorde:** M1 → M2 → M3 → M4 → M5-M8

Elk milestone is zelfstandig leesbaar en uitvoerbaar.

## Overzicht

| Milestone | Doel | Bestanden |
|-----------|------|-----------|
| [M1: Project Setup](./01-M1-database-migration.md) | Flask app + DB migration | requirements.txt, run.py, migrations/*.sql |
| [M2: Auth Service](./02-M2-auth-service.md) | API key validatie + IP allowlisting | app/services/auth_service.py, app/utils/ip_utils.py |
| [M3: Proxy Service](./03-M3-proxy-service.md) | PDNS API forwarding | app/services/proxy_service.py |
| [M4: Proxy Endpoints](./04-M4-proxy-endpoints.md) | Klant-facing API routes | app/routes/proxy.py |
| [M5-M8: Admin + Tests + Docker](./05-M5-M8-admin-docker.md) | Admin panel, tests, Docker | app/routes/admin.py, tests/, Dockerfile |

## Start

```bash
cd ~/code/pdns-api-proxy

# Lees alleen het milestone dat je gaat doen
cat docs/plans/01-M1-database-migration.md
```

## Ontwikkeling workflow

1. Lees milestone
2. Implementeer
3. Tests draaien
4. Commit
5. Volgend milestone

## Belangrijke requirements

- Python 3.11+
- MySQL database (zelfde als PowerDNS-Admin)
- PowerDNS Authoritative Server API toegang
