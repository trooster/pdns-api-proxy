# PDNS API Proxy — Testhandleiding

Twee manieren om de app te testen:

1. **Automatisch** — `tests/integration_test.py` (Python, draait tegen een live server)
2. **Manueel** — stap-voor-stap scenario hieronder (browser + curl)

---

## Automatische integratietest

### Gebruik

```bash
# Start de app eerst (zie hieronder)
source venv/bin/activate

# Minimaal (zonder web UI login):
python tests/integration_test.py

# Met web UI login:
BASE_URL=http://localhost:5000 \
ADMIN_USERNAME=admin \
ADMIN_PASSWORD=jouwwachtwoord \
TEST_DOMAIN_ID=3 \
python tests/integration_test.py

# Met 2FA:
BASE_URL=http://localhost:5000 \
ADMIN_USERNAME=admin \
ADMIN_PASSWORD=jouwwachtwoord \
ADMIN_TOTP_SECRET=BASE32SECRETVANPDA \
TEST_DOMAIN_ID=3 \
python tests/integration_test.py
```

### Omgevingsvariabelen

| Variabele | Standaard | Beschrijving |
|-----------|-----------|-------------|
| `BASE_URL` | `http://localhost:5000` | URL van de draaiende app |
| `ADMIN_USERNAME` | _(leeg)_ | PowerDNS-Admin beheerdernaam (voor web UI test) |
| `ADMIN_PASSWORD` | _(leeg)_ | Wachtwoord |
| `ADMIN_TOTP_SECRET` | _(leeg)_ | Base32 TOTP secret (alleen als 2FA aan staat) |
| `TEST_DOMAIN_ID` | `1` | Domein-ID dat toegestaan is voor de testkey |
| `OTHER_DOMAIN_ID` | `9999` | Domein-ID dat NIET toegestaan is |

**TOTP secret opzoeken:**
```sql
SELECT username, otp_secret FROM user WHERE username = 'admin';
```

### Wat wordt getest

| Sectie | Inhoud |
|--------|--------|
| 0 | Server bereikbaar |
| 1 | Health endpoints (`/ping`, `/health`, `/api/v1/ping`) |
| 2 | Proxy auth — geen key → 401, verkeerde key → 401 |
| 3 | Admin JSON API — aanmaken, ophalen, domeinen, IPs, update, 404 |
| 4 | Proxy met geldige key — zones gefilterd, 403 op niet-toegestaan domein |
| 5 | Audit logging — requests gelogd, velden aanwezig, paginering |
| 6 | IP allowlisting — restrictie blokkeert, na verwijderen werkt key weer |
| 7 | Key intrekken → 401, reactiveren → werkt weer |
| 8 | Key verwijderen → 404, verwijderde key → 401 |
| 9 | Web UI login — CSRF, verkeerd wachtwoord, juiste login, 2FA, uitloggen |

---

## Unit tests

```bash
source venv/bin/activate
pytest tests/ -v
```

Dekt: auth service, IP utils, proxy service, audit service, admin JSON API, proxy endpoints.

---

## Manuele testhandleiding

### Voorbereiding

```bash
# Terminal 1: start de app
source venv/bin/activate
python run.py

# Terminal 2: voor de curl commando's
```

---

### 1. Health checks

```bash
curl http://localhost:5000/ping
# Verwacht: {"status": "ok"}

curl http://localhost:5000/health
# Verwacht: {"database": "ok", "status": "ok"}

curl http://localhost:5000/api/v1/ping
# Verwacht: {"status": "ok"}
```

---

### 2. Admin web UI — inloggen

Open in de browser: **http://localhost:5000/admin/**

**Test A — redirect**
- Je wordt automatisch doorgestuurd naar `/admin/login` ✓

**Test B — verkeerd wachtwoord**
- Vul een verkeerde gebruikersnaam of wachtwoord in
- Verwacht: foutmelding *"Ongeldige gebruikersnaam of wachtwoord"*, pagina blijft staan ✓

**Test C — geen admin rechten**
- Log in met een gewone (niet-admin) PowerDNS-Admin gebruiker
- Verwacht: foutmelding *"Je hebt geen beheerdersrechten"* ✓

**Test D — succesvol inloggen**
- Log in met een Administrator account
- Als 2FA ingesteld: voer de 6-cijferige code in vanuit je authenticator app
- Verwacht: doorgestuurd naar het dashboard ✓

---

### 3. API key aanmaken via web UI

Ga naar **http://localhost:5000/admin/keys/new**

Vul in:
- **Gebruiker ID:** een geldig ID uit de PowerDNS-Admin `user` tabel (bijv. `1`)
- **Omschrijving:** `Testklant`
- **Domeinen:** vink één of meer domeinen aan
- **IP allowlist:** laat leeg (voor nu)

Klik **Key aanmaken**

**Verwacht:**
- Gele banner bovenaan met de volledige key: `pda_live_xxxx…` — kopieer deze! ✓
- Je bent doorgestuurd naar de detailpagina van de key ✓
- Ververs de pagina: de key is **niet meer zichtbaar** (eenmalig getoond) ✓

Sla de key op voor de volgende tests:

```bash
export KEY="pda_live_xxxx..."   # plak jouw key hier
export ZONE_ID=3                # het domein-ID dat je hebt aangevinkt
```

---

### 4. Proxy authenticatie

```bash
# Geen key → 401
curl -i http://localhost:5000/api/v1/zones
# Verwacht: 401 {"error": "API key required"}

# Verkeerde key → 401
curl -i -H "X-API-Key: verkeerd" http://localhost:5000/api/v1/zones
# Verwacht: 401 {"error": "Invalid API key"}

# Geldige key → 200 (alleen jouw toegestane zones)
curl -s -H "X-API-Key: $KEY" http://localhost:5000/api/v1/zones
# Verwacht: 200 met lijst van zones
```

---

### 5. Domain access control

```bash
# Toegestaan domein → 200 (of 502 als PDNS zelf niet draait)
curl -i -H "X-API-Key: $KEY" http://localhost:5000/api/v1/zones/$ZONE_ID
# Verwacht: 200 of 502 (nooit 403)

# NIET toegestaan domein → 403
curl -i -H "X-API-Key: $KEY" http://localhost:5000/api/v1/zones/9999
# Verwacht: 403 {"error": "Access denied to this domain"}

# Records van toegestaan domein
curl -i -H "X-API-Key: $KEY" http://localhost:5000/api/v1/zones/$ZONE_ID/records
# Verwacht: 200 of 502

# Records van niet-toegestaan domein
curl -i -H "X-API-Key: $KEY" http://localhost:5000/api/v1/zones/9999/records
# Verwacht: 403
```

---

### 6. Domeinen beheren via web UI

Ga naar de detailpagina: **http://localhost:5000/admin/** → klik op het potloodje

**Domein toevoegen:**
- Selecteer een domein uit de dropdown onder *Domein allowlist*
- Klik **Toevoegen**
- Verwacht: domein verschijnt in de lijst ✓

**Domein verwijderen:**
- Klik op het prullenbakje naast een domein
- Verwacht: domein verdwijnt uit de lijst ✓

Controleer dat het verwijderde domein nu geblokkeerd is:

```bash
# Vervang REMOVED_ZONE_ID met het zojuist verwijderde domein-ID
curl -i -H "X-API-Key: $KEY" http://localhost:5000/api/v1/zones/$REMOVED_ZONE_ID
# Verwacht: 403
```

---

### 7. IP allowlist

Ga naar de detailpagina van je key.

**IP toevoegen:**
- Vul bij *IP adres* in: `203.0.113.1` (een IP dat jij zeker niet hebt)
- Laat CIDR mask leeg
- Klik **Toevoegen**

```bash
# Jouw eigen IP is nu geblokkeerd
curl -i -H "X-API-Key: $KEY" http://localhost:5000/api/v1/zones
# Verwacht: 401 {"error": "IP address not allowed for this API key"}
```

**IP verwijderen:**
- Klik op het prullenbakje naast het IP in de web UI

```bash
# Key werkt weer
curl -i -H "X-API-Key: $KEY" http://localhost:5000/api/v1/zones
# Verwacht: 200
```

---

### 8. Key intrekken

Ga naar de detailpagina → klik **Key intrekken**

```bash
curl -i -H "X-API-Key: $KEY" http://localhost:5000/api/v1/zones
# Verwacht: 401 {"error": "API key has been revoked"}
```

Klik daarna **Key activeren** om te herstellen:

```bash
curl -i -H "X-API-Key: $KEY" http://localhost:5000/api/v1/zones
# Verwacht: 200
```

---

### 9. Audit log

Ga naar de detailpagina → klik **Audit log** (rechtsboven)

**Verwacht:**
- Alle requests die je hierboven hebt gedaan staan erin ✓
- Method (GET), pad, statuscode, IP adres en tijdstip zijn zichtbaar ✓

---

### 10. Key verwijderen

Ga naar de detailpagina → klik **Key verwijderen** → bevestig

```bash
curl -i -H "X-API-Key: $KEY" http://localhost:5000/api/v1/zones
# Verwacht: 401 {"error": "Invalid API key"}
```

Dashboard: de key staat er niet meer in ✓

---

### Checklist

| # | Test | Verwacht |
|---|------|----------|
| 1 | Health endpoints | `{"status": "ok"}` |
| 2A | `/admin/` zonder login | Redirect naar login |
| 2B | Verkeerd wachtwoord | Foutmelding, blijft op login |
| 2C | Niet-admin gebruiker | Foutmelding "geen beheerdersrechten" |
| 2D | Admin inloggen (+2FA) | Dashboard zichtbaar |
| 3 | Key aanmaken | Key eenmalig zichtbaar in banner |
| 4 | Geen/verkeerde key | 401 |
| 5 | Geldige key, toegestaan domein | 200 of 502 |
| 5 | Geldige key, geblokkeerd domein | 403 |
| 6 | Domein toevoegen/verwijderen via UI | Access control direct actief |
| 7 | IP toevoegen → eigen IP geblokkeerd | 401 |
| 7 | IP verwijderen → key werkt weer | 200 |
| 8 | Key intrekken | 401 "revoked" |
| 8 | Key reactiveren | 200 |
| 9 | Audit log | Alle requests zichtbaar |
| 10 | Key verwijderen | 401 "Invalid API key" |
