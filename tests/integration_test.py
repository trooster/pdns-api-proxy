#!/usr/bin/env python3
"""
End-to-end integration test voor PDNS API Proxy.

Gebruik:
    source venv/bin/activate
    python tests/integration_test.py

Configureer via environment variables:
    BASE_URL            standaard: http://localhost:5000
    ADMIN_USERNAME      PowerDNS-Admin beheerdersnaam  (voor web UI test)
    ADMIN_PASSWORD      PowerDNS-Admin wachtwoord       (voor web UI test)
    ADMIN_TOTP_SECRET   Base32 TOTP secret              (optioneel, alleen als 2FA aan staat)
    TEST_DOMAIN_ID      domein-ID dat bestaat in PDNS   (standaard: 1)
    OTHER_DOMAIN_ID     domein-ID dat NIET mag worden benaderd (standaard: 9999)

Voorbeeld:
    BASE_URL=http://localhost:5000 \\
    ADMIN_USERNAME=admin \\
    ADMIN_PASSWORD=geheim \\
    TEST_DOMAIN_ID=3 \\
    python tests/integration_test.py
"""

import os
import re
import sys
import json
import requests

# ── Configuratie ──────────────────────────────────────────────────────────────

BASE_URL         = os.getenv("BASE_URL", "http://localhost:5000").rstrip("/")
ADMIN_USERNAME   = os.getenv("ADMIN_USERNAME", "")
ADMIN_PASSWORD   = os.getenv("ADMIN_PASSWORD", "")
ADMIN_TOTP_SECRET = os.getenv("ADMIN_TOTP_SECRET", "")
TEST_DOMAIN_ID   = int(os.getenv("TEST_DOMAIN_ID", "1"))
OTHER_DOMAIN_ID  = int(os.getenv("OTHER_DOMAIN_ID", "9999"))

# ── Kleuren & tellers ─────────────────────────────────────────────────────────

GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
BLUE   = "\033[94m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

passed = 0
failed = 0
skipped = 0


def ok(msg):
    global passed
    passed += 1
    print(f"  {GREEN}✓{RESET}  {msg}")


def fail(msg, detail=""):
    global failed
    failed += 1
    extra = f"\n       {YELLOW}↳ {detail}{RESET}" if detail else ""
    print(f"  {RED}✗{RESET}  {msg}{extra}")


def skip(msg):
    global skipped
    skipped += 1
    print(f"  {YELLOW}○{RESET}  {msg}  {YELLOW}(overgeslagen){RESET}")


def section(title):
    print(f"\n{BOLD}{BLUE}{'═' * 60}{RESET}")
    print(f"{BOLD}{BLUE}  {title}{RESET}")
    print(f"{BOLD}{BLUE}{'═' * 60}{RESET}")


def check(cond, msg_pass, msg_fail, detail=""):
    if cond:
        ok(msg_pass)
    else:
        fail(msg_fail, detail)


def get(path, **kwargs):
    return requests.get(f"{BASE_URL}{path}", **kwargs)


def post(path, **kwargs):
    return requests.post(f"{BASE_URL}{path}", **kwargs)


def put(path, **kwargs):
    return requests.put(f"{BASE_URL}{path}", **kwargs)


def delete(path, **kwargs):
    return requests.delete(f"{BASE_URL}{path}", **kwargs)


def extract_csrf(html: str) -> str:
    m = re.search(r'name="csrf_token"\s+value="([^"]+)"', html)
    return m.group(1) if m else ""


# ── Bereikbaarheid ────────────────────────────────────────────────────────────

def test_reachability():
    section("0. Bereikbaarheid")
    try:
        r = get("/ping", timeout=5)
        check(r.status_code == 200, "Server bereikbaar", "Server NIET bereikbaar",
              f"status={r.status_code}")
        return True
    except requests.ConnectionError:
        fail("Server NIET bereikbaar", f"Kan geen verbinding maken met {BASE_URL}")
        return False


# ── Health ────────────────────────────────────────────────────────────────────

def test_health():
    section("1. Health checks")

    r = get("/ping")
    check(r.status_code == 200 and r.json().get("status") == "ok",
          "GET /ping → 200 ok",
          "GET /ping mislukt", str(r.text))

    r = get("/health")
    check(r.status_code == 200,
          "GET /health → 200",
          "GET /health mislukt", str(r.text))

    r = get("/api/v1/ping")
    check(r.status_code == 200 and r.json().get("status") == "ok",
          "GET /api/v1/ping → 200 ok",
          "GET /api/v1/ping mislukt", str(r.text))


# ── Proxy auth ────────────────────────────────────────────────────────────────

def test_proxy_auth():
    section("2. Proxy authenticatie")

    r = get("/api/v1/zones")
    check(r.status_code == 401,
          "GET /api/v1/zones zonder key → 401",
          f"Verwacht 401, kreeg {r.status_code}")

    r = get("/api/v1/zones", headers={"X-API-Key": "totaalverkeerd"})
    check(r.status_code == 401,
          "GET /api/v1/zones met ongeldige key → 401",
          f"Verwacht 401, kreeg {r.status_code}")

    r = get("/api/v1/zones/1", headers={"X-API-Key": "totaalverkeerd"})
    check(r.status_code == 401,
          "GET /api/v1/zones/1 met ongeldige key → 401",
          f"Verwacht 401, kreeg {r.status_code}")


# ── Admin JSON API ────────────────────────────────────────────────────────────

def test_admin_api():
    section("3. Admin JSON API")

    # Lege lijst
    r = get("/admin/api-keys")
    check(r.status_code == 200 and isinstance(r.json(), list),
          "GET /admin/api-keys → 200 lijst",
          "GET /admin/api-keys mislukt", str(r.text))

    # Key aanmaken zonder verplichte velden
    r = post("/admin/api-keys", json={"description": "mis user id"})
    check(r.status_code == 400,
          "POST /admin/api-keys zonder pdns_user_id → 400",
          f"Verwacht 400, kreeg {r.status_code}")

    # Key aanmaken
    r = post("/admin/api-keys", json={
        "pdns_user_id": 1,
        "description": "Integratietest key",
        "domain_ids": [TEST_DOMAIN_ID],
    })
    check(r.status_code == 201,
          "POST /admin/api-keys → 201",
          f"Key aanmaken mislukt ({r.status_code})", str(r.text))

    if r.status_code != 201:
        fail("Rest van admin tests overgeslagen wegens mislukt aanmaken")
        return None

    data = r.json()
    key_id = data["id"]
    api_key = data["api_key"]

    check(api_key.startswith("pda_live_"),
          f"api_key heeft correct formaat (pda_live_…)",
          f"Onverwacht key formaat: {api_key}")

    check(len(api_key) == 41,
          "api_key lengte correct (41 tekens)",
          f"Onverwachte lengte: {len(api_key)}")

    print(f"       {YELLOW}Key ID: {key_id} — Prefix: {data['key_prefix']}…{RESET}")

    # Key ophalen
    r = get(f"/admin/api-keys/{key_id}")
    check(r.status_code == 200 and r.json()["id"] == key_id,
          "GET /admin/api-keys/<id> → 200",
          "GET /admin/api-keys/<id> mislukt", str(r.text))

    # Domein is toegevoegd
    detail = r.json()
    check(TEST_DOMAIN_ID in detail.get("domains", []),
          f"Domein {TEST_DOMAIN_ID} in allowlist na aanmaken",
          f"Domein {TEST_DOMAIN_ID} NIET in allowlist, gevonden: {detail.get('domains')}")

    # Domein toevoegen via losse call
    r = post(f"/admin/api-keys/{key_id}/domains", json={"domain_id": TEST_DOMAIN_ID})
    check(r.status_code == 400,
          "Dubbel domein toevoegen → 400",
          f"Verwacht 400, kreeg {r.status_code}")

    # Extra domein toevoegen en verwijderen
    extra_domain = TEST_DOMAIN_ID + 1000
    r = post(f"/admin/api-keys/{key_id}/domains", json={"domain_id": extra_domain})
    check(r.status_code == 201,
          f"Extra domein {extra_domain} toevoegen → 201",
          f"Toevoegen domein mislukt ({r.status_code})")

    r = delete(f"/admin/api-keys/{key_id}/domains/{extra_domain}")
    check(r.status_code == 200,
          f"Extra domein {extra_domain} verwijderen → 200",
          f"Verwijderen domein mislukt ({r.status_code})")

    # IP toevoegen
    r = post(f"/admin/api-keys/{key_id}/ips", json={"ip_address": "10.0.0.0", "cidr_mask": 8})
    check(r.status_code == 201,
          "IP 10.0.0.0/8 toevoegen → 201",
          f"IP toevoegen mislukt ({r.status_code})")
    ip_id = r.json().get("id") if r.status_code == 201 else None

    if ip_id:
        r = delete(f"/admin/api-keys/{key_id}/ips/{ip_id}")
        check(r.status_code == 200,
              "IP verwijderen → 200",
              f"IP verwijderen mislukt ({r.status_code})")

    # Omschrijving updaten
    r = put(f"/admin/api-keys/{key_id}", json={"description": "Bijgewerkte omschrijving"})
    check(r.status_code == 200,
          "PUT /admin/api-keys/<id> omschrijving → 200",
          f"Update mislukt ({r.status_code})")

    r = get(f"/admin/api-keys/{key_id}")
    check(r.json().get("description") == "Bijgewerkte omschrijving",
          "Omschrijving correct opgeslagen",
          "Omschrijving NIET bijgewerkt")

    # Niet-bestaande key
    r = get("/admin/api-keys/999999")
    check(r.status_code == 404,
          "GET /admin/api-keys/999999 → 404",
          f"Verwacht 404, kreeg {r.status_code}")

    return key_id, api_key


# ── Proxy met geldige key ─────────────────────────────────────────────────────

def test_proxy_with_key(key_id, api_key):
    section("4. Proxy met geldige API key")

    headers = {"X-API-Key": api_key}

    # Zones ophalen (gefilterd op allowlist)
    r = get("/api/v1/zones", headers=headers)
    check(r.status_code == 200,
          "GET /api/v1/zones met geldige key → 200",
          f"Verwacht 200, kreeg {r.status_code}", str(r.text))

    if r.status_code == 200:
        data = r.json()
        if isinstance(data, list):
            zone_ids = [z.get("id") for z in data]
        elif isinstance(data, dict) and "zones" in data:
            zone_ids = [z.get("id") for z in data["zones"]]
        else:
            zone_ids = []

        check(all(zid == TEST_DOMAIN_ID or zid in zone_ids for zid in zone_ids),
              f"Zones gefilterd op allowlist (enkel domein {TEST_DOMAIN_ID} zichtbaar)",
              "Zones bevatten mogelijk niet-toegestane domeinen")

    # Toegestaan domein ophalen
    r = get(f"/api/v1/zones/{TEST_DOMAIN_ID}", headers=headers)
    check(r.status_code in (200, 502),
          f"GET /api/v1/zones/{TEST_DOMAIN_ID} → {r.status_code} "
          f"({'OK' if r.status_code == 200 else '502 = PDNS niet bereikbaar, access control werkt'})",
          f"Onverwachte statuscode {r.status_code}", str(r.text))

    # Niet-toegestaan domein → 403
    r = get(f"/api/v1/zones/{OTHER_DOMAIN_ID}", headers=headers)
    check(r.status_code == 403,
          f"GET /api/v1/zones/{OTHER_DOMAIN_ID} (niet in allowlist) → 403",
          f"Verwacht 403, kreeg {r.status_code} — access control werkt NIET!")

    if r.status_code == 403:
        check("Access denied" in r.json().get("error", ""),
              "403 bevat correct foutbericht",
              f"Onverwacht foutbericht: {r.json()}")

    # Records endpoint (toegestaan domein)
    r = get(f"/api/v1/zones/{TEST_DOMAIN_ID}/records", headers=headers)
    check(r.status_code in (200, 502),
          f"GET /api/v1/zones/{TEST_DOMAIN_ID}/records → {r.status_code}",
          f"Onverwachte statuscode {r.status_code}")

    # Records endpoint (niet-toegestaan domein) → 403
    r = get(f"/api/v1/zones/{OTHER_DOMAIN_ID}/records", headers=headers)
    check(r.status_code == 403,
          f"GET /api/v1/zones/{OTHER_DOMAIN_ID}/records → 403",
          f"Verwacht 403, kreeg {r.status_code}")


# ── Audit log ─────────────────────────────────────────────────────────────────

def test_audit_log(key_id, api_key):
    section("5. Audit logging")

    # Audit log ophalen
    r = get(f"/admin/api-keys/{key_id}/audit")
    check(r.status_code == 200,
          "GET /admin/api-keys/<id>/audit → 200",
          f"Audit log ophalen mislukt ({r.status_code})")

    if r.status_code == 200:
        data = r.json()
        total = data.get("total", 0)
        check(total > 0,
              f"Audit log heeft {total} regels (requests zijn gelogd)",
              "Audit log is leeg — requests worden NIET gelogd")

        if data.get("logs"):
            log = data["logs"][0]
            check("method" in log and "path" in log and "client_ip" in log,
                  "Audit log bevat method, path en client_ip",
                  f"Audit log mist velden: {list(log.keys())}")

        # Paginering
        check("total" in data and "pages" in data,
              "Audit log bevat paginering (total, pages)",
              "Paginering ontbreekt in audit log response")


# ── IP allowlisting ───────────────────────────────────────────────────────────

def test_ip_allowlist(key_id, api_key):
    section("6. IP allowlisting")

    headers = {"X-API-Key": api_key}

    # Voeg een specifiek IP toe dat NIET het huidige IP is
    r = post(f"/admin/api-keys/{key_id}/ips", json={"ip_address": "203.0.113.1"})
    check(r.status_code == 201,
          "IP 203.0.113.1 toegevoegd aan allowlist",
          f"IP toevoegen mislukt ({r.status_code})")
    ip_id = r.json().get("id") if r.status_code == 201 else None

    if ip_id:
        # Nu zou een verzoek van het huidige IP (127.0.0.1) geblokkeerd moeten worden
        r = get("/api/v1/zones", headers=headers)
        check(r.status_code == 401,
              "Request van localhost geblokkeerd door IP allowlist → 401",
              f"Verwacht 401, kreeg {r.status_code} — IP allowlist werkt NIET")

        # Verwijder de IP restrictie
        r = delete(f"/admin/api-keys/{key_id}/ips/{ip_id}")
        check(r.status_code == 200, "IP restrictie verwijderd", "Verwijderen mislukt")

        # Nu moet de key weer werken
        r = get("/api/v1/zones", headers=headers)
        check(r.status_code == 200,
              "Na verwijderen IP restrictie werkt de key weer → 200",
              f"Verwacht 200, kreeg {r.status_code}")


# ── Key intrekken ─────────────────────────────────────────────────────────────

def test_revoke(key_id, api_key):
    section("7. Key intrekken en reactiveren")

    headers = {"X-API-Key": api_key}

    # Key intrekken
    r = put(f"/admin/api-keys/{key_id}", json={"is_active": False})
    check(r.status_code == 200,
          "Key intrekken (is_active=false) → 200",
          f"Intrekken mislukt ({r.status_code})")

    # Ingetrokken key proberen
    r = get("/api/v1/zones", headers=headers)
    check(r.status_code == 401,
          "Ingetrokken key → 401",
          f"Verwacht 401, kreeg {r.status_code}")

    if r.status_code == 401:
        check("revoked" in r.json().get("error", "").lower(),
              "Foutbericht vermeldt 'revoked'",
              f"Onverwacht bericht: {r.json()}")

    # Reactiveren
    r = put(f"/admin/api-keys/{key_id}", json={"is_active": True})
    check(r.status_code == 200, "Key reactiveren → 200", f"Reactiveren mislukt ({r.status_code})")

    r = get("/api/v1/zones", headers=headers)
    check(r.status_code == 200,
          "Gereactiveerde key werkt weer → 200",
          f"Verwacht 200, kreeg {r.status_code}")


# ── Key verwijderen ───────────────────────────────────────────────────────────

def test_delete(key_id, api_key):
    section("8. Key verwijderen")

    headers = {"X-API-Key": api_key}

    r = delete(f"/admin/api-keys/{key_id}")
    check(r.status_code == 200,
          "DELETE /admin/api-keys/<id> → 200",
          f"Verwijderen mislukt ({r.status_code})")

    r = get(f"/admin/api-keys/{key_id}")
    check(r.status_code == 404,
          "Verwijderde key ophalen → 404",
          f"Verwacht 404, kreeg {r.status_code}")

    r = get("/api/v1/zones", headers=headers)
    check(r.status_code == 401,
          "Verwijderde key → 401",
          f"Verwacht 401, kreeg {r.status_code}")


# ── Admin web UI login ────────────────────────────────────────────────────────

def test_web_ui_login():
    section("9. Admin web UI (login)")

    if not ADMIN_USERNAME or not ADMIN_PASSWORD:
        skip("ADMIN_USERNAME en ADMIN_PASSWORD niet ingesteld — web UI test overgeslagen")
        skip("Stel in: ADMIN_USERNAME=admin ADMIN_PASSWORD=geheim python tests/integration_test.py")
        return

    session = requests.Session()

    # Niet-ingelogd → redirect naar login
    r = session.get(f"{BASE_URL}/admin/", allow_redirects=False)
    check(r.status_code in (302, 301),
          "GET /admin/ zonder sessie → redirect naar login",
          f"Verwacht redirect, kreeg {r.status_code}")

    # Login pagina ophalen
    r = session.get(f"{BASE_URL}/admin/login")
    check(r.status_code == 200,
          "GET /admin/login → 200",
          f"Login pagina niet bereikbaar ({r.status_code})")

    csrf = extract_csrf(r.text)
    check(bool(csrf),
          "CSRF token aanwezig op login pagina",
          "Geen CSRF token gevonden in HTML")

    if not csrf:
        fail("Login test gestopt: geen CSRF token")
        return

    # Verkeerd wachtwoord
    r = session.post(f"{BASE_URL}/admin/login", data={
        "username": ADMIN_USERNAME,
        "password": "ZEKERVERKEERD123!@#",
        "csrf_token": csrf,
    })
    check(r.status_code == 200 and "Ongeldige" in r.text,
          "Verkeerd wachtwoord → foutmelding op pagina",
          "Verkeerd wachtwoord gaf geen fout")

    # Niet-admin gebruiker (alleen als je een test-user hebt)
    # skip("Niet-admin test overgeslagen")

    # Correct inloggen
    csrf = extract_csrf(r.text)  # refresh CSRF token
    r = session.post(f"{BASE_URL}/admin/login", data={
        "username": ADMIN_USERNAME,
        "password": ADMIN_PASSWORD,
        "csrf_token": csrf,
    }, allow_redirects=False)

    if r.status_code == 302 and "/admin/login/2fa" in r.headers.get("Location", ""):
        print(f"  {YELLOW}ℹ{RESET}  2FA vereist — TOTP code invullen")

        if not ADMIN_TOTP_SECRET:
            skip("ADMIN_TOTP_SECRET niet ingesteld — 2FA stap overgeslagen")
            return

        import pyotp
        totp = pyotp.TOTP(ADMIN_TOTP_SECRET)
        r = session.get(f"{BASE_URL}/admin/login/2fa")
        csrf_2fa = extract_csrf(r.text)

        r = session.post(f"{BASE_URL}/admin/login/2fa", data={
            "code": totp.now(),
            "csrf_token": csrf_2fa,
        }, allow_redirects=False)

        check(r.status_code == 302,
              "2FA verificatie → redirect",
              f"2FA mislukt ({r.status_code})")

    elif r.status_code == 302:
        check(True, "Inloggen succesvol → redirect naar dashboard", "")
    else:
        fail(f"Inloggen mislukt (status {r.status_code})", r.text[:200])
        return

    # Dashboard ophalen
    r = session.get(f"{BASE_URL}/admin/")
    check(r.status_code == 200 and "API Keys" in r.text,
          "Dashboard zichtbaar na inloggen",
          f"Dashboard niet bereikbaar ({r.status_code})")

    # Nieuwe key aanmaken via web UI (formulier)
    r = session.get(f"{BASE_URL}/admin/keys/new")
    check(r.status_code == 200 and "Nieuwe API key" in r.text,
          "Aanmaken-pagina bereikbaar",
          f"Aanmaken-pagina niet bereikbaar ({r.status_code})")

    # Uitloggen
    r = session.get(f"{BASE_URL}/admin/logout", allow_redirects=False)
    check(r.status_code == 302,
          "Uitloggen → redirect",
          f"Uitloggen mislukt ({r.status_code})")

    # Na uitloggen → geen toegang
    r = session.get(f"{BASE_URL}/admin/", allow_redirects=False)
    check(r.status_code in (302, 301),
          "Na uitloggen → opnieuw redirect naar login",
          f"Sessie nog actief na uitloggen ({r.status_code})")


# ── Samenvatting ──────────────────────────────────────────────────────────────

def summary():
    total = passed + failed
    print(f"\n{BOLD}{'═' * 60}{RESET}")
    print(f"{BOLD}  Resultaat{RESET}")
    print(f"{'═' * 60}")
    print(f"  {GREEN}✓  {passed} geslaagd{RESET}")
    if failed:
        print(f"  {RED}✗  {failed} mislukt{RESET}")
    if skipped:
        print(f"  {YELLOW}○  {skipped} overgeslagen{RESET}")
    print(f"  {'─' * 40}")
    print(f"  Totaal: {total} tests")

    if failed == 0:
        print(f"\n  {GREEN}{BOLD}Alle tests geslaagd! ✓{RESET}\n")
    else:
        print(f"\n  {RED}{BOLD}{failed} test(s) mislukt.{RESET}\n")

    return failed == 0


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    print(f"\n{BOLD}PDNS API Proxy — Integratietest{RESET}")
    print(f"Server: {BOLD}{BASE_URL}{RESET}")
    print(f"Test domein ID: {TEST_DOMAIN_ID}  |  Geblokkeerd domein ID: {OTHER_DOMAIN_ID}")

    if not test_reachability():
        print(f"\n{RED}Server niet bereikbaar. Test gestopt.{RESET}\n")
        sys.exit(1)

    test_health()
    test_proxy_auth()

    result = test_admin_api()
    if result is None:
        print(f"\n{RED}Admin API mislukt. Overige tests gestopt.{RESET}\n")
        sys.exit(1)

    key_id, api_key = result

    test_proxy_with_key(key_id, api_key)
    test_audit_log(key_id, api_key)
    test_ip_allowlist(key_id, api_key)
    test_revoke(key_id, api_key)
    test_delete(key_id, api_key)
    test_web_ui_login()

    success = summary()
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
