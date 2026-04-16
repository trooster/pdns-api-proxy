import bcrypt
import pytest
from flask_login import login_user
from app import create_app, db
from app.models.api_key import ApiKey
from app.models.pdns_admin import PdnsRole, PdnsUser


@pytest.fixture
def app():
    flask_app = create_app(
        SQLALCHEMY_DATABASE_URI="sqlite:///:memory:",
        TESTING=True,
        WTF_CSRF_ENABLED=False,
    )
    with flask_app.app_context():
        db.create_all()

        # Admin role + user
        role = PdnsRole(name="Administrator", description="Admin")
        db.session.add(role)

        # Regular (non-admin) role + user
        user_role = PdnsRole(name="User", description="Regular user")
        db.session.add(user_role)
        db.session.flush()

        pw_hash = bcrypt.hashpw(b"testpass", bcrypt.gensalt()).decode()
        admin = PdnsUser(
            username="testadmin",
            password=pw_hash,
            firstname="Test",
            lastname="Admin",
            email="admin@test.local",
            role_id=role.id,
            confirmed=1,
        )
        db.session.add(admin)

        regular = PdnsUser(
            username="testuser",
            password=pw_hash,
            firstname="Test",
            lastname="User",
            email="user@test.local",
            role_id=user_role.id,
            confirmed=1,
        )
        db.session.add(regular)
        db.session.commit()

        yield flask_app
        db.drop_all()


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def admin_client(client):
    """Test client ingelogd als Administrator."""
    client.post("/login", data={
        "username": "testadmin",
        "password": "testpass",
        "csrf_token": _get_csrf(client),
    }, follow_redirects=True)
    return client


def _get_csrf(client):
    """Haal CSRF token op van de login pagina."""
    resp = client.get("/login")
    # Extraheer csrf_token uit de session via de cookie
    with client.session_transaction() as sess:
        return sess.get("csrf_token", "")


def test_list_keys_empty_unauthenticated(client):
    """Zonder login moet de API 401 teruggeven."""
    resp = client.get("/admin/api-keys")
    assert resp.status_code == 401


def test_list_keys_empty(admin_client):
    resp = admin_client.get("/admin/api-keys")
    assert resp.status_code == 200
    assert resp.get_json() == []


def test_create_key(admin_client):
    resp = admin_client.post("/admin/api-keys", json={
        "account_id": 1,
        "description": "Test key",
    })
    assert resp.status_code == 201
    data = resp.get_json()
    assert "api_key" in data
    assert data["api_key"].startswith("pda_live_")
    assert data["description"] == "Test key"


def test_create_key_missing_account_id(admin_client):
    resp = admin_client.post("/admin/api-keys", json={"description": "Bad"})
    assert resp.status_code == 400


def test_get_key(admin_client):
    create_resp = admin_client.post("/admin/api-keys", json={"account_id": 1})
    key_id = create_resp.get_json()["id"]

    resp = admin_client.get(f"/admin/api-keys/{key_id}")
    assert resp.status_code == 200
    assert resp.get_json()["id"] == key_id


def test_get_key_not_found(admin_client):
    resp = admin_client.get("/admin/api-keys/9999")
    assert resp.status_code == 404


def test_update_key(admin_client):
    create_resp = admin_client.post("/admin/api-keys", json={"account_id": 1})
    key_id = create_resp.get_json()["id"]

    resp = admin_client.put(f"/admin/api-keys/{key_id}", json={"is_active": False, "description": "Updated"})
    assert resp.status_code == 200

    detail = admin_client.get(f"/admin/api-keys/{key_id}").get_json()
    assert detail["is_active"] is False
    assert detail["description"] == "Updated"


def test_delete_key(admin_client):
    create_resp = admin_client.post("/admin/api-keys", json={"account_id": 1})
    key_id = create_resp.get_json()["id"]

    resp = admin_client.delete(f"/admin/api-keys/{key_id}")
    assert resp.status_code == 200

    assert admin_client.get(f"/admin/api-keys/{key_id}").status_code == 404


def test_add_and_remove_ip(admin_client):
    create_resp = admin_client.post("/admin/api-keys", json={"account_id": 1})
    key_id = create_resp.get_json()["id"]

    resp = admin_client.post(f"/admin/api-keys/{key_id}/ips", json={"ip_address": "10.0.0.1"})
    assert resp.status_code == 201
    ip_id = resp.get_json()["id"]

    detail = admin_client.get(f"/admin/api-keys/{key_id}").get_json()
    assert any(i["ip_address"] == "10.0.0.1" for i in detail["ip_allowlist"])

    resp = admin_client.delete(f"/admin/api-keys/{key_id}/ips/{ip_id}")
    assert resp.status_code == 200

    detail = admin_client.get(f"/admin/api-keys/{key_id}").get_json()
    assert detail["ip_allowlist"] == []


def test_add_ip_invalid(admin_client):
    """Ongeldige IP-adressen moeten 400 teruggeven."""
    create_resp = admin_client.post("/admin/api-keys", json={"account_id": 1})
    key_id = create_resp.get_json()["id"]

    resp = admin_client.post(f"/admin/api-keys/{key_id}/ips", json={"ip_address": "not-an-ip"})
    assert resp.status_code == 400


def test_audit_log_empty(admin_client):
    create_resp = admin_client.post("/admin/api-keys", json={"account_id": 1})
    key_id = create_resp.get_json()["id"]

    resp = admin_client.get(f"/admin/api-keys/{key_id}/audit")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["logs"] == []
    assert data["total"] == 0


# ── Regular user cannot access admin API ──────────────────────────────────────

@pytest.fixture
def user_client(client):
    """Test client ingelogd als gewone gebruiker (geen Administrator)."""
    client.post("/login", data={
        "username": "testuser",
        "password": "testpass",
        "csrf_token": _get_csrf(client),
    }, follow_redirects=True)
    return client


def test_regular_user_cannot_access_admin_api(user_client):
    """Gewone gebruiker mag de admin JSON API niet gebruiken."""
    resp = user_client.get("/admin/api-keys")
    assert resp.status_code == 403


def test_regular_user_cannot_create_key_via_admin_api(user_client):
    resp = user_client.post("/admin/api-keys", json={"account_id": 1, "description": "x"})
    assert resp.status_code == 403


def test_regular_user_can_access_dashboard(user_client):
    """Gewone gebruiker mag het dashboard zien (scoped op eigen accounts)."""
    resp = user_client.get("/")
    assert resp.status_code == 200
