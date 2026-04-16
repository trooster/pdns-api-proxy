"""
Tests for regular (non-admin) user access to the shared key management UI.

Regular PowerDNS-Admin users share the same /admin/ routes as administrators,
but their view is scoped to accounts they are assigned to in PowerDNS-Admin's
account_user table. They can create and revoke/activate keys, but not delete them.
"""
import bcrypt
import pytest
from app import create_app, db
from app.models.api_key import ApiKey, ApiKeyIpAllowlist
from app.models.pdns_admin import PdnsRole, PdnsUser, PdnsAccount, PdnsAccountUser


@pytest.fixture
def app():
    flask_app = create_app(
        SQLALCHEMY_DATABASE_URI="sqlite:///:memory:",
        TESTING=True,
        WTF_CSRF_ENABLED=False,
    )
    with flask_app.app_context():
        db.create_all()

        # Roles
        admin_role = PdnsRole(name="Administrator", description="Admin")
        user_role = PdnsRole(name="User", description="Regular user")
        db.session.add_all([admin_role, user_role])
        db.session.flush()

        pw_hash = bcrypt.hashpw(b"testpass", bcrypt.gensalt()).decode()

        # Users
        regular_user = PdnsUser(
            username="portaluser",
            password=pw_hash,
            firstname="Portal",
            lastname="User",
            email="portal@test.local",
            role_id=user_role.id,
            confirmed=1,
        )
        other_user = PdnsUser(
            username="otheruser",
            password=pw_hash,
            firstname="Other",
            lastname="User",
            email="other@test.local",
            role_id=user_role.id,
            confirmed=1,
        )
        admin_user = PdnsUser(
            username="adminuser",
            password=pw_hash,
            firstname="Admin",
            lastname="User",
            email="admin@test.local",
            role_id=admin_role.id,
            confirmed=1,
        )
        db.session.add_all([regular_user, other_user, admin_user])

        # Accounts
        account_a = PdnsAccount(name="acme", description="Acme Corp")
        account_b = PdnsAccount(name="globex", description="Globex Corp")
        db.session.add_all([account_a, account_b])
        db.session.flush()

        # Assign regular_user to account_a only; other_user to account_b only
        db.session.add(PdnsAccountUser(account_id=account_a.id, user_id=regular_user.id))
        db.session.add(PdnsAccountUser(account_id=account_b.id, user_id=other_user.id))
        db.session.commit()

        yield flask_app
        db.drop_all()


@pytest.fixture
def client(app):
    return app.test_client()


def _get_csrf(client):
    client.get("/login")
    with client.session_transaction() as sess:
        return sess.get("csrf_token", "")


@pytest.fixture
def portal_client(client):
    """Test client ingelogd als gewone gebruiker (account_a)."""
    client.post("/login", data={
        "username": "portaluser",
        "password": "testpass",
        "csrf_token": _get_csrf(client),
    }, follow_redirects=True)
    return client


@pytest.fixture
def other_portal_client(app):
    """Test client ingelogd als andere gewone gebruiker (account_b)."""
    with app.test_client() as c:
        c.get("/login")
        with c.session_transaction() as sess:
            csrf = sess.get("csrf_token", "")
        c.post("/login", data={
            "username": "otheruser",
            "password": "testpass",
            "csrf_token": csrf,
        }, follow_redirects=True)
        yield c


# ── Login & redirect ───────────────────────────────────────────────────────────

def test_login_redirects_to_dashboard(client):
    """Gewone gebruiker wordt na login naar / gestuurd."""
    csrf = _get_csrf(client)
    resp = client.post("/login", data={
        "username": "portaluser",
        "password": "testpass",
        "csrf_token": csrf,
    })
    assert resp.status_code == 302
    assert resp.headers["Location"].rstrip("/") in ("", "http://localhost")


def test_admin_login_also_redirects_to_dashboard(client):
    """Admin wordt ook naar / gestuurd (zelfde URL, ruimere scope)."""
    csrf = _get_csrf(client)
    resp = client.post("/login", data={
        "username": "adminuser",
        "password": "testpass",
        "csrf_token": csrf,
    })
    assert resp.status_code == 302
    assert resp.headers["Location"].rstrip("/") in ("", "http://localhost")


# ── Dashboard ─────────────────────────────────────────────────────────────────

def test_dashboard_accessible_for_regular_user(portal_client):
    resp = portal_client.get("/")
    assert resp.status_code == 200


def test_dashboard_unauthenticated(client):
    resp = client.get("/")
    assert resp.status_code == 302  # redirect to login


# ── Create key ─────────────────────────────────────────────────────────────────

def test_create_key_for_own_account(portal_client, app):
    with app.app_context():
        account_id = PdnsAccount.query.filter_by(name="acme").first().id

    with portal_client.session_transaction() as sess:
        csrf = sess.get("csrf_token", "")

    resp = portal_client.post("/keys/new", data={
        "account_id": str(account_id),
        "description": "Test key",
        "ip_addresses": "10.0.0.1",
        "csrf_token": csrf,
    }, follow_redirects=True)
    assert resp.status_code == 200
    assert b"pda_live_" in resp.data


def test_create_key_for_other_account_is_forbidden(portal_client, app):
    """Gebruiker mag geen key aanmaken voor een account dat niet van hem is."""
    with app.app_context():
        account_id = PdnsAccount.query.filter_by(name="globex").first().id

    with portal_client.session_transaction() as sess:
        csrf = sess.get("csrf_token", "")

    resp = portal_client.post("/keys/new", data={
        "account_id": str(account_id),
        "description": "Stolen key",
        "ip_addresses": "10.0.0.1",
        "csrf_token": csrf,
    })
    assert resp.status_code == 403


def test_create_key_no_account_selected(portal_client):
    with portal_client.session_transaction() as sess:
        csrf = sess.get("csrf_token", "")

    resp = portal_client.post("/keys/new", data={
        "account_id": "",
        "csrf_token": csrf,
    })
    assert resp.status_code == 200
    assert b"Selecteer een account" in resp.data


# ── Key detail / access control ────────────────────────────────────────────────

def _create_key_for_account(app, account_name, user_name="portaluser"):
    """Helper: maakt een key aan via de DB voor het opgegeven account."""
    with app.app_context():
        account = PdnsAccount.query.filter_by(name=account_name).first()
        user = PdnsUser.query.filter_by(username=user_name).first()
        from app.services.auth_service import AuthService
        full_key, key_hash, key_prefix = AuthService.generate_api_key()
        key = ApiKey(
            key_hash=key_hash,
            key_prefix=key_prefix,
            description="DB-created key",
            account_id=account.id,
            created_by=user.id,
        )
        db.session.add(key)
        db.session.commit()
        return key.id


def test_view_own_key(portal_client, app):
    key_id = _create_key_for_account(app, "acme")
    resp = portal_client.get(f"/keys/{key_id}")
    assert resp.status_code == 200


def test_view_other_users_key_is_forbidden(portal_client, app):
    key_id = _create_key_for_account(app, "globex", user_name="otheruser")
    resp = portal_client.get(f"/keys/{key_id}")
    assert resp.status_code == 403


# ── Revoke / activate ──────────────────────────────────────────────────────────

def test_revoke_own_key(portal_client, app):
    key_id = _create_key_for_account(app, "acme")
    with portal_client.session_transaction() as sess:
        csrf = sess.get("csrf_token", "")

    resp = portal_client.post(f"/keys/{key_id}/toggle",
                              data={"csrf_token": csrf},
                              follow_redirects=True)
    assert resp.status_code == 200

    with app.app_context():
        assert db.session.get(ApiKey, key_id).is_active is False


def test_revoke_other_users_key_is_forbidden(portal_client, app):
    key_id = _create_key_for_account(app, "globex", user_name="otheruser")
    with portal_client.session_transaction() as sess:
        csrf = sess.get("csrf_token", "")

    resp = portal_client.post(f"/keys/{key_id}/toggle",
                              data={"csrf_token": csrf})
    assert resp.status_code == 403


def test_regular_user_cannot_delete_key(portal_client, app):
    """Reguliere gebruiker mag geen key verwijderen, ook niet zijn eigen key."""
    key_id = _create_key_for_account(app, "acme")
    with portal_client.session_transaction() as sess:
        csrf = sess.get("csrf_token", "")

    resp = portal_client.post(f"/keys/{key_id}/delete",
                              data={"csrf_token": csrf})
    assert resp.status_code == 403


# ── IP allowlist ───────────────────────────────────────────────────────────────

def test_add_ip_to_own_key(portal_client, app):
    key_id = _create_key_for_account(app, "acme")
    with portal_client.session_transaction() as sess:
        csrf = sess.get("csrf_token", "")

    resp = portal_client.post(f"/keys/{key_id}/ips/add",
                              data={"ip_cidr": "192.168.1.1", "csrf_token": csrf},
                              follow_redirects=True)
    assert resp.status_code == 200

    with app.app_context():
        key = db.session.get(ApiKey, key_id)
        assert any(ip.ip_address == "192.168.1.1" for ip in key.ip_allowlist.all())


def test_add_ip_to_other_users_key_is_forbidden(portal_client, app):
    key_id = _create_key_for_account(app, "globex", user_name="otheruser")
    with portal_client.session_transaction() as sess:
        csrf = sess.get("csrf_token", "")

    resp = portal_client.post(f"/keys/{key_id}/ips/add",
                              data={"ip_cidr": "10.0.0.1", "csrf_token": csrf})
    assert resp.status_code == 403


def test_remove_ip_from_own_key(portal_client, app):
    key_id = _create_key_for_account(app, "acme")
    with app.app_context():
        entry = ApiKeyIpAllowlist(api_key_id=key_id, ip_address="172.16.0.1", cidr_mask=32)
        db.session.add(entry)
        db.session.commit()
        ip_id = entry.id

    with portal_client.session_transaction() as sess:
        csrf = sess.get("csrf_token", "")

    resp = portal_client.post(f"/keys/{key_id}/ips/{ip_id}/remove",
                              data={"csrf_token": csrf},
                              follow_redirects=True)
    assert resp.status_code == 200

    with app.app_context():
        assert db.session.get(ApiKeyIpAllowlist, ip_id) is None


# ── Reguliere user mag admin JSON API niet gebruiken ──────────────────────────

def test_regular_user_cannot_access_admin_api(portal_client):
    resp = portal_client.get("/admin/api-keys")
    assert resp.status_code == 403
