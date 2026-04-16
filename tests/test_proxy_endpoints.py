import pytest
import hashlib
from unittest.mock import patch, MagicMock
from app import create_app, db
from app.models.api_key import ApiKey, ApiKeyIpAllowlist
from app.models.pdns_admin import PdnsAccount, PdnsDomain


@pytest.fixture
def app():
    flask_app = create_app(
        SQLALCHEMY_DATABASE_URI="sqlite:///:memory:",
        TESTING=True,
        PDNS_API_URL="http://127.0.0.1:8081",
        PDNS_API_KEY="test-pdns-key",
    )
    with flask_app.app_context():
        db.create_all()
        yield flask_app
        db.drop_all()


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def api_key_with_zone(app):
    """Create an API key linked to account 1, which owns example.com."""
    with app.app_context():
        account = PdnsAccount(id=1, name="test-account")
        db.session.add(account)

        domain = PdnsDomain(id=42, name="example.com", type="NATIVE", account_id=1)
        db.session.add(domain)

        key_str = "pda_live_testkey00000000000000000"
        key = ApiKey(
            key_hash=hashlib.sha256(key_str.encode()).hexdigest(),
            key_prefix="pda_live_test",
            account_id=1,
            created_by=1,
        )
        db.session.add(key)
        db.session.flush()

        # Lege allowlist = geen toegang; voeg 0.0.0.0/0 toe zodat alle IPs werken
        db.session.add(ApiKeyIpAllowlist(
            api_key_id=key.id,
            ip_address="0.0.0.0",
            cidr_mask=0,
        ))
        db.session.commit()

        return key_str


def test_ping_no_auth(client):
    """Ping endpoint (health blueprint) requires no auth."""
    resp = client.get("/ping")
    assert resp.status_code == 200
    assert resp.get_json()["status"] == "ok"


def test_zones_no_auth(client):
    """Zones endpoint returns 401 without API key."""
    resp = client.get("/api/v1/servers/localhost/zones")
    assert resp.status_code == 401


def test_zones_invalid_key(client):
    """Zones endpoint returns 401 with invalid API key."""
    resp = client.get("/api/v1/servers/localhost/zones", headers={"X-API-Key": "bad-key"})
    assert resp.status_code == 401


def test_list_zones_filters_by_account(client, api_key_with_zone):
    """list_zones returns only zones linked to the API key's account.
    PDNS zone IDs are zone names with trailing dot (e.g. "example.com.").
    """
    mock_zones = [
        {"id": "example.com.", "name": "example.com."},
        {"id": "other.com.", "name": "other.com."},
    ]
    with patch("requests.request") as mock_req:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = mock_zones
        mock_req.return_value = mock_resp

        resp = client.get(
            "/api/v1/servers/localhost/zones",
            headers={"X-API-Key": api_key_with_zone},
        )

    assert resp.status_code == 200
    data = resp.get_json()
    assert len(data) == 1
    assert data[0]["id"] == "example.com."


def test_get_zone_denied_for_other_zone(client, api_key_with_zone):
    """Zone endpoint returns 403 when the zone does not belong to the key's account."""
    resp = client.get(
        "/api/v1/servers/localhost/zones/other.com.",
        headers={"X-API-Key": api_key_with_zone},
    )
    assert resp.status_code == 403


def test_get_zone_allowed(client, api_key_with_zone):
    """Zone endpoint forwards to PDNS when zone belongs to the key's account."""
    with patch("requests.request") as mock_req:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"id": "example.com.", "name": "example.com."}
        mock_req.return_value = mock_resp

        resp = client.get(
            "/api/v1/servers/localhost/zones/example.com.",
            headers={"X-API-Key": api_key_with_zone},
        )

    assert resp.status_code == 200
    assert resp.get_json()["id"] == "example.com."
