import pytest
import hashlib
from unittest.mock import patch, MagicMock
from app import create_app, db
from app.models.api_key import ApiKey, ApiKeyDomainAllowlist
from app.models.pdns_admin import PdnsDomain


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
    """Create an API key with access to zone 42 (example.com)."""
    with app.app_context():
        domain = PdnsDomain(id=42, name="example.com", type="NATIVE")
        db.session.add(domain)

        key_str = "pda_live_testkey00000000000000000"
        key = ApiKey(
            key_hash=hashlib.sha256(key_str.encode()).hexdigest(),
            key_prefix="pda_live_test",
            pdns_user_id=1,
            created_by=1,
        )
        db.session.add(key)
        db.session.flush()

        allowlist_entry = ApiKeyDomainAllowlist(api_key_id=key.id, domain_id=42)
        db.session.add(allowlist_entry)
        db.session.commit()

        return key_str


def test_ping_no_auth(client):
    """Ping endpoint on the proxy blueprint requires no auth."""
    resp = client.get("/api/v1/ping")
    assert resp.status_code == 200
    assert resp.get_json()["status"] == "ok"


def test_zones_no_auth(client):
    """Zones endpoint returns 401 without API key."""
    resp = client.get("/api/v1/zones")
    assert resp.status_code == 401


def test_zones_invalid_key(client):
    """Zones endpoint returns 401 with invalid API key."""
    resp = client.get("/api/v1/zones", headers={"X-API-Key": "bad-key"})
    assert resp.status_code == 401


def test_list_zones_filters_by_allowlist(client, api_key_with_zone):
    """list_zones returns only zones in the API key's allowlist.
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

        resp = client.get("/api/v1/zones", headers={"X-API-Key": api_key_with_zone})

    assert resp.status_code == 200
    data = resp.get_json()
    assert len(data) == 1
    assert data[0]["id"] == "example.com."


def test_get_zone_denied_for_other_zone(client, api_key_with_zone):
    """get_zone returns 403 when key has no access to the requested zone."""
    resp = client.get("/api/v1/zones/99", headers={"X-API-Key": api_key_with_zone})
    assert resp.status_code == 403


def test_get_zone_allowed(client, api_key_with_zone):
    """get_zone forwards to PDNS when access is granted."""
    with patch("requests.request") as mock_req:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"id": 42, "name": "example.com."}
        mock_req.return_value = mock_resp

        resp = client.get("/api/v1/zones/42", headers={"X-API-Key": api_key_with_zone})

    assert resp.status_code == 200
    assert resp.get_json()["id"] == 42
