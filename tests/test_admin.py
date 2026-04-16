import pytest
from app import create_app, db
from app.models.api_key import ApiKey


@pytest.fixture
def app():
    flask_app = create_app(
        SQLALCHEMY_DATABASE_URI="sqlite:///:memory:",
        TESTING=True,
    )
    with flask_app.app_context():
        db.create_all()
        yield flask_app
        db.drop_all()


@pytest.fixture
def client(app):
    return app.test_client()


def test_list_keys_empty(client):
    resp = client.get("/admin/api-keys")
    assert resp.status_code == 200
    assert resp.get_json() == []


def test_create_key(client):
    resp = client.post("/admin/api-keys", json={
        "account_id": 1,
        "description": "Test key",
    })
    assert resp.status_code == 201
    data = resp.get_json()
    assert "api_key" in data
    assert data["api_key"].startswith("pda_live_")
    assert data["description"] == "Test key"


def test_create_key_missing_account_id(client):
    resp = client.post("/admin/api-keys", json={"description": "Bad"})
    assert resp.status_code == 400


def test_get_key(client):
    create_resp = client.post("/admin/api-keys", json={"account_id": 1})
    key_id = create_resp.get_json()["id"]

    resp = client.get(f"/admin/api-keys/{key_id}")
    assert resp.status_code == 200
    assert resp.get_json()["id"] == key_id


def test_get_key_not_found(client):
    resp = client.get("/admin/api-keys/9999")
    assert resp.status_code == 404


def test_update_key(client):
    create_resp = client.post("/admin/api-keys", json={"account_id": 1})
    key_id = create_resp.get_json()["id"]

    resp = client.put(f"/admin/api-keys/{key_id}", json={"is_active": False, "description": "Updated"})
    assert resp.status_code == 200

    detail = client.get(f"/admin/api-keys/{key_id}").get_json()
    assert detail["is_active"] is False
    assert detail["description"] == "Updated"


def test_delete_key(client):
    create_resp = client.post("/admin/api-keys", json={"account_id": 1})
    key_id = create_resp.get_json()["id"]

    resp = client.delete(f"/admin/api-keys/{key_id}")
    assert resp.status_code == 200

    assert client.get(f"/admin/api-keys/{key_id}").status_code == 404


def test_add_and_remove_ip(client):
    create_resp = client.post("/admin/api-keys", json={"account_id": 1})
    key_id = create_resp.get_json()["id"]

    resp = client.post(f"/admin/api-keys/{key_id}/ips", json={"ip_address": "10.0.0.1"})
    assert resp.status_code == 201
    ip_id = resp.get_json()["id"]

    detail = client.get(f"/admin/api-keys/{key_id}").get_json()
    assert any(i["ip_address"] == "10.0.0.1" for i in detail["ip_allowlist"])

    resp = client.delete(f"/admin/api-keys/{key_id}/ips/{ip_id}")
    assert resp.status_code == 200

    detail = client.get(f"/admin/api-keys/{key_id}").get_json()
    assert detail["ip_allowlist"] == []


def test_audit_log_empty(client):
    create_resp = client.post("/admin/api-keys", json={"account_id": 1})
    key_id = create_resp.get_json()["id"]

    resp = client.get(f"/admin/api-keys/{key_id}/audit")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["logs"] == []
    assert data["total"] == 0
