import pytest
from app import create_app
from app.routes import health as health_module


class TestConfig:
    SECRET_KEY = "test-secret"
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    PDNS_API_URL = "http://127.0.0.1:8081"
    PDNS_API_KEY = ""
    TESTING = True


@pytest.fixture
def client():
    app = create_app(TestConfig)
    with app.test_client() as client:
        yield client


@pytest.fixture(autouse=True)
def reset_health_state():
    health_module._cache.update({"ts": 0.0, "body": None, "status": 503})
    health_module._rate_hits.clear()
    yield
    health_module._cache.update({"ts": 0.0, "body": None, "status": 503})
    health_module._rate_hits.clear()


def test_ping(client):
    response = client.get("/ping")
    assert response.status_code == 200
    assert response.get_json() == {"status": "ok"}


def test_health_all_ok_returns_minimal_body(client, monkeypatch):
    monkeypatch.setattr(health_module, "_check_pdns", lambda: (True, None))
    response = client.get("/health")
    assert response.status_code == 200
    assert response.get_json() == {"status": "healthy"}


def test_health_pdns_down_hides_details(client, monkeypatch):
    monkeypatch.setattr(
        health_module, "_check_pdns", lambda: (False, "pdns unreachable")
    )
    response = client.get("/health")
    assert response.status_code == 503
    body = response.get_json()
    assert body == {"status": "unhealthy"}
    # Public response must not leak which backend failed.
    assert "checks" not in body
    assert "pdns" not in str(body).lower() or body == {"status": "unhealthy"}


def test_health_database_down_hides_details(client, monkeypatch):
    monkeypatch.setattr(
        health_module, "_check_database", lambda: (False, "database unreachable")
    )
    monkeypatch.setattr(health_module, "_check_pdns", lambda: (True, None))
    response = client.get("/health")
    assert response.status_code == 503
    assert response.get_json() == {"status": "unhealthy"}


def test_health_response_is_cached(client, monkeypatch):
    call_count = {"n": 0}

    def counting_check():
        call_count["n"] += 1
        return True, None

    monkeypatch.setattr(health_module, "_check_pdns", counting_check)

    assert client.get("/health").status_code == 200
    assert client.get("/health").status_code == 200
    assert call_count["n"] == 1


def test_health_rate_limit_returns_429(client, monkeypatch):
    monkeypatch.setattr(health_module, "_check_pdns", lambda: (True, None))
    monkeypatch.setattr(health_module, "_RATE_LIMIT_MAX_REQUESTS", 3)

    assert client.get("/health").status_code == 200
    assert client.get("/health").status_code == 200
    assert client.get("/health").status_code == 200

    blocked = client.get("/health")
    assert blocked.status_code == 429
    assert blocked.get_json() == {"error": "rate limit exceeded"}


def test_health_rate_limit_is_per_ip(client, monkeypatch):
    monkeypatch.setattr(health_module, "_check_pdns", lambda: (True, None))
    monkeypatch.setattr(health_module, "_RATE_LIMIT_MAX_REQUESTS", 2)

    # Exhaust budget for IP A.
    assert client.get("/health", environ_overrides={"REMOTE_ADDR": "10.0.0.1"}).status_code == 200
    assert client.get("/health", environ_overrides={"REMOTE_ADDR": "10.0.0.1"}).status_code == 200
    assert client.get("/health", environ_overrides={"REMOTE_ADDR": "10.0.0.1"}).status_code == 429

    # IP B still has its own budget.
    assert client.get("/health", environ_overrides={"REMOTE_ADDR": "10.0.0.2"}).status_code == 200
