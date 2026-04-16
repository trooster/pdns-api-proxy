import pytest
import requests as requests_lib
from unittest.mock import patch, MagicMock
from app import create_app, db


@pytest.fixture
def app():
    flask_app = create_app(
        SQLALCHEMY_DATABASE_URI="sqlite:///:memory:",
        TESTING=True,
        PDNS_API_URL="http://127.0.0.1:8081",
        PDNS_API_KEY="test-key",
    )
    with flask_app.app_context():
        db.create_all()
        yield flask_app
        db.drop_all()


def test_proxy_service_forward_get(app):
    with patch("requests.request") as mock_request:
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"zones": []}
        mock_request.return_value = mock_response

        from app.services.proxy_service import ProxyService
        with app.app_context():
            service = ProxyService()
            status, data, error = service.forward_request("GET", "/api/v1/zones")

            assert status == 200
            assert data == {"zones": []}
            assert error == ""


def test_proxy_service_timeout(app):
    with patch("requests.request") as mock_request:
        mock_request.side_effect = requests_lib.Timeout()

        from app.services.proxy_service import ProxyService
        with app.app_context():
            service = ProxyService()
            status, data, error = service.forward_request("GET", "/api/v1/zones")

            assert status == 502
            assert "timeout" in error


def test_audit_service_log(app):
    from app.services.audit_service import AuditService
    from app.models.audit_log import AuditLog
    from app.models.api_key import ApiKey
    import hashlib

    with app.app_context():
        key = ApiKey(
            key_hash=hashlib.sha256(b"test").hexdigest(),
            key_prefix="pda_test",
            account_id=1,
            created_by=1
        )
        db.session.add(key)
        db.session.commit()

        AuditService.log(
            api_key_id=key.id,
            method="GET",
            path="/api/v1/zones",
            request_body=None,
            response_status=200,
            client_ip="127.0.0.1",
            user_agent="TestClient/1.0"
        )

        log = AuditLog.query.first()
        assert log is not None
        assert log.method == "GET"
        assert log.response_status == 200
