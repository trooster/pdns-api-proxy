import pytest
from app import create_app, db
from app.models.api_key import ApiKey, ApiKeyIpAllowlist
from app.services.auth_service import AuthService


@pytest.fixture
def app():
    app = create_app(
        SQLALCHEMY_DATABASE_URI="sqlite:///:memory:",
        TESTING=True,
    )
    with app.app_context():
        db.create_all()
        yield app
        db.drop_all()


@pytest.fixture
def client(app):
    return app.test_client()


def test_generate_api_key():
    key, key_hash, prefix = AuthService.generate_api_key()

    assert key.startswith("pda_live_")
    assert len(key) == 41  # "pda_live_" (9) + 32 hex chars
    assert key_hash.startswith("$argon2id$")
    assert ApiKey.verify_key(key, key_hash)
    assert prefix.startswith("pda_live_")
    assert len(prefix) == 13  # "pda_live_" (9) + 4 chars


def test_validate_api_key_no_key(app):
    with app.app_context():
        is_valid, _, error = AuthService.validate_api_key("", "127.0.0.1")
        assert is_valid is False
        assert "required" in error


def test_validate_api_key_invalid(app):
    with app.app_context():
        is_valid, _, error = AuthService.validate_api_key("pda_live_invalid", "127.0.0.1")
        assert is_valid is False
        assert "Invalid" in error


def test_ip_utils_exact_match():
    from app.utils.ip_utils import is_ip_in_allowlist

    allowlist = [{"ip_address": "192.168.1.1", "cidr_mask": None}]
    assert is_ip_in_allowlist("192.168.1.1", allowlist) is True
    assert is_ip_in_allowlist("192.168.1.2", allowlist) is False


def test_ip_utils_cidr():
    from app.utils.ip_utils import is_ip_in_allowlist

    allowlist = [{"ip_address": "192.168.1.0", "cidr_mask": 24}]
    assert is_ip_in_allowlist("192.168.1.100", allowlist) is True
    assert is_ip_in_allowlist("192.168.2.1", allowlist) is False


def test_ip_utils_empty_allowlist():
    from app.utils.ip_utils import is_ip_in_allowlist

    # Lege allowlist = geen toegang
    assert is_ip_in_allowlist("1.2.3.4", []) is False
