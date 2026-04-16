# Milestone M2: Auth Service (API Key Validation + IP Allowlisting)

**Start vanuit:** `~/code/pdns-api-proxy/` (M1 moet geïnstalleerd zijn)

**Nieuwe bestanden te maken:**

---

## `app/utils/ip_utils.py`

```python
import ipaddress
from typing import List, Optional


def is_ip_in_allowlist(client_ip: str, allowlist: List[dict]) -> bool:
    """
    Check of client_ip matches any entry in de IP allowlist.
    
    allowlist: list van dicts met 'ip_address' en optioneel 'cidr_mask'
    """
    if not allowlist:
        return True  # Lege allowlist = alles toegestaan
    
    client = ipaddress.ip_address(client_ip)
    
    for entry in allowlist:
        if entry.get('cidr_mask'):
            # CIDR check
            network = ipaddress.ip_network(
                f"{entry['ip_address']}/{entry['cidr_mask']}", 
                strict=False
            )
            if client in network:
                return True
        else:
            # Exact match
            if str(client) == entry['ip_address']:
                return True
    
    return False
```

---

## `app/models/api_key.py`

```python
from app import db
from datetime import datetime


class ApiKey(db.Model):
    __tablename__ = "api_keys"
    
    id = db.Column(db.Integer, primary_key=True)
    key_hash = db.Column(db.String(64), unique=True, nullable=False)
    key_prefix = db.Column(db.String(12), nullable=False)
    description = db.Column(db.String(255))
    pdns_user_id = db.Column(db.Integer, nullable=False)
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    created_by = db.Column(db.Integer, nullable=False)
    
    # Relationships
    domain_allowlist = db.relationship("ApiKeyDomainAllowlist", backref="api_key", lazy="dynamic", cascade="all, delete-orphan")
    ip_allowlist = db.relationship("ApiKeyIpAllowlist", backref="api_key", lazy="dynamic", cascade="all, delete-orphan")
    audit_logs = db.relationship("AuditLog", backref="api_key", lazy="dynamic", cascade="all, delete-orphan")
    
    @staticmethod
    def hash_key(api_key: str) -> str:
        import hashlib
        return hashlib.sha256(api_key.encode()).hexdigest()


class ApiKeyDomainAllowlist(db.Model):
    __tablename__ = "api_key_domain_allowlist"
    
    id = db.Column(db.Integer, primary_key=True)
    api_key_id = db.Column(db.Integer, db.ForeignKey("api_keys.id"), nullable=False)
    domain_id = db.Column(db.Integer, nullable=False)


class ApiKeyIpAllowlist(db.Model):
    __tablename__ = "api_key_ip_allowlist"
    
    id = db.Column(db.Integer, primary_key=True)
    api_key_id = db.Column(db.Integer, db.ForeignKey("api_keys.id"), nullable=False)
    ip_address = db.Column(db.String(45), nullable=False)
    cidr_mask = db.Column(db.Integer, nullable=True)  # NULL = exact match
```

---

## `app/models/audit_log.py`

```python
from app import db
from datetime import datetime


class AuditLog(db.Model):
    __tablename__ = "audit_logs"
    
    id = db.Column(db.BigInteger, primary_key=True)
    api_key_id = db.Column(db.Integer, db.ForeignKey("api_keys.id"), nullable=False)
    method = db.Column(db.String(10), nullable=False)
    path = db.Column(db.String(500), nullable=False)
    request_body = db.Column(db.Text)
    response_status = db.Column(db.Integer, nullable=False)
    client_ip = db.Column(db.String(45), nullable=False)
    user_agent = db.Column(db.String(255))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
```

---

## `app/services/auth_service.py`

```python
import secrets
import hashlib
from typing import Optional, Tuple
from app import db
from app.models.api_key import ApiKey, ApiKeyDomainAllowlist, ApiKeyIpAllowlist
from app.utils.ip_utils import is_ip_in_allowlist


class AuthService:
    
    @staticmethod
    def generate_api_key() -> Tuple[str, str, str]:
        """
        Genereer een nieuwe API key.
        Returns: (full_key, key_hash, key_prefix)
        """
        prefix = "pda_live_"
        random_part = secrets.token_hex(16)  # 32 chars
        full_key = prefix + random_part
        key_hash = ApiKey.hash_key(full_key)
        key_prefix = prefix + random_part[:4]
        return full_key, key_hash, key_prefix
    
    @staticmethod
    def validate_api_key(api_key: str, client_ip: str) -> Tuple[bool, Optional[ApiKey], str]:
        """
        Valideer API key en IP adres.
        Returns: (is_valid, api_key_obj, error_message)
        """
        if not api_key:
            return False, None, "API key required"
        
        key_hash = ApiKey.hash_key(api_key)
        key_obj = ApiKey.query.filter_by(key_hash=key_hash).first()
        
        if not key_obj:
            return False, None, "Invalid API key"
        
        if not key_obj.is_active:
            return False, None, "API key has been revoked"
        
        # IP check
        ip_entries = [
            {"ip_address": entry.ip_address, "cidr_mask": entry.cidr_mask}
            for entry in key_obj.ip_allowlist.all()
        ]
        
        if not is_ip_in_allowlist(client_ip, ip_entries):
            return False, None, "IP address not allowed for this API key"
        
        return True, key_obj, ""
    
    @staticmethod
    def check_domain_access(api_key_id: int, domain_id: int) -> bool:
        """Check of API key toegang heeft tot dit domain."""
        entry = ApiKeyDomainAllowlist.query.filter_by(
            api_key_id=api_key_id,
            domain_id=domain_id
        ).first()
        return entry is not None
    
    @staticmethod
    def get_allowed_domain_ids(api_key_id: int) -> list:
        """Haal lijst van toegestane domain_ids op voor een API key."""
        entries = ApiKeyDomainAllowlist.query.filter_by(api_key_id=api_key_id).all()
        return [e.domain_id for e in entries]
```

---

## Tests: `tests/test_auth_service.py`

```python
import pytest
from app import create_app, db
from app.models.api_key import ApiKey, ApiKeyIpAllowlist
from app.services.auth_service import AuthService


@pytest.fixture
def app():
    app = create_app()
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
    app.config["TESTING"] = True
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
    assert len(key) == 40  # prefix + 32 chars
    assert len(key_hash) == 64  # SHA-256 hex
    assert prefix.startswith("pda_live_")
    assert len(prefix) == 12


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
    
    assert is_ip_in_allowlist("1.2.3.4", []) is True
```

---

## Run tests

```bash
cd ~/code/pdns-api-proxy
source venv/bin/activate
pytest tests/test_auth_service.py -v
```

---

## Commit

```bash
git add -A
git commit -m "M2: Auth service met API key validatie en IP allowlisting"
```
