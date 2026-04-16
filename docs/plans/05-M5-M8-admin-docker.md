# Milestone M5: Admin Panel + M6: Audit Logging + M7: Tests + M8: Docker

**Start vanuit:** `~/code/pdns-api-proxy/` (M1-M4 moeten geïnstalleerd zijn)

---

## M5: Admin Panel (`app/routes/admin.py`)

```python
from flask import Blueprint, request, jsonify, g
from app import db
from app.models.api_key import ApiKey, ApiKeyDomainAllowlist, ApiKeyIpAllowlist
from app.services.auth_service import AuthService

bp = Blueprint("admin", __name__, url_prefix="/admin")


def admin_required(f):
    """Placeholder: vervang met echte admin session check."""
    @wraps(f)
    def decorated(*args, **kwargs):
        # TODO: Implement admin session check via PowerDNS-Admin sessie
        return f(*args, **kwargs)
    return decorated


@bp.route("/api-keys", methods=["GET"])
def list_keys():
    """Lijst alle API keys."""
    keys = ApiKey.query.all()
    return jsonify([{
        "id": k.id,
        "key_prefix": k.key_prefix,
        "description": k.description,
        "pdns_user_id": k.pdns_user_id,
        "is_active": k.is_active,
        "created_at": k.created_at.isoformat()
    } for k in keys])


@bp.route("/api-keys", methods=["POST"])
def create_key():
    """Maak nieuwe API key aan (handmatig door admin)."""
    data = request.get_json() or {}
    
    full_key, key_hash, key_prefix = AuthService.generate_api_key()
    
    new_key = ApiKey(
        key_hash=key_hash,
        key_prefix=key_prefix,
        description=data.get("description", ""),
        pdns_user_id=data["pdns_user_id"],
        created_by=data.get("created_by", 1)
    )
    db.session.add(new_key)
    db.session.commit()
    
    # Voeg domain allowlist toe
    domain_ids = data.get("domain_ids", [])
    for domain_id in domain_ids:
        entry = ApiKeyDomainAllowlist(api_key_id=new_key.id, domain_id=domain_id)
        db.session.add(entry)
    
    # Voeg IP allowlist toe
    ip_entries = data.get("ip_allowlist", [])
    for ip_entry in ip_entries:
        entry = ApiKeyIpAllowlist(
            api_key_id=new_key.id,
            ip_address=ip_entry["ip_address"],
            cidr_mask=ip_entry.get("cidr_mask")
        )
        db.session.add(entry)
    
    db.session.commit()
    
    # BELANGRIJK: Geef full_key maar één keer terug!
    return jsonify({
        "id": new_key.id,
        "api_key": full_key,  # Volledige key - maar 1x zichtbaar!
        "key_prefix": key_prefix,
        "description": new_key.description
    }), 201


@bp.route("/api-keys/<int:key_id>", methods=["GET"])
def get_key(key_id):
    """Details van één API key."""
    key = ApiKey.query.get_or_404(key_id)
    
    domains = [d.domain_id for d in key.domain_allowlist.all()]
    ips = [{"id": i.id, "ip_address": i.ip_address, "cidr_mask": i.cidr_mask} 
           for i in key.ip_allowlist.all()]
    
    return jsonify({
        "id": key.id,
        "key_prefix": key.key_prefix,
        "description": key.description,
        "pdns_user_id": key.pdns_user_id,
        "is_active": key.is_active,
        "created_at": key.created_at.isoformat(),
        "domains": domains,
        "ip_allowlist": ips
    })


@bp.route("/api-keys/<int:key_id>", methods=["PUT"])
def update_key(key_id):
    """Update API key (description, is_active)."""
    key = ApiKey.query.get_or_404(key_id)
    data = request.get_json() or {}
    
    if "description" in data:
        key.description = data["description"]
    if "is_active" in data:
        key.is_active = data["is_active"]
    
    db.session.commit()
    return jsonify({"status": "ok"})


@bp.route("/api-keys/<int:key_id>", methods=["DELETE"])
def delete_key(key_id):
    """Verwijder API key."""
    key = ApiKey.query.get_or_404(key_id)
    db.session.delete(key)
    db.session.commit()
    return jsonify({"status": "deleted"})


@bp.route("/api-keys/<int:key_id>/domains", methods=["POST"])
def add_domain(key_id):
    """Domein toevoegen aan allowlist."""
    data = request.get_json()
    domain_id = data.get("domain_id")
    
    existing = ApiKeyDomainAllowlist.query.filter_by(
        api_key_id=key_id, domain_id=domain_id
    ).first()
    if existing:
        return jsonify({"error": "Domain already in allowlist"}), 400
    
    entry = ApiKeyDomainAllowlist(api_key_id=key_id, domain_id=domain_id)
    db.session.add(entry)
    db.session.commit()
    return jsonify({"status": "added"}), 201


@bp.route("/api-keys/<int:key_id>/domains/<int:domain_id>", methods=["DELETE"])
def remove_domain(key_id, domain_id):
    """Domein verwijderen uit allowlist."""
    entry = ApiKeyDomainAllowlist.query.filter_by(
        api_key_id=key_id, domain_id=domain_id
    ).first_or_404()
    db.session.delete(entry)
    db.session.commit()
    return jsonify({"status": "removed"})


@bp.route("/api-keys/<int:key_id>/ips", methods=["POST"])
def add_ip(key_id):
    """IP toevoegen aan allowlist."""
    data = request.get_json()
    entry = ApiKeyIpAllowlist(
        api_key_id=key_id,
        ip_address=data["ip_address"],
        cidr_mask=data.get("cidr_mask")
    )
    db.session.add(entry)
    db.session.commit()
    return jsonify({"id": entry.id}), 201


@bp.route("/api-keys/<int:key_id>/ips/<int:ip_id>", methods=["DELETE"])
def remove_ip(key_id, ip_id):
    """IP verwijderen uit allowlist."""
    entry = ApiKeyIpAllowlist.query.filter_by(id=ip_id, api_key_id=key_id).first_or_404()
    db.session.delete(entry)
    db.session.commit()
    return jsonify({"status": "removed"})


@bp.route("/api-keys/<int:key_id>/audit", methods=["GET"])
def get_audit_log(key_id):
    """Audit log voor specifieke key."""
    from app.models.audit_log import AuditLog
    page = request.args.get("page", 1, type=int)
    per_page = request.args.get("per_page", 50, type=int)
    
    logs = AuditLog.query.filter_by(api_key_id=key_id)\
        .order_by(AuditLog.timestamp.desc())\
        .paginate(page=page, per_page=per_page)
    
    return jsonify({
        "logs": [{
            "id": l.id,
            "method": l.method,
            "path": l.path,
            "response_status": l.response_status,
            "client_ip": l.client_ip,
            "timestamp": l.timestamp.isoformat()
        } for l in logs.items],
        "total": logs.total,
        "pages": logs.pages
    })
```

Register blueprint in `app/__init__.py`:
```python
from app.routes.admin import bp as admin_bp
app.register_blueprint(admin_bp)
```

---

## M6: Audit Logging Middleware

Audit logging is al geïntegreerd in de proxy endpoints (M4). Voeg `before_request` toe aan proxy voor betere logging:

Update `app/routes/proxy.py` - replace the `before_request` with this enhanced version:

```python
@bp.before_request
def audit_middleware():
    """Auth check + request body opslaan voor audit."""
    from app.routes.proxy_decorators import require_api_key
    
    if request.path in ["/ping", "/health", "/api/v1/ping"]:
        return None
    
    api_key = request.headers.get("X-API-Key", "")
    client_ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    if "," in client_ip:
        client_ip = client_ip.split(",")[0].strip()
    
    from app.services.auth_service import AuthService
    is_valid, key_obj, error = AuthService.validate_api_key(api_key, client_ip)
    
    if not is_valid:
        return jsonify({"error": error}), 401
    
    g.api_key = key_obj
    g.client_ip = client_ip
    g.request_body = request.get_data(as_text=True)[:10000]  # Max 10KB log
```

---

## M7: Tests (aanvullend)

`tests/test_proxy_endpoints.py`:

```python
import pytest
from unittest.mock import patch, MagicMock
from app import create_app, db
from app.models.api_key import ApiKey, ApiKeyDomainAllowlist


@pytest.fixture
def app():
    app = create_app()
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
    app.config["TESTING"] = True
    with app.app_context():
        db.create_all()
        
        # Maak test API key
        import hashlib
        key = ApiKey(
            key_hash=hashlib.sha256(b"pda_live_testkey12345678901234").hexdigest(),
            key_prefix="pda_test",
            pdns_user_id=1,
            created_by=1
        )
        db.session.add(key)
        db.session.commit()
        
        yield app
        db.drop_all()


def test_proxy_no_api_key(app):
    client = app.test_client()
    resp = client.get("/api/v1/zones")
    assert resp.status_code == 401


def test_proxy_invalid_api_key(app):
    client = app.test_client()
    resp = client.get("/api/v1/zones", headers={"X-API-Key": "invalid"})
    assert resp.status_code == 401


@patch("app.services.proxy_service.ProxyService.list_zones")
def test_proxy_valid_key(mock_list_zones, app):
    import hashlib
    key_hash = hashlib.sha256(b"pda_live_testkey12345678901234").hexdigest()
    
    # Voeg domain toe aan allowlist
    with app.app_context():
        key = ApiKey.query.filter_by(key_hash=key_hash).first()
        entry = ApiKeyDomainAllowlist(api_key_id=key.id, domain_id=1)
        db.session.add(entry)
        db.session.commit()
    
    mock_list_zones.return_value = (200, {"zones": [{"id": 1, "name": "test.com"}]}, "")
    
    client = app.test_client()
    resp = client.get("/api/v1/zones", headers={"X-API-Key": "pda_live_testkey12345678901234"})
    
    assert resp.status_code == 200


@patch("app.services.proxy_service.ProxyService.get_zone")
def test_proxy_domain_access_denied(mock_get_zone, app):
    """Test dat toegang wordt geweigerd voor niet-geautoriseerd domain."""
    import hashlib
    key_hash = hashlib.sha256(b"pda_live_testkey12345678901234").hexdigest()
    
    client = app.test_client()
    resp = client.get("/api/v1/zones/999", headers={"X-API-Key": "pda_live_testkey12345678901234"})
    
    # Zone 999 is niet in allowlist, moet 403 geven
    assert resp.status_code == 403
```

Run:
```bash
pytest tests/ -v
```

---

## M8: Docker

### `Dockerfile`:

```dockerfile
FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    default-libmysqlclient-dev \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN useradd -m -u 1000 appuser
USER appuser

EXPOSE 5000

CMD ["python", "run.py"]
```

### `docker-compose.yml`:

```yaml
version: "3.8"

services:
  pdns-api-proxy:
    build: .
    ports:
      - "5000:5000"
    environment:
      - DATABASE_URL=${DATABASE_URL}
      - PDNS_API_URL=${PDNS_API_URL}
      - PDNS_API_KEY=${PDNS_API_KEY}
      - SECRET_KEY=${SECRET_KEY}
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:5000/ping"]
      interval: 30s
      timeout: 10s
      retries: 3
```

---

## Samenvatting commits

```bash
# M5
git add -A && git commit -m "M5: Admin panel voor API key management"

# M6 (audit logging was al in M4/M5)
git add -A && git commit -m "M6: Audit logging middleware"

# M7
git add -A && git commit -m "M7: Unit tests voor proxy endpoints"

# M8
git add -A && git commit -m "M8: Docker deployment config"
```
