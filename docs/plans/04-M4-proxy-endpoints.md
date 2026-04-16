# Milestone M4: Klant-facing Proxy Endpoints

**Start vanuit:** `~/code/pdns-api-proxy/` (M1-M3 moeten geïnstalleerd zijn)

**Te wijzigen bestand:** `app/routes/__init__.py`  
**Nieuw bestand:** `app/routes/proxy.py` (uitbreiden)

---

## `app/routes/__init__.py` (update)

```python
from flask import Blueprint, jsonify
from app.routes import health
from app.routes import proxy

# Register proxy blueprint in app factory
def register_routes(app):
    app.register_blueprint(health.bp)
    app.register_blueprint(proxy.bp)
```

---

## `app/routes/proxy.py` (vervang de vorige versie)

```python
from flask import Blueprint, request, jsonify, g
from app.services.proxy_service import ProxyService
from app.services.audit_service import AuditService
from app.routes.proxy_decorators import require_api_key, require_domain_access

bp = Blueprint("proxy", __name__, url_prefix="/api/v1")


@bp.before_request
def before_request():
    """Verplicht API key voor alle /api/v1 endpoints."""
    # Skip health endpoints
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


@bp.route("/ping", methods=["GET"])
def ping():
    """Eigen ping voor proxy."""
    return jsonify({"status": "ok"})


@bp.route("/zones", methods=["GET"])
def list_zones():
    """
    Lijst van zones die deze API key mag benaderen.
    Filtert PDNS zones op basis van domain allowlist.
    """
    service = ProxyService()
    status, data, error = service.list_zones()
    
    if error:
        return jsonify({"error": error}), status
    
    # Filter zones op basis van allowlist
    allowed_domain_ids = g.api_key.get_allowed_domain_ids()
    
    if isinstance(data, dict) and "zones" in data:
        filtered_zones = [
            zone for zone in data["zones"]
            if zone.get("id") in allowed_domain_ids
        ]
        data["zones"] = filtered_zones
    elif isinstance(data, list):
        data = [zone for zone in data if zone.get("id") in allowed_domain_ids]
    
    # Audit log
    AuditService.log(
        api_key_id=g.api_key.id,
        method="GET",
        path="/api/v1/zones",
        request_body=None,
        response_status=200,
        client_ip=g.client_ip,
        user_agent=request.headers.get("User-Agent")
    )
    
    return jsonify(data), 200


@bp.route("/zones/<int:zone_id>", methods=["GET"])
@require_domain_access("zone_id")
def get_zone(zone_id):
    """Zone details ophalen."""
    service = ProxyService()
    status, data, error = service.get_zone(zone_id)
    
    if error:
        return jsonify({"error": error}), status
    
    AuditService.log(
        api_key_id=g.api_key.id,
        method="GET",
        path=f"/api/v1/zones/{zone_id}",
        request_body=None,
        response_status=status,
        client_ip=g.client_ip,
        user_agent=request.headers.get("User-Agent")
    )
    
    return jsonify(data), status


@bp.route("/zones/<int:zone_id>", methods=["PATCH"])
@require_domain_access("zone_id")
def update_zone(zone_id):
    """Zone instellingen wijzigen."""
    json_data = request.get_json() or {}
    
    service = ProxyService()
    status, data, error = service.update_zone(zone_id, json_data)
    
    AuditService.log(
        api_key_id=g.api_key.id,
        method="PATCH",
        path=f"/api/v1/zones/{zone_id}",
        request_body=request.get_data(as_text=True),
        response_status=status,
        client_ip=g.client_ip,
        user_agent=request.headers.get("User-Agent")
    )
    
    if error:
        return jsonify({"error": error}), status
    
    return jsonify(data), status


@bp.route("/zones/<int:zone_id>/records", methods=["GET"])
@require_domain_access("zone_id")
def list_records(zone_id):
    """Alle records in een zone ophalen."""
    service = ProxyService()
    status, data, error = service.get_records(zone_id)
    
    AuditService.log(
        api_key_id=g.api_key.id,
        method="GET",
        path=f"/api/v1/zones/{zone_id}/records",
        request_body=None,
        response_status=status,
        client_ip=g.client_ip,
        user_agent=request.headers.get("User-Agent")
    )
    
    if error:
        return jsonify({"error": error}), status
    
    return jsonify(data), status


@bp.route("/zones/<int:zone_id>/records", methods=["POST"])
@require_domain_access("zone_id")
def create_record(zone_id):
    """Record toevoegen aan zone."""
    json_data = request.get_json() or {}
    
    service = ProxyService()
    status, data, error = service.create_record(zone_id, json_data)
    
    AuditService.log(
        api_key_id=g.api_key.id,
        method="POST",
        path=f"/api/v1/zones/{zone_id}/records",
        request_body=request.get_data(as_text=True),
        response_status=status,
        client_ip=g.client_ip,
        user_agent=request.headers.get("User-Agent")
    )
    
    if error:
        return jsonify({"error": error}), status
    
    return jsonify(data), status


@bp.route("/zones/<int:zone_id>/records/<record_id>", methods=["GET"])
@require_domain_access("zone_id")
def get_record(zone_id, record_id):
    """Specifiek record ophalen."""
    service = ProxyService()
    # Forward enkel de vraag - verdere filtering kan later
    status, data, error = service.forward_request("GET", f"/api/v1/zones/{zone_id}/records/{record_id}")
    
    AuditService.log(
        api_key_id=g.api_key.id,
        method="GET",
        path=f"/api/v1/zones/{zone_id}/records/{record_id}",
        request_body=None,
        response_status=status,
        client_ip=g.client_ip,
        user_agent=request.headers.get("User-Agent")
    )
    
    if error:
        return jsonify({"error": error}), status
    
    return jsonify(data), status


@bp.route("/zones/<int:zone_id>/records/<record_id>", methods=["PATCH"])
@require_domain_access("zone_id")
def update_record(zone_id, record_id):
    """Record wijzigen."""
    json_data = request.get_json() or {}
    
    service = ProxyService()
    status, data, error = service.update_record(zone_id, record_id, json_data)
    
    AuditService.log(
        api_key_id=g.api_key.id,
        method="PATCH",
        path=f"/api/v1/zones/{zone_id}/records/{record_id}",
        request_body=request.get_data(as_text=True),
        response_status=status,
        client_ip=g.client_ip,
        user_agent=request.headers.get("User-Agent")
    )
    
    if error:
        return jsonify({"error": error}), status
    
    return jsonify(data), status


@bp.route("/zones/<int:zone_id>/records/<record_id>", methods=["DELETE"])
@require_domain_access("zone_id")
def delete_record(zone_id, record_id):
    """Record verwijderen."""
    service = ProxyService()
    status, data, error = service.delete_record(zone_id, record_id)
    
    AuditService.log(
        api_key_id=g.api_key.id,
        method="DELETE",
        path=f"/api/v1/zones/{zone_id}/records/{record_id}",
        request_body=None,
        response_status=status,
        client_ip=g.client_ip,
        user_agent=request.headers.get("User-Agent")
    )
    
    if error:
        return jsonify({"error": error}), status
    
    return jsonify(data), status
```

---

## `app/routes/proxy_decorators.py`

```python
from functools import wraps
from flask import jsonify, g, request
from app.services.auth_service import AuthService


def require_domain_access(domain_id_param: str = "zone_id"):
    """
    Decorator die domain access control afdwingt.
    Gebruik: @require_domain_access("zone_id")
    """
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            zone_id = kwargs.get(domain_id_param)
            if zone_id:
                if not AuthService.check_domain_access(g.api_key.id, zone_id):
                    return jsonify({"error": "Access denied to this domain"}), 403
            return f(*args, **kwargs)
        return decorated
    return decorator
```

---

## Update `app/__init__.py`

```python
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from app.config import Config

db = SQLAlchemy()


def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)
    
    db.init_app(app)
    
    # Import en register blueprints
    from app.routes.health import bp as health_bp
    from app.routes.proxy import bp as proxy_bp
    
    app.register_blueprint(health_bp)
    app.register_blueprint(proxy_bp)
    
    return app
```

---

## Commit

```bash
git add -A
git commit -m "M4: Klant-facing proxy endpoints"
```
