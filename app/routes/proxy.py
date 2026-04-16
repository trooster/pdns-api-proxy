from flask import Blueprint, request, jsonify, g
from app.services.proxy_service import ProxyService
from app.services.audit_service import AuditService
from app.services.auth_service import AuthService
from app.routes.proxy_decorators import require_domain_access

bp = Blueprint("proxy", __name__, url_prefix="/api/v1")


@bp.before_request
def before_request():
    """Auth check + request body opslaan voor audit (max 10KB)."""
    if request.path in ["/ping", "/health", "/api/v1/ping"]:
        return None

    api_key = request.headers.get("X-API-Key", "")
    client_ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    if "," in client_ip:
        client_ip = client_ip.split(",")[0].strip()

    is_valid, key_obj, error = AuthService.validate_api_key(api_key, client_ip)

    if not is_valid:
        return jsonify({"error": error}), 401

    g.api_key = key_obj
    g.client_ip = client_ip
    g.request_body = request.get_data(as_text=True)[:10000]  # Max 10KB log


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

    # Haal domeinen op die aan het account gekoppeld zijn in PowerDNS-Admin.
    # PDNS zone IDs hebben een trailing dot ("example.com."); PdnsDomain.name heeft die niet.
    # Normaliseer beide kanten: lowercase, zonder trailing dot.
    allowed_domains = AuthService.get_allowed_domains(g.api_key.account_id)
    allowed_names = {d.name.rstrip(".").lower() for d in allowed_domains}

    def _zone_allowed(zone):
        zone_id = zone.get("id", "").rstrip(".").lower()
        return zone_id in allowed_names

    if isinstance(data, dict) and "zones" in data:
        data["zones"] = [z for z in data["zones"] if _zone_allowed(z)]
    elif isinstance(data, list):
        data = [z for z in data if _zone_allowed(z)]

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

    AuditService.log(
        api_key_id=g.api_key.id,
        method="GET",
        path=f"/api/v1/zones/{zone_id}",
        request_body=None,
        response_status=status,
        client_ip=g.client_ip,
        user_agent=request.headers.get("User-Agent")
    )

    if error:
        return jsonify({"error": error}), status

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
        request_body=g.request_body,
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
        request_body=g.request_body,
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
        request_body=g.request_body,
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
