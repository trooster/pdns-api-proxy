from flask import Blueprint, request, jsonify, g
from app.services.proxy_service import ProxyService
from app.services.audit_service import AuditService
from app.services.auth_service import AuthService

bp = Blueprint("proxy", __name__, url_prefix="/api/v1")


@bp.before_request
def before_request():
    """Auth check + request body opslaan voor audit (max 10KB)."""
    api_key = request.headers.get("X-API-Key", "")
    # ProxyFix (geconfigureerd via PROXY_COUNT) verwerkt X-Forwarded-For
    # en zet request.remote_addr op het echte client-IP.
    client_ip = request.remote_addr

    is_valid, key_obj, error = AuthService.validate_api_key(api_key, client_ip)
    if not is_valid:
        return jsonify({"error": error}), 401

    g.api_key = key_obj
    g.client_ip = client_ip
    g.request_body = request.get_data(as_text=True)[:10000]


def _audit(method, path, status, body=None):
    AuditService.log(
        api_key_id=g.api_key.id,
        method=method,
        path=path,
        request_body=body,
        response_status=status,
        client_ip=g.client_ip,
        user_agent=request.headers.get("User-Agent"),
    )


def _proxy(method, pdns_path, json_data=None):
    """Forward naar PDNS en geef (flask response, status_code) terug."""
    service = ProxyService()
    status, data, error = service.forward_request(method, pdns_path, json_data=json_data)
    if error:
        return jsonify({"error": error}), status
    return jsonify(data), status


# ── Server-niveau ─────────────────────────────────────────────────────────────
# Klanten mogen de server-ID opvragen (nodig voor client-libraries).
# Configuratie en statistieken zijn voorbehouden aan beheerders.

@bp.route("/servers", methods=["GET"])
def list_servers():
    return _proxy("GET", "/api/v1/servers")


@bp.route("/servers/<server_id>", methods=["GET"])
def get_server(server_id):
    return _proxy("GET", f"/api/v1/servers/{server_id}")


@bp.route("/servers/<server_id>/config", methods=["GET"])
@bp.route("/servers/<server_id>/config/<path:item>", methods=["GET"])
def get_config(server_id, item=None):
    return jsonify({"error": "Access to server configuration is not allowed via this API"}), 403


@bp.route("/servers/<server_id>/statistics", methods=["GET"])
def get_statistics(server_id):
    return jsonify({"error": "Access to server statistics is not allowed via this API"}), 403


# ── Zones – lijst (gefilterd op account) ─────────────────────────────────────

@bp.route("/servers/<server_id>/zones", methods=["GET"])
def list_zones(server_id):
    service = ProxyService()
    status, data, error = service.forward_request("GET", f"/api/v1/servers/{server_id}/zones")

    if error:
        _audit("GET", request.path, status)
        return jsonify({"error": error}), status

    # Filter: alleen zones die aan het account gekoppeld zijn
    allowed_domains = AuthService.get_allowed_domains(g.api_key.account_id)
    allowed_names = {d.name.rstrip(".").lower() for d in allowed_domains}

    def _allowed(zone):
        return zone.get("id", "").rstrip(".").lower() in allowed_names

    if isinstance(data, list):
        data = [z for z in data if _allowed(z)]
    elif isinstance(data, dict) and "zones" in data:
        data["zones"] = [z for z in data["zones"] if _allowed(z)]

    _audit("GET", request.path, status)
    return jsonify(data), status


# Zone aanmaken is niet toegestaan via de proxy (beheer via PowerDNS-Admin)
@bp.route("/servers/<server_id>/zones", methods=["POST"])
def create_zone(server_id):
    return jsonify({"error": "Zone creation is not allowed via this API. Use PowerDNS-Admin."}), 403


# ── Specifieke zone (access control op zone_id) ───────────────────────────────

@bp.route("/servers/<server_id>/zones/<string:zone_id>",
          methods=["GET", "PUT", "PATCH"])
def zone(server_id, zone_id):
    if not AuthService.check_domain_access(g.api_key.account_id, zone_id):
        return jsonify({"error": "Access denied to this zone"}), 403

    json_data = request.get_json(silent=True) if request.method in ("PUT", "PATCH") else None
    pdns_path = f"/api/v1/servers/{server_id}/zones/{zone_id}"

    service = ProxyService()
    status, data, error = service.forward_request(request.method, pdns_path, json_data=json_data)

    body = g.request_body if request.method in ("PUT", "PATCH") else None
    _audit(request.method, request.path, status, body)

    if error:
        return jsonify({"error": error}), status
    return jsonify(data), status


@bp.route("/servers/<server_id>/zones/<string:zone_id>", methods=["DELETE"])
def zone_delete(server_id, zone_id):
    return jsonify({"error": "Zone deletion is not allowed via this API. Use PowerDNS-Admin."}), 403


# Sub-resources die klanten NIET mogen gebruiken (beheer via PowerDNS-Admin)
_BLOCKED_ZONE_SUBPATHS = {"cryptokeys", "metadata", "notify", "rectify"}

# Zone sub-resources: /rrsets, /export, etc.
@bp.route("/servers/<server_id>/zones/<string:zone_id>/<path:subpath>",
          methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
def zone_subresource(server_id, zone_id, subpath):
    top = subpath.split("/")[0].lower()
    if top in _BLOCKED_ZONE_SUBPATHS:
        return jsonify({"error": f"Access to /{top} is not allowed via this API"}), 403

    if not AuthService.check_domain_access(g.api_key.account_id, zone_id):
        return jsonify({"error": "Access denied to this zone"}), 403

    json_data = request.get_json(silent=True) if request.method in ("POST", "PUT", "PATCH") else None
    pdns_path = f"/api/v1/servers/{server_id}/zones/{zone_id}/{subpath}"

    service = ProxyService()
    status, data, error = service.forward_request(request.method, pdns_path, json_data=json_data)

    body = g.request_body if request.method in ("POST", "PUT", "PATCH") else None
    _audit(request.method, request.path, status, body)

    if error:
        return jsonify({"error": error}), status
    if not data:
        return "", status
    return jsonify(data), status
