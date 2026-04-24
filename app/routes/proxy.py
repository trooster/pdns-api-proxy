import html
import re
from urllib.parse import quote
from flask import Blueprint, request, jsonify, g
from app.services.proxy_service import ProxyService
from app.services.audit_service import AuditService
from app.services.auth_service import AuthService

bp = Blueprint("proxy", __name__, url_prefix="/api/v1")


# Strict allowlists for URL path parameters that are forwarded to the upstream
# PDNS API. Rejecting anything outside these character sets at the entry point
# cuts taint from reflected-XSS (CWE-79 / CWE-116) flows at the source.
# The ID/segment pattern deliberately excludes `/` so that `..` and empty
# segments are impossible in a single component.
_VALID_PDNS_ID = re.compile(r"\A[A-Za-z0-9._-]+\Z")


def _reject_invalid_path(*parts):
    """Return a 400 response tuple if any path component is invalid, else None.

    Each part is (value, pattern). Patterns are pre-compiled re.Pattern objects.
    """
    for value, pattern in parts:
        if not isinstance(value, str) or not pattern.match(value):
            return jsonify({"error": "Invalid path parameter"}), 400
    return None


def _validate_zone_subpath(subpath):
    """Split a zone sub-resource subpath into segments and validate each.

    Returns the list of segments when every segment matches `_VALID_PDNS_ID`
    and is not empty / `.` / `..`; returns `None` otherwise.

    Rejecting `.` and `..` up-front is critical: `requests`/`urllib3` normalise
    `..` path components client-side, which would otherwise let an attacker
    authorise against zone A while mutating zone B (CWE-22 / CWE-639).
    """
    if not isinstance(subpath, str) or not subpath:
        return None
    segments = subpath.split("/")
    for seg in segments:
        if seg in ("", ".", "..") or not _VALID_PDNS_ID.match(seg):
            return None
    return segments


@bp.after_request
def _set_security_headers(response):
    """Defense-in-depth: prevent MIME sniffing of proxy responses."""
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    return response


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


def _sanitize_response(data):
    """Recursively HTML-escape all strings in a proxied response.

    The proxy forwards upstream PDNS payloads that can reflect
    client-supplied values (server_id, zone_id, subpath, rrset names, ...).
    Escaping every string value before serialization prevents reflected XSS
    (CWE-79) regardless of how the consumer renders the payload.
    """
    if isinstance(data, str):
        return html.escape(data)
    if isinstance(data, dict):
        return {k: _sanitize_response(v) for k, v in data.items()}
    if isinstance(data, (list, tuple)):
        return [_sanitize_response(item) for item in data]
    return data


def _proxy(method, pdns_path, json_data=None):
    """Forward naar PDNS en geef (flask response, status_code) terug."""
    service = ProxyService()
    status, data, error = service.forward_request(method, pdns_path, json_data=json_data)
    if error:
        return jsonify({"error": html.escape(error)}), status
    return jsonify(_sanitize_response(data)), status


# ── Server-niveau ─────────────────────────────────────────────────────────────
# Klanten mogen de server-ID opvragen (nodig voor client-libraries).
# Configuratie en statistieken zijn voorbehouden aan beheerders.

@bp.route("/servers", methods=["GET"])
def list_servers():
    return _proxy("GET", "/api/v1/servers")


@bp.route("/servers/<server_id>", methods=["GET"])
def get_server(server_id):
    invalid = _reject_invalid_path((server_id, _VALID_PDNS_ID))
    if invalid:
        return invalid
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
    invalid = _reject_invalid_path((server_id, _VALID_PDNS_ID))
    if invalid:
        return invalid
    service = ProxyService()
    status, data, error = service.forward_request("GET", f"/api/v1/servers/{server_id}/zones")

    if error:
        _audit("GET", request.path, status)
        return jsonify({"error": html.escape(error)}), status

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
    return jsonify(_sanitize_response(data)), status


# Zone aanmaken is niet toegestaan via de proxy (beheer via PowerDNS-Admin)
@bp.route("/servers/<server_id>/zones", methods=["POST"])
def create_zone(server_id):
    return jsonify({"error": "Zone creation is not allowed via this API. Use PowerDNS-Admin."}), 403


# ── Specifieke zone (access control op zone_id) ───────────────────────────────

@bp.route("/servers/<server_id>/zones/<string:zone_id>",
          methods=["GET", "PUT", "PATCH"])
def zone(server_id, zone_id):
    invalid = _reject_invalid_path(
        (server_id, _VALID_PDNS_ID),
        (zone_id, _VALID_PDNS_ID),
    )
    if invalid:
        return invalid
    if not AuthService.check_domain_access(g.api_key.account_id, zone_id):
        return jsonify({"error": "Access denied to this zone"}), 403

    json_data = request.get_json(silent=True) if request.method in ("PUT", "PATCH") else None
    pdns_path = f"/api/v1/servers/{server_id}/zones/{zone_id}"

    service = ProxyService()
    status, data, error = service.forward_request(request.method, pdns_path, json_data=json_data)

    body = g.request_body if request.method in ("PUT", "PATCH") else None
    _audit(request.method, request.path, status, body)

    if error:
        return jsonify({"error": html.escape(error)}), status
    return jsonify(_sanitize_response(data)), status


@bp.route("/servers/<server_id>/zones/<string:zone_id>", methods=["DELETE"])
def zone_delete(server_id, zone_id):
    return jsonify({"error": "Zone deletion is not allowed via this API. Use PowerDNS-Admin."}), 403


# Sub-resources die klanten WEL mogen gebruiken. Alles buiten deze allowlist
# is impliciet geblokkeerd — denylists op `cryptokeys`/`metadata`/`notify`/
# `rectify` zijn niet robuust genoeg omdat nieuwe PDNS-versies nieuwe sub-
# resources toevoegen.
_ALLOWED_ZONE_SUBRESOURCES = {"rrsets", "export"}

# Zone sub-resources: /rrsets, /export.
@bp.route("/servers/<server_id>/zones/<string:zone_id>/<path:subpath>",
          methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
def zone_subresource(server_id, zone_id, subpath):
    invalid = _reject_invalid_path(
        (server_id, _VALID_PDNS_ID),
        (zone_id, _VALID_PDNS_ID),
    )
    if invalid:
        return invalid

    segments = _validate_zone_subpath(subpath)
    if segments is None:
        return jsonify({"error": "Invalid path parameter"}), 400

    if segments[0].lower() not in _ALLOWED_ZONE_SUBRESOURCES:
        return jsonify({"error": "Access to this zone sub-resource is not allowed via this API"}), 403

    if not AuthService.check_domain_access(g.api_key.account_id, zone_id):
        return jsonify({"error": "Access denied to this zone"}), 403

    json_data = request.get_json(silent=True) if request.method in ("POST", "PUT", "PATCH") else None

    # Rebouw het pad uit de gevalideerde segmenten en percent-encode elk segment.
    # Samen met de `..`-check in _validate_zone_subpath() sluit dit het
    # cross-zone traversal-vector (urllib3 normaliseert `..` client-side).
    safe_subpath = "/".join(quote(s, safe="") for s in segments)
    pdns_path = (
        f"/api/v1/servers/{quote(server_id, safe='')}"
        f"/zones/{quote(zone_id, safe='')}/{safe_subpath}"
    )

    service = ProxyService()
    status, data, error = service.forward_request(request.method, pdns_path, json_data=json_data)

    body = g.request_body if request.method in ("POST", "PUT", "PATCH") else None
    _audit(request.method, request.path, status, body)

    if error:
        return jsonify({"error": html.escape(error)}), status
    if not data:
        return jsonify({}), status
    return jsonify(_sanitize_response(data)), status
