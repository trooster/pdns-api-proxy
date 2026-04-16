from functools import wraps
from flask import Blueprint, request, jsonify
from app import db
from app.models.api_key import ApiKey, ApiKeyIpAllowlist
from app.models.audit_log import AuditLog
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
        "account_id": k.account_id,
        "is_active": k.is_active,
        "created_at": k.created_at.isoformat() if k.created_at else None
    } for k in keys])


@bp.route("/api-keys", methods=["POST"])
def create_key():
    """Maak nieuwe API key aan (handmatig door admin)."""
    data = request.get_json() or {}

    if "account_id" not in data:
        return jsonify({"error": "account_id is required"}), 400

    full_key, key_hash, key_prefix = AuthService.generate_api_key()

    new_key = ApiKey(
        key_hash=key_hash,
        key_prefix=key_prefix,
        description=data.get("description", ""),
        account_id=data["account_id"],
        created_by=data.get("created_by", 1)
    )
    db.session.add(new_key)
    db.session.flush()  # get new_key.id before adding relations

    for ip_entry in data.get("ip_allowlist", []):
        db.session.add(ApiKeyIpAllowlist(
            api_key_id=new_key.id,
            ip_address=ip_entry["ip_address"],
            cidr_mask=ip_entry.get("cidr_mask")
        ))

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
    key = db.session.get(ApiKey, key_id)
    if key is None:
        return jsonify({"error": "Not found"}), 404

    return jsonify({
        "id": key.id,
        "key_prefix": key.key_prefix,
        "description": key.description,
        "account_id": key.account_id,
        "is_active": key.is_active,
        "created_at": key.created_at.isoformat() if key.created_at else None,
        "ip_allowlist": [
            {"id": i.id, "ip_address": i.ip_address, "cidr_mask": i.cidr_mask}
            for i in key.ip_allowlist.all()
        ]
    })


@bp.route("/api-keys/<int:key_id>", methods=["PUT"])
def update_key(key_id):
    """Update API key (description, is_active)."""
    key = db.session.get(ApiKey, key_id)
    if key is None:
        return jsonify({"error": "Not found"}), 404
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
    key = db.session.get(ApiKey, key_id)
    if key is None:
        return jsonify({"error": "Not found"}), 404
    db.session.delete(key)
    db.session.commit()
    return jsonify({"status": "deleted"})


@bp.route("/api-keys/<int:key_id>/ips", methods=["POST"])
def add_ip(key_id):
    """IP toevoegen aan allowlist."""
    if db.session.get(ApiKey, key_id) is None:
        return jsonify({"error": "Not found"}), 404
    data = request.get_json() or {}

    if "ip_address" not in data:
        return jsonify({"error": "ip_address is required"}), 400

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
    if db.session.get(ApiKey, key_id) is None:
        return jsonify({"error": "Not found"}), 404
    page = request.args.get("page", 1, type=int)
    per_page = min(request.args.get("per_page", 50, type=int), 200)

    logs = AuditLog.query.filter_by(api_key_id=key_id)\
        .order_by(AuditLog.timestamp.desc())\
        .paginate(page=page, per_page=per_page)

    return jsonify({
        "logs": [{
            "id": log.id,
            "method": log.method,
            "path": log.path,
            "response_status": log.response_status,
            "client_ip": log.client_ip,
            "timestamp": log.timestamp.isoformat()
        } for log in logs.items],
        "total": logs.total,
        "pages": logs.pages
    })
