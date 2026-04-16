from functools import wraps
from flask import jsonify, g
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
            if zone_id is not None:
                if not AuthService.check_domain_access(g.api_key.id, zone_id):
                    return jsonify({"error": "Access denied to this domain"}), 403
            return f(*args, **kwargs)
        return decorated
    return decorator
