import threading
import time
from collections import deque

import requests
from flask import Blueprint, current_app, jsonify, request
from sqlalchemy import text

from app import db

bp = Blueprint("health", __name__)

_CACHE_TTL_SECONDS = 5
_UPSTREAM_TIMEOUT_SECONDS = 2

_RATE_LIMIT_MAX_REQUESTS = 30
_RATE_LIMIT_WINDOW_SECONDS = 60
_RATE_LIMIT_MAX_TRACKED_IPS = 10_000

_cache_lock = threading.Lock()
_cache: dict = {"ts": 0.0, "body": None, "status": 503}

_rate_lock = threading.Lock()
_rate_hits: dict = {}


@bp.route("/ping")
def ping():
    return jsonify({"status": "ok"})


def _rate_limit_ok(ip: str) -> bool:
    """Sliding-window per-IP limiter, in-process per worker."""
    now = time.monotonic()
    cutoff = now - _RATE_LIMIT_WINDOW_SECONDS
    with _rate_lock:
        hits = _rate_hits.get(ip)
        if hits is None:
            hits = deque()
            _rate_hits[ip] = hits
        while hits and hits[0] < cutoff:
            hits.popleft()
        if len(hits) >= _RATE_LIMIT_MAX_REQUESTS:
            return False
        hits.append(now)
        if len(_rate_hits) > _RATE_LIMIT_MAX_TRACKED_IPS:
            stale = [k for k, v in _rate_hits.items() if not v or v[-1] < cutoff]
            for k in stale:
                _rate_hits.pop(k, None)
        return True


def _check_database():
    try:
        db.session.execute(text("SELECT 1"))
        return True, None
    except Exception as exc:
        current_app.logger.warning("Health check: database unreachable: %s", exc)
        return False, "database unreachable"


def _check_pdns():
    base = current_app.config.get("PDNS_API_URL", "http://127.0.0.1:8081").rstrip("/")
    api_key = current_app.config.get("PDNS_API_KEY", "")
    url = f"{base}/api/v1/servers/localhost"
    try:
        response = requests.get(
            url,
            headers={"X-API-Key": api_key, "Accept": "application/json"},
            timeout=_UPSTREAM_TIMEOUT_SECONDS,
        )
        if response.status_code == 200:
            return True, None
        return False, f"pdns returned status {response.status_code}"
    except requests.Timeout:
        return False, "pdns timeout"
    except requests.ConnectionError:
        return False, "pdns unreachable"
    except Exception as exc:
        current_app.logger.warning("Health check: pdns failed: %s", exc)
        return False, "pdns error"


@bp.route("/health")
def health():
    client_ip = request.remote_addr or "unknown"
    if not _rate_limit_ok(client_ip):
        return jsonify({"error": "rate limit exceeded"}), 429

    # Cache briefly so an unauthenticated /health cannot amplify load against
    # the PDNS API or the database.
    now = time.monotonic()
    with _cache_lock:
        if _cache["body"] is not None and now - _cache["ts"] < _CACHE_TTL_SECONDS:
            return jsonify(_cache["body"]), _cache["status"]

    db_ok, db_error = _check_database()
    pdns_ok, pdns_error = _check_pdns()
    overall_ok = db_ok and pdns_ok

    # Public body intentionally omits per-check details to avoid leaking which
    # backend is unreachable to unauthenticated callers. Details go to the log.
    if not overall_ok:
        current_app.logger.warning(
            "Health check failed: database=%s pdns=%s",
            "ok" if db_ok else (db_error or "fail"),
            "ok" if pdns_ok else (pdns_error or "fail"),
        )

    body = {"status": "healthy" if overall_ok else "unhealthy"}
    status_code = 200 if overall_ok else 503

    with _cache_lock:
        _cache["ts"] = now
        _cache["body"] = body
        _cache["status"] = status_code

    return jsonify(body), status_code
