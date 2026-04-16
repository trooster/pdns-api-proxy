from flask import Blueprint, jsonify

bp = Blueprint("health", __name__)


@bp.route("/ping")
def ping():
    return jsonify({"status": "ok"})


@bp.route("/health")
def health():
    return jsonify({"status": "healthy"})
