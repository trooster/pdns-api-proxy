from app import db
from datetime import datetime
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, InvalidHash

_ph = PasswordHasher()


class ApiKey(db.Model):
    __tablename__ = "api_keys"

    id = db.Column(db.Integer, primary_key=True)
    key_hash = db.Column(db.String(255), unique=True, nullable=False)
    key_prefix = db.Column(db.String(13), nullable=False)
    description = db.Column(db.String(255))
    account_id = db.Column(db.Integer, nullable=False)
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    created_by = db.Column(db.Integer, nullable=False)

    # Relationships
    ip_allowlist = db.relationship("ApiKeyIpAllowlist", backref="api_key", lazy="dynamic", cascade="all, delete-orphan")
    audit_logs = db.relationship("AuditLog", backref="api_key", lazy="dynamic", cascade="all, delete-orphan")

    @staticmethod
    def hash_key(api_key: str) -> str:
        return _ph.hash(api_key)

    @staticmethod
    def verify_key(api_key: str, stored_hash: str) -> bool:
        try:
            return _ph.verify(stored_hash, api_key)
        except (VerifyMismatchError, InvalidHash):
            return False


class ApiKeyIpAllowlist(db.Model):
    __tablename__ = "api_key_ip_allowlist"

    id = db.Column(db.Integer, primary_key=True)
    api_key_id = db.Column(db.Integer, db.ForeignKey("api_keys.id"), nullable=False)
    ip_address = db.Column(db.String(45), nullable=False)
    cidr_mask = db.Column(db.Integer, nullable=True)  # NULL = exact match
