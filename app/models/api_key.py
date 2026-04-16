from app import db
from datetime import datetime


class ApiKey(db.Model):
    __tablename__ = "api_keys"

    id = db.Column(db.Integer, primary_key=True)
    key_hash = db.Column(db.String(64), unique=True, nullable=False)
    key_prefix = db.Column(db.String(12), nullable=False)
    description = db.Column(db.String(255))
    pdns_user_id = db.Column(db.Integer, nullable=False)
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    created_by = db.Column(db.Integer, nullable=False)

    # Relationships
    domain_allowlist = db.relationship("ApiKeyDomainAllowlist", backref="api_key", lazy="dynamic", cascade="all, delete-orphan")
    ip_allowlist = db.relationship("ApiKeyIpAllowlist", backref="api_key", lazy="dynamic", cascade="all, delete-orphan")
    audit_logs = db.relationship("AuditLog", backref="api_key", lazy="dynamic", cascade="all, delete-orphan")

    @staticmethod
    def hash_key(api_key: str) -> str:
        import hashlib
        return hashlib.sha256(api_key.encode()).hexdigest()


class ApiKeyDomainAllowlist(db.Model):
    __tablename__ = "api_key_domain_allowlist"

    id = db.Column(db.Integer, primary_key=True)
    api_key_id = db.Column(db.Integer, db.ForeignKey("api_keys.id"), nullable=False)
    domain_id = db.Column(db.Integer, nullable=False)


class ApiKeyIpAllowlist(db.Model):
    __tablename__ = "api_key_ip_allowlist"

    id = db.Column(db.Integer, primary_key=True)
    api_key_id = db.Column(db.Integer, db.ForeignKey("api_keys.id"), nullable=False)
    ip_address = db.Column(db.String(45), nullable=False)
    cidr_mask = db.Column(db.Integer, nullable=True)  # NULL = exact match
