from app import db
from datetime import datetime


class AuditLog(db.Model):
    __tablename__ = "audit_logs"

    id = db.Column(db.BigInteger().with_variant(db.Integer, "sqlite"), primary_key=True)
    api_key_id = db.Column(db.Integer, db.ForeignKey("api_keys.id"), nullable=False)
    method = db.Column(db.String(10), nullable=False)
    path = db.Column(db.String(500), nullable=False)
    request_body = db.Column(db.Text)
    response_status = db.Column(db.Integer, nullable=False)
    client_ip = db.Column(db.String(45), nullable=False)
    user_agent = db.Column(db.String(255))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
