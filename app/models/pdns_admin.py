"""
Read-only SQLAlchemy models for PowerDNS-Admin tables.
These map to existing tables in the powerdnsadmin database.
"""
from flask_login import UserMixin
from app import db


class PdnsRole(db.Model):
    __tablename__ = "role"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64))
    description = db.Column(db.String(128))


class PdnsUser(UserMixin, db.Model):
    __tablename__ = "user"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True)
    password = db.Column(db.String(255))  # bcrypt hash
    firstname = db.Column(db.String(64))
    lastname = db.Column(db.String(64))
    email = db.Column(db.String(128), unique=True)
    otp_secret = db.Column(db.String(64), nullable=True)
    role_id = db.Column(db.Integer, db.ForeignKey("role.id"))
    confirmed = db.Column(db.SmallInteger, default=0)

    role = db.relationship("PdnsRole", backref="users")

    @property
    def is_admin(self):
        return self.role is not None and self.role.name == "Administrator"

    @property
    def has_2fa(self):
        return bool(self.otp_secret)

    def verify_password(self, password: str) -> bool:
        import bcrypt as _bcrypt
        try:
            return _bcrypt.checkpw(
                password.encode("utf-8"),
                self.password.encode("utf-8")
            )
        except Exception:
            return False

    def verify_totp(self, code: str) -> bool:
        import pyotp
        if not self.otp_secret:
            return True
        totp = pyotp.TOTP(self.otp_secret)
        return totp.verify(code, valid_window=1)


class PdnsDomain(db.Model):
    """PowerDNS domain table — used to select which zones to allow per key."""
    __tablename__ = "domain"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255))
    type = db.Column(db.String(6))
