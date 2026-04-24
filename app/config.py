import os
from dotenv import load_dotenv

load_dotenv()


def _env_bool(name: str, default: bool) -> bool:
    val = os.getenv(name)
    if val is None:
        return default
    return val.strip().lower() in ("1", "true", "yes", "on")


class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-change-me")
    SQLALCHEMY_DATABASE_URI = os.getenv("DATABASE_URL")
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    PDNS_API_URL = os.getenv("PDNS_API_URL", "http://127.0.0.1:8081")
    PDNS_API_KEY = os.getenv("PDNS_API_KEY", "")

    # Aantal trusted reverse proxies voor X-Forwarded-For verwerking.
    # Stel in op het aantal load balancers/proxies voor deze app.
    # 0 = geen proxy (gebruik remote_addr direct, X-Forwarded-For wordt genegeerd).
    PROXY_COUNT = int(os.getenv("PROXY_COUNT", "1"))

    # Session-cookie hardening. Secure is standaard True omdat de app in
    # productie altijd achter Caddy (HTTPS) draait; voor een lokale dev-server
    # zonder TLS kan `SESSION_COOKIE_SECURE=false` in .env worden gezet.
    SESSION_COOKIE_SECURE = _env_bool("SESSION_COOKIE_SECURE", True)
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    REMEMBER_COOKIE_SECURE = _env_bool("REMEMBER_COOKIE_SECURE", True)
    REMEMBER_COOKIE_HTTPONLY = True
    REMEMBER_COOKIE_SAMESITE = "Lax"
