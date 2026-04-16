# PDNS API Proxy - Implementation Plan

> **Deze plan is modulair opgezet: elke milestone is zelfstandig uitvoerbaar.**
> **Lees alleen de milestone die je gaat implementeren, niet alles tegelijk.**

**Project:** `~/code/pdns-api-proxy/`  
**Design doc:** `docs/superpowers/specs/2026-04-12-pdns-api-proxy-design.md`

---

## Milestone M1: Project Setup & Database Migration

**Doel:** Flask app met health endpoint + database migration voor nieuwe tabellen.

### Stap 1: Create project structure

```bash
cd ~/code/pdns-api-proxy
mkdir -p app/models app/services app/routes app/utils migrations tests
touch app/__init__.py app/models/__init__.py app/services/__init__.py app/routes/__init__.py app/utils/__init__.py tests/__init__.py
```

### Stap 2: Create `.env.example`

```bash
cat > ~/code/pdns-api-proxy/.env.example << 'EOF'
DATABASE_URL=mysql+pymysql://powerdnsadmin:password@localhost:3306/powerdnsadmin
PDNS_API_URL=http://127.0.0.1:8081
PDNS_API_KEY=your-pdns-api-key-here
SECRET_KEY=change-me-in-production
FLASK_ENV=development
EOF
```

### Stap 3: Create `requirements.txt`

```txt
Flask>=3.0.0
Flask-SQLAlchemy>=3.1.0
Flask-Login>=0.6.0
PyMySQL>=1.1.0
requests>=2.31.0
python-dotenv>=1.0.0
cryptography>=41.0.0
```

### Stap 4: Create `migrations/001_create_api_tables.sql`

```sql
-- Migration: Create API keys, allowlists, and audit log tables
-- Run this against the PowerDNS-Admin MySQL database

CREATE TABLE IF NOT EXISTS `api_keys` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `key_hash` VARCHAR(64) NOT NULL UNIQUE,
    `key_prefix` VARCHAR(12) NOT NULL,
    `description` VARCHAR(255),
    `pdns_user_id` INT NOT NULL,
    `is_active` TINYINT(1) NOT NULL DEFAULT 1,
    `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `created_by` INT NOT NULL,
    INDEX `idx_pdns_user_id` (`pdns_user_id`),
    INDEX `idx_is_active` (`is_active`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS `api_key_domain_allowlist` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `api_key_id` INT NOT NULL,
    `domain_id` INT NOT NULL,
    UNIQUE KEY `uk_api_key_domain` (`api_key_id`, `domain_id`),
    INDEX `idx_api_key_id` (`api_key_id`),
    CONSTRAINT `fk_api_key_domain_key` FOREIGN KEY (`api_key_id`) REFERENCES `api_keys`(`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS `api_key_ip_allowlist` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `api_key_id` INT NOT NULL,
    `ip_address` VARCHAR(45) NOT NULL,
    `cidr_mask` INT DEFAULT NULL,
    INDEX `idx_api_key_id` (`api_key_id`),
    CONSTRAINT `fk_api_key_ip_key` FOREIGN KEY (`api_key_id`) REFERENCES `api_keys`(`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS `audit_logs` (
    `id` BIGINT AUTO_INCREMENT PRIMARY KEY,
    `api_key_id` INT NOT NULL,
    `method` VARCHAR(10) NOT NULL,
    `path` VARCHAR(500) NOT NULL,
    `request_body` TEXT,
    `response_status` INT NOT NULL,
    `client_ip` VARCHAR(45) NOT NULL,
    `user_agent` VARCHAR(255),
    `timestamp` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX `idx_api_key_id` (`api_key_id`),
    INDEX `idx_timestamp` (`timestamp`),
    CONSTRAINT `fk_audit_api_key` FOREIGN KEY (`api_key_id`) REFERENCES `api_keys`(`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
```

### Stap 5: Create `app/config.py`

```python
import os
from dotenv import load_dotenv

load_dotenv()


class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-change-me")
    SQLALCHEMY_DATABASE_URI = os.getenv("DATABASE_URL")
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # PowerDNS settings
    PDNS_API_URL = os.getenv("PDNS_API_URL", "http://127.0.0.1:8081")
    PDNS_API_KEY = os.getenv("PDNS_API_KEY", "")
```

### Stap 6: Create `app/__init__.py`

```python
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from app.config import Config

db = SQLAlchemy()


def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)
    
    db.init_app(app)
    
    from app.routes import health
    app.register_blueprint(health.bp)
    
    return app
```

### Stap 7: Create `app/routes/health.py`

```python
from flask import Blueprint, jsonify

bp = Blueprint("health", __name__)


@bp.route("/ping")
def ping():
    return jsonify({"status": "ok"})


@bp.route("/health")
def health():
    return jsonify({"status": "healthy"})
```

### Stap 8: Create `run.py`

```python
from app import create_app

app = create_app()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
```

### Stap 9: Verify

```bash
cd ~/code/pdns-api-proxy
source venv/bin/activate  # als je al een venv hebt
pip install -r requirements.txt
python run.py &
sleep 2
curl http://localhost:5000/ping
curl http://localhost:5000/health
```

Verwachte output:
```json
{"status": "ok"}
{"status": "healthy"}
```

### Stap 10: Commit

```bash
git add -A
git commit -m "M1: Project setup met Flask app en health endpoints"
```
