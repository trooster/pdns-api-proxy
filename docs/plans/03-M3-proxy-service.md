# Milestone M3: Proxy Service (PDNS API Forwarding)

**Start vanuit:** `~/code/pdns-api-proxy/` (M1 + M2 moeten geïnstalleerd zijn)

**Nieuwe bestanden te maken:**

---

## `app/services/proxy_service.py`

```python
import requests
from typing import Optional, Dict, Any, Tuple
from flask import current_app


class ProxyService:
    
    def __init__(self):
        self.pdns_url = current_app.config.get("PDNS_API_URL", "http://127.0.0.1:8081")
        self.pdns_api_key = current_app.config.get("PDNS_API_KEY", "")
        self.timeout = 10
    
    def _get_headers(self) -> Dict[str, str]:
        return {
            "X-API-Key": self.pdns_api_key,
            "Content-Type": "application/json",
            "Accept": "application/json"
        }
    
    def _build_url(self, path: str) -> str:
        """Build full PDNS API URL."""
        base = self.pdns_url.rstrip("/")
        path = path.lstrip("/")
        return f"{base}/{path}"
    
    def forward_request(
        self, 
        method: str, 
        path: str, 
        domain_id: Optional[int] = None,
        json_data: Optional[Dict] = None,
        params: Optional[Dict] = None
    ) -> Tuple[int, Dict[str, Any], str]:
        """
        Forward request naar PDNS API.
        
        Returns: (status_code, response_json, error_message)
        """
        url = self._build_url(path)
        headers = self._get_headers()
        
        try:
            response = requests.request(
                method=method,
                url=url,
                headers=headers,
                json=json_data,
                params=params,
                timeout=self.timeout
            )
            
            try:
                response_json = response.json()
            except:
                response_json = {"raw": response.text}
            
            return response.status_code, response_json, ""
            
        except requests.Timeout:
            return 502, {}, "Upstream DNS server timeout"
        except requests.ConnectionError:
            return 502, {}, "Upstream DNS server unavailable"
        except Exception as e:
            return 502, {}, f"Upstream error: {str(e)}"
    
    def get_zone(self, zone_id: int) -> Tuple[int, Dict, str]:
        """Haal zone details op van PDNS."""
        return self.forward_request("GET", f"/api/v1/zones/{zone_id}")
    
    def list_zones(self) -> Tuple[int, Dict, str]:
        """Haal alle zones op van PDNS."""
        return self.forward_request("GET", "/api/v1/zones")
    
    def get_records(self, zone_id: int) -> Tuple[int, Dict, str]:
        """Haal alle records in een zone op."""
        return self.forward_request("GET", f"/api/v1/zones/{zone_id}/records")
    
    def create_record(self, zone_id: int, record_data: Dict) -> Tuple[int, Dict, str]:
        """Voeg record toe aan zone."""
        return self.forward_request("POST", f"/api/v1/zones/{zone_id}/records", json_data=record_data)
    
    def update_record(self, zone_id: int, record_id: str, record_data: Dict) -> Tuple[int, Dict, str]:
        """Wijzig record in zone."""
        return self.forward_request("PATCH", f"/api/v1/zones/{zone_id}/records/{record_id}", json_data=record_data)
    
    def delete_record(self, zone_id: int, record_id: str) -> Tuple[int, Dict, str]:
        """Verwijder record uit zone."""
        return self.forward_request("DELETE", f"/api/v1/zones/{zone_id}/records/{record_id}")
    
    def update_zone(self, zone_id: int, zone_data: Dict) -> Tuple[int, Dict, str]:
        """Wijzig zone instellingen."""
        return self.forward_request("PATCH", f"/api/v1/zones/{zone_id}", json_data=zone_data)
```

---

## `app/services/audit_service.py`

```python
from datetime import datetime
from app import db
from app.models.audit_log import AuditLog


class AuditService:
    
    @staticmethod
    def log(
        api_key_id: int,
        method: str,
        path: str,
        request_body: str,
        response_status: int,
        client_ip: str,
        user_agent: str
    ):
        """Log een API request naar audit_logs."""
        log_entry = AuditLog(
            api_key_id=api_key_id,
            method=method,
            path=path,
            request_body=request_body,
            response_status=response_status,
            client_ip=client_ip,
            user_agent=user_agent,
            timestamp=datetime.utcnow()
        )
        db.session.add(log_entry)
        db.session.commit()
```

---

## `app/routes/proxy.py` (decorator voor auth)

```python
from functools import wraps
from flask import request, jsonify, g
from app.services.auth_service import AuthService


def require_api_key(f):
    """Decorator die API key authenticatie afdwingt."""
    @wraps(f)
    def decorated(*args, **kwargs):
        api_key = request.headers.get("X-API-Key", "")
        client_ip = request.headers.get("X-Forwarded-For", request.remote_addr)
        if "," in client_ip:
            client_ip = client_ip.split(",")[0].strip()
        
        is_valid, key_obj, error = AuthService.validate_api_key(api_key, client_ip)
        
        if not is_valid:
            return jsonify({"error": error}), 401
        
        # Sla key_obj op in flask.g voor gebruik in route
        g.api_key = key_obj
        g.client_ip = client_ip
        
        return f(*args, **kwargs)
    return decorated


def require_domain_access(domain_id_param: str = "zone_id"):
    """Decorator die domain access control afdwingt."""
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            zone_id = kwargs.get(domain_id_param)
            if zone_id:
                # Check of API key toegang heeft tot dit domain
                if not AuthService.check_domain_access(g.api_key.id, zone_id):
                    return jsonify({"error": "Access denied to this domain"}), 403
            return f(*args, **kwargs)
        return decorated
    return decorator
```

---

## Tests: `tests/test_proxy_service.py`

```python
import pytest
from unittest.mock import patch, MagicMock
from app import create_app, db


@pytest.fixture
def app():
    app = create_app()
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
    app.config["TESTING"] = True
    app.config["PDNS_API_URL"] = "http://127.0.0.1:8081"
    app.config["PDNS_API_KEY"] = "test-key"
    with app.app_context():
        db.create_all()
        yield app
        db.drop_all()


def test_proxy_service_forward_get():
    with patch("requests.request") as mock_request:
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"zones": []}
        mock_request.return_value = mock_response
        
        from app.services.proxy_service import ProxyService
        with app.app_context():
            service = ProxyService()
            status, data, error = service.forward_request("GET", "/api/v1/zones")
            
            assert status == 200
            assert data == {"zones": []}
            assert error == ""


def test_proxy_service_timeout():
    import requests
    with patch("requests.request") as mock_request:
        mock_request.side_effect = requests.Timeout()
        
        from app.services.proxy_service import ProxyService
        with app.app_context():
            service = ProxyService()
            status, data, error = service.forward_request("GET", "/api/v1/zones")
            
            assert status == 502
            assert "timeout" in error


def test_audit_service_log():
    from app.services.audit_service import AuditService
    from app.models.audit_log import AuditLog
    
    with app.app_context():
        # Eerst een fake API key aanmaken (vereist voor FK)
        from app.models.api_key import ApiKey
        import hashlib
        key = ApiKey(
            key_hash=hashlib.sha256(b"test").hexdigest(),
            key_prefix="pda_test",
            pdns_user_id=1,
            created_by=1
        )
        db.session.add(key)
        db.session.commit()
        
        AuditService.log(
            api_key_id=key.id,
            method="GET",
            path="/api/v1/zones",
            request_body=None,
            response_status=200,
            client_ip="127.0.0.1",
            user_agent="TestClient/1.0"
        )
        
        log = AuditLog.query.first()
        assert log is not None
        assert log.method == "GET"
        assert log.response_status == 200
```

---

## Run tests

```bash
cd ~/code/pdns-api-proxy
source venv/bin/activate
pytest tests/test_proxy_service.py -v
```

---

## Commit

```bash
git add -A
git commit -m "M3: Proxy service voor PDNS API forwarding"
```
