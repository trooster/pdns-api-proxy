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
            except Exception:
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
