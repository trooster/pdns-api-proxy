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
            "Accept": "application/json",
        }

    def _build_url(self, path: str) -> str:
        base = self.pdns_url.rstrip("/")
        path = path.lstrip("/")
        return f"{base}/{path}"

    def forward_request(
        self,
        method: str,
        path: str,
        json_data: Optional[Dict] = None,
        params: Optional[Dict] = None,
    ) -> Tuple[int, Any, str]:
        """
        Stuur request door naar PDNS API.
        Returns: (status_code, response_json_or_none, error_message)
        """
        url = self._build_url(path)
        try:
            response = requests.request(
                method=method,
                url=url,
                headers=self._get_headers(),
                json=json_data,
                params=params,
                timeout=self.timeout,
            )
            try:
                data = response.json()
            except Exception:
                data = {"raw": response.text} if response.text else None
            return response.status_code, data, ""
        except requests.Timeout:
            return 502, None, "Upstream DNS server timeout"
        except requests.ConnectionError:
            return 502, None, "Upstream DNS server unavailable"
        except Exception as e:
            return 502, None, f"Upstream error: {str(e)}"
