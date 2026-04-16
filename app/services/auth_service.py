import secrets
import hashlib
from typing import Optional, Tuple
from app import db
from app.models.api_key import ApiKey, ApiKeyDomainAllowlist, ApiKeyIpAllowlist
from app.utils.ip_utils import is_ip_in_allowlist


class AuthService:

    @staticmethod
    def generate_api_key() -> Tuple[str, str, str]:
        """
        Genereer een nieuwe API key.
        Returns: (full_key, key_hash, key_prefix)
        """
        prefix = "pda_live_"
        random_part = secrets.token_hex(16)  # 32 chars
        full_key = prefix + random_part
        key_hash = ApiKey.hash_key(full_key)
        key_prefix = prefix + random_part[:4]
        return full_key, key_hash, key_prefix

    @staticmethod
    def validate_api_key(api_key: str, client_ip: str) -> Tuple[bool, Optional[ApiKey], str]:
        """
        Valideer API key en IP adres.
        Returns: (is_valid, api_key_obj, error_message)
        """
        if not api_key:
            return False, None, "API key required"

        key_hash = ApiKey.hash_key(api_key)
        key_obj = ApiKey.query.filter_by(key_hash=key_hash).first()

        if not key_obj:
            return False, None, "Invalid API key"

        if not key_obj.is_active:
            return False, None, "API key has been revoked"

        # IP check
        ip_entries = [
            {"ip_address": entry.ip_address, "cidr_mask": entry.cidr_mask}
            for entry in key_obj.ip_allowlist.all()
        ]

        if not is_ip_in_allowlist(client_ip, ip_entries):
            return False, None, "IP address not allowed for this API key"

        return True, key_obj, ""

    @staticmethod
    def check_domain_access(api_key_id: int, domain_id: int) -> bool:
        """Check of API key toegang heeft tot dit domain."""
        entry = ApiKeyDomainAllowlist.query.filter_by(
            api_key_id=api_key_id,
            domain_id=domain_id
        ).first()
        return entry is not None

    @staticmethod
    def get_allowed_domain_ids(api_key_id: int) -> list:
        """Haal lijst van toegestane domain_ids op voor een API key."""
        entries = ApiKeyDomainAllowlist.query.filter_by(api_key_id=api_key_id).all()
        return [e.domain_id for e in entries]
