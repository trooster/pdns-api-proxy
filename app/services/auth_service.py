import secrets
from typing import Optional, Tuple
from argon2 import PasswordHasher

from app import db
from app.models.api_key import ApiKey, ApiKeyIpAllowlist
from app.utils.ip_utils import is_ip_in_allowlist


# Sentinel hash gebruikt om timing te nivelleren wanneer er geen kandidaat is.
# De waarde is irrelevant; het doel is ervoor te zorgen dat argon2id altijd
# precies één verify-aanroep doet per auth-poging (CWE-208 defence-in-depth).
_TIMING_DUMMY_HASH = PasswordHasher().hash("pda_live_timing_dummy")

# Length of the key_prefix column — "pda_live_" (9) + first 4 hex chars.
_PREFIX_LEN = 13


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

        Gebruikt de opgeslagen `key_prefix` kolom voor een O(1) lookup in
        plaats van een lineaire scan door alle actieve sleutels. Daardoor:
          1. Verdwijnt de timing-side-channel die het totale aantal actieve
             sleutels lekte (elke argon2id-verify duurt ~100ms).
          2. Schaalt authenticatie niet langer lineair met het aantal keys.

        Timing wordt aanvullend genivelleerd door ook bij een cache-miss een
        argon2id-verify tegen een dummy-hash uit te voeren, zodat de paden
        "geldig formaat maar onbekend" en "ongeldig formaat" niet meer
        onderscheidbaar zijn.

        Returns: (is_valid, api_key_obj, error_message)
        """
        if not api_key:
            return False, None, "API key required"

        key_prefix = api_key[:_PREFIX_LEN]
        candidates = ApiKey.query.filter_by(
            key_prefix=key_prefix, is_active=True
        ).all()

        matched: Optional[ApiKey] = None
        for candidate in candidates:
            if ApiKey.verify_key(api_key, candidate.key_hash):
                matched = candidate
                break

        if matched is None:
            # Equaliseer timing met het "candidate gevonden maar verkeerde
            # hash" pad — altijd minstens één argon2id-verify uitvoeren.
            if not candidates:
                ApiKey.verify_key(api_key, _TIMING_DUMMY_HASH)
            return False, None, "Invalid API key"

        # IP check
        ip_entries = [
            {"ip_address": entry.ip_address, "cidr_mask": entry.cidr_mask}
            for entry in matched.ip_allowlist.all()
        ]

        if not is_ip_in_allowlist(client_ip, ip_entries):
            return False, None, "IP address not allowed for this API key"

        return True, matched, ""

    @staticmethod
    def check_domain_access(account_id: int, zone_id: str) -> bool:
        """
        Check of de zone gekoppeld is aan het account van de API key.
        zone_id is de PDNS zone-ID, bijv. 'example.com.' (met trailing dot).
        """
        from app.models.pdns_admin import PdnsDomain
        zone_name = zone_id.rstrip(".").lower()
        domain = PdnsDomain.query.filter_by(name=zone_name, account_id=account_id).first()
        return domain is not None

    @staticmethod
    def get_allowed_domains(account_id: int):
        """Haal alle domeinen op die gekoppeld zijn aan dit account in PowerDNS-Admin."""
        from app.models.pdns_admin import PdnsDomain
        return PdnsDomain.query.filter_by(account_id=account_id).all()
