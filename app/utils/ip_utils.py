import ipaddress
from typing import List, Optional


def is_ip_in_allowlist(client_ip: str, allowlist: List[dict]) -> bool:
    """
    Check of client_ip matches any entry in de IP allowlist.

    allowlist: list van dicts met 'ip_address' en optioneel 'cidr_mask'
    """
    if not allowlist:
        return True  # Lege allowlist = alles toegestaan

    client = ipaddress.ip_address(client_ip)

    for entry in allowlist:
        if entry.get('cidr_mask'):
            # CIDR check
            network = ipaddress.ip_network(
                f"{entry['ip_address']}/{entry['cidr_mask']}",
                strict=False
            )
            if client in network:
                return True
        else:
            # Exact match
            if str(client) == entry['ip_address']:
                return True

    return False
