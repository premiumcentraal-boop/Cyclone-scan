"""Fleet intelligence (Run 12): patterns across devices rather than within one.

Device farms and mule networks look normal one device at a time. They stand
out as bursts: many enrollments from one network block, many enrollments of
the same model/patch/key-type cohort in a short window, many distinct devices
acting from one network.

Privacy: client IP addresses are never stored. Only a keyed hash of the
network block (/24 for IPv4, /48 for IPv6) is kept, so fraud teams can see
that devices share a network without learning the address.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import logging
import secrets

log = logging.getLogger("device_trust.fleet")


class NetworkHasher:
    def __init__(self, key: str | None):
        if not key:
            # Works, but hashes change on restart, so fleet history resets.
            log.warning("fleet_hash_key not set: using a random per-process key")
            key = secrets.token_hex(32)
        self._key = key.encode()

    def network_key(self, ip: str | None) -> str | None:
        """Keyed hash of the IP's network block, or None for missing/invalid input."""
        if not ip:
            return None
        try:
            addr = ipaddress.ip_address(ip.strip())
        except ValueError:
            return None
        if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
            addr = addr.ipv4_mapped
        prefix = 24 if addr.version == 4 else 48
        block = ipaddress.ip_network(f"{addr}/{prefix}", strict=False)
        return hmac.new(self._key, str(block).encode(), hashlib.sha256).hexdigest()[:32]


def cohort_key(evidence: dict, reported: dict | None = None) -> str | None:
    """Model + attested patch + key provenance: the shape a batch of farm phones shares."""
    ids = evidence.get("attested_ids") or {}
    model = ids.get("model") or (reported or {}).get("model")
    patch = evidence.get("os_patch_level")
    if not model or not patch:
        return None
    return f"{model.lower()}|{patch}|{evidence.get('chain_type', 'UNKNOWN')}"
