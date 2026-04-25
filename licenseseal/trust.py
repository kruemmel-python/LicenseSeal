"""
LicenseSeal Trust Infrastructure Module
=======================================
Provides decentralized public key discovery via DNS and .well-known endpoints.
"""

from __future__ import annotations

import json
import socket
import urllib.request
import urllib.parse
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


# DNS TXT record prefix for LicenseSeal keys
DNS_PREFIX = "_licenseseal"
WELL_KNOWN_PATH = "/.well-known/licenseseal-keys.json"


@dataclass
class DiscoveredKey:
    """Represents a discovered public key."""
    key_id: str
    public_key_pem: str
    owner: str
    domain: str
    discovered_via: str  # "dns" or "well-known"
    discovered_at: str
    expires_at: Optional[str] = None


class TrustDiscovery:
    """Decentralized trust infrastructure for public key discovery."""

    def __init__(self, cache_dir: Path | None = None):
        self.cache_dir = cache_dir
        self._cache: dict[str, DiscoveredKey] = {}

    def fetch_public_key(self, domain: str, use_cache: bool = True) -> Optional[DiscoveredKey]:
        """
        Fetch public key for a domain using multiple discovery methods.
        
        Tries in order:
        1. .well-known HTTPS endpoint
        2. DNS TXT records
        """
        if use_cache and domain in self._cache:
            return self._cache[domain]

        # Try .well-known first (more secure - HTTPS)
        key = self._fetch_well_known(domain)
        if key:
            self._cache[domain] = key
            return key

        # Fallback to DNS
        key = self._fetch_dns_txt(domain)
        if key:
            self._cache[domain] = key
            return key

        return None

    def _fetch_well_known(self, domain: str) -> Optional[DiscoveredKey]:
        """Fetch public key from .well-known HTTPS endpoint."""
        url = f"https://{domain}{WELL_KNOWN_PATH}"

        try:
            # Create request with timeout
            req = urllib.request.Request(
                url,
                headers={
                    "User-Agent": "LicenseSeal/1.0",
                    "Accept": "application/json",
                },
            )

            with urllib.request.urlopen(req, timeout=10) as response:
                if response.status != 200:
                    return None

                data = json.loads(response.read().decode("utf-8"))
                return self._parse_well_known_response(data, domain)

        except Exception:
            return None

    def _parse_well_known_response(self, data: dict, domain: str) -> Optional[DiscoveredKey]:
        """Parse response from .well-known endpoint."""
        keys = data.get("keys", [])
        if not keys:
            return None

        # Use the first key for now
        key_data = keys[0]

        return DiscoveredKey(
            key_id=key_data.get("keyId", ""),
            public_key_pem=key_data.get("publicKeyPem", ""),
            owner=key_data.get("owner", domain),
            domain=domain,
            discovered_via="well-known",
            discovered_at=data.get("discoveredAt", ""),
            expires_at=key_data.get("expiresAt"),
        )

    def _fetch_dns_txt(self, domain: str) -> Optional[DiscoveredKey]:
        """Fetch public key from DNS TXT records."""
        try:
            # Construct the TXT record name
            record_name = f"{DNS_PREFIX}.{domain}"

            # Use socket for DNS query
            resolver = socket.getaddrinfo(record_name, 0, socket.AF_INET, socket.SOCK_DGRAM)

            # Try to query TXT record using dnspython if available
            try:
                import dns.resolver
                answers = dns.resolver.resolve(record_name, "TXT")
                for rdata in answers:
                    txt = rdata.to_text().strip('"')
                    if txt.startswith("licenseseal="):
                        return self._parse_dns_txt(txt, domain)
            except ImportError:
                # Fallback: try using system dig command
                return self._fetch_dns_via_dig(domain)

        except Exception:
            return None

    def _fetch_dns_via_dig(self, domain: str) -> Optional[DiscoveredKey]:
        """Fallback: use dig command to fetch DNS TXT records."""
        import subprocess

        record_name = f"{DNS_PREFIX}.{domain}"

        try:
            result = subprocess.run(
                ["dig", "+short", "TXT", record_name],
                capture_output=True,
                text=True,
                timeout=5,
            )

            if result.returncode != 0:
                return None

            for line in result.stdout.strip().splitlines():
                if "licenseseal=" in line:
                    return self._parse_dns_txt(line, domain)

        except (FileNotFoundError, subprocess.TimeoutExpired):
            return None

        return None

    def _parse_dns_txt(self, txt: str, domain: str) -> Optional[DiscoveredKey]:
        """Parse DNS TXT record data."""
        # Format: licenseseal=base64(json)
        prefix = "licenseseal="
        if not txt.startswith(prefix):
            return None

        try:
            import base64
            json_str = base64.b64decode(txt[len(prefix):]).decode("utf-8")
            data = json.loads(json_str)

            return DiscoveredKey(
                key_id=data.get("keyId", ""),
                public_key_pem=data.get("publicKeyPem", ""),
                owner=data.get("owner", domain),
                domain=domain,
                discovered_via="dns",
                discovered_at=data.get("discoveredAt", ""),
                expires_at=data.get("expiresAt"),
            )
        except Exception:
            return None

    def clear_cache(self, domain: Optional[str] = None) -> None:
        """Clear cached keys."""
        if domain:
            self._cache.pop(domain, None)
        else:
            self._cache.clear()

    def get_cached_key(self, domain: str) -> Optional[DiscoveredKey]:
        """Get a cached key without fetching."""
        return self._cache.get(domain)


def create_well_known_file(
    output_path: Path,
    key_id: str,
    public_key_pem: str,
    owner: str,
    domains: list[str],
) -> None:
    """
    Create a .well-known/licenseseal-keys.json file for a domain.
    """
    data = {
        "schema": "licenseseal-keys.v1",
        "keys": [
            {
                "keyId": key_id,
                "publicKeyPem": public_key_pem,
                "owner": owner,
                "createdAt": "",
                "domains": domains,
            }
        ],
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(data, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )


def generate_dns_txt_record(
    key_id: str,
    public_key_pem: str,
    owner: str,
) -> str:
    """
    Generate a DNS TXT record value for LicenseSeal key discovery.
    """
    import base64
    import json
    from datetime import datetime, timezone

    data = {
        "keyId": key_id,
        "publicKeyPem": public_key_pem,
        "owner": owner,
        "discoveredAt": datetime.now(timezone.utc).isoformat(),
    }

    json_str = json.dumps(data, separators=(",", ":"))
    encoded = base64.b64encode(json_str.encode("utf-8")).decode("ascii")

    return f"licenseseal={encoded}"


def verify_key_for_domain(
    public_key_pem: str,
    domain: str,
    trust_discovery: Optional[TrustDiscovery] = None,
) -> bool:
    """
    Verify that a public key is associated with a domain.
    Uses the trust discovery infrastructure.
    """
    if trust_discovery is None:
        trust_discovery = TrustDiscovery()

    discovered = trust_discovery.fetch_public_key(domain, use_cache=False)

    if discovered is None:
        return False

    # Compare key IDs or full PEM
    if discovered.public_key_pem.strip() == public_key_pem.strip():
        return True

    return False


def create_trust_chain(
    domains: list[str],
    cache_dir: Path | None = None,
) -> list[DiscoveredKey]:
    """
    Create a trust chain by discovering keys for multiple domains.
    """
    trust = TrustDiscovery(cache_dir)
    chain: list[DiscoveredKey] = []

    for domain in domains:
        key = trust.fetch_public_key(domain)
        if key:
            chain.append(key)

    return chain