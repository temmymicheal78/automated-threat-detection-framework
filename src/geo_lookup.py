"""Geographic and ASN enrichment for attacker IPs.

Uses ip-api.com (free, no API key required) to look up:
- Country / region / city
- ASN (Autonomous System Number)
- ISP and organisation

Results are cached to minimise external calls. Free tier allows ~45 requests/min.
"""

from __future__ import annotations

import ipaddress
import logging
import secrets
from dataclasses import dataclass, field
from threading import Lock
from typing import Optional

import requests

logger = logging.getLogger(__name__)


@dataclass
class GeoInfo:
    ip_address: str
    country: str = ""
    country_code: str = ""
    region: str = ""
    city: str = ""
    asn: str = ""
    isp: str = ""
    organization: str = ""
    from_cache: bool = False
    api_error: bool = False


class GeoLookupClient:
    """Enrich an IP with geographic + ASN data via ip-api.com."""

    BASE_URL = "http://ip-api.com/json"

    def __init__(self, timeout: float = 5.0) -> None:
        self._timeout = timeout
        self._cache: dict[str, GeoInfo] = {}
        self._lock: Lock = Lock()

    def lookup(self, ip_address: str) -> GeoInfo:
        """Return GeoInfo for *ip_address*, caching results."""
        # Private / loopback / link-local IPs are never in the geolocation db
        try:
            addr = ipaddress.ip_address(ip_address)
            if addr.is_private or addr.is_loopback or addr.is_link_local:
                return GeoInfo(
                    ip_address=ip_address,
                    country="Private Network",
                    country_code="--",
                    region="LAN",
                    city="Internal",
                    asn="N/A",
                    isp="Private",
                    organization="Internal network",
                )
        except ValueError:
            return self._safe_default(ip_address)

        with self._lock:
            if ip_address in self._cache:
                cached = self._cache[ip_address]
                return GeoInfo(
                    ip_address=cached.ip_address,
                    country=cached.country,
                    country_code=cached.country_code,
                    region=cached.region,
                    city=cached.city,
                    asn=cached.asn,
                    isp=cached.isp,
                    organization=cached.organization,
                    from_cache=True,
                    api_error=cached.api_error,
                )

        try:
            params = {"fields": "status,country,countryCode,regionName,city,isp,org,as"}
            response = requests.get(
                f"{self.BASE_URL}/{ip_address}",
                params=params,
                timeout=self._timeout,
            )
        except requests.RequestException as exc:
            logger.warning("Geo lookup network error for %s: %s", ip_address, exc)
            return self._safe_default(ip_address)

        if response.status_code != 200:
            logger.warning("Geo lookup returned %s for %s", response.status_code, ip_address)
            return self._safe_default(ip_address)

        try:
            data = response.json()
        except ValueError as exc:
            logger.warning("Geo lookup JSON parse error for %s: %s", ip_address, exc)
            return self._safe_default(ip_address)

        if data.get("status") != "success":
            logger.debug("Geo lookup unsuccessful for %s: %s", ip_address, data.get("message"))
            return self._safe_default(ip_address)

        info = GeoInfo(
            ip_address=ip_address,
            country=data.get("country", "") or "",
            country_code=data.get("countryCode", "") or "",
            region=data.get("regionName", "") or "",
            city=data.get("city", "") or "",
            asn=data.get("as", "") or "",
            isp=data.get("isp", "") or "",
            organization=data.get("org", "") or "",
        )

        with self._lock:
            self._cache[ip_address] = info

        return info

    def _safe_default(self, ip_address: str) -> GeoInfo:
        """Return a permissive default on API failure — fail open."""
        return GeoInfo(
            ip_address=ip_address,
            country="Unknown",
            country_code="",
            region="",
            city="",
            asn="",
            isp="",
            organization="",
            api_error=True,
        )

    @property
    def cache_size(self) -> int:
        with self._lock:
            return len(self._cache)


def generate_session_id() -> str:
    """Generate a short, unique identifier for a detection session (8 hex chars)."""
    return secrets.token_hex(4)
