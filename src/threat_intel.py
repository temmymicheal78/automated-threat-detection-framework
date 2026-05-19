"""Additional threat intelligence sources — VirusTotal and AlienVault OTX.

These clients follow the same interface pattern as AbuseIPDBClient:
each has a check_ip(ip) method returning an IPReputationResult.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Optional

import requests

from src.config import Config

logger = logging.getLogger(__name__)


@dataclass
class ThreatIntelResult:
    """Unified result from any threat intelligence source."""
    ip_address: str
    source: str               # "virustotal", "alienvault", "abuseipdb"
    threat_score: int          # 0-100 normalised score
    is_malicious: bool
    total_reports: int
    country_code: str
    tags: list[str]            # e.g. ["malware", "botnet", "brute-force"]
    raw_data: dict             # original API response for debugging
    from_cache: bool = False
    api_error: bool = False


# ---------------------------------------------------------------------------
# VirusTotal Client
# ---------------------------------------------------------------------------

class VirusTotalClient:
    """Query VirusTotal IP address reports (v3 API).

    Free tier: 500 lookups/day, 4 per minute.
    Docs: https://docs.virustotal.com/reference/ip-info
    """

    API_BASE = "https://www.virustotal.com/api/v3"

    def __init__(self, api_key: str) -> None:
        self._api_key = api_key
        self._cache: dict[str, ThreatIntelResult] = {}

    def check_ip(self, ip_address: str) -> ThreatIntelResult:
        if ip_address in self._cache:
            result = self._cache[ip_address]
            return ThreatIntelResult(
                ip_address=result.ip_address,
                source=result.source,
                threat_score=result.threat_score,
                is_malicious=result.is_malicious,
                total_reports=result.total_reports,
                country_code=result.country_code,
                tags=result.tags,
                raw_data=result.raw_data,
                from_cache=True,
                api_error=result.api_error,
            )

        result = self._make_request(ip_address)
        self._cache[ip_address] = result
        return result

    def _make_request(self, ip_address: str) -> ThreatIntelResult:
        url = f"{self.API_BASE}/ip_addresses/{ip_address}"
        headers = {"x-apikey": self._api_key}

        try:
            resp = requests.get(url, headers=headers, timeout=10)
        except requests.RequestException as exc:
            logger.warning("VirusTotal network error for %s: %s", ip_address, exc)
            return self._safe_default(ip_address)

        if resp.status_code == 200:
            return self._parse_response(resp.json(), ip_address)

        if resp.status_code == 429:
            logger.warning("VirusTotal rate limit hit for %s", ip_address)
        elif resp.status_code == 401:
            logger.warning("VirusTotal 401 Unauthorized — check API key")
        else:
            logger.warning("VirusTotal returned %s for %s", resp.status_code, ip_address)

        return self._safe_default(ip_address)

    def _parse_response(self, data: dict, ip_address: str) -> ThreatIntelResult:
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})

        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total = sum(stats.values()) if stats else 1

        # Normalise to 0-100 score
        threat_score = min(100, int(((malicious + suspicious) / max(total, 1)) * 100))

        tags = []
        if malicious > 0:
            tags.append("malicious")
        if suspicious > 0:
            tags.append("suspicious")

        return ThreatIntelResult(
            ip_address=ip_address,
            source="virustotal",
            threat_score=threat_score,
            is_malicious=malicious > 0,
            total_reports=malicious + suspicious,
            country_code=attrs.get("country", ""),
            tags=tags,
            raw_data={"last_analysis_stats": stats},
            from_cache=False,
            api_error=False,
        )

    def _safe_default(self, ip_address: str) -> ThreatIntelResult:
        return ThreatIntelResult(
            ip_address=ip_address,
            source="virustotal",
            threat_score=0,
            is_malicious=False,
            total_reports=0,
            country_code="",
            tags=[],
            raw_data={},
            api_error=True,
        )

    @property
    def cache_size(self) -> int:
        return len(self._cache)


# ---------------------------------------------------------------------------
# AlienVault OTX Client
# ---------------------------------------------------------------------------

class AlienVaultOTXClient:
    """Query AlienVault OTX for IP reputation (v1 API).

    Free tier: unlimited lookups.
    Docs: https://otx.alienvault.com/assets/static/external_api.html
    """

    API_BASE = "https://otx.alienvault.com/api/v1"

    def __init__(self, api_key: str) -> None:
        self._api_key = api_key
        self._cache: dict[str, ThreatIntelResult] = {}

    def check_ip(self, ip_address: str) -> ThreatIntelResult:
        if ip_address in self._cache:
            result = self._cache[ip_address]
            return ThreatIntelResult(
                ip_address=result.ip_address,
                source=result.source,
                threat_score=result.threat_score,
                is_malicious=result.is_malicious,
                total_reports=result.total_reports,
                country_code=result.country_code,
                tags=result.tags,
                raw_data=result.raw_data,
                from_cache=True,
                api_error=result.api_error,
            )

        result = self._make_request(ip_address)
        self._cache[ip_address] = result
        return result

    def _make_request(self, ip_address: str) -> ThreatIntelResult:
        url = f"{self.API_BASE}/indicators/IPv4/{ip_address}/general"
        headers = {"X-OTX-API-KEY": self._api_key}

        try:
            resp = requests.get(url, headers=headers, timeout=10)
        except requests.RequestException as exc:
            logger.warning("AlienVault OTX network error for %s: %s", ip_address, exc)
            return self._safe_default(ip_address)

        if resp.status_code == 200:
            return self._parse_response(resp.json(), ip_address)

        if resp.status_code == 403:
            logger.warning("AlienVault OTX 403 Forbidden — check API key")
        else:
            logger.warning("AlienVault OTX returned %s for %s", resp.status_code, ip_address)

        return self._safe_default(ip_address)

    def _parse_response(self, data: dict, ip_address: str) -> ThreatIntelResult:
        pulse_count = data.get("pulse_info", {}).get("count", 0)
        country = data.get("country_code", "")
        reputation = data.get("reputation", 0)

        # Normalise: pulse_count maps roughly to threat level
        # 0 pulses = 0, 1-2 = 30, 3-5 = 60, 6+ = 90
        if pulse_count == 0:
            threat_score = 0
        elif pulse_count <= 2:
            threat_score = 30
        elif pulse_count <= 5:
            threat_score = 60
        else:
            threat_score = min(100, 70 + pulse_count * 2)

        tags = []
        pulses = data.get("pulse_info", {}).get("pulses", [])
        for pulse in pulses[:5]:
            tags.extend(pulse.get("tags", []))
        tags = list(set(tags))[:10]  # deduplicate, limit to 10

        return ThreatIntelResult(
            ip_address=ip_address,
            source="alienvault",
            threat_score=threat_score,
            is_malicious=pulse_count > 0,
            total_reports=pulse_count,
            country_code=country,
            tags=tags,
            raw_data={"pulse_count": pulse_count, "reputation": reputation},
            from_cache=False,
            api_error=False,
        )

    def _safe_default(self, ip_address: str) -> ThreatIntelResult:
        return ThreatIntelResult(
            ip_address=ip_address,
            source="alienvault",
            threat_score=0,
            is_malicious=False,
            total_reports=0,
            country_code="",
            tags=[],
            raw_data={},
            api_error=True,
        )

    @property
    def cache_size(self) -> int:
        return len(self._cache)


# ---------------------------------------------------------------------------
# Mock Threat Intel Client (for lab/testing)
# ---------------------------------------------------------------------------

class MockThreatIntelClient:
    """Returns realistic threat scores for known lab attacker IPs.

    In the lab, private IPs like 10.0.0.20 won't appear in any real database.
    This mock simulates what a real API would return for a known attacker.
    """

    # Default attacker IPs in the lab get high scores
    DEFAULT_ATTACKERS: dict[str, int] = {
        "10.0.0.20": 95,       # Kali attacker
        "192.168.56.20": 95,   # Kali (host-only)
    }

    def __init__(
        self,
        source: str = "mock",
        known_ips: Optional[dict[str, int]] = None,
    ) -> None:
        self._source = source
        self._known_ips: dict[str, int] = {**self.DEFAULT_ATTACKERS}
        if known_ips:
            self._known_ips.update(known_ips)

    def check_ip(self, ip_address: str) -> ThreatIntelResult:
        score = self._known_ips.get(ip_address, 0)
        return ThreatIntelResult(
            ip_address=ip_address,
            source=self._source,
            threat_score=score,
            is_malicious=score > 50,
            total_reports=score // 10,
            country_code="XX" if score > 0 else "",
            tags=["brute-force", "ssh"] if score > 50 else [],
            raw_data={"mock": True},
            from_cache=False,
            api_error=False,
        )

    @property
    def cache_size(self) -> int:
        return 0
