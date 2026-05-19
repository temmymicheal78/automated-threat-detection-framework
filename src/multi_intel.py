"""Multi-source threat intelligence aggregator.

Queries multiple threat intel backends (AbuseIPDB, VirusTotal, AlienVault OTX)
and combines their results into a single IPReputationResult that the existing
DecisionEngine can consume — no changes needed to decision.py or firewall.py.
"""

from __future__ import annotations

import logging
from typing import Optional, Union

from src.config import Config
from src.api_client import (
    AbuseIPDBClient,
    MockAbuseIPDBClient,
    IPReputationResult,
)
from src.threat_intel import (
    VirusTotalClient,
    AlienVaultOTXClient,
    MockThreatIntelClient,
    ThreatIntelResult,
)

logger = logging.getLogger(__name__)


class MultiIntelAggregator:
    """Query multiple threat intel sources and return a combined IPReputationResult.

    The aggregated score is the **maximum** across all sources — if any source
    flags an IP as dangerous, the combined result reflects that.

    This class exposes the same ``check_ip()`` / ``cache_size`` interface that
    DecisionEngine already expects, so it can be used as a drop-in replacement
    for AbuseIPDBClient or MockAbuseIPDBClient.
    """

    def __init__(
        self,
        abuseipdb: Union[AbuseIPDBClient, MockAbuseIPDBClient],
        extra_sources: list[Union[VirusTotalClient, AlienVaultOTXClient, MockThreatIntelClient]] | None = None,
    ) -> None:
        self._abuseipdb = abuseipdb
        self._extra_sources = extra_sources or []

    def check_ip(self, ip_address: str) -> IPReputationResult:
        """Query all configured sources and return a merged IPReputationResult."""
        # 1. Always query AbuseIPDB (primary source)
        primary = self._abuseipdb.check_ip(ip_address)

        if not self._extra_sources:
            return primary

        # 2. Query extra sources, collect their scores
        extra_results: list[ThreatIntelResult] = []
        for source in self._extra_sources:
            try:
                result = source.check_ip(ip_address)
                extra_results.append(result)
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "Error querying %s for %s: %s",
                    type(source).__name__,
                    ip_address,
                    exc,
                )

        # 3. Aggregate: take the maximum score across all sources
        all_scores = [primary.abuse_confidence_score]
        all_reports = [primary.total_reports]
        all_tags: list[str] = []
        any_api_error = primary.api_error

        for r in extra_results:
            all_scores.append(r.threat_score)
            all_reports.append(r.total_reports)
            all_tags.extend(r.tags)
            if r.api_error:
                any_api_error = True

        max_score = max(all_scores)
        total_reports = sum(all_reports)

        # Build source summary for logging
        source_summary = f"abuseipdb={primary.abuse_confidence_score}"
        for r in extra_results:
            source_summary += f", {r.source}={r.threat_score}"

        if extra_results:
            logger.debug(
                "Multi-intel for %s: %s → combined=%d",
                ip_address,
                source_summary,
                max_score,
            )

        # 4. Return a combined IPReputationResult (compatible with DecisionEngine)
        return IPReputationResult(
            ip_address=ip_address,
            abuse_confidence_score=max_score,
            total_reports=total_reports,
            country_code=primary.country_code or self._first_country(extra_results),
            is_public=primary.is_public,
            is_whitelisted=primary.is_whitelisted,
            usage_type=primary.usage_type,
            isp=primary.isp,
            domain=primary.domain,
            last_reported_at=primary.last_reported_at,
            from_cache=primary.from_cache and all(r.from_cache for r in extra_results),
            api_error=any_api_error and max_score == 0,
        )

    def _first_country(self, results: list[ThreatIntelResult]) -> str:
        """Return the first non-empty country code from extra results."""
        for r in results:
            if r.country_code:
                return r.country_code
        return ""

    @property
    def cache_size(self) -> int:
        """Total cached entries across all sources."""
        total = self._abuseipdb.cache_size
        for source in self._extra_sources:
            total += source.cache_size
        return total

    @property
    def source_count(self) -> int:
        """Number of active threat intel sources (including AbuseIPDB)."""
        return 1 + len(self._extra_sources)


def create_multi_intel(config: Config) -> MultiIntelAggregator:
    """Factory: build a MultiIntelAggregator from the current config.

    - If config.use_mock_api is True → MockAbuseIPDBClient + MockThreatIntelClient
    - Otherwise → real clients for any source that has an API key configured
    """
    from src.api_client import create_api_client

    # Primary source (AbuseIPDB)
    abuseipdb = create_api_client(config)

    extra_sources: list = []

    if config.use_mock_api:
        # Lab mode: mock all sources with known attacker IPs
        extra_sources.append(MockThreatIntelClient(source="virustotal-mock"))
        extra_sources.append(MockThreatIntelClient(source="alienvault-mock"))
    else:
        # Real mode: only add sources that have API keys
        if config.virustotal_api_key:
            extra_sources.append(VirusTotalClient(config.virustotal_api_key))
            logger.info("VirusTotal client enabled")

        if config.alienvault_api_key:
            extra_sources.append(AlienVaultOTXClient(config.alienvault_api_key))
            logger.info("AlienVault OTX client enabled")

        # If no extra keys are provided, that's fine — just AbuseIPDB alone
        if not extra_sources:
            logger.info("No extra threat intel API keys configured — using AbuseIPDB only")

    return MultiIntelAggregator(abuseipdb=abuseipdb, extra_sources=extra_sources)
