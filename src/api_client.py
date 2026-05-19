from __future__ import annotations

from dataclasses import dataclass, field
from collections import deque
from threading import Lock
from typing import Optional
import time
import logging
import requests

from src.config import Config

logger = logging.getLogger(__name__)


@dataclass
class IPReputationResult:
    ip_address: str
    abuse_confidence_score: int    # 0-100
    total_reports: int
    country_code: str
    is_public: bool
    is_whitelisted: bool
    usage_type: str
    isp: str
    domain: str
    last_reported_at: Optional[str]
    from_cache: bool = False
    api_error: bool = False        # True when result is a safe default due to API failure


class AbuseIPDBClient:
    """Real AbuseIPDB API client with caching and rate limiting."""

    def __init__(self, config: Config) -> None:
        self._config = config
        self._cache: dict[str, IPReputationResult] = {}
        self._lock: Lock = Lock()
        self._request_timestamps: deque[float] = deque()

    def check_ip(self, ip_address: str) -> IPReputationResult:
        """Return reputation data for *ip_address*, using cache when available."""
        with self._lock:
            if ip_address in self._cache:
                cached = self._cache[ip_address]
                # Return a copy flagged as from_cache so callers can distinguish
                return IPReputationResult(
                    ip_address=cached.ip_address,
                    abuse_confidence_score=cached.abuse_confidence_score,
                    total_reports=cached.total_reports,
                    country_code=cached.country_code,
                    is_public=cached.is_public,
                    is_whitelisted=cached.is_whitelisted,
                    usage_type=cached.usage_type,
                    isp=cached.isp,
                    domain=cached.domain,
                    last_reported_at=cached.last_reported_at,
                    from_cache=True,
                    api_error=cached.api_error,
                )

        self._rate_limit_wait()
        result = self._make_request(ip_address)

        with self._lock:
            self._cache[ip_address] = result

        return result

    def _make_request(self, ip_address: str) -> IPReputationResult:
        """Perform the HTTP GET to AbuseIPDB with retry logic."""
        url = f"{self._config.api_base_url}/check"
        headers = {
            "Accept": "application/json",
            "Key": self._config.api_key,
        }
        params = {
            "ipAddress": ip_address,
            "maxAgeInDays": self._config.max_age_days,
        }

        backoff_seconds = [1, 2, 4]
        last_status: Optional[int] = None

        for attempt in range(3):
            try:
                response = requests.get(url, headers=headers, params=params, timeout=10)
            except requests.RequestException as exc:
                logger.warning("Network error checking IP %s: %s", ip_address, exc)
                return self._safe_default(ip_address)

            last_status = response.status_code

            if response.status_code == 200:
                try:
                    data = response.json()
                    return self._parse_response(data, ip_address)
                except (ValueError, KeyError) as exc:
                    logger.warning("Failed to parse AbuseIPDB response for %s: %s", ip_address, exc)
                    return self._safe_default(ip_address)

            if response.status_code == 401:
                logger.warning(
                    "AbuseIPDB returned 401 Unauthorized for IP %s — check API key.", ip_address
                )
                return self._safe_default(ip_address)

            if response.status_code == 429 or response.status_code >= 500:
                if attempt < 2:
                    sleep_time = backoff_seconds[attempt]
                    logger.warning(
                        "AbuseIPDB returned %s for IP %s, retrying in %ss (attempt %s/3).",
                        response.status_code,
                        ip_address,
                        sleep_time,
                        attempt + 1,
                    )
                    time.sleep(sleep_time)
                    continue
                # Exhausted retries
                logger.warning(
                    "AbuseIPDB returned %s for IP %s after 3 attempts, returning safe default.",
                    response.status_code,
                    ip_address,
                )
                return self._safe_default(ip_address)

            # Any other unexpected status code
            logger.warning(
                "Unexpected AbuseIPDB status %s for IP %s.", response.status_code, ip_address
            )
            return self._safe_default(ip_address)

        # Should not be reachable, but guard against loop exhaustion
        logger.warning(
            "Exhausted retries for IP %s (last status: %s).", ip_address, last_status
        )
        return self._safe_default(ip_address)

    def _rate_limit_wait(self) -> None:
        """Block until sending another request stays within the configured rate limit.

        Uses a sliding 60-second window tracked via *_request_timestamps*.
        """
        with self._lock:
            while True:
                now = time.monotonic()
                # Evict timestamps older than 60 seconds
                while self._request_timestamps and now - self._request_timestamps[0] >= 60.0:
                    self._request_timestamps.popleft()

                if len(self._request_timestamps) < self._config.api_rate_limit_per_minute:
                    # Capacity available — record this request and proceed
                    self._request_timestamps.append(now)
                    return

                # Window is full; sleep until the oldest request falls out
                oldest = self._request_timestamps[0]
                sleep_duration = 60.0 - (now - oldest)
                if sleep_duration > 0:
                    # Release the lock while sleeping so other threads are not blocked
                    self._lock.release()
                    try:
                        time.sleep(sleep_duration)
                    finally:
                        self._lock.acquire()

    def _parse_response(self, data: dict, ip_address: str) -> IPReputationResult:
        """Extract an :class:`IPReputationResult` from a successful AbuseIPDB JSON payload."""
        payload = data["data"]
        return IPReputationResult(
            ip_address=payload.get("ipAddress", ip_address),
            abuse_confidence_score=int(payload.get("abuseConfidenceScore", 0)),
            total_reports=int(payload.get("totalReports", 0)),
            country_code=payload.get("countryCode", "") or "",
            is_public=bool(payload.get("isPublic", True)),
            is_whitelisted=bool(payload.get("isWhitelisted", False)),
            usage_type=payload.get("usageType", "") or "",
            isp=payload.get("isp", "") or "",
            domain=payload.get("domain", "") or "",
            last_reported_at=payload.get("lastReportedAt"),
            from_cache=False,
            api_error=False,
        )

    def _safe_default(self, ip_address: str) -> IPReputationResult:
        """Return a permissive default result to fail open on API errors."""
        return IPReputationResult(
            ip_address=ip_address,
            abuse_confidence_score=0,
            total_reports=0,
            country_code="",
            is_public=True,
            is_whitelisted=False,
            usage_type="",
            isp="",
            domain="",
            last_reported_at=None,
            api_error=True,
        )

    def clear_cache(self) -> None:
        """Remove all cached results."""
        with self._lock:
            self._cache.clear()

    @property
    def cache_size(self) -> int:
        """Return the number of IPs currently held in the cache."""
        with self._lock:
            return len(self._cache)


class MockAbuseIPDBClient:
    """Drop-in replacement for :class:`AbuseIPDBClient` that never makes HTTP calls.

    Useful for testing and dry-run scenarios.
    """

    def __init__(
        self,
        default_score: int = 0,
        known_ips: Optional[dict[str, int]] = None,
    ) -> None:
        self._default_score = default_score
        self._known_ips: dict[str, int] = known_ips if known_ips is not None else {}

    def check_ip(self, ip_address: str) -> IPReputationResult:
        """Return a synthetic :class:`IPReputationResult` for *ip_address*."""
        score = self._known_ips.get(ip_address, self._default_score)
        return IPReputationResult(
            ip_address=ip_address,
            abuse_confidence_score=score,
            total_reports=0,
            country_code="",
            is_public=True,
            is_whitelisted=False,
            usage_type="",
            isp="",
            domain="",
            last_reported_at=None,
            from_cache=False,
            api_error=False,
        )

    def clear_cache(self) -> None:
        """No-op — mock client holds no cache."""

    @property
    def cache_size(self) -> int:
        """Always 0 — mock client holds no cache."""
        return 0


def create_api_client(config: Config) -> AbuseIPDBClient | MockAbuseIPDBClient:
    """Return MockAbuseIPDBClient if config.use_mock_api or config.api_key is empty, else AbuseIPDBClient."""
    if config.use_mock_api or not config.api_key:
        return MockAbuseIPDBClient()
    return AbuseIPDBClient(config)
