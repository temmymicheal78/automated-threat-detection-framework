from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Union
import ipaddress
import time
import logging

from src.config import Config
from src.detector import DetectionEvent
from src.api_client import IPReputationResult, AbuseIPDBClient, MockAbuseIPDBClient
from src.geo_lookup import GeoLookupClient, GeoInfo, generate_session_id

logger = logging.getLogger(__name__)


class Decision(Enum):
    BLOCK = "block"
    MONITOR = "monitor"
    IGNORE = "ignore"


@dataclass
class ThreatAssessment:
    ip_address: str
    decision: Decision
    detection_event: DetectionEvent
    reputation: IPReputationResult
    reason: str
    timestamp: datetime
    response_time_ms: float
    session_id: str = ""
    geo: GeoInfo | None = None


class DecisionEngine:
    def __init__(
        self,
        config: Config,
        api_client: Union[AbuseIPDBClient, MockAbuseIPDBClient],
        geo_client: GeoLookupClient | None = None,
    ) -> None:
        self._config = config
        self._api = api_client
        self._geo = geo_client or GeoLookupClient()

    def evaluate(self, detection_event: DetectionEvent) -> ThreatAssessment:
        """Evaluate a DetectionEvent and return a ThreatAssessment with a block/monitor/ignore decision."""
        start = time.monotonic()

        reputation = self._api.check_ip(detection_event.ip_address)
        geo = self._geo.lookup(detection_event.ip_address)
        session_id = generate_session_id()

        fail_count = detection_event.fail_count
        threshold = self._config.fail_threshold
        score = reputation.abuse_confidence_score
        score_threshold = self._config.abuse_score_threshold

        # Private IPs (e.g. 10.x, 192.168.x) won't appear in public threat
        # databases, so skip the score check and block on fail count alone.
        is_private = ipaddress.ip_address(detection_event.ip_address).is_private

        if reputation.is_whitelisted:
            decision = Decision.IGNORE
        elif is_private and fail_count >= threshold:
            # Private IP — no public threat data available, block on behaviour
            decision = Decision.BLOCK
        elif reputation.api_error and fail_count >= threshold:
            # Fail-safe: do not BLOCK on API failure alone; degrade to MONITOR
            decision = Decision.MONITOR
        elif fail_count >= threshold and score >= score_threshold:
            decision = Decision.BLOCK
        elif fail_count >= threshold or score >= score_threshold:
            decision = Decision.MONITOR
        else:
            decision = Decision.IGNORE

        reason = self._build_reason(detection_event, reputation, decision)
        response_time_ms = (time.monotonic() - start) * 1000

        return ThreatAssessment(
            ip_address=detection_event.ip_address,
            decision=decision,
            detection_event=detection_event,
            reputation=reputation,
            reason=reason,
            timestamp=datetime.now(),
            response_time_ms=response_time_ms,
            session_id=session_id,
            geo=geo,
        )

    def _build_reason(
        self,
        event: DetectionEvent,
        rep: IPReputationResult,
        decision: Decision,
    ) -> str:
        """Return a human-readable explanation of the decision."""
        if rep.is_whitelisted:
            return (
                f"IP {event.ip_address}: whitelisted — automatically ignored "
                f"({event.fail_count} failed logins in {event.window_seconds}s, "
                f"AbuseIPDB score: {rep.abuse_confidence_score}/100) → {decision.value.upper()}"
            )

        if rep.api_error:
            return (
                f"IP {event.ip_address}: {event.fail_count} failed logins in {event.window_seconds}s "
                f"(threshold: {self._config.fail_threshold}), "
                f"AbuseIPDB score unavailable (API error) → {decision.value.upper()}"
            )

        return (
            f"IP {event.ip_address}: {event.fail_count} failed logins in {event.window_seconds}s "
            f"(threshold: {self._config.fail_threshold}), "
            f"AbuseIPDB score: {rep.abuse_confidence_score}/100 "
            f"(threshold: {self._config.abuse_score_threshold}) → {decision.value.upper()}"
        )
