from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Optional

from src.log_parser import LogEntry


@dataclass
class DetectionEvent:
    ip_address: str
    first_seen: datetime
    last_seen: datetime
    fail_count: int
    window_seconds: int


class SlidingWindowDetector:
    """
    Maintains a per-IP deque of failed-login timestamps.
    On each new event, prunes entries older than window_seconds.
    Fires a DetectionEvent when len(deque) >= threshold for the first time.
    """

    def __init__(self, threshold: int, window_seconds: int) -> None:
        self.threshold = threshold
        self.window_seconds = window_seconds
        self._windows: dict[str, deque[datetime]] = defaultdict(deque)
        self._flagged: set[str] = set()

    def process_event(self, entry: LogEntry) -> Optional[DetectionEvent]:
        """
        Feed one LogEntry.
        - Only processes event_type == "failed_password"
        - If event_type == "accepted_password", calls self.reset(ip) (legitimate login clears history)
        - Returns DetectionEvent first time threshold is crossed, None otherwise
        - Once an IP is in _flagged, never returns another DetectionEvent for it
        """
        ip = entry.ip_address

        if entry.event_type == "accepted_password":
            self.reset(ip)
            return None

        if entry.event_type not in ("failed_password", "ssh_attempt"):
            return None

        window = self._windows[ip]
        window.append(entry.timestamp)
        self._prune_window(ip, entry.timestamp)

        # Already flagged — never fire again
        if ip in self._flagged:
            return None

        if len(window) >= self.threshold:
            self._flagged.add(ip)
            return DetectionEvent(
                ip_address=ip,
                first_seen=window[0],
                last_seen=window[-1],
                fail_count=len(window),
                window_seconds=self.window_seconds,
            )

        return None

    def _prune_window(self, ip: str, reference_time: datetime) -> None:
        """Remove entries older than window_seconds from the left of the deque."""
        cutoff = reference_time - timedelta(seconds=self.window_seconds)
        window = self._windows[ip]
        while window and window[0] <= cutoff:
            window.popleft()

    def get_flagged_ips(self) -> list[str]:
        """Return list of all currently flagged IPs."""
        return list(self._flagged)

    def get_fail_count(self, ip: str) -> int:
        """Return current count of events in the window for this IP."""
        return len(self._windows[ip])

    def reset(self, ip: str) -> None:
        """Clear an IP's history and remove from flagged set."""
        self._windows[ip].clear()
        self._flagged.discard(ip)

    def unflag(self, ip: str) -> None:
        """Remove from flagged set only (keeps window history)."""
        self._flagged.discard(ip)
