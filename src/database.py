"""SQLite persistence layer for the threat detection system.

Stores parsed log events, detector firings, threat assessments, and
blocked-IP state in a local SQLite database with WAL journaling.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
from typing import Union

from src.log_parser import LogEntry
from src.detector import DetectionEvent
from src.decision import ThreatAssessment


class ThreatDatabase:
    """Thin wrapper around a SQLite database for threat-detection persistence."""

    def __init__(self, db_path: Union[str, Path] = "data/threat_detector.db") -> None:
        db_path = Path(db_path)
        db_path.parent.mkdir(parents=True, exist_ok=True)

        self._conn = sqlite3.connect(str(db_path))
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._init_schema()

    # ------------------------------------------------------------------ schema
    def _init_schema(self) -> None:
        """Create tables and indexes if they do not already exist."""
        cur = self._conn.cursor()

        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS events (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp   TEXT,
                ip_address  TEXT,
                username    TEXT,
                event_type  TEXT,
                port        INTEGER,
                raw_line    TEXT
            )
            """
        )
        cur.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_events_ip_ts
            ON events (ip_address, timestamp)
            """
        )

        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS detections (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address    TEXT,
                fail_count    INTEGER,
                window_start  TEXT,
                window_end    TEXT,
                detected_at   TEXT
            )
            """
        )

        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS assessments (
                id               INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address       TEXT,
                decision         TEXT,
                abuse_score      INTEGER,
                fail_count       INTEGER,
                reason           TEXT,
                response_time_ms REAL,
                assessed_at      TEXT
            )
            """
        )

        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS blocked_ips (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address   TEXT UNIQUE,
                blocked_at   TEXT,
                unblocked_at TEXT,
                source       TEXT DEFAULT 'system'
            )
            """
        )
        cur.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_blocked_active
            ON blocked_ips (ip_address) WHERE unblocked_at IS NULL
            """
        )

        self._conn.commit()

    # --------------------------------------------------------------- inserts
    def insert_event(self, entry: LogEntry) -> None:
        """Persist a parsed log entry."""
        self._conn.execute(
            """
            INSERT INTO events (timestamp, ip_address, username, event_type, port, raw_line)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                entry.timestamp.isoformat(),
                entry.ip_address,
                entry.username,
                entry.event_type,
                entry.port,
                entry.raw_line,
            ),
        )
        self._conn.commit()

    def insert_detection(self, event: DetectionEvent) -> None:
        """Persist a detection event fired by the sliding-window detector."""
        self._conn.execute(
            """
            INSERT INTO detections (ip_address, fail_count, window_start, window_end, detected_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                event.ip_address,
                event.fail_count,
                event.first_seen.isoformat(),
                event.last_seen.isoformat(),
                datetime.now().isoformat(),
            ),
        )
        self._conn.commit()

    def insert_assessment(self, assessment: ThreatAssessment) -> None:
        """Persist a threat assessment (decision made by the DecisionEngine)."""
        self._conn.execute(
            """
            INSERT INTO assessments
                (ip_address, decision, abuse_score, fail_count, reason, response_time_ms, assessed_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                assessment.ip_address,
                assessment.decision.value,
                assessment.reputation.abuse_confidence_score,
                assessment.detection_event.fail_count,
                assessment.reason,
                assessment.response_time_ms,
                assessment.detection_event.last_seen.isoformat(),
            ),
        )
        self._conn.commit()

    # --------------------------------------------------------- blocked-IP ops
    def add_blocked_ip(self, ip: str, source: str = "system") -> None:
        """Record a newly blocked IP (ignored if already present)."""
        self._conn.execute(
            """
            INSERT OR IGNORE INTO blocked_ips (ip_address, blocked_at, source)
            VALUES (?, datetime('now'), ?)
            """,
            (ip, source),
        )
        self._conn.commit()

    def remove_blocked_ip(self, ip: str) -> None:
        """Mark an active block as removed by setting unblocked_at."""
        self._conn.execute(
            """
            UPDATE blocked_ips
            SET unblocked_at = datetime('now')
            WHERE ip_address = ? AND unblocked_at IS NULL
            """,
            (ip,),
        )
        self._conn.commit()

    def get_active_blocked_ips(self) -> list[str]:
        """Return all IP addresses that are currently blocked."""
        rows = self._conn.execute(
            "SELECT ip_address FROM blocked_ips WHERE unblocked_at IS NULL"
        ).fetchall()
        return [row["ip_address"] for row in rows]

    # -------------------------------------------------------------- queries
    def get_all_assessments(self) -> list[dict]:
        """Return every assessment row as a plain dict."""
        rows = self._conn.execute("SELECT * FROM assessments").fetchall()
        return [dict(row) for row in rows]

    def count_events_for_ip(self, ip: str, since_minutes: int) -> int:
        """Count events for *ip* within the last *since_minutes* minutes."""
        cutoff = (datetime.now() - timedelta(minutes=since_minutes)).isoformat()
        row = self._conn.execute(
            "SELECT COUNT(*) AS cnt FROM events WHERE ip_address = ? AND timestamp > ?",
            (ip, cutoff),
        ).fetchone()
        return row["cnt"]

    # --------------------------------------------------- lifecycle / context
    def close(self) -> None:
        """Commit pending changes and close the database connection."""
        self._conn.commit()
        self._conn.close()

    def __enter__(self) -> ThreatDatabase:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:  # type: ignore[override]
        self.close()
