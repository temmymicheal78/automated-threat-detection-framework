"""Email notification module for the automated threat detection system."""

from __future__ import annotations

import logging
import smtplib
from email.mime.text import MIMEText

from src.config import Config
from src.decision import ThreatAssessment

logger = logging.getLogger(__name__)


class EmailNotifier:
    """Sends email alerts when threats are blocked."""

    def __init__(self, config: Config) -> None:
        self.enabled: bool = config.email_enabled
        self._host: str = config.smtp_host
        self._port: int = config.smtp_port
        self._user: str = config.smtp_user
        self._password: str = config.smtp_password
        self._to: str = config.alert_email_to
        self._from: str = config.alert_email_from

        if not self._host:
            self.enabled = False

    def notify_block(self, assessment: ThreatAssessment) -> bool:
        """Send an email alert for a blocked threat. Returns True on success."""
        if not self.enabled:
            return False

        subject = f"[THREAT BLOCKED] {assessment.ip_address}"
        body = (
            f"Threat Blocked\n"
            f"{'=' * 40}\n"
            f"IP Address:    {assessment.ip_address}\n"
            f"Abuse Score:   {assessment.reputation.abuse_confidence_score}/100\n"
            f"Country:       {assessment.reputation.country_code}\n"
            f"Fail Count:    {assessment.detection_event.fail_count}\n"
            f"First Seen:    {assessment.detection_event.first_seen}\n"
            f"Last Seen:     {assessment.detection_event.last_seen}\n"
            f"Timestamp:     {assessment.timestamp}\n"
            f"Decision:      {assessment.decision.value.upper()}\n"
            f"Reason:        {assessment.reason}\n"
            f"Response Time: {assessment.response_time_ms:.1f} ms\n"
        )

        msg = MIMEText(body)
        msg["Subject"] = subject
        msg["From"] = self._from
        msg["To"] = self._to

        try:
            if self._port == 465:
                server = smtplib.SMTP_SSL(self._host, self._port, timeout=10)
            else:
                server = smtplib.SMTP(self._host, self._port, timeout=10)
                if self._port == 587:
                    server.starttls()

            with server:
                if self._user and self._password:
                    server.login(self._user, self._password)
                server.sendmail(self._from, [self._to], msg.as_string())

            logger.info("Email alert sent for %s", assessment.ip_address)
            return True
        except Exception:
            logger.exception("Failed to send email alert for %s", assessment.ip_address)
            return False
