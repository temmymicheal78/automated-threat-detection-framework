from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Iterator, Optional
import re
import ipaddress
import time


@dataclass
class LogEntry:
    timestamp: datetime
    ip_address: str
    username: str
    event_type: str   # "failed_password" | "accepted_password"
    port: int
    raw_line: str


# Compiled SSH regex patterns (module-level for performance)
SSH_FAILED_RE = re.compile(
    r'(?P<month>\w{3})\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})'
    r'.*Failed password for (?:invalid user )?(?P<user>\S+)'
    r' from (?P<ip>(?:\d{1,3}\.){3}\d{1,3})'
    r' port (?P<port>\d+)'
)

SSH_ACCEPTED_RE = re.compile(
    r'(?P<month>\w{3})\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})'
    r'.*Accepted (?:password|publickey) for (?P<user>\S+)'
    r' from (?P<ip>(?:\d{1,3}\.){3}\d{1,3})'
    r' port (?P<port>\d+)'
)

# Matches iptables LOG lines with SSH_ATTEMPT prefix (IPS / firewall mode)
# Syslog format: "Apr  7 14:23:01 firewall kernel: [...] SSH_ATTEMPT: ..."
IPTABLES_LOG_RE = re.compile(
    r'(?P<month>\w{3})\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})'
    r'.*SSH_ATTEMPT:.*'
    r'SRC=(?P<src_ip>(?:\d{1,3}\.){3}\d{1,3}).*'
    r'DPT=(?P<dpt>\d+)'
)

# ISO 8601 format (Ubuntu 24.04+): "2026-04-08T12:16:25.817373+00:00 firewall kernel: SSH_ATTEMPT: ..."
IPTABLES_LOG_ISO_RE = re.compile(
    r'(?P<isotime>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})'
    r'.*SSH_ATTEMPT:.*'
    r'SRC=(?P<src_ip>(?:\d{1,3}\.){3}\d{1,3}).*'
    r'DPT=(?P<dpt>\d+)'
)


def parse_timestamp(month: str, day: str, time_str: str, year: int) -> datetime:
    """Convert auth.log timestamp components to a datetime."""
    dt = datetime.strptime(f"{year} {month} {day} {time_str}", "%Y %b %d %H:%M:%S")
    now = datetime.now()
    if dt > now:
        dt = dt.replace(year=dt.year - 1)
    return dt


def validate_ip(ip_str: str) -> bool:
    """Return True for any valid IP address (including private/lab IPs)."""
    try:
        ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return True


def parse_firewall_line(line: str, year: int) -> Optional[LogEntry]:
    """Parse an iptables LOG line with SSH_ATTEMPT prefix (IPS / firewall mode).

    Supports both traditional syslog timestamps (Apr  7 14:23:01) and
    ISO 8601 timestamps used by Ubuntu 24.04+ (2026-04-08T12:16:25...).
    """
    # Try syslog format first
    m = IPTABLES_LOG_RE.search(line)
    if m:
        ts = parse_timestamp(m.group("month"), m.group("day"), m.group("time"), year)
        return LogEntry(
            timestamp=ts,
            ip_address=m.group("src_ip"),
            username="",
            event_type="ssh_attempt",
            port=int(m.group("dpt")),
            raw_line=line.rstrip("\n"),
        )

    # Try ISO 8601 format (Ubuntu 24.04+)
    m = IPTABLES_LOG_ISO_RE.search(line)
    if m:
        ts = datetime.fromisoformat(m.group("isotime"))
        return LogEntry(
            timestamp=ts,
            ip_address=m.group("src_ip"),
            username="",
            event_type="ssh_attempt",
            port=int(m.group("dpt")),
            raw_line=line.rstrip("\n"),
        )

    return None


def parse_line(line: str, year: int) -> Optional[LogEntry]:
    """Try SSH failed and accepted regexes against line; return LogEntry or None."""
    m = SSH_FAILED_RE.search(line)
    if m:
        ip = m.group("ip")
        if not validate_ip(ip):
            return None
        ts = parse_timestamp(m.group("month"), m.group("day"), m.group("time"), year)
        return LogEntry(
            timestamp=ts,
            ip_address=ip,
            username=m.group("user"),
            event_type="failed_password",
            port=int(m.group("port")),
            raw_line=line.rstrip("\n"),
        )

    m = SSH_ACCEPTED_RE.search(line)
    if m:
        ip = m.group("ip")
        if not validate_ip(ip):
            return None
        ts = parse_timestamp(m.group("month"), m.group("day"), m.group("time"), year)
        return LogEntry(
            timestamp=ts,
            ip_address=ip,
            username=m.group("user"),
            event_type="accepted_password",
            port=int(m.group("port")),
            raw_line=line.rstrip("\n"),
        )

    return None


def parse_log_file(
    log_path: Path, year: int | None = None, log_source: str = "auth"
) -> Iterator[LogEntry]:
    """Yield LogEntry objects for every matched line in the log file."""
    if not log_path.exists():
        raise FileNotFoundError(f"Log file not found: {log_path}")

    if year is None:
        year = datetime.now().year

    _parse = parse_firewall_line if log_source == "firewall" else parse_line

    with open(log_path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            entry = _parse(line, year)
            if entry is not None:
                yield entry


def tail_log_file(
    log_path: Path, poll_interval: float = 0.5, log_source: str = "auth"
) -> Iterator[LogEntry]:
    """Continuously yield new LogEntry objects appended to a log file."""
    year = datetime.now().year
    _parse = parse_firewall_line if log_source == "firewall" else parse_line

    with open(log_path, "r", encoding="utf-8", errors="replace") as fh:
        fh.seek(0, 2)

        while True:
            line = fh.readline()
            if line:
                entry = _parse(line, year)
                if entry is not None:
                    yield entry
            else:
                try:
                    current_size = log_path.stat().st_size
                except FileNotFoundError:
                    time.sleep(poll_interval)
                    continue

                if fh.tell() > current_size:
                    fh.seek(0)
                    year = datetime.now().year
                else:
                    time.sleep(poll_interval)
