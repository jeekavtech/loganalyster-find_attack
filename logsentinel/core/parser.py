"""Log parser that converts raw log lines into structured events."""

import re
from datetime import datetime

from dateutil import parser as dateparser

from logsentinel.utils.ip_utils import extract_ip
from logsentinel.utils.time_utils import parse_timestamp

SYSLOG_REGEX = re.compile(
    r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+(?P<prog>[^:\[]+)(?:\[(?P<pid>\d+)\])?:\s+(?P<msg>.*)$"
)

NGINX_ACCESS_REGEX = re.compile(r'''
(?P<ip>\d+\.\d+\.\d+\.\d+)\s+-\s+-\s+\[(?P<time>[^\]]+)\]\s+
"(?P<method>\S+)\s+(?P<path>[^\s]+)\s+HTTP/(?P<http>[0-9.]+)"\s+
(?P<status>\d{3})\s+(?P<size>\d+|-)\s+
"(?P<referrer>[^"]*)"\s+"(?P<agent>[^"]*)"
''', re.VERBOSE)


def parse_syslog_line(line: str, source: str = "syslog") -> dict | None:
    """Parse a syslog-like line into a structured event."""
    match = SYSLOG_REGEX.match(line.strip())
    if not match:
        return None

    data = match.groupdict()
    year = datetime.now().year
    timestamp = parse_timestamp(f"{data['month']} {data['day']} {data['time']} {year}")

    event = {
        "timestamp": timestamp,
        "source": source,
        "host": data.get("host"),
        "program": data.get("prog"),
        "pid": data.get("pid"),
        "message": data.get("msg"),
        "raw": line.strip(),
    }

    # Enrich with lightweight event type hints
    event["event_type"] = guess_event_type(event)
    event["ip"] = extract_ip(event["message"])
    return event


def parse_nginx_access(line: str, source: str = "nginx") -> dict | None:
    """Parse a single NGINX access log line into an event."""
    match = NGINX_ACCESS_REGEX.match(line.strip())
    if not match:
        return None

    data = match.groupdict()
    try:
        timestamp = dateparser.parse(data["time"], fuzzy=False)
    except Exception:
        timestamp = datetime.now()

    event = {
        "timestamp": timestamp,
        "source": source,
        "ip": data.get("ip"),
        "method": data.get("method"),
        "path": data.get("path"),
        "status": int(data.get("status", 0)),
        "size": data.get("size"),
        "referrer": data.get("referrer"),
        "agent": data.get("agent"),
        "raw": line.strip(),
        "event_type": "nginx_access",
    }
    return event


def guess_event_type(event: dict) -> str:
    """Guess a lightweight event type based on message contents."""
    msg = event.get("message", "")
    if "Failed password" in msg or "authentication failure" in msg.lower():
        return "ssh_failed_login"
    if "Accepted password" in msg or "Accepted publickey" in msg:
        return "ssh_success_login"
    if "session opened" in msg.lower():
        return "ssh_session_opened"
    return "unknown"


def parse_log_line(line: str, source: str) -> dict | None:
    """Dispatch to the correct parser based on source type."""
    if source.endswith("auth.log") or "sshd" in source:
        return parse_syslog_line(line, source=source)
    if source.endswith("syslog"):
        return parse_syslog_line(line, source=source)
    if "nginx" in source and "access" in source:
        return parse_nginx_access(line, source=source)
    # Fallback: try syslog-style parse
    return parse_syslog_line(line, source=source)
