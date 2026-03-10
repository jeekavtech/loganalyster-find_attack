"""Utilities for working with timestamps and time ranges."""

from datetime import datetime, time

from dateutil import parser as dateparser


def parse_timestamp(value: str) -> datetime:
    """Parse a timestamp string into a datetime object."""
    try:
        return dateparser.parse(value, fuzzy=True)
    except Exception:
        return datetime.now()


def is_time_between(dt: datetime, start_hour: int, end_hour: int) -> bool:
    """Return True if dt is within the [start_hour, end_hour) window."""
    if start_hour <= end_hour:
        return time(start_hour) <= dt.time() < time(end_hour)
    # Window wraps around midnight
    return dt.time() >= time(start_hour) or dt.time() < time(end_hour)


def isoformat(dt: datetime) -> str:
    """Return ISO-8601 string for a datetime."""
    if dt is None:
        return ""
    return dt.isoformat()
