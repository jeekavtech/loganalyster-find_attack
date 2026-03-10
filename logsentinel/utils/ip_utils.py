"""IP helpers for log events."""

import ipaddress
import re

IPV4_REGEX = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")


def extract_ip(text: str) -> str | None:
    """Extract the first IPv4 address found in text."""
    if not text:
        return None

    match = IPV4_REGEX.search(text)
    if not match:
        return None

    candidate = match.group(0)
    try:
        ipaddress.ip_address(candidate)
        return candidate
    except ValueError:
        return None


def is_public_ip(ip_str: str) -> bool:
    """Return True if the IP string is a public IPv4 address."""
    try:
        ip = ipaddress.ip_address(ip_str)
    except Exception:
        return False
    return not (ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_multicast)
