"""Rule-based detection engine for suspicious log activity."""

from collections import defaultdict, deque
from datetime import datetime, timedelta

from logsentinel.utils.time_utils import is_time_between, isoformat


class Detector:
    """A simple rule-based detector for log events."""

    def __init__(self, config: dict):
        self.config = config
        self.failed_attempts = defaultdict(deque)  # ip -> deque[datetime]
        self.alerts = []

        self.brute_force_threshold = config.get("brute_force_threshold", 5)
        self.brute_force_window_minutes = config.get("brute_force_window_minutes", 5)
        self.abnormal_start = config.get("abnormal_hour_start", 0)
        self.abnormal_end = config.get("abnormal_hour_end", 5)

    def process_event(self, event: dict) -> list[dict]:
        """Process a parsed event and return any generated alerts."""
        alerts = []
        event_type = event.get("event_type")
        ip = event.get("ip")
        timestamp = event.get("timestamp") or datetime.now()

        if event_type == "ssh_failed_login" and ip:
            alerts += self._process_failed_login(ip, timestamp)

        if event_type == "ssh_success_login" and ip:
            alerts += self._process_success_login(ip, timestamp)

        # Potential extension: detect suspicious nginx access patterns

        self.alerts.extend(alerts)
        return alerts

    def _process_failed_login(self, ip: str, timestamp: datetime) -> list[dict]:
        """Track failed SSH login attempts and detect brute-force-like behavior."""
        window = timedelta(minutes=self.brute_force_window_minutes)
        bucket = self.failed_attempts[ip]
        bucket.append(timestamp)

        # Remove old entries outside the window
        cutoff = timestamp - window
        while bucket and bucket[0] < cutoff:
            bucket.popleft()

        alerts = []
        if len(bucket) >= self.brute_force_threshold:
            alerts.append(
                {
                    "attack_type": "brute_force",
                    "ip": ip,
                    "attempts": len(bucket),
                    "timestamp": isoformat(timestamp),
                    "details": f"{len(bucket)} failed SSH logins within {self.brute_force_window_minutes} minutes",
                }
            )

        # Repeated login attempts from a single IP
        if len(bucket) > 1:
            alerts.append(
                {
                    "attack_type": "repeated_failed_logins",
                    "ip": ip,
                    "attempts": len(bucket),
                    "timestamp": isoformat(timestamp),
                    "details": "Repeated failed SSH login attempts detected",
                }
            )

        return alerts

    def _process_success_login(self, ip: str, timestamp: datetime) -> list[dict]:
        """Detect abnormal login times and correlate with prior failures."""
        alerts = []
        if is_time_between(timestamp, self.abnormal_start, self.abnormal_end):
            alerts.append(
                {
                    "attack_type": "abnormal_login_time",
                    "ip": ip,
                    "attempts": 1,
                    "timestamp": isoformat(timestamp),
                    "details": f"Login at abnormal hour ({timestamp.hour:02d})",
                }
            )

        # If there were recent failures from same IP, raise a suspicious login alert
        recent_failures = len(self.failed_attempts.get(ip, []))
        if recent_failures:
            alerts.append(
                {
                    "attack_type": "suspicious_success_after_failures",
                    "ip": ip,
                    "attempts": recent_failures,
                    "timestamp": isoformat(timestamp),
                    "details": "Successful login after recent failures",
                }
            )

        return alerts

    def reset(self):
        """Reset detector state (for tests or new sessions)."""
        self.failed_attempts.clear()
        self.alerts.clear()
