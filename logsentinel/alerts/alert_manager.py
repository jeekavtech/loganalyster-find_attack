"""Alert generation and dispatching for LogSentinel."""

from typing import Iterable, Optional

from logsentinel.storage.event_store import EventStore


class AlertManager:
    """Manages alerts produced by the detector."""

    def __init__(self, store: EventStore):
        self.store = store

    def emit(self, alert: dict):
        """Emit a single alert to storage and console."""
        self.store.add_alert(alert)
        self._print_alert(alert)

    def emit_many(self, alerts: Iterable[dict]):
        """Emit multiple alerts."""
        for a in alerts:
            self.emit(a)

    def _print_alert(self, alert: dict):
        msg = (
            f"[ALERT] {alert.get('attack_type')} | ip={alert.get('ip')} "
            f"attempts={alert.get('attempts')} time={alert.get('timestamp')}"
        )
        if alert.get("details"):
            msg += f" | {alert.get('details')}"
        print(msg)
