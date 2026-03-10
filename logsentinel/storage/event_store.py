"""Simple JSON-backed storage for events and alerts."""

import json
from pathlib import Path
from typing import Any


class EventStore:
    """Stores parsed events and generated alerts to JSON files."""

    def __init__(self, events_path: str, alerts_path: str):
        self.events_path = Path(events_path)
        self.alerts_path = Path(alerts_path)
        self._ensure_file(self.events_path, [])
        self._ensure_file(self.alerts_path, [])

    def _ensure_file(self, path: Path, default: Any):
        path.parent.mkdir(parents=True, exist_ok=True)
        if not path.exists():
            path.write_text(json.dumps(default, indent=2))

    def load_events(self) -> list[dict]:
        return self._load(self.events_path)

    def load_alerts(self) -> list[dict]:
        return self._load(self.alerts_path)

    def add_event(self, event: dict):
        self._append(self.events_path, event)

    def add_alert(self, alert: dict):
        self._append(self.alerts_path, alert)

    def _load(self, path: Path) -> list[dict]:
        try:
            return json.loads(path.read_text())
        except Exception:
            return []

    def _append(self, path: Path, item: dict):
        data = self._load(path)
        data.append(item)
        path.write_text(json.dumps(data, indent=2, default=str))
