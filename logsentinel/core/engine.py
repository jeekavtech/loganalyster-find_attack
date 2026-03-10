"""Core engine that wires together parsing, detection, storage, and reporting."""

import argparse
import json
import os
from datetime import datetime

import yaml
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

from logsentinel.alerts.alert_manager import AlertManager
from logsentinel.core.detector import Detector
from logsentinel.core.parser import parse_log_line
from logsentinel.storage.event_store import EventStore


class Engine:
    """Main engine for running scans, monitoring, and reporting."""

    def __init__(self, config_path: str = "config.yaml"):
        self.config_path = config_path
        self.config = self._load_config(config_path)
        self.store = EventStore(
            events_path=self.config["storage"]["events"],
            alerts_path=self.config["storage"]["alerts"],
        )
        self.detector = Detector(self.config.get("scan", {}))
        self.alert_manager = AlertManager(self.store)

    def _load_config(self, path: str) -> dict:
        if not os.path.exists(path):
            raise FileNotFoundError(f"Config file not found: {path}")
        with open(path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f)

    def scan(self):
        """Scan configured logs and run detection rules."""
        existing_events = self.store.load_events()
        seen_raw = {e.get("raw") for e in existing_events if e.get("raw")}

        for name, path in self.config.get("logs", {}).items():
            if not os.path.exists(path):
                continue
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    if not line.strip():
                        continue
                    event = parse_log_line(line, source=path)
                    if event is None or event.get("raw") in seen_raw:
                        continue
                    self.store.add_event(event)
                    seen_raw.add(event.get("raw"))
                    alerts = self.detector.process_event(event)
                    self.alert_manager.emit_many(alerts)

    def report(self):
        """Generate a simple report from stored events and alerts."""
        events = self.store.load_events()
        alerts = self.store.load_alerts()

        summary = {
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "event_count": len(events),
            "alert_count": len(alerts),
            "alerts_by_type": {},
        }

        for a in alerts:
            key = a.get("attack_type", "unknown")
            summary["alerts_by_type"][key] = summary["alerts_by_type"].get(key, 0) + 1

        report_path = self.config["storage"].get("reports")
        if report_path:
            os.makedirs(os.path.dirname(report_path), exist_ok=True)
            with open(report_path, "w", encoding="utf-8") as f:
                json.dump(summary, f, indent=2, sort_keys=True)

        print("Report generated:")
        print(json.dumps(summary, indent=2, sort_keys=False))

    def _tail_file(self, path: str):
        """Tail a file like `tail -F` and yield new lines."""
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            f.seek(0, os.SEEK_END)
            while True:
                line = f.readline()
                if not line:
                    # Sleep briefly between checks
                    time.sleep(0.5)
                    continue
                yield line

    def monitor(self):
        """Monitor configured log files for new lines and run detection."""
        import time

        class LogFileHandler(FileSystemEventHandler):
            """Watchdog handler that tails a file and emits new lines."""

            def __init__(self, engine, paths):
                self.engine = engine
                self.paths = {os.path.abspath(p) for p in paths if os.path.exists(p)}
                self.offsets = {p: os.path.getsize(p) for p in self.paths}

            def on_modified(self, event):
                if event.is_directory:
                    return
                path = os.path.abspath(event.src_path)
                if path not in self.paths:
                    return

                try:
                    with open(path, "r", encoding="utf-8", errors="ignore") as f:
                        f.seek(self.offsets.get(path, 0))
                        for line in f:
                            if not line.strip():
                                continue
                            ev = parse_log_line(line, source=path)
                            if ev is None:
                                continue
                            self.engine.store.add_event(ev)
                            alerts = self.engine.detector.process_event(ev)
                            self.engine.alert_manager.emit_many(alerts)
                        self.offsets[path] = f.tell()
                except FileNotFoundError:
                    pass

        paths = [p for p in self.config.get("logs", {}).values() if os.path.exists(p)]
        if not paths:
            print("No log files found to monitor.")
            return

        print("Starting real-time monitoring. Press Ctrl+C to stop.")

        handler = LogFileHandler(self, paths)
        observer = Observer()
        watched_dirs = {os.path.dirname(p) or "." for p in paths}
        for d in watched_dirs:
            observer.schedule(handler, d, recursive=False)

        observer.start()
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("Stopping monitor.")
        finally:
            observer.stop()
            observer.join()


def main(argv=None):
    parser = argparse.ArgumentParser(prog="logsentinel")
    parser.add_argument(
        "--config",
        default="config.yaml",
        help="Path to configuration YAML file.",
    )

    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("scan", help="Scan configured log files once.")
    sub.add_parser("monitor", help="Monitor logs in real time.")
    sub.add_parser("report", help="Generate a report from stored events.")

    args = parser.parse_args(argv)

    engine = Engine(config_path=args.config)

    if args.command == "scan":
        engine.scan()
    elif args.command == "monitor":
        engine.monitor()
    elif args.command == "report":
        engine.report()


if __name__ == "__main__":
    main()
