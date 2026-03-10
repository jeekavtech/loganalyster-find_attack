# LogSentinel(By Jeekavtech)

[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10%2B-brightgreen)](https://www.python.org)

> A lightweight local security log analyzer (mini SIEM) for Linux. Parse logs, detect suspicious activity, and generate alerts + reports.

---

## 🚀 Quickstart

### 1) Install dependencies

```sh
python -m pip install -r requirements.txt
```

### 2) Configure log paths

Edit `config.yaml` to point at the logs you want to analyze. Example:

```yaml
logs:
  auth: /var/log/auth.log
  syslog: /var/log/syslog
  nginx: /var/log/nginx/access.log
```

> Tip: Use `config.sample.yaml` if you want to test using the included sample log (`logs/sample_auth.log`).

### 3) Run LogSentinel

Scan logs once:

```sh
python main.py scan
```

Monitor logs in real time:

```sh
python main.py monitor
```

Generate a report:

```sh
python main.py report
```

---

## ✅ Built-in Detection Rules

LogSentinel currently detects:

- **SSH failed logins**
- **SSH successful logins**
- **Brute-force patterns** (configurable threshold + window)
- **Repeated attempts from the same IP**
- **Abnormal login times** (configurable time window)

Alerts include:

- `attack_type`
- `ip`
- `attempts`
- `timestamp`
- `details`

---

## 🧩 Architecture Overview

```
logsentinel/
  main.py                # CLI entrypoint
  config.yaml            # runtime configuration
  core/
    parser.py            # raw log → structured event
    detector.py          # rule-based alerting
    engine.py            # scan / monitor / report workflow
  alerts/
    alert_manager.py     # alert printing + storage
  storage/
    event_store.py       # JSON persistence for events/alerts
  utils/
    time_utils.py        # timestamp helpers
    ip_utils.py          # IP extraction + validation
  logs/
    sample_auth.log      # example logs for testing
  data/
    events.json
    alerts.json
  reports/
    daily_report.json
```

---

## 🛠️ Extending LogSentinel

### 🔥 Firewall Blocking
Implement a blocking action in `alerts/alert_manager.py` (e.g., call `subprocess.run(["ufw", "deny", ip])`) when a critical alert is emitted.

### 🌍 GeoIP Enrichment
Use a GeoIP library like `geoip2` to resolve `event["ip"]` into location metadata and include the result in alert details.

### 🤖 Machine Learning Anomaly Detection
Add an ML module (e.g., `core/anomaly.py`) that trains on event features (time, counts, source IP, etc.). Use scikit-learn to score live events and emit alerts when anomalies are detected.

---

## 🧪 Testing with the included sample log

```sh
python main.py --config config.sample.yaml scan
python main.py --config config.sample.yaml report
```

---

Made with 💙 for security engineers and sysadmins.
