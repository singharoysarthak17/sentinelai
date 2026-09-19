import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

DATA = Path(__file__).resolve().parent
USER = "priya.sharma"

events = []

# Normal history: six daily logins from the usual place and device
for d in range(6, 0, -1):
    ts = datetime(2026, 9, 18, 9, 30, tzinfo=timezone.utc) - timedelta(days=d)
    events.append(dict(timestamp=ts, source="identity", type="login_success",
                       principal=USER, indicator="198.51.100.7",
                       geo="Kolkata, IN", device_id="LAP-001"))

# Attack: 37 failures from one IP, 30 seconds apart, then a success
start = datetime(2026, 9, 18, 2, 0, tzinfo=timezone.utc)
for i in range(37):
    events.append(dict(timestamp=start + timedelta(seconds=30 * i),
                       source="identity", type="login_failed",
                       principal=USER, indicator="203.0.113.10",
                       geo="Bucharest, RO", device_id="DEV-UNKNOWN-99",
                       raw_payload={"reason": "bad_password"}))
events.append(dict(timestamp=start + timedelta(seconds=30 * 37 + 40),
                   source="identity", type="login_success",
                   principal=USER, indicator="203.0.113.10",
                   geo="Bucharest, RO", device_id="DEV-UNKNOWN-99"))

events.sort(key=lambda e: e["timestamp"])
for n, e in enumerate(events, 1):
    e["event_id"] = f"EVT-{n:04d}"
    e["timestamp"] = e["timestamp"].isoformat()

users = {USER: {"role": "finance-admin", "usual_geo": "Kolkata, IN",
                "known_devices": ["LAP-001"], "department": "Finance"}}
threat_intel = {"203.0.113.10": {"reputation": "malicious", "confidence": 0.82,
                                 "tags": ["password-spraying"],
                                 "sources": ["synthetic-feed-A"]}}

for name, obj in [("events", events), ("users", users), ("threat_intel", threat_intel)]:
    (DATA / f"{name}.json").write_text(json.dumps(obj, indent=2))
print(f"wrote {len(events)} events")