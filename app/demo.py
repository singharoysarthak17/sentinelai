from datetime import datetime, timezone

from app.schemas import Alert

DEMO_ALERT = Alert(
    alert_id="ALR-0001",
    title="Repeated failed logins followed by a successful login from a new location and device",
    description=("37 failed logins for priya.sharma from 203.0.113.10 within 20 minutes, "
                 "then a successful login from the same IP on an unrecognised device."),
    entities=["priya.sharma", "203.0.113.10"],
    created_at=datetime(2026, 9, 18, 2, 25, tzinfo=timezone.utc),
)