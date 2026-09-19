from agents.risk import assess_risk


def run(type_, ind, geo, dev, count, first, last):
    return {"type": type_, "indicator": ind, "geo": geo, "device_id": dev,
            "count": count, "first_seen": first, "last_seen": last}


USER = {"role": "finance-admin", "usual_geo": "Kolkata, IN", "known_devices": ["LAP-001"]}
HOME = run("login_success", "198.51.100.7", "Kolkata, IN", "LAP-001", 6,
           "2026-09-12T09:30:00+00:00", "2026-09-17T09:30:00+00:00")
BURST = run("login_failed", "203.0.113.10", "Bucharest, RO", "DEV-UNKNOWN-99", 37,
            "2026-09-18T02:00:00+00:00", "2026-09-18T02:18:00+00:00")
TAKEOVER = run("login_success", "203.0.113.10", "Bucharest, RO", "DEV-UNKNOWN-99", 1,
               "2026-09-18T02:19:10+00:00", "2026-09-18T02:19:10+00:00")
NEW_DEVICE = run("login_success", "198.51.100.9", "Kolkata, IN", "LAP-777", 1,
                 "2026-09-18T09:30:00+00:00", "2026-09-18T09:30:00+00:00")
BAD_IP = {"ip": "203.0.113.10", "reputation": "malicious", "confidence": 0.82}


def test_full_attack_is_critical_and_explained():
    r = assess_risk([HOME, BURST, TAKEOVER], USER, [BAD_IP])
    assert r.severity == "critical" and r.score == 11 and r.requires_escalation
    assert len(r.reasons) == 5


def test_benign_new_device_is_not_critical():
    r = assess_risk([HOME, NEW_DEVICE], USER, [])
    assert r.severity == "medium" and not r.requires_escalation


def test_unprivileged_new_device_is_low():
    r = assess_risk([HOME, NEW_DEVICE], {**USER, "role": "analyst"}, [])
    assert r.severity == "low"


def test_weak_intel_does_not_count():
    r = assess_risk([HOME, BURST, TAKEOVER], USER, [{**BAD_IP, "confidence": 0.3}])
    assert r.score == 9