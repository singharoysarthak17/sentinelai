import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from app.schemas import Finding, SecurityEvent

DATA = Path(__file__).resolve().parents[1] / "data"


def load_events():
    return [SecurityEvent(**e) for e in json.loads((DATA / "events.json").read_text())]


def test_incident_shape():
    events = load_events()
    users = json.loads((DATA / "users.json").read_text())
    known = users["priya.sharma"]["known_devices"]
    failed = [e for e in events if e.type == "login_failed"]
    odd_success = [e for e in events
                   if e.type == "login_success" and e.device_id not in known]
    assert len(failed) == 37
    assert len(odd_success) == 1


def test_fact_without_evidence_is_rejected():
    with pytest.raises(ValidationError):
        Finding(statement="Login was malicious", kind="fact", confidence=0.9)


def test_hypothesis_without_evidence_is_allowed():
    Finding(statement="Possible credential stuffing", kind="hypothesis", confidence=0.4)