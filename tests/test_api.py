from fastapi.testclient import TestClient

from app import main
from app.llm import ReplayMiss
from guardrails.approval import request_action
from observability.audit import audit

client = TestClient(main.app)


def test_health():
    assert client.get("/health").json() == {"status": "ok"}


def test_incident_lifecycle_with_fake_investigation(monkeypatch):
    monkeypatch.setattr(main, "investigate_full",
                        lambda incident_id, alert: {"status": "complete", "note": "fake"})
    inc = client.post("/incidents/demo").json()
    assert inc["incident_id"].startswith("INC-") and inc["status"] == "submitted"
    done = client.post(f"/incidents/{inc['incident_id']}/investigate").json()
    assert done["status"] == "complete"
    assert client.get(f"/incidents/{inc['incident_id']}").json()["status"] == "complete"


def test_replay_miss_maps_to_409(monkeypatch):
    def boom(incident_id, alert):
        raise ReplayMiss("x")
    monkeypatch.setattr(main, "investigate_full", boom)
    inc = client.post("/incidents/demo").json()
    assert client.post(f"/incidents/{inc['incident_id']}/investigate").status_code == 409


def test_unknown_incident_is_404():
    assert client.get("/incidents/INC-nope").status_code == 404


def test_trace_summarises_events_for_the_incident():
    inc = client.post("/incidents/demo").json()
    audit({"event": "llm_call", "agent": "triage", "incident_id": inc["incident_id"],
           "cached": False, "input_tokens": 10, "output_tokens": 5, "latency_s": 1.0})
    t = client.get(f"/incidents/{inc['incident_id']}/trace").json()
    assert t["summary"]["totals"]["llm_calls"] == 1


def test_approval_flow_and_separation_of_duties():
    req = request_action("INC-T", "response", "disable_account", {"target": "u"})
    r = client.post(f"/actions/{req.action_id}/approve", json={"approver": "response"})
    assert r.status_code == 403
    ok = client.post(f"/actions/{req.action_id}/approve", json={"approver": "analyst.raj"})
    assert ok.status_code == 200 and ok.json()["status"] == "executed"
    assert "approval_token" not in ok.json()


def test_reject_and_unknown_action():
    req = request_action("INC-T", "response", "block_ip_production", {"target": "1.2.3.4"})
    r = client.post(f"/actions/{req.action_id}/reject", json={"approver": "analyst.raj"})
    assert r.json()["status"] == "rejected"
    assert client.post("/actions/ACT-nope/approve", json={"approver": "analyst.raj"}).status_code == 404