from fastapi.testclient import TestClient

from a2a import server as a2a_server
from a2a.client import delegate_enrich_ip
from agents import pipeline as p

client = TestClient(a2a_server.app)


def test_agent_card_advertises_supported_tasks():
    card = client.get("/a2a/agent-card").json()
    assert card["name"] == "threat-intel-agent"
    assert card["supported_tasks"] == ["enrich_ip"]


def test_enrich_ip_task_returns_structured_result():
    r = client.post("/a2a/tasks", json={
        "incident_id": "INC-T", "sender": "triage", "receiver": "threat-intel-agent",
        "task_type": "enrich_ip", "entity": "203.0.113.10",
    })
    body = r.json()
    assert r.status_code == 200
    assert body["status"] == "completed"
    assert body["sender"] == "threat-intel-agent"
    assert body["evidence"][0]["reputation"] == "malicious"
    assert body["confidence"] == 0.82


def test_unsupported_task_type_is_rejected():
    r = client.post("/a2a/tasks", json={
        "incident_id": "INC-T", "sender": "triage", "receiver": "threat-intel-agent",
        "task_type": "disable_account", "entity": "priya.sharma",
    })
    assert r.status_code == 400


def test_client_delegates_in_process_with_no_open_port():
    res = delegate_enrich_ip("203.0.113.10", "INC-T")
    assert res.status == "completed"
    assert res.confidence == 0.82
    assert "synthetic-feed-A" in res.sources


def test_unknown_ip_still_completes_as_unknown_not_failed():
    res = delegate_enrich_ip("203.0.113.250", "INC-T")
    assert res.status == "completed"
    assert res.evidence[0]["reputation"] == "unknown"


def test_pipeline_uses_a2a_for_threat_intel_when_enabled(monkeypatch):
    monkeypatch.setenv("A2A_ENABLED", "1")

    def fake(messages, model_cls, agent, incident_id="-", max_retries=1):
        if model_cls is p.TriagePlan:
            return p.TriagePlan(initial_severity="high", specialists=["threat_intel"], rationale="t")
        if model_cls is p.SpecialistOutput:
            return p.SpecialistOutput(summary=f"{agent} ok", findings=[])
        return p.IncidentNarrative(summary="n", findings=[], contradictions=[])

    monkeypatch.setattr(p, "complete_json", fake)
    out = p.investigate_multi("INC-T")
    evidence = out["specialists"]["threat_intel"]["evidence"]
    assert evidence[0]["evidence_id"] == "TI-1"
    assert "malicious" in evidence[0]["excerpt"]
    assert out["issues"] == []


def test_pipeline_ignores_a2a_by_default(monkeypatch):
    monkeypatch.delenv("A2A_ENABLED", raising=False)

    def fake(messages, model_cls, agent, incident_id="-", max_retries=1):
        if model_cls is p.TriagePlan:
            return p.TriagePlan(initial_severity="high", specialists=["threat_intel"], rationale="t")
        if model_cls is p.SpecialistOutput:
            return p.SpecialistOutput(summary=f"{agent} ok", findings=[])
        return p.IncidentNarrative(summary="n", findings=[], contradictions=[])

    monkeypatch.setattr(p, "complete_json", fake)
    out = p.investigate_multi("INC-T")
    assert "malicious" in out["specialists"]["threat_intel"]["evidence"][0]["excerpt"]