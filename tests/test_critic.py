from agents import critic as c
from agents.pipeline import IncidentNarrative
from app.schemas import Evidence, Finding


def narrative(*findings):
    return IncidentNarrative(summary="s", findings=list(findings), contradictions=[])


FACT = Finding(statement="37 failed logins", kind="fact", evidence_ids=["LOG-1"], confidence=1.0)
MISSING = Finding(statement="no MFA data", kind="missing_evidence", evidence_ids=[], confidence=1.0)
EVID = [Evidence(evidence_id="LOG-1", source_type="log", source_ref="x",
                 excerpt="{}", trust_level="trusted")]


def hyp(conf):
    return Finding(statement="account compromised", kind="hypothesis",
                   evidence_ids=["LOG-1"], confidence=conf)


def test_overconfident_hypothesis_with_missing_evidence_blocks():
    issues = c.rule_checks(narrative(FACT, hyp(0.9), MISSING), EVID)
    assert any(i.severity == "blocking" for i in issues)


def test_calibrated_hypothesis_passes_rules():
    assert c.rule_checks(narrative(FACT, hyp(0.6), MISSING), EVID) == []


def test_unknown_citation_blocks():
    bad = Finding(statement="x", kind="fact", evidence_ids=["LOG-9"], confidence=1.0)
    assert c.rule_checks(narrative(bad), EVID)


def test_verdict_fails_only_on_blocking(monkeypatch):
    minor = c.CriticIssue(source="llm", severity="minor", problem="p", required_fix="f")
    monkeypatch.setattr(c, "llm_check", lambda *a, **k: [minor])
    assert c.review(narrative(FACT, MISSING), EVID, "INC-T").verdict == "pass"
    blocking = minor.model_copy(update={"severity": "blocking"})
    monkeypatch.setattr(c, "llm_check", lambda *a, **k: [blocking])
    assert c.review(narrative(FACT, MISSING), EVID, "INC-T").verdict == "fail"

import pytest
from pydantic import ValidationError


def test_rambling_critic_reason_is_rejected_by_schema():
    with pytest.raises(ValidationError):
        c.FactCheck(fact_index=0, supported=False, reason="x" * 300)


def test_unsupported_fact_becomes_blocking_and_supported_does_not(monkeypatch):
    ok = c.LLMCriticOutput(checks=[c.FactCheck(fact_index=0, supported=True, reason="ok")])
    monkeypatch.setattr(c, "complete_json", lambda *a, **k: ok)
    assert c.llm_check(narrative(FACT, MISSING), EVID, "INC-T") == []

    bad = c.LLMCriticOutput(checks=[c.FactCheck(fact_index=0, supported=False, reason="not in evidence")])
    monkeypatch.setattr(c, "complete_json", lambda *a, **k: bad)
    issues = c.llm_check(narrative(FACT, MISSING), EVID, "INC-T")
    assert len(issues) == 1 and issues[0].severity == "blocking"