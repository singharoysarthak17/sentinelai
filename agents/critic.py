import json
from typing import Literal

from pydantic import BaseModel,Field

from agents.pipeline import IncidentNarrative, _evidence_text, _schema, check_grounding
from app.llm import complete_json
from app.schemas import Evidence
from guardrails.content import wrap_untrusted
from observability.audit import audit

MAX_UNCERTAIN_CONFIDENCE = 0.75


class CriticIssue(BaseModel):
    source: Literal["rule", "llm"]
    severity: Literal["blocking", "minor"]
    problem: str
    required_fix: str


class CriticVerdict(BaseModel):
    verdict: Literal["pass", "fail"]
    issues: list[CriticIssue]








def rule_checks(narrative: IncidentNarrative, evidence: list[Evidence]) -> list[CriticIssue]:
    issues: list[CriticIssue] = []
    known = {e.evidence_id for e in evidence}
    for msg in check_grounding(narrative.findings, known, "narrative"):
        issues.append(CriticIssue(source="rule", severity="blocking", problem=msg,
                                  required_fix="cite only evidence ids that exist"))
    if any(f.kind == "missing_evidence" for f in narrative.findings):
        for f in narrative.findings:
            if f.kind == "hypothesis" and f.confidence > MAX_UNCERTAIN_CONFIDENCE:
                issues.append(CriticIssue(
                    source="rule", severity="blocking",
                    problem=(f"hypothesis stated at confidence {f.confidence} while material "
                             f"evidence is missing: {f.statement[:80]}"),
                    required_fix=(f"lower the confidence to {MAX_UNCERTAIN_CONFIDENCE} or less, "
                                  "or state what evidence closes the gap")))
    return issues


class FactCheck(BaseModel):
    fact_index: int
    supported: bool
    # One short sentence. A rambling reply fails validation and triggers the retry loop.
    reason: str = Field(max_length=200)


class LLMCriticOutput(BaseModel):
    checks: list[FactCheck]


def llm_check(narrative: IncidentNarrative, evidence: list[Evidence],
              incident_id: str) -> list[CriticIssue]:
    by_id = {e.evidence_id: e for e in evidence}
    facts = [f for f in narrative.findings if f.kind == "fact"]
    if not facts:
        return []
    blocks = []
    for n, f in enumerate(facts):
        cited = "\n".join(f"  [{i}] {by_id[i].excerpt}" for i in f.evidence_ids if i in by_id)
        blocks.append(f"FACT {n}: {f.statement}\n  CITED EVIDENCE:\n{cited}")
    joined = "\n\n".join(blocks)

    system = ("You are the Critic in a SOC. You did not write these facts. For each FACT, decide "
              "whether the cited evidence supports what the statement asserts. "
              "Set supported=false ONLY if the statement asserts something that the cited evidence "
              "does not contain or that it contradicts. Leaving out extra detail is NOT a problem: "
              "supported stays true. Give one short sentence as the reason and no other commentary. "
              "Output JSON only.")
    user = f"{wrap_untrusted(joined, 'facts-and-evidence')}\n\n{_schema(LLMCriticOutput)}"
    out = complete_json([{"role": "system", "content": system},
                         {"role": "user", "content": user}],
                        LLMCriticOutput, agent="critic", incident_id=incident_id)

    issues = []
    for chk in out.checks:
        if 0 <= chk.fact_index < len(facts) and not chk.supported:
            f = facts[chk.fact_index]
            issues.append(CriticIssue(
                source="llm", severity="blocking",
                problem=f"{f.statement[:80]}: {chk.reason}",
                required_fix="rewrite the statement so the cited evidence supports it, "
                             "or cite better evidence"))
    return issues

def review(narrative: IncidentNarrative, evidence: list[Evidence],
           incident_id: str) -> CriticVerdict:
    issues = rule_checks(narrative, evidence) + llm_check(narrative, evidence, incident_id)
    # The verdict is computed in code, never taken from the LLM.
    verdict = "fail" if any(i.severity == "blocking" for i in issues) else "pass"
    audit({"event": "critic_verdict", "incident_id": incident_id, "verdict": verdict,
           "blocking": sum(i.severity == "blocking" for i in issues), "total": len(issues)})
    return CriticVerdict(verdict=verdict, issues=issues)


def format_feedback(verdict: CriticVerdict) -> str:
    return "\n".join(f"- {i.problem} -> {i.required_fix}"
                     for i in verdict.issues if i.severity == "blocking")