from agents import pipeline as pl
from agents.critic import format_feedback, review
from agents.response import run_response
from agents.risk import assess_from_specialists
from app.demo import DEMO_ALERT
from app.schemas import Alert, Evidence, Finding

MAX_REWORKS = 1


def _rebuild(specialists: dict) -> list[dict]:
    return [{"agent": name,
             "evidence": [Evidence(**e) for e in s["evidence"]],
             "output": pl.SpecialistOutput(summary=s["summary"],
                                           findings=[Finding(**f) for f in s["findings"]])}
            for name, s in specialists.items()]


def investigate_full(incident_id: str = "INC-DEMO-001", alert: Alert = DEMO_ALERT) -> dict:
    out = pl.investigate_multi(incident_id, alert)
    results = _rebuild(out["specialists"])
    evidence = [e for r in results for e in r["evidence"]]
    narrative = pl.IncidentNarrative(**out["narrative"])

    verdict = review(narrative, evidence, incident_id)
    reviews = [verdict.model_dump()]
    reworks = 0
    while verdict.verdict == "fail" and reworks < MAX_REWORKS:
        reworks += 1
        narrative = pl.run_investigation(alert, incident_id, results,
                                         feedback=format_feedback(verdict))
        verdict = review(narrative, evidence, incident_id)
        reviews.append(verdict.model_dump())

    status = "complete" if verdict.verdict == "pass" else "needs_human_review"
    risk = assess_from_specialists(out["specialists"])
    if status == "complete":
        response = run_response(narrative.model_dump(), risk, incident_id,
                                {e.evidence_id for e in evidence})
    else:
        response = {"skipped": "critic did not approve the narrative; escalated to a human"}
    return {**out, "narrative": narrative.model_dump(), "reviews": reviews,
            "reworks": reworks, "status": status, "risk": risk.model_dump(),
            "response": response}


def _show(res: dict) -> None:
    print("STATUS:", res["status"], "| reworks:", res["reworks"])
    for n, r in enumerate(res["reviews"], 1):
        print(f"CRITIC review {n}: {r['verdict']}")
        for i in r["issues"]:
            print(f"   [{i['severity']}/{i['source']}] {i['problem']} -> {i['required_fix']}")
    nar = res["narrative"]
    print("\nNARRATIVE:", nar["summary"])
    for f in nar["findings"]:
        print(f"  [{f['kind']}] ({f['confidence']}) {f['statement']}  cites={f['evidence_ids']}")
    rk = res["risk"]
    print(f"\nRISK: {rk['severity']} (score {rk['score']}) escalate={rk['requires_escalation']}")
    for reason in rk["reasons"]:
        print("   ", reason)
    resp = res["response"]
    print("\nRESPONSE:", resp.get("skipped", ""))
    if resp.get("policy_chunks"):
        print("   retrieved policy:", [c["chunk_id"] for c in resp["policy_chunks"]])
    for a in resp.get("requests", []):
        print(f"   {a['action_id']}: {a['action_type']} -> {a['status']} "
              f"(policy={a['parameters'].get('policy_ids')})")
    for d in resp.get("dropped", []):
        print("   dropped:", d["action"]["action_type"], "-", d["reason"])


if __name__ == "__main__":
    _show(investigate_full())