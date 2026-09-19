import json
from typing import Literal

from pydantic import BaseModel


class RiskAssessment(BaseModel):
    score: int
    severity: Literal["low", "medium", "high", "critical"]
    reasons: list[str]
    requires_escalation: bool


THRESHOLDS = [(9, "critical"), (6, "high"), (3, "medium"), (0, "low")]
BURST_MIN_FAILURES = 10
MALICIOUS_MIN_CONFIDENCE = 0.7


def assess_risk(timeline: list[dict], user: dict, intel: list[dict]) -> RiskAssessment:
    score, reasons = 0, []

    bursts = [r for r in timeline
              if r["type"] == "login_failed" and r["count"] >= BURST_MIN_FAILURES]
    if bursts:
        score += 2
        reasons.append(f"+2 burst of {max(r['count'] for r in bursts)} failed logins")

    takeover = any(
        s["type"] == "login_success" and s["indicator"] == b["indicator"]
        and s["first_seen"] >= b["last_seen"]
        for b in bursts for s in timeline)
    if takeover:
        score += 3
        reasons.append("+3 successful login from the same source right after the failures")

    known = set(user.get("known_devices", []))
    successes = [r for r in timeline if r["type"] == "login_success"]
    if successes:
        latest = successes[-1]
        if latest["device_id"] not in known or latest["geo"] != user.get("usual_geo"):
            score += 2
            reasons.append("+2 latest successful login is from an unrecognised device or unusual location")

    if any(i.get("reputation") == "malicious"
           and i.get("confidence", 0) >= MALICIOUS_MIN_CONFIDENCE for i in intel):
        score += 2
        reasons.append("+2 source IP has a malicious reputation")

    if "admin" in user.get("role", ""):
        score += 2
        reasons.append("+2 privileged account (admin role)")

    severity = next(name for floor, name in THRESHOLDS if score >= floor)
    return RiskAssessment(score=score, severity=severity, reasons=reasons,
                          requires_escalation=severity in ("high", "critical"))


def assess_from_specialists(specialists: dict) -> RiskAssessment:
    def excerpts(agent: str, tool: str) -> list:
        return [json.loads(e["excerpt"])
                for e in specialists.get(agent, {}).get("evidence", [])
                if e["source_ref"].startswith(tool + ":")]

    timeline = next(iter(excerpts("log_analysis", "build_timeline")), [])
    user = next(iter(excerpts("asset_identity", "get_user")), {})
    intel = excerpts("threat_intel", "lookup_ip")
    return assess_risk(timeline, user, intel)