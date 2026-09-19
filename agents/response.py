import json
from typing import Literal

from pydantic import BaseModel, model_validator

from agents.pipeline import _schema
from agents.risk import RiskAssessment
from app.llm import complete_json
from guardrails.approval import request_action
from observability.audit import audit

ActionName = Literal["create_ticket", "block_ip_simulation", "quarantine_simulation",
                     "disable_account", "block_ip_production"]


class ProposedAction(BaseModel):
    action_type: ActionName
    target: str
    justification: str
    evidence_ids: list[str]

    @model_validator(mode="after")
    def needs_evidence(self):
        if not self.evidence_ids:
            raise ValueError("a proposed action must cite evidence_ids")
        return self


class ResponsePlan(BaseModel):
    actions: list[ProposedAction]


SYSTEM = """You are the response planner in a SOC. Propose actions ONLY from the allowed action types.
create_ticket, block_ip_simulation and quarantine_simulation are simulated and reversible.
disable_account and block_ip_production are high impact and need human approval.
You cannot execute anything: every proposal goes through a policy engine.
Prefer the least disruptive action that addresses the evidence. For low severity, propose only a ticket.
Every action must cite evidence ids that appear in the narrative findings.
Output JSON only."""


def run_response(narrative: dict, risk: RiskAssessment, incident_id: str,
                 known_ids: set[str]) -> dict:
    user = (f"RISK ASSESSMENT (computed by policy code, not negotiable):\n{risk.model_dump_json()}\n\n"
            f"INCIDENT NARRATIVE:\n{json.dumps(narrative)}\n\n{_schema(ResponsePlan)}")
    plan = complete_json([{"role": "system", "content": SYSTEM},
                          {"role": "user", "content": user}],
                         ResponsePlan, agent="response", incident_id=incident_id)
    requests, dropped = [], []
    for a in plan.actions:
        unknown = [i for i in a.evidence_ids if i not in known_ids]
        if unknown:
            dropped.append({"action": a.model_dump(), "reason": f"cites unknown evidence {unknown}"})
            audit({"event": "proposal_dropped", "incident_id": incident_id,
                   "action_type": a.action_type, "unknown_evidence": unknown})
            continue
        req = request_action(incident_id, "response", a.action_type,
                             {"target": a.target, "justification": a.justification,
                              "evidence_ids": a.evidence_ids})
        requests.append(req.model_dump())
    return {"plan": plan.model_dump(), "requests": requests, "dropped": dropped}