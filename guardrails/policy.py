from enum import IntEnum
from typing import Literal, Optional

from pydantic import BaseModel


class RiskClass(IntEnum):
    L0 = 0  # informational
    L1 = 1  # read-only enrichment
    L2 = 2  # reversible / simulated
    L3 = 3  # high impact
    L4 = 4  # destructive


ACTION_CATALOG: dict[str, RiskClass] = {
    "summarize_alert": RiskClass.L0,
    "enrich_indicator": RiskClass.L1,
    "create_ticket": RiskClass.L2,
    "block_ip_simulation": RiskClass.L2,
    "quarantine_simulation": RiskClass.L2,
    "disable_account": RiskClass.L3,
    "block_ip_production": RiskClass.L3,
    "delete_data": RiskClass.L4,
}

# Which agent may even *request* which action.
ACTION_PERMISSIONS: dict[str, set[str]] = {
    "triage": {"summarize_alert"},
    "response": {"create_ticket", "block_ip_simulation", "quarantine_simulation",
                 "disable_account", "block_ip_production"},
}


class Decision(BaseModel):
    outcome: Literal["allow", "require_approval", "deny"]
    risk_class: Optional[int] = None
    reason: str


def decide(requester: str, action_type: str) -> Decision:
    risk = ACTION_CATALOG.get(action_type)
    if risk is None:
        return Decision(outcome="deny", reason="unknown action (default deny)")
    if risk == RiskClass.L4:
        return Decision(outcome="deny", risk_class=int(risk), reason="L4 actions are prohibited")
    if action_type not in ACTION_PERMISSIONS.get(requester, set()):
        return Decision(outcome="deny", risk_class=int(risk),
                        reason=f"agent '{requester}' may not request '{action_type}'")
    if risk >= RiskClass.L3:
        return Decision(outcome="require_approval", risk_class=int(risk),
                        reason="L3 action requires human approval")
    return Decision(outcome="allow", risk_class=int(risk), reason="within automatic policy")