import secrets
import uuid
from typing import Literal, Optional

from pydantic import BaseModel

from guardrails.policy import decide
from observability.audit import audit

Status = Literal["executed", "pending_approval", "approved", "rejected", "denied"]


class ActionRequest(BaseModel):
    action_id: str
    incident_id: str
    action_type: str
    requested_by: str
    parameters: dict
    risk_class: Optional[int] = None
    status: Status
    reason: str
    approval_token: Optional[str] = None
    approved_by: Optional[str] = None


_ACTIONS: dict[str, ActionRequest] = {}


def _log(event: str, req: ActionRequest, actor: str, **extra) -> None:
    audit({"event": event, "action_id": req.action_id, "incident_id": req.incident_id,
           "action_type": req.action_type, "actor": actor, "status": req.status, **extra})


def _get(action_id: str) -> ActionRequest:
    if action_id not in _ACTIONS:
        raise KeyError(f"unknown action '{action_id}'")
    return _ACTIONS[action_id]


def _simulate(req: ActionRequest) -> None:
    # Portfolio scope: nothing real is ever changed.
    req.status = "executed"
    _log("action_executed", req, actor="system", simulated=True)


def request_action(incident_id: str, requester: str, action_type: str,
                   parameters: Optional[dict] = None) -> ActionRequest:
    d = decide(requester, action_type)
    status = {"deny": "denied", "require_approval": "pending_approval", "allow": "approved"}[d.outcome]
    req = ActionRequest(action_id=f"ACT-{uuid.uuid4().hex[:8]}", incident_id=incident_id,
                        action_type=action_type, requested_by=requester,
                        parameters=parameters or {}, risk_class=d.risk_class,
                        status=status, reason=d.reason)
    _ACTIONS[req.action_id] = req
    _log("action_requested", req, actor=requester, reason=d.reason)
    if d.outcome == "allow":
        _simulate(req)
    return req


def approve(action_id: str, approver: str) -> str:
    req = _get(action_id)
    if req.status != "pending_approval":
        raise ValueError(f"action is '{req.status}', not pending approval")
    if approver == req.requested_by:
        raise PermissionError("separation of duties: requester cannot approve own action")
    req.approval_token = uuid.uuid4().hex
    req.approved_by = approver
    req.status = "approved"
    _log("action_approved", req, actor=approver)
    return req.approval_token


def reject(action_id: str, approver: str, reason: str = "") -> ActionRequest:
    req = _get(action_id)
    if req.status != "pending_approval":
        raise ValueError(f"action is '{req.status}', not pending approval")
    req.status = "rejected"
    _log("action_rejected", req, actor=approver, reason=reason)
    return req


def execute(action_id: str, token: str) -> ActionRequest:
    req = _get(action_id)
    ok = (req.status == "approved" and req.approval_token is not None
          and secrets.compare_digest(token, req.approval_token))
    if not ok:
        _log("execute_refused", req, actor="system")
        raise PermissionError("valid approval token required")
    _simulate(req)
    return req