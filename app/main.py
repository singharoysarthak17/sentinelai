import uuid
from datetime import datetime, timezone

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from agents.orchestrator import investigate_full
from app.demo import DEMO_ALERT
from app.llm import ReplayMiss
from app.schemas import Alert
from guardrails.approval import approve, execute, get_action, list_actions, reject
from observability.trace import read_events, summarize, trace_for

app = FastAPI(title="SentinelAI")

_INCIDENTS: dict[str, dict] = {}  # in memory: a restart loses incidents


class AlertIn(BaseModel):
    title: str = Field(min_length=3, max_length=200)
    description: str = Field(min_length=3, max_length=2000)
    entities: list[str] = Field(min_length=1, max_length=10)


class ApprovalIn(BaseModel):
    approver: str = Field(min_length=2, max_length=64)  # self-reported in this demo
    reason: str = ""


def _create(alert: Alert) -> dict:
    incident_id = f"INC-{datetime.now(timezone.utc):%Y%m%d}-{uuid.uuid4().hex[:6]}"
    _INCIDENTS[incident_id] = {"incident_id": incident_id, "status": "submitted",
                               "alert": alert.model_dump(mode="json"), "result": None}
    return _INCIDENTS[incident_id]


def _incident(incident_id: str) -> dict:
    if incident_id not in _INCIDENTS:
        raise HTTPException(404, "unknown incident")
    return _INCIDENTS[incident_id]


def _action(action_id: str):
    try:
        return get_action(action_id)
    except KeyError:
        raise HTTPException(404, "unknown action")


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/incidents")
def submit_incident(body: AlertIn):
    alert = Alert(alert_id=f"ALR-{uuid.uuid4().hex[:6]}", title=body.title,
                  description=body.description, entities=body.entities,
                  created_at=datetime.now(timezone.utc))
    return _create(alert)


@app.post("/incidents/demo")
def submit_demo_incident():
    return _create(DEMO_ALERT)


@app.post("/incidents/{incident_id}/investigate")
def investigate(incident_id: str):
    inc = _incident(incident_id)
    try:
        result = investigate_full(incident_id, Alert(**inc["alert"]))
    except ReplayMiss as e:
        raise HTTPException(409, f"no recorded LLM response for this alert; run with live keys ({e})")
    except Exception as e:
        raise HTTPException(500, f"investigation failed: {type(e).__name__}")
    inc["result"], inc["status"] = result, result["status"]
    return inc


@app.get("/incidents/{incident_id}")
def get_incident(incident_id: str):
    inc = _incident(incident_id)
    actions = [a.model_dump(exclude={"approval_token"}) for a in list_actions(incident_id)]
    return {**inc, "actions": actions}


@app.get("/incidents/{incident_id}/trace")
def get_trace(incident_id: str):
    _incident(incident_id)
    events = trace_for(incident_id)
    return {"incident_id": incident_id, "summary": summarize(events), "events": events}


@app.get("/metrics")
def metrics():
    return summarize(read_events())


@app.post("/actions/{action_id}/approve")
def approve_action(action_id: str, body: ApprovalIn):
    _action(action_id)
    try:
        token = approve(action_id, body.approver)
        return execute(action_id, token).model_dump(exclude={"approval_token"})
    except PermissionError as e:
        raise HTTPException(403, str(e))
    except ValueError as e:
        raise HTTPException(409, str(e))


@app.post("/actions/{action_id}/reject")
def reject_action(action_id: str, body: ApprovalIn):
    _action(action_id)
    try:
        return reject(action_id, body.approver, body.reason).model_dump(exclude={"approval_token"})
    except ValueError as e:
        raise HTTPException(409, str(e))