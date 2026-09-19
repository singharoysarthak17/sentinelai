"""Runs as an independently deployable service reachable over HTTP: any
A2A-compatible caller (SentinelAI's own Triage agent, or in principle a
completely different agent framework) POSTs a structured task here and
gets back a structured result, the exact delegation example in Section 5:

    Triage Agent -> Threat Intel Agent: "Enrich this IP and return
    reputation, related indicators, confidence, and sources within
    5 seconds."

This deliberately calls the deterministic tool registry directly rather
than an LLM: enrichment is a lookup, not a reasoning task, so the demo
needs no LLM cache entry and no API key to run this service standalone.

Run standalone:
    uvicorn a2a.server:app --port 8100

Discover it:
    curl http://localhost:8100/a2a/agent-card
"""
from __future__ import annotations

from fastapi import FastAPI, HTTPException

from a2a.schemas import AgentResult, AgentTask
from observability.audit import audit
from tools.registry import call_tool

app = FastAPI(title="SentinelAI A2A - Threat Intel Agent")

RECEIVER = "threat-intel-agent"    # this agent's identity on the A2A network
TOOL_AGENT = "threat_intel"         # this agent's identity in tools/registry.py's PERMISSIONS
SUPPORTED_TASKS = {"enrich_ip"}


@app.get("/a2a/agent-card")
def agent_card() -> dict:
    """Minimal agent discovery card: who this agent is and what it can do,
    without exposing its internal tools, memory, or prompts."""
    return {
        "name": RECEIVER,
        "description": "Enriches IP indicators with threat-intel reputation, confidence, and sources.",
        "supported_tasks": sorted(SUPPORTED_TASKS),
    }


@app.post("/a2a/tasks", response_model=AgentResult)
def handle_task(task: AgentTask) -> AgentResult:
    audit({"event": "a2a_task_received", "task_id": task.task_id,
           "incident_id": task.incident_id, "sender": task.sender,
           "receiver": task.receiver, "task_type": task.task_type})

    if task.task_type not in SUPPORTED_TASKS:
        raise HTTPException(400, f"unsupported task_type '{task.task_type}'; "
                                  f"this agent handles {sorted(SUPPORTED_TASKS)}")

    # Never trust a remote sender's claim blindly (Section 8's design rule) -
    # go through the same permission-checked, audited tool call the
    # in-process specialist agent would use.
    result = call_tool(TOOL_AGENT, task.incident_id, "lookup_ip", ip=task.entity)

    if not result.ok:
        audit({"event": "a2a_task_failed", "task_id": task.task_id, "error": result.error})
        return AgentResult(task_id=task.task_id, incident_id=task.incident_id,
                            sender=RECEIVER, status="failed", error=result.error)

    data = result.data
    return AgentResult(task_id=task.task_id, incident_id=task.incident_id,
                        sender=RECEIVER, status="completed",
                        evidence=[data], confidence=data.get("confidence"),
                        sources=data.get("sources", []))