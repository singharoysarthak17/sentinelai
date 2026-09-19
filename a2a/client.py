from __future__ import annotations

import os

import httpx

from a2a.schemas import AgentResult, AgentTask


def _client():
    url = os.getenv("A2A_THREAT_INTEL_URL")
    if url:
        return httpx.Client(base_url=url, timeout=10.0), True
    # In-process path: ASGITransport is async-only, so for a plain sync
    # call we reuse Starlette's TestClient, which runs the ASGI app
    # under the hood via an anyio portal. Same request/response shape
    # as a real HTTP call - the caller can't tell the difference.
    from fastapi.testclient import TestClient
    from a2a.server import app
    return TestClient(app), False


def delegate_enrich_ip(ip: str, incident_id: str, requested_by: str = "triage",
                        deadline_ms: int = 5000) -> AgentResult:
    task = AgentTask(incident_id=incident_id, sender=requested_by,
                      receiver="threat-intel-agent", task_type="enrich_ip",
                      entity=ip, deadline_ms=deadline_ms)
    client, is_remote = _client()
    kwargs = {"timeout": deadline_ms / 1000} if is_remote else {}
    try:
        r = client.post("/a2a/tasks", json=task.model_dump(mode="json"), **kwargs)
    except httpx.TimeoutException:
        return AgentResult(task_id=task.task_id, incident_id=incident_id,
                            sender="threat-intel-agent", status="timeout",
                            error=f"no response within {deadline_ms}ms")
    except httpx.HTTPError as e:
        return AgentResult(task_id=task.task_id, incident_id=incident_id,
                            sender="threat-intel-agent", status="failed", error=str(e))
    finally:
        client.close()

    if r.status_code != 200:
        return AgentResult(task_id=task.task_id, incident_id=incident_id,
                            sender="threat-intel-agent", status="failed",
                            error=f"HTTP {r.status_code}: {r.text[:200]}")
    return AgentResult(**r.json())