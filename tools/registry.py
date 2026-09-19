import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional

from pydantic import BaseModel, ValidationError

from observability.audit import AUDIT_FILE, audit as _audit

class ToolResult(BaseModel):
    ok: bool
    tool: str
    agent: str
    incident_id: str
    data: Any = None
    error: Optional[str] = None


_TOOLS: dict[str, tuple[Callable, type[BaseModel]]] = {}

# Least privilege: each agent may call only the tools listed here.
PERMISSIONS: dict[str, set[str]] = {
    "triage": {"get_user"},
    "threat_intel": {"lookup_ip"},
    "log_analysis": {"query_logs", "build_timeline"},
    "asset_identity": {"get_user"},
    "investigation": {"query_logs", "get_user", "lookup_ip", "build_timeline"},
    "response": {"search_policy"},
}


def tool(name: str, params_model: type[BaseModel]):
    def wrap(fn: Callable):
        _TOOLS[name] = (fn, params_model)
        return fn
    return wrap





def call_tool(agent: str, incident_id: str, name: str, **params) -> ToolResult:
    started = time.perf_counter()
    base = dict(tool=name, agent=agent, incident_id=incident_id)

    if name not in _TOOLS:
        result = ToolResult(ok=False, error="unknown tool", **base)
    elif name not in PERMISSIONS.get(agent, set()):
        result = ToolResult(ok=False, error=f"agent '{agent}' is not authorized to call '{name}'", **base)
    else:
        fn, model = _TOOLS[name]
        try:
            args = model(**params)
            result = ToolResult(ok=True, data=fn(args), **base)
        except ValidationError as e:
            result = ToolResult(ok=False, error=f"invalid parameters ({e.error_count()} error(s))", **base)
        except Exception as e:
            result = ToolResult(ok=False, error=str(e), **base)

    _audit({
        "ts": datetime.now(timezone.utc).isoformat(),
        "agent": agent,
        "incident_id": incident_id,
        "tool": name,
        "params": params,
        "ok": result.ok,
        "error": result.error,
        "latency_ms": round((time.perf_counter() - started) * 1000, 2),
    })
    return result