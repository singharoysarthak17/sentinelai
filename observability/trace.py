import json

from observability.audit import AUDIT_FILE


def read_events() -> list[dict]:
    if not AUDIT_FILE.exists():
        return []
    events = []
    for line in AUDIT_FILE.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            continue  # a torn line must never take down the trace endpoint
    return events


def trace_for(incident_id: str) -> list[dict]:
    return [e for e in read_events() if e.get("incident_id") == incident_id]


def summarize(events: list[dict]) -> dict:
    by_agent: dict[str, dict] = {}

    def agent(name):
        return by_agent.setdefault(name or "unknown", {
            "llm_calls": 0, "cached": 0, "input_tokens": 0, "output_tokens": 0,
            "live_latency_s": 0.0, "tool_calls": 0, "tools_denied": 0})

    out = {"schema_retries": 0, "guardrail_trips": 0, "critic_verdicts": [], "actions": {}}
    for e in events:
        kind = e.get("event")
        if kind == "llm_call":
            a = agent(e.get("agent"))
            a["llm_calls"] += 1
            a["cached"] += 1 if e.get("cached") else 0
            a["input_tokens"] += e.get("input_tokens") or 0
            a["output_tokens"] += e.get("output_tokens") or 0
            if not e.get("cached"):  # replayed calls cost no time
                a["live_latency_s"] += e.get("latency_s") or 0
        elif kind is None and "tool" in e:  # tool-call records have no "event" key
            a = agent(e.get("agent"))
            a["tool_calls"] += 1
            if not e.get("ok") and "not authorized" in (e.get("error") or ""):
                a["tools_denied"] += 1
        elif kind == "schema_retry":
            out["schema_retries"] += 1
        elif kind == "guardrail_trip":
            out["guardrail_trips"] += 1
        elif kind == "critic_verdict":
            out["critic_verdicts"].append(e.get("verdict"))
        elif kind and (kind.startswith("action_") or kind == "execute_refused"):
            out["actions"][kind] = out["actions"].get(kind, 0) + 1

    out["by_agent"] = by_agent
    out["totals"] = {
        "llm_calls": sum(a["llm_calls"] for a in by_agent.values()),
        "cached_calls": sum(a["cached"] for a in by_agent.values()),
        "input_tokens": sum(a["input_tokens"] for a in by_agent.values()),
        "output_tokens": sum(a["output_tokens"] for a in by_agent.values()),
        "tool_calls": sum(a["tool_calls"] for a in by_agent.values()),
    }
    return out