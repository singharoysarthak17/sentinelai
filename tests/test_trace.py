from observability.trace import summarize

EVENTS = [
    {"event": "llm_call", "agent": "triage", "cached": False,
     "input_tokens": 100, "output_tokens": 50, "latency_s": 2.0},
    {"event": "llm_call", "agent": "triage", "cached": True,
     "input_tokens": 100, "output_tokens": 50, "latency_s": 2.0},
    {"agent": "log_analysis", "tool": "query_logs", "ok": True, "error": None},
    {"agent": "threat_intel", "tool": "query_logs", "ok": False,
     "error": "agent 'threat_intel' is not authorized to call 'query_logs'"},
    {"event": "schema_retry"},
    {"event": "guardrail_trip"},
    {"event": "critic_verdict", "verdict": "fail"},
    {"event": "critic_verdict", "verdict": "pass"},
    {"event": "action_requested"},
    {"event": "action_approved"},
]


def test_summary_counts_and_ignores_cached_latency():
    s = summarize(EVENTS)
    t = s["by_agent"]["triage"]
    assert t["llm_calls"] == 2 and t["cached"] == 1
    assert t["live_latency_s"] == 2.0 and t["input_tokens"] == 200
    assert s["by_agent"]["threat_intel"]["tools_denied"] == 1
    assert s["schema_retries"] == 1 and s["guardrail_trips"] == 1
    assert s["critic_verdicts"] == ["fail", "pass"]
    assert s["actions"] == {"action_requested": 1, "action_approved": 1}
    assert s["totals"]["llm_calls"] == 2

import json
import threading

from observability import audit as audit_mod
from observability import trace


def test_reader_skips_corrupt_lines(tmp_path, monkeypatch):
    f = tmp_path / "audit.jsonl"
    f.write_text('{"event": "schema_retry"}\n: 1.32}\n{"event": "guardrail_trip"}\n',
                 encoding="utf-8")
    monkeypatch.setattr(trace, "AUDIT_FILE", f)
    assert [e["event"] for e in trace.read_events()] == ["schema_retry", "guardrail_trip"]


def test_parallel_audit_writes_never_tear_lines(tmp_path, monkeypatch):
    f = tmp_path / "audit.jsonl"
    monkeypatch.setattr(audit_mod, "AUDIT_FILE", f)

    def work(n):
        for i in range(50):
            audit_mod.audit({"event": "x", "n": n, "i": i, "pad": "y" * 200})

    threads = [threading.Thread(target=work, args=(n,)) for n in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    lines = f.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 400
    assert all(json.loads(line)["event"] == "x" for line in lines)