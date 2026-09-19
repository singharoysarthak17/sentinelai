# SentinelAI
Multi-agent Security Operations Center assistant (portfolio project, synthetic data only).

## What it does
Takes a security alert, gathers evidence through permission-checked tools, has specialist agents analyse it, has a critic challenge the reasoning, scores risk with deterministic rules, and proposes response actions that must cite evidence and company policy. High-impact actions always wait for human approval.

## Built so far
- Typed schemas and a synthetic incident (37 failed logins, then a login from a new country and device)
- Tool registry with per-agent permissions, parameter validation and an audit log
- Guardrails: action risk classes L0-L4, approval gate with separation of duties, injection scan, secret redaction
- LLM layer with schema validation, retries and a record/replay cache
- Single-agent baseline and a multi-agent pipeline (triage, parallel specialists, investigator, critic with bounded rework)
- Deterministic risk scoring and a response planner constrained to an action catalog
- RAG over policy documents: BM25 retrieval, per-role access control, quarantine of poisoned documents, policy citations
- Tracing summary and a FastAPI service (incidents, trace, metrics, approvals)
- MCP server (`mcp_servers/security_mcp.py`) exposing the same permission-checked, audited tools over the Model Context Protocol — read-only (query_logs, build_timeline, lookup_ip, get_user, search_policy). No high-impact action is reachable this way; those stay behind the approval gate.
- A2A: the Threat Intel agent runs as an independent service (`a2a/server.py`) with its own agent card and a structured task/result message. Triage can delegate `enrich_ip` to it over real HTTP (`A2A_ENABLED=1`) instead of an in-process call — same evidence, same audit trail, different transport. In-process by default so tests stay fast; point `A2A_THREAT_INTEL_URL` at a real `uvicorn` process to run it as an actually-separate service.

Coming: a formal evaluation suite (beyond unit tests) - golden incidents, retrieval/groundedness metrics, regression scoring.


## Setup
    python -m venv .venv
    .venv\Scripts\Activate.ps1
    pip install -r requirements.txt
    Set-Content .env "LLM_PROVIDER=gemini`nGEMINI_MODEL=gemini-3.5-flash-lite`nLLM_MODE=replay"
    python data/generate.py
    python data/make_kb.py
    python -m pytest -q

## Run the API without an API key
`LLM_MODE=replay` serves recorded LLM responses from `data/llm_cache`.

    $env:LLM_MODE = "replay"
    uvicorn app.main:app

Open http://127.0.0.1:8000/docs, then: POST /incidents/demo, POST /incidents/{id}/investigate, POST /actions/{id}/approve, GET /incidents/{id}/trace.

## Run the MCP server
    python -m mcp_servers.security_mcp

Speaks stdio MCP, so it can be pointed to from Claude Desktop, `mcp dev`, or any MCP-compatible client/inspector. It exposes only the read-only tools (`query_logs`, `build_timeline`, `lookup_ip`, `get_user`, `search_policy`); every call still goes through the same permission check and audit log as the agents use internally.

## Run the A2A Threat Intel service
    uvicorn a2a.server:app --port 8100

Discover it: `curl http://localhost:8100/a2a/agent-card`. Delegate a task the same way Triage does:

    curl -X POST http://localhost:8100/a2a/tasks -H "Content-Type: application/json" -d "{\"incident_id\":\"INC-DEMO\",\"sender\":\"triage\",\"receiver\":\"threat-intel-agent\",\"task_type\":\"enrich_ip\",\"entity\":\"203.0.113.10\"}"

To make the full pipeline actually route through this service instead of an in-process call, set `A2A_ENABLED=1` (and, if the service is a separate process, `A2A_THREAT_INTEL_URL=http://localhost:8100`) before running `python -m agents.orchestrator` or the API.

## Known limitations
Approver identity is self-reported (production needs authentication and role checks). Incidents are held in memory. Retrieval is lexical (BM25); a dense retriever is not built yet.
