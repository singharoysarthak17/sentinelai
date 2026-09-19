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

Coming: A2A agent service, a formal evaluation suite (beyond unit tests).


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

## Known limitations
Approver identity is self-reported (production needs authentication and role checks). Incidents are held in memory. Retrieval is lexical (BM25); a dense retriever is not built yet.
