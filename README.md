# SentinelAI

**Multi-agent Security Operations Center (SOC) assistant** for security alert investigation.

> Portfolio project using **synthetic data only**.

## What it does

SentinelAI takes a security alert, gathers evidence through permission-checked tools, and has specialist agents analyze it.

The pipeline includes:

* **Triage** to determine the initial severity and select specialist agents
* **Parallel specialist agents** for threat intelligence, log analysis, and identity/asset analysis
* **Investigation** to combine evidence into a grounded incident narrative
* **Critic review** to challenge unsupported reasoning and request bounded rework
* **Deterministic risk scoring** with explicit reasons
* **Response planning** constrained to a controlled action catalog
* **Guardrails** for tool access, action risk, prompt injection, and secret handling
* **Human approval** for high-impact actions
* **Audit logging and tracing** across the investigation

Every finding is expected to cite supporting evidence, and policy-sensitive response actions must be grounded in company policy.

## Built so far

* Typed schemas and a synthetic incident containing **37 failed logins followed by a login from a new country and device**
* Tool registry with:

  * Per-agent permissions
  * Parameter validation
  * Audited tool calls
* Guardrails:

  * Action risk classes **L0-L4**
  * Approval gate with separation of duties
  * Prompt-injection scanning
  * Secret redaction
* LLM layer with:

  * Schema validation
  * Retries
  * Record/replay cache
* Single-agent baseline and multi-agent pipeline:

  * Triage
  * Parallel specialists
  * Investigator
  * Critic with bounded rework
* Deterministic risk scoring
* Response planner constrained to an action catalog
* RAG over policy documents:

  * BM25 retrieval
  * Per-role access control
  * Poisoned-document quarantine
  * Policy citations
* Tracing summary and FastAPI service with:

  * Incidents
  * Trace
  * Metrics
  * Approvals
* MCP server at `mcp_servers/security_mcp.py` exposing the same permission-checked and audited tools over the **Model Context Protocol**

  * Read-only tools:

    * `query_logs`
    * `build_timeline`
    * `lookup_ip`
    * `get_user`
    * `search_policy`
  * No high-impact action is reachable through MCP; those actions remain behind the approval gate
* A2A support:

  * The Threat Intel agent can run as an independent service at `a2a/server.py`
  * Includes its own agent card and structured task/result message
  * Triage can delegate `enrich_ip` over real HTTP when `A2A_ENABLED=1`
  * Uses the same evidence and audit trail, but a different transport
  * In-process mode remains the default so tests stay fast
  * Set `A2A_THREAT_INTEL_URL` to a running `uvicorn` service to use a separate process

### Coming next

A formal evaluation suite beyond unit tests:

* Golden incidents
* Retrieval and groundedness metrics
* Regression scoring

## Setup

Create and activate a virtual environment:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
```

Install dependencies:

```powershell
pip install -r requirements.txt
```

Create a `.env` file for replay mode:

```powershell
@"
LLM_PROVIDER=gemini
GEMINI_MODEL=gemini-3.5-flash-lite
LLM_MODE=replay
"@ | Set-Content .env
```

Generate the synthetic data and policy knowledge base:

```powershell
python data/generate.py
python data/make_kb.py
```

Run the tests:

```powershell
python -m pytest -q
```

## Run the API without an API key

`LLM_MODE=replay` serves recorded LLM responses from `data/llm_cache`.

PowerShell:

```powershell
$env:LLM_MODE = "replay"
uvicorn app.main:app
```

Open the FastAPI documentation:

**http://127.0.0.1:8000/docs**

Available endpoints include:

* `POST /incidents/demo`
* `POST /incidents/{id}/investigate`
* `POST /actions/{id}/approve`
* `GET /incidents/{id}/trace`

## Run the MCP server

Start the MCP server:

```powershell
python -m mcp_servers.security_mcp
```

The server speaks **stdio MCP**, so it can be connected to Claude Desktop, `mcp dev`, or another MCP-compatible client/inspector.

It exposes only the following read-only tools:

* `query_logs`
* `build_timeline`
* `lookup_ip`
* `get_user`
* `search_policy`

Every MCP call still goes through the same permission checks and audit logging used by the internal agent tools.

High-impact actions are **not exposed through MCP** and remain behind the approval gate.

## Run the A2A Threat Intel service

Start the Threat Intel agent as a separate service:

```powershell
uvicorn a2a.server:app --port 8100
```

Discover the agent:

```powershell
curl http://localhost:8100/a2a/agent-card
```

Delegate a task:

```powershell
curl -X POST http://localhost:8100/a2a/tasks `
  -H "Content-Type: application/json" `
  -d '{"incident_id":"INC-DEMO","sender":"triage","receiver":"threat-intel-agent","task_type":"enrich_ip","entity":"203.0.113.10"}'
```

To make the full pipeline route Threat Intel requests through this separate service instead of using the in-process implementation, enable A2A:

```powershell
$env:A2A_ENABLED = "1"
$env:A2A_THREAT_INTEL_URL = "http://localhost:8100"
```

Then run the orchestrator or API normally:

```powershell
python -m agents.orchestrator
```

or:

```powershell
uvicorn app.main:app
```

## Security design

SentinelAI is designed around **least privilege, evidence grounding, and human control**.

### Tool permissions

Each agent can access only the tools explicitly assigned to it.

### Evidence grounding

Findings must reference evidence IDs, and unsupported evidence references are detected by deterministic checks.

### Untrusted data

Tool output and other external content are treated as data rather than instructions and are wrapped before being passed to the model.

### Action controls

Response actions are classified by risk level:

```text
L0 → Low/no-impact action
L1 → Low-risk action
L2 → Moderate-risk action
L3 → High-impact action requiring approval
L4 → Prohibited action
```

High-impact actions never bypass the approval gate.

## Demo scenario

The current synthetic incident represents a suspicious account-login pattern:

```text
37 failed login attempts
        ↓
Successful login
        ↓
New country
        ↓
New device
        ↓
Threat-intelligence check on source IP
        ↓
Investigation
        ↓
Critic review
        ↓
Deterministic risk scoring
        ↓
Recommended response
        ↓
Human approval for high-impact actions
```

The demo uses synthetic data only and does not connect to real user accounts or production security infrastructure.

## Known limitations

* Approver identity is currently self-reported. Production use would require authentication and role-based approval checks.
* Incidents are currently held in memory.
* Retrieval currently uses **BM25 lexical search**; a dense retriever has not yet been built.
* The formal evaluation suite is still planned and will extend beyond the current unit tests.

## Project status

The current implementation includes the core multi-agent investigation pipeline, guardrails, deterministic risk scoring, policy RAG, FastAPI service, MCP integration, and A2A support.

The next stage is to strengthen the evaluation and retrieval layers with formal benchmarks, groundedness metrics, and regression testing.

