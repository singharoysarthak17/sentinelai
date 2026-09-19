# SentinelAI
Multi-agent Security Operations Center assistant (portfolio project, synthetic data only).

## Status
Work in progress. Built so far: typed schemas, a permission-checked tool registry with an audit log,
guardrails and an approval gate, an LLM layer with a record/replay cache, a single-agent baseline,
and a multi-agent pipeline (triage, parallel specialists, investigator).
Coming: critic, risk and response agents, RAG, MCP/A2A, tracing, evals.

## Setup
    python -m venv .venv
    .venv\Scripts\Activate.ps1
    pip install -r requirements.txt
    Set-Content .env "LLM_PROVIDER=gemini`nGEMINI_MODEL=gemini-3.5-flash-lite`nLLM_MODE=replay"
    python data/generate.py
    python -m pytest -q

## Run without an API key
`LLM_MODE=replay` serves recorded LLM responses from `data/llm_cache`, so no key is needed.

    python -m agents.baseline
    python -m agents.pipeline
