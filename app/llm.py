import hashlib
import json
import os
import re
import time
from pathlib import Path
from typing import Type, TypeVar

from dotenv import load_dotenv
from openai import OpenAI
from pydantic import BaseModel, ValidationError

from observability.audit import audit

load_dotenv()

T = TypeVar("T", bound=BaseModel)
CACHE_DIR = Path(__file__).resolve().parents[1] / "data" / "llm_cache"

PROVIDERS = {
    "gemini": ("https://generativelanguage.googleapis.com/v1beta/openai/", "GEMINI_API_KEY", "GEMINI_MODEL"),
    "groq": ("https://api.groq.com/openai/v1", "GROQ_API_KEY", "GROQ_MODEL"),
}


class ReplayMiss(RuntimeError):
    """Replay mode was on but no recorded response exists for this prompt."""


def _provider() -> str:
    return os.getenv("LLM_PROVIDER", "gemini")


def _mode() -> str:
    return os.getenv("LLM_MODE", "live")  # live | replay


def _call_provider(provider: str, messages: list[dict]) -> dict:
    base_url, key_var, model_var = PROVIDERS[provider]
    client = OpenAI(base_url=base_url, api_key=os.environ[key_var])
    model = os.environ[model_var]
    t0 = time.perf_counter()
    r = client.chat.completions.create(
        model=model, messages=messages, temperature=0, max_tokens=4000
    )
    usage = r.usage
    return {
        "model": model,
        "content": r.choices[0].message.content or "",
        "input_tokens": getattr(usage, "prompt_tokens", None),
        "output_tokens": getattr(usage, "completion_tokens", None),
        "latency_s": round(time.perf_counter() - t0, 2),
    }


def _key(provider: str, messages: list[dict]) -> str:
    model = os.getenv(PROVIDERS[provider][2], "")
    blob = json.dumps({"p": provider, "m": model, "msgs": messages}, sort_keys=True)
    return hashlib.sha256(blob.encode()).hexdigest()[:24]


def chat(messages: list[dict], agent: str = "unknown", incident_id: str = "-") -> str:
    provider = _provider()
    path = CACHE_DIR / f"{_key(provider, messages)}.json"
    if path.exists():
        rec = json.loads(path.read_text(encoding="utf-8"))
        cached = True
    elif _mode() == "replay":
        raise ReplayMiss(f"no recorded response for this prompt ({path.name})")
    else:
        rec = _call_provider(provider, messages)
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(rec, indent=2), encoding="utf-8")
        cached = False
    audit({
        "event": "llm_call", "agent": agent, "incident_id": incident_id,
        "provider": provider, "model": rec.get("model"), "cached": cached,
        "input_tokens": rec.get("input_tokens"), "output_tokens": rec.get("output_tokens"),
        "latency_s": rec.get("latency_s"),
    })
    return rec["content"]


def _extract_json(text: str) -> dict:
    text = text.strip()
    fenced = re.search(r"```(?:json)?\s*(.*?)```", text, re.S)
    if fenced:
        text = fenced.group(1).strip()
    start, end = text.find("{"), text.rfind("}")
    if start == -1 or end == -1:
        raise ValueError("no JSON object found in reply")
    return json.loads(text[start:end + 1])


def complete_json(messages: list[dict], model_cls: Type[T], agent: str,
                  incident_id: str = "-", max_retries: int = 1) -> T:
    msgs = list(messages)
    last_error: Exception | None = None
    for attempt in range(max_retries + 1):
        raw = chat(msgs, agent, incident_id)
        try:
            return model_cls.model_validate(_extract_json(raw))
        except (ValueError, ValidationError) as e:
            last_error = e
            audit({"event": "schema_retry", "agent": agent, "incident_id": incident_id,
                   "attempt": attempt, "error": str(e)[:300]})
            msgs = msgs + [
                {"role": "assistant", "content": raw},
                {"role": "user", "content":
                    f"Your reply was invalid: {str(e)[:500]}\n"
                    "Reply again with ONLY a corrected JSON object."},
            ]
    raise ValueError(f"LLM output failed validation after retries: {last_error}")