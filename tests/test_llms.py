import pytest
from pydantic import BaseModel

from app import llm


class Out(BaseModel):
    answer: str


@pytest.fixture(autouse=True)
def isolate(tmp_path, monkeypatch):
    monkeypatch.setattr(llm, "CACHE_DIR", tmp_path)
    monkeypatch.setenv("LLM_PROVIDER", "gemini")
    monkeypatch.setenv("GEMINI_MODEL", "test-model")
    monkeypatch.setenv("LLM_MODE", "live")


def fake_provider(monkeypatch, responses):
    calls = []

    def _call(provider, messages):
        calls.append(messages)
        return {"model": "test-model", "content": responses[len(calls) - 1],
                "input_tokens": 1, "output_tokens": 1, "latency_s": 0.0}

    monkeypatch.setattr(llm, "_call_provider", _call)
    return calls


MSGS = [{"role": "user", "content": "hi"}]


def test_second_identical_call_is_served_from_cache(monkeypatch):
    calls = fake_provider(monkeypatch, ["one"])
    assert llm.chat(MSGS) == "one"
    assert llm.chat(MSGS) == "one"
    assert len(calls) == 1


def test_replay_mode_miss_raises(monkeypatch):
    monkeypatch.setenv("LLM_MODE", "replay")
    with pytest.raises(llm.ReplayMiss):
        llm.chat(MSGS)


def test_fenced_json_is_parsed(monkeypatch):
    fake_provider(monkeypatch, ['```json\n{"answer": "hi"}\n```'])
    assert llm.complete_json(MSGS, Out, agent="t").answer == "hi"


def test_invalid_output_retries_once(monkeypatch):
    calls = fake_provider(monkeypatch, ["not json at all", '{"answer": "ok"}'])
    assert llm.complete_json(MSGS, Out, agent="t").answer == "ok"
    assert len(calls) == 2


def test_gives_up_after_retries(monkeypatch):
    fake_provider(monkeypatch, ["bad", "bad"])
    with pytest.raises(ValueError):
        llm.complete_json(MSGS, Out, agent="t")