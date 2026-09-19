from rag.retrieve import quarantined_docs, search
from tools.registry import call_tool


def test_relevant_policy_is_found():
    top = search("disabling a user account requires approval", "analyst")[0]
    assert top["doc_id"] in {"POL-001", "POL-003"}
    assert "approval" in top["text"].lower()


def test_acl_hides_restricted_docs_from_analyst_but_not_hr():
    q = "compensation bands finance"
    assert all(r["doc_id"] != "POL-005" for r in search(q, "analyst"))
    assert any(r["doc_id"] == "POL-005" for r in search(q, "hr"))


def test_poisoned_advisory_is_quarantined():
    assert "POL-006" in quarantined_docs()
    hits = search("password spraying campaigns finance administrators", "analyst", k=5)
    assert hits and all(r["doc_id"] != "POL-006" for r in hits)


def test_unknown_role_gets_nothing():
    assert search("account approval", "guest") == []


def test_search_policy_tool_is_permission_checked():
    ok = call_tool("response", "INC-T", "search_policy", query="disabling privileged account")
    assert ok.ok and ok.data and "#" in ok.data[0]["chunk_id"]
    denied = call_tool("threat_intel", "INC-T", "search_policy", query="disabling privileged account")
    assert not denied.ok and "not authorized" in denied.error


def test_too_short_query_is_rejected():
    r = call_tool("response", "INC-T", "search_policy", query="ab")
    assert not r.ok and "invalid parameters" in r.error