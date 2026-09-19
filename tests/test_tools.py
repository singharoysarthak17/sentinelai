from tools.registry import AUDIT_FILE, call_tool


def test_query_logs_counts_failures():
    r = call_tool("log_analysis", "INC-T", "query_logs",
                  principal="priya.sharma", event_type="login_failed")
    assert r.ok and r.data["count"] == 37


def test_unauthorized_tool_is_denied():
    r = call_tool("threat_intel", "INC-T", "query_logs", principal="priya.sharma")
    assert not r.ok and "not authorized" in r.error


def test_bad_ip_is_rejected():
    r = call_tool("threat_intel", "INC-T", "lookup_ip", ip="not-an-ip")
    assert not r.ok and "invalid parameters" in r.error


def test_known_and_unknown_ip():
    known = call_tool("threat_intel", "INC-T", "lookup_ip", ip="203.0.113.10")
    unknown = call_tool("threat_intel", "INC-T", "lookup_ip", ip="203.0.113.99")
    assert known.data["reputation"] == "malicious"
    assert unknown.data["reputation"] == "unknown"


def test_timeline_compresses_the_attack():
    r = call_tool("log_analysis", "INC-T", "build_timeline", principal="priya.sharma")
    runs = r.data
    assert any(x["type"] == "login_failed" and x["count"] == 37 for x in runs)
    assert len(runs) == 3  # normal history, the attack burst, the suspicious success


def test_every_call_is_audited():
    before = len(AUDIT_FILE.read_text().splitlines()) if AUDIT_FILE.exists() else 0
    call_tool("triage", "INC-T", "get_user", user="priya.sharma")
    call_tool("triage", "INC-T", "query_logs")  # denied, still logged
    after = len(AUDIT_FILE.read_text().splitlines())
    assert after == before + 2