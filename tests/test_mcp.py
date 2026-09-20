import pytest

pytest.importorskip("mcp")

from mcp.shared.memory import create_connected_server_and_client_session as connect

from mcp_servers.security_mcp import mcp
from tools.registry import PERMISSIONS


@pytest.mark.asyncio
async def test_lists_only_read_only_tools():
    async with connect(mcp._mcp_server) as client:
        tools = await client.list_tools()
    names = {t.name for t in tools.tools}
    assert names == PERMISSIONS["mcp_client"]
    # nothing that creates a high-impact action is exposed over MCP
    assert "block_ip_production" not in names
    assert "disable_account" not in names


@pytest.mark.asyncio
async def test_call_tool_over_mcp_matches_registry_result():
    async with connect(mcp._mcp_server) as client:
        res = await client.call_tool("lookup_ip", {"ip": "203.0.113.10"})
    assert not res.isError
    assert "malicious" in res.content[0].text


@pytest.mark.asyncio
async def test_bad_params_surface_as_tool_error_not_crash():
    async with connect(mcp._mcp_server) as client:
        res = await client.call_tool("lookup_ip", {"ip": "not-an-ip"})
    assert "invalid parameters" in res.content[0].text

import inspect
from datetime import datetime

from mcp_servers import security_mcp


def test_search_policy_does_not_let_the_caller_pick_a_role():
    assert "role" not in inspect.signature(security_mcp.search_policy).parameters
    out = security_mcp.search_policy(query="compensation bands finance")
    assert all(h["doc_id"] != "POL-005" for h in (out["data"] or []))


def test_time_window_queries_do_not_crash_the_audit_log():
    out = security_mcp.query_logs(principal="priya.sharma", start=datetime(2026, 9, 18))
    assert out["ok"] is True