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