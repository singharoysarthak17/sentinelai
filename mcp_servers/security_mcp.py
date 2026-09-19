"""Exposes the same permission-checked, audit-logged tools the agents use
internally, over the Model Context Protocol, so any MCP-compatible client
(Claude Desktop, an MCP inspector, another agent framework) can call them
the same way SentinelAI's own agents do.

This process is read-only by design: it is granted the "mcp_client"
permission group in tools/registry.py, which covers SIEM, threat-intel,
identity and knowledge lookups only. Write/high-impact actions
(block_ip, disable_account, ...) stay behind guardrails/approval.py and
are intentionally NOT exposed here — see Section 7's least-privilege
policy and Section 9's action risk classes in the design doc.

Run standalone (stdio transport, e.g. for Claude Desktop or `mcp dev`):
    python -m mcp_servers.security_mcp

Or import `mcp` and mount it in a larger app if you later add an HTTP
transport.
"""
from __future__ import annotations

from datetime import datetime
from typing import Optional

from mcp.server.fastmcp import FastMCP

import tools.security_tools  # noqa: F401  (registers query_logs, get_user, lookup_ip, build_timeline)
import tools.knowledge_tools  # noqa: F401  (registers search_policy)
from tools.registry import call_tool

AGENT = "mcp_client"

mcp = FastMCP(
    "sentinelai-security",
    instructions=(
        "Read-only security data for SOC investigations: log queries, "
        "IP threat-intel lookups, identity/asset context, and policy/"
        "playbook search. All calls are permission-checked and appear "
        "in SentinelAI's audit log (observability/audit.py). No tool "
        "here can take a high-impact action; those require human "
        "approval through the SentinelAI API."
    ),
)


def _incident_id(incident_id: Optional[str]) -> str:
    # MCP clients calling ad hoc (outside a live incident) still get
    # audited under a synthetic incident id rather than failing.
    return incident_id or "INC-MCP-ADHOC"


@mcp.tool()
def query_logs(
    principal: Optional[str] = None,
    indicator: Optional[str] = None,
    event_type: Optional[str] = None,
    start: Optional[datetime] = None,
    end: Optional[datetime] = None,
    limit: int = 20,
    incident_id: Optional[str] = None,
) -> dict:
    """Search the synthetic SIEM/identity event log. Filter by principal
    (user), indicator (e.g. an IP), event_type, and/or a time window."""
    result = call_tool(AGENT, _incident_id(incident_id), "query_logs",
                        principal=principal, indicator=indicator, event_type=event_type,
                        start=start, end=end, limit=limit)
    return result.model_dump(mode="json")


@mcp.tool()
def build_timeline(principal: str, incident_id: Optional[str] = None) -> dict:
    """Build a de-duplicated, run-length-encoded event timeline for one
    principal (user), ordered by time."""
    result = call_tool(AGENT, _incident_id(incident_id), "build_timeline", principal=principal)
    return result.model_dump(mode="json")


@mcp.tool()
def lookup_ip(ip: str, incident_id: Optional[str] = None) -> dict:
    """Look up threat-intel reputation, confidence, and tags for an IP
    address. Unknown IPs are returned as 'unknown', never as clean."""
    result = call_tool(AGENT, _incident_id(incident_id), "lookup_ip", ip=ip)
    return result.model_dump(mode="json")


@mcp.tool()
def get_user(user: str, incident_id: Optional[str] = None) -> dict:
    """Look up identity/asset context for a user: role, department,
    usual location, and known device."""
    result = call_tool(AGENT, _incident_id(incident_id), "get_user", user=user)
    return result.model_dump(mode="json")


@mcp.tool()
def search_policy(query: str, role: str = "analyst", k: int = 3,
                   incident_id: Optional[str] = None) -> dict:
    """Search security policies/playbooks (BM25, role-scoped access
    control). Returns cited chunks, never raw unfiltered documents."""
    result = call_tool(AGENT, _incident_id(incident_id), "search_policy",
                        query=query, role=role, k=k)
    return result.model_dump(mode="json")


if __name__ == "__main__":
    mcp.run()