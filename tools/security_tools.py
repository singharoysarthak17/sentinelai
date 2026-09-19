import ipaddress
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from pydantic import BaseModel, Field, field_validator

from app.schemas import SecurityEvent
from tools.registry import tool

DATA = Path(__file__).resolve().parents[1] / "data"


def _events() -> list[SecurityEvent]:
    return [SecurityEvent(**e) for e in json.loads((DATA / "events.json").read_text())]


def _load(name: str) -> dict:
    return json.loads((DATA / f"{name}.json").read_text())


class QueryLogsParams(BaseModel):
    principal: Optional[str] = None
    indicator: Optional[str] = None
    event_type: Optional[str] = None
    start: Optional[datetime] = None
    end: Optional[datetime] = None
    limit: int = Field(default=20, ge=1, le=100)

    @field_validator("start", "end")
    @classmethod
    def assume_utc(cls, v):
        if v is not None and v.tzinfo is None:
            return v.replace(tzinfo=timezone.utc)
        return v


@tool("query_logs", QueryLogsParams)
def query_logs(p: QueryLogsParams):
    matches = [
        e for e in _events()
        if (p.principal is None or e.principal == p.principal)
        and (p.indicator is None or e.indicator == p.indicator)
        and (p.event_type is None or e.type == p.event_type)
        and (p.start is None or e.timestamp >= p.start)
        and (p.end is None or e.timestamp <= p.end)
    ]
    by_type: dict[str, int] = {}
    for e in matches:
        by_type[e.type] = by_type.get(e.type, 0) + 1
    return {
        "count": len(matches),
        "by_type": by_type,
        "events": [e.model_dump(mode="json") for e in matches[: p.limit]],
        "truncated": len(matches) > p.limit,
    }


class GetUserParams(BaseModel):
    user: str


@tool("get_user", GetUserParams)
def get_user(p: GetUserParams):
    users = _load("users")
    if p.user not in users:
        raise KeyError(f"user '{p.user}' not found")
    return {"user": p.user, **users[p.user]}


class LookupIpParams(BaseModel):
    ip: str

    @field_validator("ip")
    @classmethod
    def must_be_ip(cls, v):
        ipaddress.ip_address(v)  # raises ValueError if not a valid IP
        return v


@tool("lookup_ip", LookupIpParams)
def lookup_ip(p: LookupIpParams):
    intel = _load("threat_intel")
    if p.ip in intel:
        return {"ip": p.ip, **intel[p.ip]}
    # No data is NOT the same as clean.
    return {"ip": p.ip, "reputation": "unknown", "confidence": 0.0, "tags": [], "sources": []}


class TimelineParams(BaseModel):
    principal: str


@tool("build_timeline", TimelineParams)
def build_timeline(p: TimelineParams):
    evs = sorted((e for e in _events() if e.principal == p.principal), key=lambda e: e.timestamp)
    runs: list[dict] = []
    for e in evs:
        key = (e.type, e.indicator, e.geo, e.device_id)
        if runs and runs[-1]["_key"] == key:
            runs[-1]["count"] += 1
            runs[-1]["last_seen"] = e.timestamp.isoformat()
            runs[-1]["last_event_id"] = e.event_id
        else:
            runs.append({
                "_key": key, "type": e.type, "indicator": e.indicator, "geo": e.geo,
                "device_id": e.device_id, "count": 1,
                "first_seen": e.timestamp.isoformat(), "last_seen": e.timestamp.isoformat(),
                "first_event_id": e.event_id, "last_event_id": e.event_id,
            })
    for r in runs:
        del r["_key"]
    return runs