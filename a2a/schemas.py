from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Literal, Optional

from pydantic import BaseModel, Field

TaskStatus = Literal["completed", "failed", "timeout"]


class AgentTask(BaseModel):
    task_id: str = Field(default_factory=lambda: f"TASK-{uuid.uuid4().hex[:8]}")
    incident_id: str
    sender: str            # who is delegating the task, e.g. "triage"
    receiver: str           # who should handle it, e.g. "threat-intel-agent"
    task_type: str          # e.g. "enrich_ip"
    entity: str              # the thing to act on, e.g. an IP
    priority: Literal["low", "normal", "high"] = "normal"
    deadline_ms: int = Field(default=5000, ge=100, le=60000)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class AgentResult(BaseModel):
    task_id: str
    incident_id: str
    sender: str  # who produced this result, e.g. "threat-intel-agent"
    status: TaskStatus
    evidence: list[dict] = []
    confidence: Optional[float] = None
    sources: list[str] = []
    error: Optional[str] = None