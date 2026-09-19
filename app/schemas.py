from datetime import datetime
from typing import Literal, Optional

from pydantic import BaseModel, Field, model_validator


class SecurityEvent(BaseModel):
    event_id: str
    timestamp: datetime
    source: Literal["identity", "endpoint", "network"]
    type: str                      # e.g. login_failed, login_success
    principal: str                 # the user account involved
    indicator: Optional[str] = None  # source IP
    geo: Optional[str] = None
    device_id: Optional[str] = None
    raw_payload: dict = Field(default_factory=dict)


class Alert(BaseModel):
    alert_id: str
    title: str
    description: str
    entities: list[str]            # users, IPs the alert mentions
    created_at: datetime


class Evidence(BaseModel):
    evidence_id: str
    source_type: Literal["log", "threat_intel", "policy", "identity"]
    source_ref: str                # where it came from (event id, doc id...)
    excerpt: str
    trust_level: Literal["trusted", "untrusted"]


class Finding(BaseModel):
    statement: str
    kind: Literal["fact", "hypothesis", "missing_evidence"]
    evidence_ids: list[str] = Field(default_factory=list)
    confidence: float = Field(ge=0, le=1)

    @model_validator(mode="after")
    def facts_need_evidence(self):
        if self.kind == "fact" and not self.evidence_ids:
            raise ValueError("a fact must cite at least one evidence_id")
        return self