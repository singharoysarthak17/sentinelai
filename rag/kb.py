import json
from pathlib import Path

from pydantic import BaseModel

from guardrails.content import scan_for_injection
from observability.audit import audit

KB_FILE = Path(__file__).resolve().parents[1] / "data" / "knowledge.json"


class Chunk(BaseModel):
    chunk_id: str
    doc_id: str
    title: str
    doc_type: str
    trust_level: str
    acl: list[str]
    text: str


def load_chunks(path: Path = KB_FILE) -> tuple[list[Chunk], list[str]]:
    chunks: list[Chunk] = []
    quarantined: list[str] = []
    for doc in json.loads(path.read_text(encoding="utf-8")):
        paragraphs = [p.strip() for p in doc["text"].split("\n\n") if p.strip()]
        if any(scan_for_injection(p) for p in paragraphs):
            quarantined.append(doc["doc_id"])  # whole document is suspect
            audit({"event": "guardrail_trip", "kind": "retrieval_poisoning",
                   "doc_id": doc["doc_id"]})
            continue
        for n, p in enumerate(paragraphs, 1):
            chunks.append(Chunk(chunk_id=f"{doc['doc_id']}#{n}", doc_id=doc["doc_id"],
                                title=doc["title"], doc_type=doc["doc_type"],
                                trust_level=doc["trust_level"], acl=doc["acl"], text=p))
    return chunks, quarantined