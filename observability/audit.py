import json
from pathlib import Path

AUDIT_FILE = Path(__file__).resolve().parents[1] / "observability" / "audit.jsonl"


def audit(record: dict) -> None:
    AUDIT_FILE.parent.mkdir(parents=True, exist_ok=True)
    with AUDIT_FILE.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record) + "\n")