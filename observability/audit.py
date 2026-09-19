import json
import threading
from datetime import datetime, timezone
from pathlib import Path

AUDIT_FILE = Path(__file__).resolve().parents[1] / "observability" / "audit.jsonl"
_LOCK = threading.Lock()


def audit(record: dict) -> None:
    record.setdefault("ts", datetime.now(timezone.utc).isoformat())
    line = json.dumps(record) + "\n"
    with _LOCK:  # parallel agents must never interleave their writes
        AUDIT_FILE.parent.mkdir(parents=True, exist_ok=True)
        with AUDIT_FILE.open("a", encoding="utf-8") as f:
            f.write(line)