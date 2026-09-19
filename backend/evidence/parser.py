"""Normalize JSON/CSV/TXT uploads into the canonical Evidence shape.

MVP scope per spec: JSON (list of event objects), CSV (header + rows), and
TXT (one JSON object per line, or 'key: value' blocks separated by blank
lines). Anything else is rejected -- this also doubles as the upload-type
allowlist referenced in the security section of the spec.
"""
import csv
import io
import json
import uuid
from typing import List, Dict

from evidence.hashing import hash_evidence

ALLOWED_EXTENSIONS = {".json", ".csv", ".txt"}
MAX_UPLOAD_BYTES = 2 * 1024 * 1024  # 2MB per file -- MVP guardrail

METADATA_FIELDS = {"user", "host", "process", "command", "src_ip", "dst_ip", "url", "domain"}


def _normalize_one(raw: dict, case_id: str, source: str) -> dict:
    evidence_id = raw.get("event_id") or raw.get("evidence_id") or f"EVT-{uuid.uuid4().hex[:8].upper()}"
    metadata = {k: raw[k] for k in METADATA_FIELDS if k in raw}
    content = {k: v for k, v in raw.items()}
    return {
        "evidence_id": evidence_id,
        "case_id": case_id,
        "source": raw.get("source", source),
        "evidence_type": raw.get("event_type", "unknown"),
        "timestamp": raw.get("timestamp"),
        "content": content,
        "content_hash": hash_evidence(content),
        "metadata": metadata,
        "severity": raw.get("severity", "low"),
        "confidence": None,
    }


def parse_upload(filename: str, raw_bytes: bytes, case_id: str) -> List[Dict]:
    if len(raw_bytes) > MAX_UPLOAD_BYTES:
        raise ValueError(f"File exceeds {MAX_UPLOAD_BYTES} byte limit for MVP evidence uploads")

    ext = "." + filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    if ext not in ALLOWED_EXTENSIONS:
        raise ValueError(f"Unsupported evidence file type '{ext}'. Allowed: {sorted(ALLOWED_EXTENSIONS)}")

    text = raw_bytes.decode("utf-8", errors="replace")

    if ext == ".json":
        data = json.loads(text)
        events = data if isinstance(data, list) else [data]
    elif ext == ".csv":
        reader = csv.DictReader(io.StringIO(text))
        events = list(reader)
    else:  # .txt -- one JSON object per non-empty line
        events = []
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                events.append({"event_type": "log_line", "raw": line})

    return [_normalize_one(e, case_id, filename) for e in events]
