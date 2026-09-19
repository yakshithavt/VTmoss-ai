"""Deterministic canonical hashing for evidence and reports.

Everything that goes into a hash is first serialized with sort_keys=True and
no incidental whitespace, so the same logical content always produces the
same SHA-256 digest regardless of key ordering or formatting drift.
"""
import hashlib
import json
from typing import Any


def canonicalize(obj: Any) -> str:
    """Turn a Python object into a deterministic JSON string."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


def sha256_hex(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def hash_evidence(content: dict) -> str:
    """Content hash for a single normalized evidence item."""
    return "0x" + sha256_hex(canonicalize(content))


def hash_report(report: dict) -> str:
    """Final investigation report hash (used as the Web3 anchor's reportHash)."""
    return "0x" + sha256_hex(canonicalize(report))
