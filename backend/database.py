"""SQLite schema + connection helper for Venkathanu.Ai."""
import sqlite3
from pathlib import Path
from contextlib import contextmanager

DB_PATH = Path(__file__).parent / "venkathanu.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS cases (
    case_id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    evidence_source TEXT,
    investigation_type TEXT,
    status TEXT DEFAULT 'CREATED',
    threat_score INTEGER,
    evidence_trust_score INTEGER,
    final_verdict TEXT,
    created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS evidence (
    evidence_id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL,
    source TEXT,
    evidence_type TEXT,
    timestamp TEXT,
    content TEXT,
    content_hash TEXT,
    metadata TEXT,
    severity TEXT,
    confidence REAL,
    FOREIGN KEY (case_id) REFERENCES cases (case_id)
);

CREATE TABLE IF NOT EXISTS findings (
    finding_id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL,
    title TEXT,
    description TEXT,
    mitre_id TEXT,
    confidence REAL,
    adjusted_confidence REAL,
    supporting_evidence TEXT,
    contradicting_evidence TEXT,
    status TEXT DEFAULT 'OPEN',
    FOREIGN KEY (case_id) REFERENCES cases (case_id)
);

CREATE TABLE IF NOT EXISTS hypotheses (
    hypothesis_id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL,
    description TEXT,
    status TEXT,
    confidence REAL,
    FOREIGN KEY (case_id) REFERENCES cases (case_id)
);

CREATE TABLE IF NOT EXISTS blockchain_records (
    case_id TEXT PRIMARY KEY,
    merkle_root TEXT,
    report_hash TEXT,
    transaction_hash TEXT,
    contract_address TEXT,
    network TEXT,
    mode TEXT,
    registered_at TEXT,
    FOREIGN KEY (case_id) REFERENCES cases (case_id)
);

CREATE TABLE IF NOT EXISTS response_actions (
    action_id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL,
    action TEXT,
    severity TEXT,
    status TEXT,
    requires_approval INTEGER,
    FOREIGN KEY (case_id) REFERENCES cases (case_id)
);
"""


def init_db():
    with get_conn() as conn:
        conn.executescript(SCHEMA)


@contextmanager
def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()
