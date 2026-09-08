"""
db.py — SQLite connection management + schema migrations.

All other modules must go through get_conn() / init_db() rather than
opening their own sqlite3 connections, so the schema stays centralized.
"""

import hashlib
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone

from . import config

SCHEMA = """
CREATE TABLE IF NOT EXISTS cases (
  id TEXT PRIMARY KEY,
  created_at TEXT,
  sender_domain TEXT,
  from_address TEXT,
  subject TEXT,
  threat_score INTEGER,
  verdict TEXT,
  attribution_label TEXT,
  attribution_confidence REAL,
  campaign_id TEXT,
  raw_eml_path TEXT,
  evidence_sha256 TEXT,
  analysis_json TEXT,
  limited_forensics INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS indicators (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  case_id TEXT,
  type TEXT,      -- 'domain' | 'ip' | 'url'
  value TEXT
);

CREATE TABLE IF NOT EXISTS audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  case_id TEXT,
  action TEXT,    -- 'analyzed' | 'viewed' | 'report_exported'
  actor TEXT,
  timestamp TEXT
);

CREATE TABLE IF NOT EXISTS evidence_chain (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  case_id TEXT,
  evidence_hash TEXT,
  previous_hash TEXT,
  chain_hash TEXT,  -- sha256(evidence_hash + previous_hash)
  timestamp TEXT
);

CREATE INDEX IF NOT EXISTS idx_indicators_value ON indicators(value);
CREATE INDEX IF NOT EXISTS idx_indicators_case ON indicators(case_id);
CREATE INDEX IF NOT EXISTS idx_cases_campaign ON cases(campaign_id);
"""


def get_conn():
    conn = sqlite3.connect(config.DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


@contextmanager
def conn_ctx():
    conn = get_conn()
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db():
    with conn_ctx() as conn:
        conn.executescript(SCHEMA)


def row_to_dict(row):
    if row is None:
        return None
    return dict(row)


def append_evidence_chain(conn, case_id: str, evidence_hash: str) -> str:
    """
    Practical stand-in for the 'Blockchain' theme requirement: each new
    case's evidence_sha256 is hashed together with the previous entry's
    chain_hash to form its own chain_hash, giving a simple tamper-evident
    local ledger. Returns the new chain_hash.
    """
    last = conn.execute(
        "SELECT chain_hash FROM evidence_chain ORDER BY id DESC LIMIT 1"
    ).fetchone()
    previous_hash = last["chain_hash"] if last else "0" * 64
    chain_hash = hashlib.sha256((evidence_hash + previous_hash).encode("utf-8")).hexdigest()
    timestamp = datetime.now(timezone.utc).isoformat()

    conn.execute(
        "INSERT INTO evidence_chain (case_id, evidence_hash, previous_hash, chain_hash, timestamp) "
        "VALUES (?, ?, ?, ?, ?)",
        (case_id, evidence_hash, previous_hash, chain_hash, timestamp),
    )
    return chain_hash


def verify_evidence_chain() -> dict:
    """Walks the full evidence_chain table and confirms no link has been
    tampered with (each chain_hash must equal sha256(evidence_hash + previous_hash))."""
    with conn_ctx() as conn:
        rows = conn.execute("SELECT * FROM evidence_chain ORDER BY id ASC").fetchall()

    broken_at = None
    for row in rows:
        expected = hashlib.sha256((row["evidence_hash"] + row["previous_hash"]).encode("utf-8")).hexdigest()
        if expected != row["chain_hash"]:
            broken_at = row["case_id"]
            break

    return {"valid": broken_at is None, "broken_at_case": broken_at, "entries": len(rows)}
