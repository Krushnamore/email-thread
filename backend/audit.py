"""
audit.py — writes an audit_log row on every analyze/view/report-export
action. No auth system is required for the MVP, so a placeholder actor
identifier is used unless the caller supplies one.
"""

from datetime import datetime, timezone

from . import config
from . import db


def log_action(case_id: str, action: str, actor: str = None, conn=None):
    """
    action should be one of: 'analyzed' | 'viewed' | 'report_exported'.
    If a `conn` is supplied, writes on that connection without committing
    (so callers can batch this inside a larger transaction); otherwise
    opens and commits its own connection.
    """
    actor = actor or config.DEFAULT_ACTOR
    timestamp = datetime.now(timezone.utc).isoformat()

    if conn is not None:
        conn.execute(
            "INSERT INTO audit_log (case_id, action, actor, timestamp) VALUES (?, ?, ?, ?)",
            (case_id, action, actor, timestamp),
        )
        return

    with db.conn_ctx() as c:
        c.execute(
            "INSERT INTO audit_log (case_id, action, actor, timestamp) VALUES (?, ?, ?, ?)",
            (case_id, action, actor, timestamp),
        )


def get_audit_trail(case_id: str) -> list:
    with db.conn_ctx() as conn:
        rows = conn.execute(
            "SELECT * FROM audit_log WHERE case_id = ? ORDER BY timestamp ASC",
            (case_id,),
        ).fetchall()
        return [db.row_to_dict(r) for r in rows]
