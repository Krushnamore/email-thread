"""
privacy.py — PII masking and retention/purge helpers.

mask_pii() must be applied consistently wherever raw sender/body text is
rendered to the dashboard or a report.
"""

import re

from . import db

_EMAIL_RE = re.compile(r"([A-Za-z0-9._%+\-]+)@([A-Za-z0-9.\-]+\.[A-Za-z]{2,})")
_PHONE_RE = re.compile(r"(?<!\d)(\+?\d{1,3}[\s.\-]?)?(\(?\d{3,4}\)?[\s.\-]?)\d{3,4}[\s.\-]?\d{3,4}(?!\d)")


def _mask_email(match: re.Match) -> str:
    local, domain = match.group(1), match.group(2)
    visible = local[:2] if len(local) > 2 else local[:1]
    return f"{visible}{'*' * max(len(local) - len(visible), 2)}@{domain}"


def _mask_phone(match: re.Match) -> str:
    digits = re.sub(r"\D", "", match.group(0))
    if len(digits) < 6:
        return match.group(0)  # too short to confidently be a phone number
    return f"{'*' * (len(digits) - 4)}{digits[-4:]}"


def mask_pii(text: str) -> str:
    if not text:
        return text
    text = _EMAIL_RE.sub(_mask_email, text)
    text = _PHONE_RE.sub(_mask_phone, text)
    return text


def purge_case(case_id: str) -> bool:
    """Retention helper: deletes a case and its related rows entirely."""
    with db.conn_ctx() as conn:
        conn.execute("DELETE FROM indicators WHERE case_id = ?", (case_id,))
        conn.execute("DELETE FROM audit_log WHERE case_id = ?", (case_id,))
        conn.execute("DELETE FROM evidence_chain WHERE case_id = ?", (case_id,))
        cur = conn.execute("DELETE FROM cases WHERE id = ?", (case_id,))
        return cur.rowcount > 0


def purge_cases_older_than(days: int) -> int:
    """Retention helper: purges cases older than N days. Returns count purged."""
    with db.conn_ctx() as conn:
        rows = conn.execute(
            "SELECT id FROM cases WHERE created_at < datetime('now', ?)",
            (f"-{days} days",),
        ).fetchall()
        ids = [r["id"] for r in rows]
    for case_id in ids:
        purge_case(case_id)
    return len(ids)
