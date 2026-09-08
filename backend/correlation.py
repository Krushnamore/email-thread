"""
correlation.py — campaign correlation via plain SQL (no graph DB needed).

After inserting a new case's indicators, query `indicators` for any prior
case sharing the same value. If 2+ cases share a domain, IP, or URL,
assign them all the same campaign_id.
"""

import uuid

from . import db


def extract_indicators(analysis: dict, url_results: list) -> list:
    """Builds the (type, value) indicator list for a case."""
    indicators = []
    from_domain = analysis.get("from_domain")
    if from_domain:
        indicators.append(("domain", from_domain))

    earliest_ip = (analysis.get("_intel_results") or {}).get("earliest_public_ip")
    if earliest_ip:
        indicators.append(("ip", earliest_ip))

    for u in url_results or []:
        host = u.get("host")
        if host:
            indicators.append(("url", host))

    # de-dup while preserving order
    seen = set()
    unique = []
    for t, v in indicators:
        key = (t, v)
        if key not in seen:
            seen.add(key)
            unique.append((t, v))
    return unique


def correlate_and_store(conn, case_id: str, indicators: list) -> dict:
    """
    Inserts indicators for this case, then checks for shared indicators
    with any prior case. If found, assigns a shared campaign_id to both
    the new case and all matching prior cases. Returns correlation info.
    """
    for ind_type, value in indicators:
        conn.execute(
            "INSERT INTO indicators (case_id, type, value) VALUES (?, ?, ?)",
            (case_id, ind_type, value),
        )

    related_case_ids = set()
    for ind_type, value in indicators:
        rows = conn.execute(
            "SELECT DISTINCT case_id FROM indicators WHERE type = ? AND value = ? AND case_id != ?",
            (ind_type, value, case_id),
        ).fetchall()
        for r in rows:
            related_case_ids.add(r["case_id"])

    if not related_case_ids:
        return {"campaign_id": None, "related_case_count": 0}

    # Find an existing campaign_id among related cases, reuse it; else mint a new one.
    existing_campaign_id = None
    placeholders = ",".join("?" for _ in related_case_ids)
    rows = conn.execute(
        f"SELECT campaign_id FROM cases WHERE id IN ({placeholders}) AND campaign_id IS NOT NULL",
        tuple(related_case_ids),
    ).fetchall()
    for r in rows:
        if r["campaign_id"]:
            existing_campaign_id = r["campaign_id"]
            break

    campaign_id = existing_campaign_id or f"campaign_{uuid.uuid4().hex[:10]}"

    all_case_ids = list(related_case_ids) + [case_id]
    placeholders_all = ",".join("?" for _ in all_case_ids)
    conn.execute(
        f"UPDATE cases SET campaign_id = ? WHERE id IN ({placeholders_all})",
        tuple([campaign_id] + all_case_ids),
    )

    return {"campaign_id": campaign_id, "related_case_count": len(related_case_ids)}


def list_campaigns(conn) -> list:
    rows = conn.execute(
        """
        SELECT campaign_id, COUNT(*) as case_count, MAX(created_at) as last_seen
        FROM cases
        WHERE campaign_id IS NOT NULL
        GROUP BY campaign_id
        ORDER BY last_seen DESC
        """
    ).fetchall()
    return [db.row_to_dict(r) for r in rows]


def cases_in_campaign(conn, campaign_id: str) -> list:
    rows = conn.execute(
        "SELECT * FROM cases WHERE campaign_id = ? ORDER BY created_at DESC",
        (campaign_id,),
    ).fetchall()
    return [db.row_to_dict(r) for r in rows]
