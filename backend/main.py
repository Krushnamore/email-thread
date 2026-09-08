"""
main.py — FastAPI app + route registration only. All actual logic lives
in the other modules; this file just wires HTTP endpoints to them.
"""

import json
import uuid
from datetime import datetime, timezone

from fastapi import FastAPI, File, HTTPException, Query, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from pydantic import BaseModel

from . import audit, config, correlation, db, ingestion, privacy, reports, scoring

app = FastAPI(title="Email Forensic Intelligence Platform", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def _startup():
    db.init_db()


class PasteRequest(BaseModel):
    raw_text: str
    mode: str = "headers"  # "headers" | "text"


def _persist_and_correlate(analysis: dict, pipeline_result: dict) -> dict:
    case_id = f"case_{uuid.uuid4().hex[:12]}"
    created_at = datetime.now(timezone.utc).isoformat()
    scoring_result = pipeline_result["scoring"]
    attribution_result = pipeline_result["attribution"]

    # Strip the raw eml bytes before persisting the analysis JSON blob —
    # evidence bytes live on disk / in evidence_sha256, not duplicated in DB.
    analysis_for_storage = {k: v for k, v in analysis.items() if k != "raw_eml"}
    storable_result = dict(pipeline_result)
    storable_result["analysis"] = analysis_for_storage

    url_results = analysis.get("_url_analysis_results", [])
    indicators = correlation.extract_indicators(analysis, url_results)

    with db.conn_ctx() as conn:
        conn.execute(
            """
            INSERT INTO cases (id, created_at, sender_domain, from_address, subject,
                                threat_score, verdict, attribution_label, attribution_confidence,
                                campaign_id, raw_eml_path, evidence_sha256, analysis_json, limited_forensics)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, ?, ?, ?)
            """,
            (
                case_id, created_at, analysis.get("from_domain"), analysis.get("from_address"),
                analysis.get("subject"), scoring_result["score"], scoring_result["verdict"],
                attribution_result["label"], attribution_result["confidence"],
                None, analysis.get("evidence_sha256"),
                json.dumps(storable_result, default=str),
                1 if analysis.get("limited_forensics") else 0,
            ),
        )

        correlation_info = correlation.correlate_and_store(conn, case_id, indicators)
        if correlation_info["campaign_id"]:
            conn.execute("UPDATE cases SET campaign_id = ? WHERE id = ?",
                         (correlation_info["campaign_id"], case_id))

        db.append_evidence_chain(conn, case_id, analysis.get("evidence_sha256", ""))
        audit.log_action(case_id, "analyzed", conn=conn)

    return {
        "case_id": case_id,
        "created_at": created_at,
        "from_address": privacy.mask_pii(analysis.get("from_address", "")),
        "from_domain": analysis.get("from_domain"),
        "subject": analysis.get("subject"),
        "scoring": scoring_result,
        "attribution": attribution_result,
        "recommendations": pipeline_result.get("recommendations", {}),
        "header_forensics": _serializable_header_forensics(pipeline_result["header_forensics"]),
        "intel": pipeline_result["intel"],
        "limited_forensics": analysis.get("limited_forensics", False),
        "campaign": correlation_info,
        "url_analysis": url_results,
        "attachment_analysis": analysis.get("_attachment_analysis_results", []),
    }


def _serializable_header_forensics(hf: dict) -> dict:
    # already JSON-safe; kept as a seam in case future fields need cleanup
    return hf


@app.post("/analyze/eml")
async def analyze_eml(file: UploadFile = File(...)):
    raw_bytes = await file.read()
    try:
        analysis = ingestion.parse_eml_bytes(raw_bytes)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Failed to parse .eml file: {exc}")

    pipeline_result = scoring.analyze_pipeline(analysis)
    return _persist_and_correlate(analysis, pipeline_result)


@app.post("/analyze/paste")
async def analyze_paste(req: PasteRequest):
    if not req.raw_text or not req.raw_text.strip():
        raise HTTPException(status_code=400, detail="raw_text must not be empty")

    try:
        if req.mode == "text":
            analysis = ingestion.parse_plain_text(req.raw_text)
        else:
            analysis = ingestion.parse_raw_headers(req.raw_text)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Failed to parse input: {exc}")

    pipeline_result = scoring.analyze_pipeline(analysis)
    return _persist_and_correlate(analysis, pipeline_result)


@app.get("/cases")
def list_cases(verdict: str | None = Query(default=None)):
    with db.conn_ctx() as conn:
        if verdict:
            rows = conn.execute(
                "SELECT id, created_at, sender_domain, from_address, subject, threat_score, "
                "verdict, attribution_label, attribution_confidence, campaign_id "
                "FROM cases WHERE verdict = ? ORDER BY created_at DESC",
                (verdict.upper(),),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT id, created_at, sender_domain, from_address, subject, threat_score, "
                "verdict, attribution_label, attribution_confidence, campaign_id "
                "FROM cases ORDER BY created_at DESC"
            ).fetchall()
        cases = [db.row_to_dict(r) for r in rows]
        for c in cases:
            c["from_address"] = privacy.mask_pii(c.get("from_address", ""))
        return {"cases": cases, "count": len(cases)}


@app.get("/cases/{case_id}")
def get_case(case_id: str):
    with db.conn_ctx() as conn:
        row = conn.execute("SELECT * FROM cases WHERE id = ?", (case_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Case not found")
        case = db.row_to_dict(row)
        audit.log_action(case_id, "viewed", conn=conn)

    full = json.loads(case["analysis_json"])
    masked_analysis = dict(full.get("analysis", {}))
    masked_analysis["from_address"] = privacy.mask_pii(masked_analysis.get("from_address", ""))
    masked_analysis["body"] = privacy.mask_pii(masked_analysis.get("body", ""))
    full["analysis"] = masked_analysis

    return {
        "case_id": case["id"],
        "created_at": case["created_at"],
        "verdict": case["verdict"],
        "threat_score": case["threat_score"],
        "attribution_label": case["attribution_label"],
        "attribution_confidence": case["attribution_confidence"],
        "campaign_id": case["campaign_id"],
        "evidence_sha256": case["evidence_sha256"],
        "limited_forensics": bool(case["limited_forensics"]),
        "details": full,
    }


@app.get("/cases/{case_id}/report")
def get_case_report(case_id: str):
    with db.conn_ctx() as conn:
        row = conn.execute("SELECT * FROM cases WHERE id = ?", (case_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Case not found")
        case = db.row_to_dict(row)
        audit.log_action(case_id, "report_exported", conn=conn)

        pdf_bytes = reports.generate_case_report(case)
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{case_id}_report.pdf"'},
    )


@app.delete("/cases/{case_id}")
def delete_case(case_id: str):
    """
    Deletes a case and its indicator rows. The evidence_chain and
    audit_log entries for this case are intentionally NOT deleted —
    they are the tamper-evident ledger, and removing a link would
    invalidate the hash chain for every later entry. A 'deleted'
    audit row is written before removal so the deletion itself is
    part of the permanent audit trail.
    """
    with db.conn_ctx() as conn:
        row = conn.execute("SELECT id FROM cases WHERE id = ?", (case_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Case not found")
        audit.log_action(case_id, "deleted", conn=conn)
        conn.execute("DELETE FROM indicators WHERE case_id = ?", (case_id,))
        conn.execute("DELETE FROM cases WHERE id = ?", (case_id,))
    return {"deleted": True, "case_id": case_id}

@app.get("/campaigns")
def list_campaigns():
    with db.conn_ctx() as conn:
        return {"campaigns": correlation.list_campaigns(conn)}


@app.get("/campaigns/{campaign_id}")
def get_campaign(campaign_id: str):
    with db.conn_ctx() as conn:
        cases = correlation.cases_in_campaign(conn, campaign_id)
        if not cases:
            raise HTTPException(status_code=404, detail="Campaign not found")
        for c in cases:
            c["from_address"] = privacy.mask_pii(c.get("from_address", ""))
        return {
            "campaign_id": campaign_id,
            "case_count": len(cases),
            "cases": cases,
            "note": f"{len(cases)} related emails share this infrastructure",
        }


@app.get("/health")
def health():
    chain_status = db.verify_evidence_chain()
    return {
        "status": "ok",
        "ml_enabled": config.ENABLE_ML,
        "evidence_chain": chain_status,
    }
