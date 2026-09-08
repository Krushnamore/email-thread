"""
reports.py — generates a PDF forensic report (ReportLab) for a case.

Includes: case ID, classification, threat score, sender/auth/network/
relay-chain/URL/indicator sections, attribution label + confidence,
evidence SHA-256, and an explicit Attribution Limitations disclaimer.
"""

import io
import json

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak,
)

from . import privacy

ATTRIBUTION_LIMITATIONS_TEXT = (
    "Attribution Limitations: The indicators in this report (IP addresses, "
    "geolocation, relay hops, and domain intelligence) describe observed "
    "sending infrastructure only. An IP address or hosting location is not "
    "equivalent to the identity of a person. Email headers, including "
    "Received and Authentication-Results headers, can be forged or "
    "manipulated by a sufficiently capable actor. All conclusions in this "
    "report should be treated as investigative leads requiring further "
    "corroboration, not as definitive proof of identity or location."
)


def _styles():
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="SectionHeading", fontSize=13, spaceBefore=14, spaceAfter=6,
                               textColor=colors.HexColor("#1a1a2e"), fontName="Helvetica-Bold"))
    styles.add(ParagraphStyle(name="Mono", fontName="Courier", fontSize=8, leading=10))
    return styles


def _kv_table(rows, col_widths=(5 * cm, 11 * cm)):
    data = [[str(k), str(v) if v is not None else "—"] for k, v in rows]
    table = Table(data, colWidths=col_widths)
    table.setStyle(TableStyle([
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f0f0f5")),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cccccc")),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    return table


def generate_case_report(case: dict) -> bytes:
    """
    `case` is the stored case row plus its parsed analysis_json blob
    (see main.py for how it's assembled before calling this).
    """
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, topMargin=1.5 * cm, bottomMargin=1.5 * cm)
    styles = _styles()
    story = []

    full = json.loads(case.get("analysis_json") or "{}")
    analysis = full.get("analysis", {})
    header_results = full.get("header_forensics", {})
    intel_results = full.get("intel", {})
    scoring_result = full.get("scoring", {})
    attribution_result = full.get("attribution", {})

    story.append(Paragraph("Email Forensic Investigation Report", styles["Title"]))
    story.append(Paragraph(f"Case ID: {case.get('id')}", styles["Normal"]))
    story.append(Paragraph(f"Generated: {case.get('created_at')}", styles["Normal"]))
    story.append(Spacer(1, 12))

    story.append(Paragraph("Verdict Summary", styles["SectionHeading"]))
    story.append(_kv_table([
        ("Threat Score", f"{scoring_result.get('score', case.get('threat_score'))} / 100"),
        ("Verdict", scoring_result.get("verdict", case.get("verdict"))),
        ("Attribution Label", attribution_result.get("label", case.get("attribution_label"))),
        ("Attribution Confidence", f"{attribution_result.get('confidence', case.get('attribution_confidence'))}%"),
        ("Campaign ID", case.get("campaign_id") or "Not correlated with other cases"),
        ("Limited Forensics Mode", "Yes — plain text only, header checks skipped" if analysis.get("limited_forensics") else "No"),
    ]))

    story.append(Paragraph("Sender Information", styles["SectionHeading"]))
    masked_from = privacy.mask_pii(analysis.get("from_address", ""))
    story.append(_kv_table([
        ("From (masked)", masked_from),
        ("From Display Name", analysis.get("from_display_name") or "—"),
        ("From Domain", analysis.get("from_domain") or "—"),
        ("Return-Path Domain", (header_results.get("return_path") or {}).get("return_path_domain") or "—"),
        ("Subject", analysis.get("subject") or "—"),
        ("Date", analysis.get("date") or "—"),
    ]))

    auth = header_results.get("authentication", {})
    story.append(Paragraph("Authentication (SPF / DKIM / DMARC)", styles["SectionHeading"]))
    if auth.get("available"):
        story.append(_kv_table([
            ("SPF", auth.get("spf")),
            ("DKIM", auth.get("dkim")),
            ("DMARC", auth.get("dmarc")),
            ("SPF Aligned with From domain", auth.get("spf_aligned")),
            ("DKIM Aligned with From domain", auth.get("dkim_aligned")),
        ]))
    else:
        story.append(Paragraph("Authentication headers unavailable in this input mode.", styles["Normal"]))

    story.append(Paragraph("Network & Geolocation Intelligence", styles["SectionHeading"]))
    geo = intel_results.get("geoip") or {}
    story.append(_kv_table([
        ("Earliest Public Relay IP", intel_results.get("earliest_public_ip") or "—"),
        ("Probable Country", geo.get("country") or "—"),
        ("Probable City", geo.get("city") or "—"),
        ("ISP / Org", geo.get("isp") or geo.get("org") or "—"),
        ("Location Disclaimer", "Probable sending infrastructure location — NOT a confirmed attacker location."),
        ("Tor Exit Node", intel_results.get("is_tor_exit_node")),
        ("Known VPN Provider", intel_results.get("is_known_vpn")),
        ("Generic Cloud Hosting", intel_results.get("is_cloud_hosting")),
    ]))

    whois_data = intel_results.get("whois") or {}
    if whois_data:
        story.append(Paragraph("Domain (WHOIS) Intelligence", styles["SectionHeading"]))
        story.append(_kv_table([
            ("Registrar", whois_data.get("registrar")),
            ("Creation Date", whois_data.get("creation_date")),
            ("Domain Age (days)", whois_data.get("domain_age_days")),
        ]))

    relay_chain = header_results.get("relay_chain", {})
    story.append(Paragraph("Relay Path (Oldest Hop First)", styles["SectionHeading"]))
    if relay_chain.get("available") and relay_chain.get("hops"):
        rows = [("Hop", "From", "By", "IP", "Note")]
        for hop in relay_chain["hops"]:
            rows.append((
                hop["hop_index"], hop.get("from_host") or "—", hop.get("by_host") or "—",
                hop.get("ip") or "—", hop.get("label") or "",
            ))
        table = Table(rows, colWidths=[1.3 * cm, 4 * cm, 4 * cm, 3 * cm, 4.7 * cm])
        table.setStyle(TableStyle([
            ("FONTSIZE", (0, 0), (-1, -1), 7.5),
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a1a2e")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cccccc")),
        ]))
        story.append(table)
    else:
        story.append(Paragraph("No relay chain available for this input mode.", styles["Normal"]))

    url_results = analysis.get("_url_analysis_results") or []
    if url_results:
        story.append(Paragraph("URL Indicators", styles["SectionHeading"]))
        for u in url_results:
            if u.get("signals"):
                story.append(Paragraph(f"• {u['host']} — {', '.join(u['signals'])}", styles["Normal"]))

    attachment_results = analysis.get("_attachment_analysis_results") or []
    if attachment_results:
        story.append(Paragraph("Attachment Indicators", styles["SectionHeading"]))
        for a in attachment_results:
            flag = "HIGH RISK" if a["is_high_risk"] else "clean"
            story.append(Paragraph(f"• {a['filename']} ({a['content_type']}, sha256={a['sha256'][:16]}...) — {flag}", styles["Normal"]))

    story.append(Paragraph("Scoring Rationale", styles["SectionHeading"]))
    for reason in scoring_result.get("reasons", []):
        story.append(Paragraph(f"• {privacy.mask_pii(reason)}", styles["Normal"]))

    if scoring_result.get("ml_applied"):
        story.append(Paragraph("Machine Learning Assessment", styles["SectionHeading"]))
        story.append(Paragraph(privacy.mask_pii(scoring_result.get("ml_explanation", "")), styles["Normal"]))
        top_features = scoring_result.get("ml_top_features") or []
        if top_features:
            story.append(Spacer(1, 4))
            story.append(Paragraph(
                "Top phrases driving this classification (extracted from the trained "
                "model's own learned weights for this specific message, not a "
                "predefined keyword list):",
                styles["Normal"],
            ))
            for phrase, weight in top_features:
                story.append(Paragraph(f"• '{phrase}' (weight {weight:.3f})", styles["Mono"]))
    else:
        story.append(Paragraph("Machine Learning Assessment", styles["SectionHeading"]))
        story.append(Paragraph(
            "The ML classifier was unavailable for this case. Scoring relied on structural "
            "forensic signals only (authentication, URL structure, attachments, domain identity).",
            styles["Normal"],
        ))

    recommendations_result = full.get("recommendations") or {}
    if recommendations_result:
        story.append(Paragraph("Recommended Actions", styles["SectionHeading"]))
        summary = recommendations_result.get("summary")
        if summary:
            story.append(Paragraph(summary, styles["Normal"]))
            story.append(Spacer(1, 4))
        for action in recommendations_result.get("actions", []):
            story.append(Paragraph(f"• {action}", styles["Normal"]))
        attribution_note = recommendations_result.get("attribution_note")
        if attribution_note:
            story.append(Spacer(1, 4))
            story.append(Paragraph(attribution_note, styles["Normal"]))

    story.append(Paragraph("Evidence Integrity", styles["SectionHeading"]))
    story.append(_kv_table([
        ("Evidence SHA-256", case.get("evidence_sha256")),
    ]))

    story.append(PageBreak())
    story.append(Paragraph("Attribution Limitations", styles["SectionHeading"]))
    story.append(Paragraph(ATTRIBUTION_LIMITATIONS_TEXT, styles["Normal"]))

    doc.build(story)
    return buffer.getvalue()
