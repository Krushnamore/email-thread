"""
attachment_analysis.py — flags dangerous extensions and double-extension
tricks. A high-risk attachment sets analysis['has_high_risk_attachment'] =
True, which scoring.py uses to force a verdict floor of HIGH regardless
of the additive score.
"""

from . import config

_DOUBLE_EXT_RE_SUFFIXES = tuple(config.DANGEROUS_EXTENSIONS)


def _has_double_extension(filename: str) -> bool:
    """e.g. 'invoice.pdf.exe' — a benign-looking extension immediately
    followed by a dangerous one."""
    lower = filename.lower()
    parts = lower.split(".")
    if len(parts) < 3:
        return False
    last_ext = "." + parts[-1]
    return last_ext in config.DANGEROUS_EXTENSIONS


def analyze_attachment(att: dict) -> dict:
    filename = att.get("filename", "") or "unnamed"
    lower = filename.lower()
    dangerous_ext = next((ext for ext in config.DANGEROUS_EXTENSIONS if lower.endswith(ext)), None)
    double_ext = _has_double_extension(filename)

    return {
        "filename": filename,
        "content_type": att.get("content_type", ""),
        "size": att.get("size", 0),
        "sha256": att.get("sha256", ""),
        "dangerous_extension": dangerous_ext,
        "double_extension_trick": double_ext,
        "is_high_risk": bool(dangerous_ext or double_ext),
    }


def attachment_signals(analysis: dict) -> list:
    contributions = []
    attachments = analysis.get("attachments", []) or []
    analyzed = [analyze_attachment(a) for a in attachments]
    analysis["_attachment_analysis_results"] = analyzed

    has_high_risk = any(a["is_high_risk"] for a in analyzed)
    analysis["has_high_risk_attachment"] = has_high_risk

    for a in analyzed:
        if a["dangerous_extension"]:
            contributions.append({
                "points": 35,
                "reason": f"Attachment '{a['filename']}' has a dangerous extension "
                          f"({a['dangerous_extension']})",
            })
        elif a["double_extension_trick"]:
            contributions.append({
                "points": 35,
                "reason": f"Attachment '{a['filename']}' uses a double-extension trick "
                          f"to disguise an executable",
            })

    return contributions
