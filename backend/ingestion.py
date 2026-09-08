"""
ingestion.py — three input modes converge on one internal `analysis` dict:

    parse_eml_bytes(raw_bytes)      -> analysis dict
    parse_raw_headers(raw_text)     -> analysis dict
    parse_plain_text(raw_text)      -> analysis dict (limited_forensics=True)

The resulting dict is the single shared contract consumed by every
downstream module (header_forensics, content_signals, url_analysis,
attachment_analysis, intel, attribution, scoring).
"""

import hashlib
import re
from email import policy
from email.parser import BytesParser, Parser
from email.utils import getaddresses, parseaddr


def _domain_of(address: str) -> str:
    if not address or "@" not in address:
        return ""
    return address.rsplit("@", 1)[-1].strip().lower().rstrip(">")


def _extract_common(msg) -> dict:
    """Shared extraction logic for email.message.Message objects."""
    from_raw = msg.get("From", "") or ""
    to_raw = msg.get("To", "") or ""
    reply_to_raw = msg.get("Reply-To", "") or ""
    return_path_raw = msg.get("Return-Path", "") or ""

    from_name, from_addr = parseaddr(from_raw)
    reply_name, reply_addr = parseaddr(reply_to_raw)
    _, return_path_addr = parseaddr(return_path_raw)

    received_headers = msg.get_all("Received", []) or []
    auth_results_headers = msg.get_all("Authentication-Results", []) or []

    body_text = ""
    body_html = ""
    attachments = []

    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get("Content-Disposition") or "")
            filename = part.get_filename()

            if filename or "attachment" in content_disposition.lower():
                payload = part.get_payload(decode=True) or b""
                sha256 = hashlib.sha256(payload).hexdigest() if payload else ""
                attachments.append({
                    "filename": filename or "unnamed",
                    "content_type": content_type,
                    "size": len(payload),
                    "sha256": sha256,
                })
                continue

            if content_type == "text/plain" and not body_text:
                try:
                    body_text = part.get_payload(decode=True).decode(
                        part.get_content_charset() or "utf-8", errors="replace"
                    )
                except Exception:
                    body_text = str(part.get_payload())
            elif content_type == "text/html" and not body_html:
                try:
                    body_html = part.get_payload(decode=True).decode(
                        part.get_content_charset() or "utf-8", errors="replace"
                    )
                except Exception:
                    body_html = str(part.get_payload())
    else:
        content_type = msg.get_content_type()
        try:
            payload = msg.get_payload(decode=True)
            decoded = payload.decode(msg.get_content_charset() or "utf-8", errors="replace") if payload else msg.get_payload()
        except Exception:
            decoded = str(msg.get_payload())
        if content_type == "text/html":
            body_html = decoded
        else:
            body_text = decoded

    body = body_text.strip() if body_text.strip() else _strip_html(body_html)

    return {
        "from_display_name": from_name,
        "from_address": from_addr.lower(),
        "from_domain": _domain_of(from_addr),
        "to": to_raw,
        "reply_to_address": reply_addr.lower(),
        "reply_to_domain": _domain_of(reply_addr),
        "return_path_address": return_path_addr.lower(),
        "return_path_domain": _domain_of(return_path_addr),
        "subject": msg.get("Subject", "") or "",
        "date": msg.get("Date", "") or "",
        "message_id": msg.get("Message-ID", "") or "",
        "received_headers_raw": [str(h) for h in received_headers],
        "authentication_results_raw": [str(h) for h in auth_results_headers],
        "body": body,
        "attachments": attachments,
        "limited_forensics": False,
    }


def _strip_html(html: str) -> str:
    if not html:
        return ""
    text = re.sub(r"<(script|style)[^>]*>.*?</\1>", " ", html, flags=re.DOTALL | re.IGNORECASE)
    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def parse_eml_bytes(raw_bytes: bytes) -> dict:
    msg = BytesParser(policy=policy.default).parsebytes(raw_bytes)
    analysis = _extract_common(msg)
    analysis["source_mode"] = "eml_upload"
    analysis["raw_eml"] = raw_bytes
    analysis["evidence_sha256"] = hashlib.sha256(raw_bytes).hexdigest()
    return analysis


def parse_raw_headers(raw_text: str) -> dict:
    """
    Accepts a paste of raw internet headers, optionally followed by a
    blank line and the body (Gmail 'Show original' / Outlook 'Internet
    headers' style paste). Falls back gracefully if no body is present.
    """
    msg = Parser(policy=policy.default).parsestr(raw_text)
    analysis = _extract_common(msg)
    analysis["source_mode"] = "raw_headers_paste"
    analysis["raw_eml"] = raw_text.encode("utf-8", errors="replace")
    analysis["evidence_sha256"] = hashlib.sha256(analysis["raw_eml"]).hexdigest()
    return analysis


def parse_plain_text(raw_text: str) -> dict:
    """
    Degraded mode: only visible email text was pasted (no headers
    available). Explicitly mark limited_forensics=True and skip
    header-dependent checks downstream rather than guessing.
    """
    # Best-effort: try to sniff a From:/Subject: line if the user pasted them,
    # but never fabricate values.
    from_addr = ""
    subject = ""
    for line in raw_text.splitlines()[:15]:
        low = line.strip().lower()
        if low.startswith("from:") and not from_addr:
            _, from_addr = parseaddr(line.split(":", 1)[1])
            from_addr = from_addr.lower()
        elif low.startswith("subject:") and not subject:
            subject = line.split(":", 1)[1].strip()

    evidence_bytes = raw_text.encode("utf-8", errors="replace")
    return {
        "from_display_name": "",
        "from_address": from_addr,
        "from_domain": _domain_of(from_addr),
        "to": "",
        "reply_to_address": "",
        "reply_to_domain": "",
        "return_path_address": "",
        "return_path_domain": "",
        "subject": subject,
        "date": "",
        "message_id": "",
        "received_headers_raw": [],
        "authentication_results_raw": [],
        "body": raw_text.strip(),
        "attachments": [],
        "limited_forensics": True,
        "source_mode": "plain_text_paste",
        "raw_eml": evidence_bytes,
        "evidence_sha256": hashlib.sha256(evidence_bytes).hexdigest(),
    }
