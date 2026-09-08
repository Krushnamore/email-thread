"""
header_forensics.py — Received-chain reconstruction, SPF/DKIM/DMARC
parsing across ALL Authentication-Results headers (worst verdict wins),
alignment checks, and Return-Path domain comparison.
"""

import re

_VERDICT_RANK = {"pass": 0, "neutral": 1, "none": 1, "softfail": 2, "fail": 3, "permerror": 3, "temperror": 2}

_IP_RE = re.compile(r"\[?(\d{1,3}(?:\.\d{1,3}){3})\]?")
_FROM_RE = re.compile(r"from\s+([^\s;]+)", re.IGNORECASE)
_BY_RE = re.compile(r"by\s+([^\s;]+)", re.IGNORECASE)


def _worst(a: str, b: str) -> str:
    ra = _VERDICT_RANK.get((a or "none").lower(), 1)
    rb = _VERDICT_RANK.get((b or "none").lower(), 1)
    return a if ra >= rb else b


def org_domain(d: str) -> str:
    """Organizational/registered-domain approximation: last two labels,
    except for common two-part public suffixes (co.in, co.uk, com.au,
    gov.in, etc.) where we keep three labels instead. Used so that
    legitimate parent/child or bounce-handler subdomains of the same
    organization (e.g. 'gaia.bounces.google.com' vs 'accounts.google.com')
    aren't treated as a domain mismatch."""
    parts = (d or "").lower().strip(".").split(".")
    if len(parts) < 2:
        return d or ""
    two_part_suffixes = {"co", "com", "gov", "ac", "org", "net", "edu"}
    if len(parts) >= 3 and parts[-2] in two_part_suffixes:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def _extract_mechanism(auth_header: str, mechanism: str) -> str:
    """
    Extract the verdict for a mechanism (spf/dkim/dmarc) from one
    Authentication-Results header string, e.g. 'spf=pass smtp.mailfrom=...'.
    """
    pattern = re.compile(rf"{mechanism}\s*=\s*(\w+)", re.IGNORECASE)
    m = pattern.search(auth_header)
    return m.group(1).lower() if m else "none"


def _extract_mechanism_domain(auth_header: str, mechanism: str) -> str:
    """
    Best-effort extraction of the domain a mechanism authenticated against,
    e.g. dkim=pass header.d=example.com  ->  example.com
         spf=pass smtp.mailfrom=alerts@example.com -> example.com
    """
    d_match = re.search(rf"{mechanism}=\w+[^;]*?header\.d=([^\s;]+)", auth_header, re.IGNORECASE)
    if d_match:
        return d_match.group(1).lower().strip()
    mailfrom_match = re.search(r"smtp\.mailfrom=([^\s;]+)", auth_header, re.IGNORECASE)
    if mechanism == "spf" and mailfrom_match:
        val = mailfrom_match.group(1)
        return val.split("@")[-1].lower().strip() if "@" in val else val.lower().strip()
    return ""


def analyze_authentication(analysis: dict) -> dict:
    """
    Parse ALL Authentication-Results headers and take the WORST verdict
    per mechanism (spf/dkim/dmarc) rather than only the first occurrence.
    Also computes alignment: does the authenticated domain match From domain?
    """
    if analysis.get("limited_forensics"):
        return {
            "available": False,
            "spf": None, "dkim": None, "dmarc": None,
            "spf_aligned": None, "dkim_aligned": None,
            "note": "No headers available in plain-text paste mode; "
                    "authentication checks skipped rather than guessed.",
        }

    headers = analysis.get("authentication_results_raw", [])
    from_domain = (analysis.get("from_domain") or "").lower()

    # BUGFIX: these used to be seeded with the string "none" so that the
    # very first real header's verdict was immediately compared against a
    # placeholder via _worst(). Since "none" ranks the same as a genuine
    # neutral result (rank 1) — which is >= "pass" (rank 0) — _worst() kept
    # picking the placeholder over a real "pass", so every email reported
    # spf/dkim/dmarc == "none" even when the raw Authentication-Results
    # header clearly said pass/fail. Seed with None (no verdict seen yet)
    # and only fall back to "none" if no header ever supplied one.
    spf_verdict, dkim_verdict, dmarc_verdict = None, None, None
    spf_domain, dkim_domain = "", ""

    for h in headers:
        spf_extracted = _extract_mechanism(h, "spf")
        dkim_extracted = _extract_mechanism(h, "dkim")
        dmarc_extracted = _extract_mechanism(h, "dmarc")

        spf_verdict = spf_extracted if spf_verdict is None else _worst(spf_verdict, spf_extracted)
        dkim_verdict = dkim_extracted if dkim_verdict is None else _worst(dkim_verdict, dkim_extracted)
        dmarc_verdict = dmarc_extracted if dmarc_verdict is None else _worst(dmarc_verdict, dmarc_extracted)

        if not spf_domain:
            spf_domain = _extract_mechanism_domain(h, "spf")
        if not dkim_domain:
            dkim_domain = _extract_mechanism_domain(h, "dkim")

    spf_verdict = spf_verdict or "none"
    dkim_verdict = dkim_verdict or "none"
    dmarc_verdict = dmarc_verdict or "none"

    def _aligned(mech_domain: str) -> bool:
        if not mech_domain or not from_domain:
            return False
        # Alignment allows exact match or organizational-domain match
        # (relaxed alignment, e.g. RFC 7489 §3.1's "Relaxed" mode), so a
        # legitimate bounce/subdomain handler under the same parent domain
        # isn't penalized.
        return mech_domain == from_domain or org_domain(mech_domain) == org_domain(from_domain)

    return {
        "available": True,
        "spf": spf_verdict,
        "dkim": dkim_verdict,
        "dmarc": dmarc_verdict,
        "spf_authenticated_domain": spf_domain,
        "dkim_authenticated_domain": dkim_domain,
        "spf_aligned": _aligned(spf_domain) if spf_domain else None,
        "dkim_aligned": _aligned(dkim_domain) if dkim_domain else None,
        "raw_header_count": len(headers),
    }


def analyze_return_path(analysis: dict) -> dict:
    """
    BUGFIX: this used to require an EXACT string match between the
    Return-Path domain and the From domain, which flagged every
    legitimate bounce-handler subdomain (e.g. Return-Path
    'gaia.bounces.google.com' vs From 'accounts.google.com') as a
    mismatch. Real mail systems route bounces through dedicated VERP/
    bounce subdomains under the SAME parent organization, so alignment
    should be checked at the organizational-domain level (same relaxed
    definition used for SPF/DKIM alignment above), not by exact string
    equality.
    """
    return_path_domain = (analysis.get("return_path_domain") or "").lower()
    from_domain = (analysis.get("from_domain") or "").lower()
    aligned = bool(
        return_path_domain
        and from_domain
        and (return_path_domain == from_domain or org_domain(return_path_domain) == org_domain(from_domain))
    )
    mismatch = bool(return_path_domain and from_domain and not aligned)
    return {
        "return_path_domain": return_path_domain or None,
        "from_domain": from_domain or None,
        "mismatch": mismatch,
    }


def reconstruct_relay_chain(analysis: dict) -> dict:
    """
    Reverses the Received headers (mail systems prepend newest-first) so
    hop[0] is the oldest/earliest hop. The earliest hop is labeled
    'earliest observable/reliable sending node' — never claimed to be the
    attacker's location or identity.
    """
    if analysis.get("limited_forensics") or not analysis.get("received_headers_raw"):
        return {
            "available": False,
            "hops": [],
            "note": "No Received headers available; relay chain skipped.",
        }

    raw_headers = list(analysis["received_headers_raw"])
    raw_headers.reverse()  # oldest hop first

    hops = []
    for idx, h in enumerate(raw_headers):
        from_match = _FROM_RE.search(h)
        by_match = _BY_RE.search(h)
        ip_match = _IP_RE.search(h)
        hops.append({
            "hop_index": idx,
            "raw": h.strip(),
            "from_host": from_match.group(1) if from_match else None,
            "by_host": by_match.group(1) if by_match else None,
            "ip": ip_match.group(1) if ip_match else None,
            "label": "earliest observable/reliable sending node" if idx == 0 else None,
        })

    return {"available": True, "hops": hops}


def run(analysis: dict) -> dict:
    """Aggregate entry point used by scoring/attribution pipelines."""
    return {
        "authentication": analyze_authentication(analysis),
        "return_path": analyze_return_path(analysis),
        "relay_chain": reconstruct_relay_chain(analysis),
    }