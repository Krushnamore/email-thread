"""
content_signals.py — domain-identity signals only.

IMPORTANT (post-restructure): this module used to also contain
"urgency" and "credential-harvesting" KEYWORD LISTS (config.py's
URGENCY_KEYWORDS / CREDENTIAL_HARVEST_KEYWORDS) that scored an email's
BODY TEXT by literal substring matching against a hand-written wordlist,
plus an EXEC_ROLE_PATTERNS / TRUST_KEYWORDS list for BEC/suspicious-
domain guessing. That is exactly the "static blacklist / rule-based
signature" approach PS-106 explicitly calls insufficient. It has been
REMOVED. All content/body classification is now done by the trained ML
model in backend/ml/classifier.py, which learns which phrasing patterns
correlate with phishing from data instead of a fixed list someone wrote
by hand — see scoring.py.

What's left here is domain-IDENTITY analysis: is the From domain
attempting to impersonate a specific known brand via character-
substitution / hyphenation lookalike tricks? This is a structural,
algorithmic string-similarity check (difflib) against a brand list, not
a content keyword match — it answers "does this domain resemble
paypal.com," not "does this email contain scary words."
"""

import difflib

from . import config


def _core_token(domain: str) -> str:
    """'paypal.com' -> 'paypal'; used so we compare on the brand token."""
    if not domain:
        return ""
    parts = domain.lower().split(".")
    return parts[0] if parts else domain.lower()


def detect_lookalike_domain(domain: str) -> dict | None:
    """
    Compares the sender domain's core token against each known brand's
    core token using difflib similarity, catching both hyphenated
    lookalikes (paypal-support.com) and character-substitution lookalikes
    (paypa1.com) against paypal.com. Also checks each hyphen-separated
    segment individually, since a lookalike brand token is often just one
    segment of a longer hyphenated domain (paypa1-secure.com).
    """
    if not domain:
        return None
    domain = domain.lower()

    # A genuine subdomain of a known brand (e.g. 'accounts.google.com')
    # is not a lookalike of that brand — it IS that brand's infrastructure.
    for brand in config.KNOWN_BRAND_DOMAINS:
        if domain == brand or domain.endswith("." + brand):
            return None

    no_tld = domain.rsplit(".", 1)[0] if "." in domain else domain
    segments = [s for s in no_tld.split("-") if s] or [no_tld]
    candidates = list(dict.fromkeys([no_tld.replace("-", "")] + segments))

    best_match, best_ratio = None, 0.0
    for brand in config.KNOWN_BRAND_DOMAINS:
        brand_token = _core_token(brand)

        for candidate_token in candidates:
            if candidate_token == brand_token:
                continue  # identical token to a brand isn't itself suspicious without more context
            ratio = difflib.SequenceMatcher(None, candidate_token, brand_token).ratio()
            contains = brand_token in candidate_token and candidate_token != brand_token
            if contains:
                ratio = max(ratio, 0.9)
            if ratio > best_ratio:
                best_ratio, best_match = ratio, brand

    if best_match and best_ratio >= 0.72:
        return {"matched_brand": best_match, "similarity": round(best_ratio, 2)}
    return None


def domain_signals(analysis: dict) -> list:
    contributions = []
    from_domain = analysis.get("from_domain") or ""

    lookalike = detect_lookalike_domain(from_domain)
    if lookalike:
        contributions.append({
            "points": 20,
            "reason": f"Sender domain '{from_domain}' closely resembles known brand "
                      f"'{lookalike['matched_brand']}' (similarity {lookalike['similarity']}) "
                      f"— algorithmic string-similarity check, not a keyword match",
        })

    return contributions
