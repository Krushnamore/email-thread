"""
scoring.py — the aggregator.

POST-RESTRUCTURE: the ML classifier (backend/ml/classifier.py) is now
the PRIMARY signal for email CONTENT (is the text itself phishing-style
writing?), replacing the old urgency/credential-harvesting keyword
lists entirely. Everything else contributed here is STRUCTURAL,
verifiable forensic evidence that content classification can't see on
its own: cryptographic auth results (SPF/DKIM/DMARC), URL host
structure, attachment file types, and domain-identity (algorithmic
lookalike-domain similarity, not a keyword match). These two kinds of
evidence are complementary — ML reads what the email SAYS, structural
forensics checks what the email's transport/technical facts ARE — and
both are combined into one explainable score.

IMPORTANT: this module must never import sklearn, joblib, or any ML
library directly — only backend/ml/classifier.py does. This keeps the
rest of the platform free of ML dependencies until ENABLE_ML is flipped.
"""

from . import attachment_analysis
from . import attribution
from . import config
from . import content_signals as cs
from . import header_forensics
from . import intel
from . import recommendations
from . import url_analysis
from .ml import classifier as ml_classifier

VERDICT_LEVELS = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]


def verdict_rank(verdict: str) -> int:
    try:
        return VERDICT_LEVELS.index(verdict)
    except ValueError:
        return 0


def level_from_score(score: int) -> str:
    if score >= 80:
        return "CRITICAL"
    if score >= 55:
        return "HIGH"
    if score >= 30:
        return "MEDIUM"
    return "LOW"


def _auth_signals(analysis: dict) -> list:
    header_results = analysis.get("_header_results") or {}
    auth = header_results.get("authentication", {})
    return_path = header_results.get("return_path", {})
    contributions = []

    if not auth.get("available"):
        return contributions  # limited_forensics mode — nothing to score here

    fail_weights = {"spf": 8, "dkim": 8, "dmarc": 10}
    for mechanism, weight in fail_weights.items():
        verdict = auth.get(mechanism)
        if verdict in ("fail", "permerror"):
            contributions.append({
                "points": weight,
                "reason": f"{mechanism.upper()} verdict is '{verdict}' across authentication headers",
            })
        elif verdict == "softfail":
            contributions.append({
                "points": max(weight // 2, 4),
                "reason": f"{mechanism.upper()} verdict is 'softfail'",
            })

    if auth.get("spf_aligned") is False:
        contributions.append({"points": 10, "reason": "SPF passes but authenticated domain is not aligned with the From domain"})
    if auth.get("dkim_aligned") is False:
        contributions.append({"points": 10, "reason": "DKIM passes but authenticated domain is not aligned with the From domain"})

    if return_path.get("mismatch"):
        contributions.append({
            "points": 8,
            "reason": f"Return-Path domain '{return_path.get('return_path_domain')}' differs from From domain "
                      f"'{return_path.get('from_domain')}'",
        })

    return contributions


def _high_value_brand_spoof_override(analysis: dict) -> dict | None:
    """
    Hard gate, not an additive score contribution: if the From domain
    belongs to (or claims to be a subdomain of) a high-value brand
    (bank/webmail/etc. from KNOWN_BRAND_DOMAINS) and NONE of SPF/DKIM/DMARC
    authenticated at all, that is not "a slightly suspicious email" — it is
    a domain with zero cryptographic proof it came from where it claims,
    impersonating a brand people implicitly trust. Weighted additive
    scoring can let that get diluted down to LOW/MEDIUM by an otherwise
    unremarkable body/URL set, so this is treated as an absolute override
    to CRITICAL rather than a handful of extra points, mirroring the
    verdict-floor pattern already used for high-risk attachments below.
    """
    header_results = analysis.get("_header_results") or {}
    auth = header_results.get("authentication", {})
    if not auth.get("available"):
        return None

    from_domain = (analysis.get("from_domain") or "").lower()
    if not from_domain:
        return None

    is_high_value_brand = any(
        from_domain == brand or from_domain.endswith("." + brand)
        for brand in config.KNOWN_BRAND_DOMAINS
    )
    if not is_high_value_brand:
        return None

    no_auth_at_all = (
        (auth.get("spf") or "none") == "none"
        and (auth.get("dkim") or "none") == "none"
        and (auth.get("dmarc") or "none") == "none"
    )
    if not no_auth_at_all:
        return None

    return {
        "reason": f"From domain '{from_domain}' matches/claims a high-value brand but SPF, DKIM, "
                  f"and DMARC are all 'none' — no cryptographic proof of origin for a brand this "
                  f"commonly impersonated; overriding to CRITICAL regardless of additive score",
    }


# --- ML weighting ---------------------------------------------------------
# ML is the primary content signal, so it gets the largest single weight
# in the additive score. Scored directly off phishing_probability (not
# "confidence in whatever label won"), so a 70%-phishing email always
# contributes the same regardless of which label technically "won" at
# the 50% line.
ML_MAX_POINTS = 55
ML_PHISHING_FLOOR = 0.5  # below this, ML contributes 0 suspicion points


def _ml_contribution_from_result(ml_result: dict) -> dict:
    """
    Turns an ml_classifier.classify() result into a score contribution.
    Scored directly off phishing_probability (not "confidence in whatever
    label won"), so a 70%-phishing email always contributes the same
    regardless of which label technically "won" at the 50% line.
    """
    p = ml_result["phishing_probability"]
    if p >= ML_PHISHING_FLOOR:
        return {
            "points": round(p * ML_MAX_POINTS),
            "reason": f"ML model classifies message content as phishing "
                      f"({round(p * 100)}% probability)",
        }
    # BUGFIX: the previous version added round(confidence * 20) points
    # UNCONDITIONALLY, including when the model's own label was
    # "legitimate" — so a confident LEGITIMATE classification still
    # pushed the threat score up, rewarding the exact case that should
    # reduce suspicion. A legitimate classification must never add
    # suspicion points; it's still logged for transparency.
    return {
        "points": 0,
        "reason": f"ML model assesses message content as legitimate "
                  f"({round((1 - p) * 100)}% confidence) — no content-based "
                  f"suspicion contributed",
    }


def _ml_signal(analysis: dict) -> tuple[dict | None, dict | None]:
    """Runs the ML classifier once and returns (ml_result, contribution|None)."""
    ml_result = ml_classifier.classify(analysis)
    if ml_result is None:
        return None, None
    return ml_result, _ml_contribution_from_result(ml_result)


def score_email(analysis: dict, ml_result: dict | None = None) -> dict:
    """
    Assumes analysis already carries:
      - analysis['_header_results']   (from header_forensics.run)
      - analysis['_intel_results']    (from intel.gather_intel)
    which the orchestrator (analyze_pipeline, below) populates before
    calling this function. attachment/url/content signal functions
    populate their own analysis['_..._results'] caches as a side effect.

    `ml_result`, if provided, skips re-running inference (analyze_pipeline
    runs it once and shares it with attribution.py too).
    """
    contributions = []
    contributions += _auth_signals(analysis)
    contributions += cs.domain_signals(analysis)
    contributions += url_analysis.url_signals(analysis)
    contributions += attachment_analysis.attachment_signals(analysis)
    contributions += intel.intel_signals(analysis)

    # --- ML: primary content signal ---
    if ml_result is None:
        ml_result, ml_contribution = _ml_signal(analysis)
    else:
        ml_contribution = _ml_contribution_from_result(ml_result)
    if ml_contribution is not None:
        contributions.append(ml_contribution)

    ml_explanation = ml_classifier.explain_in_plain_language(ml_result) if ml_result else (
        "The ML model was unavailable for this analysis; scoring relied on structural "
        "forensic signals only (authentication, URL structure, attachments, domain identity)."
    )

    score = min(sum(c["points"] for c in contributions), 100)
    reasons = [c["reason"] for c in contributions]

    # Verdict floors: some single signals must not be diluted by an
    # otherwise-clean-looking email.
    verdict = level_from_score(score)
    if analysis.get("has_high_risk_attachment"):
        if verdict_rank(verdict) < verdict_rank("HIGH"):
            verdict = "HIGH"

    brand_override = _high_value_brand_spoof_override(analysis)
    if brand_override:
        reasons.append(brand_override["reason"])
        score = max(score, 95)
        verdict = "CRITICAL"

    return {
        "score": score,
        "verdict": verdict,
        "reasons": reasons,
        "ml_applied": ml_result is not None,
        "ml_explanation": ml_explanation,
        "ml_top_features": ml_result.get("top_features") if ml_result else [],
        "contributions": contributions,
    }


def analyze_pipeline(analysis: dict) -> dict:
    """
    Full orchestration used by the API routes:
      1. header forensics (auth, return-path, relay chain)
      2. intel gathering (geoip/whois/tor/vpn/cloud) off the relay chain
      3. ML content classification, run ONCE and shared with both scoring
         and attribution (avoids running inference twice per case)
      4. scoring (populates analysis['has_high_risk_attachment'] etc. as
         a side effect via attachment_analysis / url_analysis)
      5. attribution classification (structural forensics + ML content signal)
      6. plain-language recommended actions for the reader (see
         recommendations.py) — PS-106 asks for human-readable guidance,
         not only technical scores/labels.

    Returns a dict combining everything the API/report/UI layers need.
    """
    header_results = header_forensics.run(analysis)
    analysis["_header_results"] = header_results

    intel_results = intel.gather_intel(analysis, header_results.get("relay_chain", {}))
    analysis["_intel_results"] = intel_results

    ml_result = ml_classifier.classify(analysis)

    scoring_result = score_email(analysis, ml_result=ml_result)

    attribution_result = attribution.classify_attribution(
        analysis, header_results, intel_results, ml_result=ml_result,
    )

    recommendations_result = recommendations.build_recommendations(
        analysis, scoring_result, attribution_result,
    )

    return {
        "analysis": analysis,
        "header_forensics": header_results,
        "intel": intel_results,
        "scoring": scoring_result,
        "attribution": attribution_result,
        "recommendations": recommendations_result,
    }