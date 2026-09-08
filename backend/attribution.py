"""
attribution.py — attribution classifier combining structural forensics
(header/auth/WHOIS/intel — objective, verifiable facts) with the ML
model's content judgment (backend/ml/classifier.py) in place of the
literal urgency/credential-harvesting keyword lists this used to use.
Domain-identity is still the algorithmic lookalike-domain check
(content_signals.py), not a keyword match.

Rule table (documented here so it's easy to explain to judges):

  LIKELY_SPOOFED_DOMAIN            auth fails (spf/dkim/dmarc fail or
                                    misaligned) AND lookalike domain

  LIKELY_COMPROMISED_ACCOUNT       auth passes AND aligned AND the ML
                                    model classifies the content as
                                    phishing AND no domain anomaly
                                    (legit infra sending bad content
                                    usually means the account is
                                    compromised, not the domain spoofed)

  LIKELY_ANONYMIZED_INFRASTRUCTURE origin IP is Tor exit node, known VPN,
                                    or generic cloud host, AND no other
                                    strong identifying signal fired

  LIKELY_DIRECT_MALICIOUS_ACTOR    multiple strong signals converge with
                                    no plausible innocent explanation
                                    (e.g. new domain + auth fail +
                                    malicious attachment + ML-classified
                                    phishing content — 3+ of these
                                    together)

  INSUFFICIENT_SIGNAL              default when nothing meaningfully
                                    correlates

Confidence = proportion of corroborating signals present for the chosen
label, expressed as a percentage.
"""

from . import content_signals as cs
from .ml import classifier as ml_classifier


def _auth_failed_or_misaligned(auth: dict) -> bool:
    if not auth or not auth.get("available"):
        return False
    fails = auth.get("spf") == "fail" or auth.get("dkim") == "fail" or auth.get("dmarc") == "fail"
    misaligned = auth.get("spf_aligned") is False or auth.get("dkim_aligned") is False
    return fails or misaligned


def _auth_passed_and_aligned(auth: dict) -> bool:
    if not auth or not auth.get("available"):
        return False
    passed = auth.get("spf") == "pass" or auth.get("dkim") == "pass"
    aligned = auth.get("spf_aligned") or auth.get("dkim_aligned")
    return bool(passed and aligned)


ML_PHISHING_THRESHOLD = 0.6  # ML must lean "phishing" with at least this confidence to count as a signal here


def classify_attribution(analysis: dict, header_results: dict, intel_results: dict,
                          ml_result: dict | None = None) -> dict:
    auth = header_results.get("authentication", {})
    from_domain = analysis.get("from_domain") or ""

    domain_anomaly = cs.detect_lookalike_domain(from_domain) is not None

    if ml_result is None:
        ml_result = ml_classifier.classify(analysis)
    ml_says_phishing = bool(
        ml_result and ml_result.get("label") == "phishing"
        and ml_result.get("phishing_probability", 0) >= ML_PHISHING_THRESHOLD
    )

    has_malicious_attachment = bool(analysis.get("has_high_risk_attachment"))
    whois_data = intel_results.get("whois") or {}
    is_new_domain = bool(whois_data.get("domain_age_days") is not None and whois_data["domain_age_days"] <= 30)

    is_anonymized_infra = bool(
        intel_results.get("is_tor_exit_node") or intel_results.get("is_known_vpn") or intel_results.get("is_cloud_hosting")
    )

    auth_fail = _auth_failed_or_misaligned(auth)
    auth_pass_aligned = _auth_passed_and_aligned(auth)

    # --- LIKELY_DIRECT_MALICIOUS_ACTOR: 3+ strong signals converge ---
    strong_signals = [auth_fail, domain_anomaly, has_malicious_attachment, ml_says_phishing, is_new_domain]
    strong_signal_count = sum(bool(s) for s in strong_signals)
    if strong_signal_count >= 3:
        return {
            "label": "LIKELY_DIRECT_MALICIOUS_ACTOR",
            "confidence": round(min(strong_signal_count / len(strong_signals), 1.0) * 100, 1),
            "corroborating_signals": _named(strong_signals, [
                "auth_fail_or_misaligned", "domain_anomaly", "malicious_attachment",
                "ml_classified_phishing_content", "newly_registered_domain",
            ]),
        }

    # --- LIKELY_SPOOFED_DOMAIN: auth fails + domain anomaly ---
    if auth_fail and domain_anomaly:
        signals = [auth_fail, domain_anomaly]
        return {
            "label": "LIKELY_SPOOFED_DOMAIN",
            "confidence": round(sum(signals) / len(signals) * 100, 1),
            "corroborating_signals": _named(signals, ["auth_fail_or_misaligned", "domain_anomaly"]),
        }

    # --- LIKELY_COMPROMISED_ACCOUNT: auth passes/aligned + ML-flagged content + no domain anomaly ---
    if auth_pass_aligned and ml_says_phishing and not domain_anomaly:
        signals = [auth_pass_aligned, ml_says_phishing, not domain_anomaly]
        return {
            "label": "LIKELY_COMPROMISED_ACCOUNT",
            "confidence": round(sum(signals) / len(signals) * 100, 1),
            "corroborating_signals": _named(signals, [
                "auth_pass_and_aligned", "ml_classified_phishing_content", "no_domain_anomaly",
            ]),
        }

    # --- LIKELY_ANONYMIZED_INFRASTRUCTURE: anonymized origin, nothing else strong ---
    if is_anonymized_infra and not domain_anomaly and not has_malicious_attachment:
        signals = [is_anonymized_infra, not domain_anomaly, not has_malicious_attachment]
        return {
            "label": "LIKELY_ANONYMIZED_INFRASTRUCTURE",
            "confidence": round(sum(signals) / len(signals) * 100, 1),
            "corroborating_signals": _named(signals, [
                "anonymized_origin_infrastructure", "no_domain_anomaly", "no_malicious_attachment",
            ]),
        }

    return {
        "label": "INSUFFICIENT_SIGNAL",
        "confidence": 0.0,
        "corroborating_signals": [],
    }


def _named(bool_list, names):
    return [name for flag, name in zip(bool_list, names) if flag]
