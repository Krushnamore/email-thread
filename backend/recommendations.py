"""
recommendations.py — plain-language, actionable guidance for the reader
of a case report, independent of the technical scoring detail.

PS-106 explicitly asks for forensic output that isn't only technical
terms/scores — it should tell the reader (an investigator, an end user,
an org's IT/security desk) what to actually DO about a given case. This
module maps verdict + attribution label + concrete evidence (malicious
attachment, spoofed domain, anonymized infra, etc.) to a short ordered
list of recommended actions, written for a non-technical reader.

This is NOT a scoring signal — it never influences threat_score or
verdict. It only shapes what advice is shown.
"""

_BASE_LOW = [
    "No strong indicators of phishing or compromise were found in this message.",
    "Still avoid entering passwords or payment details unless you initiated the contact yourself.",
]

_BASE_MEDIUM = [
    "Treat this message with caution — some suspicious indicators were found.",
    "Do not click any links or open any attachments in this email until you've verified the sender through a separate, known channel (e.g. calling the organization's official number, not one in the email).",
    "If it claims to be from a colleague or vendor, confirm the request by phone or in person before acting on it.",
]

_BASE_HIGH_OR_CRITICAL = [
    "Do not click any links, open any attachments, or reply to this email.",
    "Do not enter any login credentials, OTPs, card numbers, or personal information on any page this email links to.",
    "Report this email to your organization's IT/security team (or your email provider's 'report phishing' option) and then delete it.",
    "If you already clicked a link or entered any details, change that account's password immediately from a trusted device and enable two-factor authentication if available.",
]

_ATTRIBUTION_ADVICE = {
    "LIKELY_SPOOFED_DOMAIN": (
        "The sending domain appears to imitate a well-known brand rather than being that brand's "
        "real domain. Do not trust the sender name alone — verify the actual domain shown in the "
        "'From' address character-by-character, or contact the real organization directly."
    ),
    "LIKELY_COMPROMISED_ACCOUNT": (
        "The sending infrastructure/domain checks out, but the message content itself looks like an "
        "attack — this often means a real account (a colleague's, a vendor's) has been compromised. "
        "Notify that person/organization through a separate channel so they can secure their account."
    ),
    "LIKELY_ANONYMIZED_INFRASTRUCTURE": (
        "The email originated from infrastructure commonly used to hide the sender's real location "
        "(Tor, a VPN, or generic cloud hosting). This alone isn't proof of malicious intent, but it "
        "removes a normal identifying signal, so extra caution and independent verification are "
        "warranted before acting on anything the message asks for."
    ),
    "LIKELY_DIRECT_MALICIOUS_ACTOR": (
        "Multiple independent red flags point the same direction with no plausible innocent "
        "explanation. Treat this as an active attack: do not engage with it at all, and report it "
        "to your security team as a priority."
    ),
}

_ATTACHMENT_ADVICE = (
    "This email contains an attachment with a dangerous or disguised file type. Do not open it under "
    "any circumstances, even if the filename looks familiar (e.g. 'invoice.pdf.exe') — forward it to "
    "your security team for analysis instead of opening it yourself."
)


def build_recommendations(analysis: dict, scoring_result: dict, attribution_result: dict) -> dict:
    verdict = scoring_result.get("verdict", "LOW")

    if verdict in ("HIGH", "CRITICAL"):
        actions = list(_BASE_HIGH_OR_CRITICAL)
    elif verdict == "MEDIUM":
        actions = list(_BASE_MEDIUM)
    else:
        actions = list(_BASE_LOW)

    if analysis.get("has_high_risk_attachment"):
        actions.insert(1, _ATTACHMENT_ADVICE)

    label = attribution_result.get("label")
    attribution_note = _ATTRIBUTION_ADVICE.get(label)

    summary = {
        "LOW": "This message currently looks safe, but stay alert for the basics.",
        "MEDIUM": "This message has some suspicious signs — verify before you act on it.",
        "HIGH": "This message shows strong signs of phishing or compromise — do not act on it.",
        "CRITICAL": "This message shows critical, multi-signal signs of a targeted attack — treat it as malicious.",
    }.get(verdict, "Review this message carefully before acting on it.")

    return {
        "summary": summary,
        "actions": actions,
        "attribution_note": attribution_note,
    }
