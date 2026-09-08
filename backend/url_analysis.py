"""
url_analysis.py — extracts URLs from the body and scores each on the
NUMBER and SEVERITY of signals found (IP-based host, non-HTTPS, excessive
hyphens, unusually long, suspicious TLD, known shortener) — not on raw
URL count.
"""

import re
from urllib.parse import urlparse

from . import config

_URL_RE = re.compile(r"https?://[^\s<>\"')\]]+", re.IGNORECASE)
_IP_HOST_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def extract_urls(text: str) -> list:
    if not text:
        return []
    return list(dict.fromkeys(_URL_RE.findall(text)))  # de-dup, preserve order


def analyze_url(url: str) -> dict:
    parsed = urlparse(url)
    host = parsed.hostname or ""
    signals = []

    if _IP_HOST_RE.match(host):
        signals.append("ip_based_host")
    if parsed.scheme != "https":
        signals.append("non_https")
    if host.count("-") >= 3:
        signals.append("excessive_hyphens")
    # BUGFIX: this used to measure len(url) — the ENTIRE string, including
    # query params/tracking tokens — so a short, suspicious redirector
    # domain like 'c.gle' with a long tracking query string got flagged as
    # "unusually_long", while the actual heuristic that matters (an
    # abnormally long HOSTNAME, e.g. a stitched-together phishing subdomain)
    # was never checked. Measure the host/FQDN length instead. Short
    # domains are handled by known_shortener / brand-similarity checks, not
    # length.
    if len(host) > 30:
        signals.append("unusually_long")
    if any(host.endswith(tld) for tld in config.SUSPICIOUS_TLDS):
        signals.append("suspicious_tld")
    # BUGFIX: this used to be `shortener in host`, a raw substring test.
    # 't.co' (Twitter's shortener) is a substring of any '...t.com' domain,
    # so 'support.com', 'paypa1-support.com', 'client.com' etc. all falsely
    # matched 'known_shortener'. A host is only "the shortener" if it IS
    # that domain or a subdomain of it (api.bit.ly, x.bit.ly) — never a
    # coincidental substring.
    if any(host == shortener or host.endswith("." + shortener) for shortener in config.KNOWN_URL_SHORTENERS):
        signals.append("known_shortener")

    return {"url": url, "host": host, "signals": signals, "signal_count": len(signals)}


def analyze_urls(analysis: dict) -> list:
    urls = extract_urls(analysis.get("body", ""))
    return [analyze_url(u) for u in urls]


_SIGNAL_WEIGHTS = {
    "ip_based_host": 12,
    "non_https": 4,
    "excessive_hyphens": 6,
    "unusually_long": 5,
    "suspicious_tld": 8,
    "known_shortener": 6,
}


def url_signals(analysis: dict) -> list:
    contributions = []
    results = analyze_urls(analysis)
    analysis["_url_analysis_results"] = results  # cache for reports/UI

    for r in results:
        if not r["signals"]:
            continue
        points = sum(_SIGNAL_WEIGHTS.get(s, 3) for s in r["signals"])
        points = min(points, 25)  # cap per-URL contribution
        contributions.append({
            "points": points,
            "reason": f"URL '{r['host']}' flagged for: {', '.join(r['signals'])}",
        })

    return contributions