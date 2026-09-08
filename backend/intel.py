"""
intel.py — GeoIP, WHOIS domain intelligence, and hosting/VPN/Tor
heuristics on the earliest public relay IP.

Every external lookup here is OPTIONAL ENRICHMENT: if it fails or times
out, the corresponding field is None and the rest of the pipeline still
completes. Nothing in here may raise out to the caller.
"""

import ipaddress
import json
import os
import time
from datetime import datetime, timezone

from . import config

_TOR_CACHE_TTL_SECONDS = 6 * 60 * 60  # refresh every 6h, not on every request


def _is_public_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return not (addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved)
    except ValueError:
        return False


def find_earliest_public_ip(relay_chain: dict) -> str | None:
    """Earliest hop (index 0, oldest) with a public IP. Skips private/
    internal hops which are internal to the sender's own infrastructure."""
    for hop in relay_chain.get("hops", []):
        ip = hop.get("ip")
        if ip and _is_public_ip(ip):
            return ip
    return None


def geoip_lookup(ip: str) -> dict | None:
    """
    Best-effort GeoIP lookup. Wrapped so any network/library failure
    degrades to None rather than breaking the pipeline. Results are
    explicitly labeled as probable sending infrastructure location, never
    a confirmed attacker location.
    """
    if not ip:
        return None
    try:
        import requests
        resp = requests.get(f"http://ip-api.com/json/{ip}", timeout=2.5)
        if resp.status_code != 200:
            return None
        data = resp.json()
        if data.get("status") != "success":
            return None
        return {
            "ip": ip,
            "country": data.get("country"),
            "city": data.get("city"),
            "isp": data.get("isp"),
            "org": data.get("org"),
            "as": data.get("as"),
            "disclaimer": "Probable sending infrastructure location — NOT a confirmed attacker location.",
        }
    except Exception:
        return None


def _load_tor_exit_cache() -> set:
    try:
        if os.path.exists(config.TOR_EXIT_LIST_CACHE):
            with open(config.TOR_EXIT_LIST_CACHE, "r") as f:
                cached = json.load(f)
            if time.time() - cached.get("fetched_at", 0) < _TOR_CACHE_TTL_SECONDS:
                return set(cached.get("ips", []))
    except Exception:
        pass
    return _refresh_tor_exit_cache()


def _refresh_tor_exit_cache() -> set:
    try:
        import requests
        resp = requests.get("https://check.torproject.org/torbulkexitlist", timeout=3)
        if resp.status_code != 200:
            return set()
        ips = set(line.strip() for line in resp.text.splitlines() if line.strip())
        try:
            with open(config.TOR_EXIT_LIST_CACHE, "w") as f:
                json.dump({"fetched_at": time.time(), "ips": list(ips)}, f)
        except Exception:
            pass
        return ips
    except Exception:
        return set()


def is_tor_exit_node(ip: str) -> bool | None:
    """Returns None (unknown) if the cache/network is unavailable, rather
    than a false 'not Tor'."""
    if not ip:
        return None
    try:
        exit_nodes = _load_tor_exit_cache()
        if not exit_nodes:
            return None
        return ip in exit_nodes
    except Exception:
        return None


def is_known_vpn(org_string: str) -> bool:
    if not org_string:
        return False
    lower = org_string.lower()
    return any(kw in lower for kw in config.KNOWN_VPN_ASN_KEYWORDS)


def is_cloud_hosting(org_string: str) -> bool:
    if not org_string:
        return False
    lower = org_string.lower()
    return any(kw in lower for kw in config.CLOUD_HOSTING_KEYWORDS)


def whois_lookup(domain: str) -> dict | None:
    """Best-effort WHOIS lookup; returns None on any failure (library
    missing, network error, parse error, rate limit, etc.)."""
    if not domain:
        return None
    try:
        import whois  # python-whois, optional dependency
        w = whois.whois(domain)
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0] if creation_date else None
        if not creation_date:
            return None
        if creation_date.tzinfo is None:
            creation_date = creation_date.replace(tzinfo=timezone.utc)
        age_days = (datetime.now(timezone.utc) - creation_date).days
        return {
            "domain": domain,
            "registrar": w.registrar,
            "creation_date": creation_date.isoformat(),
            "domain_age_days": age_days,
        }
    except Exception:
        return None


def domain_age_score(age_days: int | None) -> int:
    """Escalating weight the newer the domain is."""
    if age_days is None:
        return 0
    if age_days <= 7:
        return 30
    if age_days <= 30:
        return 20
    if age_days <= 90:
        return 10
    return 0


def gather_intel(analysis: dict, relay_chain: dict) -> dict:
    """Runs all optional enrichment lookups and returns a combined dict.
    Never raises; missing lookups simply appear as None."""
    earliest_ip = find_earliest_public_ip(relay_chain) if relay_chain.get("available") else None

    geo = geoip_lookup(earliest_ip) if earliest_ip else None
    tor_flag = is_tor_exit_node(earliest_ip) if earliest_ip else None
    org_string = (geo or {}).get("org") or (geo or {}).get("isp") or ""
    vpn_flag = is_known_vpn(org_string)
    cloud_flag = is_cloud_hosting(org_string)

    domain_whois = whois_lookup(analysis.get("from_domain"))

    return {
        "earliest_public_ip": earliest_ip,
        "geoip": geo,
        "is_tor_exit_node": tor_flag,
        "is_known_vpn": vpn_flag,
        "is_cloud_hosting": cloud_flag,
        "whois": domain_whois,
    }


def intel_signals(analysis: dict) -> list:
    """Contribution list for scoring.py's aggregator."""
    contributions = []
    intel = analysis.get("_intel_results") or {}

    whois_data = intel.get("whois")
    if whois_data:
        age_days = whois_data.get("domain_age_days")
        pts = domain_age_score(age_days)
        if pts:
            contributions.append({
                "points": pts,
                "reason": f"Sender domain registered only {age_days} day(s) ago "
                          f"(registrar: {whois_data.get('registrar')})",
            })

    if intel.get("is_tor_exit_node"):
        contributions.append({"points": 20, "reason": "Earliest relay IP is a known Tor exit node"})
    if intel.get("is_known_vpn"):
        contributions.append({"points": 10, "reason": "Earliest relay IP belongs to a known VPN provider"})
    if intel.get("is_cloud_hosting"):
        contributions.append({"points": 5, "reason": "Earliest relay IP belongs to generic cloud hosting infrastructure"})

    return contributions
