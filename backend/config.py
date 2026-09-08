"""
config.py — global feature flags and tunables.

ENABLE_ML controls whether ml/classifier.py attempts to load and run a
trained model. Keep this False until model.pkl + vectorizer.pkl are
dropped into backend/ml/artifacts/. The platform is fully demoable and
scores correctly with this flag off.
"""

import os

# --- ML integration flag -----------------------------------------------
ENABLE_ML = True

# --- Paths ---------------------------------------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "forensics.db")
EML_STORAGE_DIR = os.path.join(BASE_DIR, "stored_emails")
TOR_EXIT_LIST_CACHE = os.path.join(BASE_DIR, "tor_exit_nodes.cache.json")

os.makedirs(EML_STORAGE_DIR, exist_ok=True)

# --- Brand list for lookalike-domain detection ---------------------------
KNOWN_BRAND_DOMAINS = [
    "paypal.com", "microsoft.com", "google.com", "apple.com", "amazon.com",
    "bankofamerica.com", "wellsfargo.com", "chase.com", "netflix.com",
    "dhl.com", "fedex.com", "linkedin.com", "facebook.com", "hdfcbank.com",
    "icicibank.com", "sbi.co.in", "irctc.co.in", "gov.in",
]

# --- REMOVED: TRUST_KEYWORDS, EXEC_ROLE_PATTERNS, ORG_KNOWN_DOMAINS,
# URGENCY_KEYWORDS, CREDENTIAL_HARVEST_KEYWORDS.
#
# These were static, hand-written wordlists used to score email BODY
# TEXT by literal substring matching -- exactly the "static blacklist /
# rule-based signature mechanism" PS-106 says is insufficient. All
# content classification is now done by the trained ML model in
# backend/ml/classifier.py, which learns phishing-associated phrasing
# from data rather than a fixed list. See content_signals.py and
# scoring.py for what replaced them.

# --- URL heuristics --------------------------------------------------------
KNOWN_URL_SHORTENERS = [
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly",
]

SUSPICIOUS_TLDS = [
    ".zip", ".mov", ".xyz", ".top", ".click", ".gq", ".tk", ".ml", ".cf",
    ".work", ".support", ".loan",
]

# --- Attachment heuristics -------------------------------------------------
DANGEROUS_EXTENSIONS = [
    ".exe", ".scr", ".js", ".vbs", ".bat", ".cmd", ".jar", ".msi", ".ps1", ".hta",
]

# --- Cloud hosting keyword list (for hosting/VPN heuristic) ---------------
CLOUD_HOSTING_KEYWORDS = [
    "amazon", "aws", "digitalocean", "linode", "ovh", "hetzner", "google cloud",
    "azure", "microsoft corporation", "vultr", "contabo", "alibaba cloud",
]

KNOWN_VPN_ASN_KEYWORDS = [
    "nordvpn", "expressvpn", "surfshark", "privateinternetaccess", "protonvpn",
    "mullvad", "cyberghost", "ipvanish",
]

# Placeholder actor id used for audit logging until an auth system exists.
DEFAULT_ACTOR = "analyst_default"
