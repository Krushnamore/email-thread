# Email Forensic Intelligence Platform (SIH26106)

An **ML-driven** email forensic intelligence platform that detects
phishing, spoofing, and Business Email Compromise (BEC) attempts,
traces relay paths and probable sending infrastructure, correlates
indicators across cases into campaigns, manages cases, and generates
PDF forensic reports with plain-language recommended actions.

Built for **SIH26106 — "AI-Powered Email Threat Detection, GeoLocation
and Forensic Intelligence Platform"** (Theme: Blockchain & Cybersecurity).

**Architecture note (post-restructure):** email *content* (is the text
itself phishing-style writing?) is classified by a trained ML model
(TF-IDF + Logistic Regression), not by matching a hand-written list of
"suspicious words." That keyword-list approach — literal substring
matching against `URGENCY_KEYWORDS` / `CREDENTIAL_HARVEST_KEYWORDS` /
`EXEC_ROLE_PATTERNS` — has been removed entirely. It is exactly the
"static blacklist / rule-based signature mechanism" the SIH26106
description calls insufficient. Everything else in the pipeline
(SPF/DKIM/DMARC authentication, URL host structure, attachment file
types, WHOIS/GeoIP/Tor/VPN intel, algorithmic domain-lookalike
similarity) is **structural forensic evidence**, not content guessing —
those checks answer objective technical questions ("did this pass
DKIM," "is this an .exe," "does this domain string resemble
paypal.com") that ML text classification can't see on its own. See
[ML integration](#ml-integration) for exactly how the two are combined,
and the model's honest, measured limitations.

## Features

- **Three ingestion modes**: upload a `.eml` file, paste raw internet
  headers, or paste plain visible text (degraded mode, clearly labeled).
- **Header forensics**: parses *every* `Authentication-Results` header
  (not just the first), computes SPF/DKIM/DMARC verdicts and domain
  alignment, flags `Return-Path` mismatches, and reconstructs the relay
  chain oldest-hop-first.
- **ML-driven content classification (primary detection engine)**: a
  TF-IDF + Logistic Regression model classifies the message text as
  phishing/legitimate and drives the largest single share of the threat
  score. Explanations are extracted from the trained model's own
  learned weights *for that specific email* (see
  [ML integration](#ml-integration)) — not from a predefined keyword
  list.
- **Domain-identity signal**: algorithmic lookalike-domain detection
  (character-substitution / hyphenation typosquatting) against a brand
  list — a string-similarity check, not a content keyword match.
- **URL & attachment analysis**: per-URL risk signals (IP host,
  non-HTTPS, suspicious TLD, shorteners, etc.), dangerous-extension and
  double-extension attachment detection with a **verdict floor** (a
  malicious attachment always forces at least a HIGH verdict).
- **Origin intelligence**: GeoIP, WHOIS domain age, Tor-exit-node /
  known-VPN / cloud-hosting heuristics on the earliest public relay IP —
  always labeled as *probable sending infrastructure*, never a confirmed
  attacker identity. All external lookups are optional enrichment and
  degrade to `null` on failure without breaking the pipeline.
- **Attribution**: classifies each case into one of
  `LIKELY_SPOOFED_DOMAIN`, `LIKELY_COMPROMISED_ACCOUNT`,
  `LIKELY_ANONYMIZED_INFRASTRUCTURE`, `LIKELY_DIRECT_MALICIOUS_ACTOR`, or
  `INSUFFICIENT_SIGNAL`, with a confidence percentage, combining
  structural forensics with the ML content signal (see
  `backend/attribution.py` for the full rule table).
- **Human-readable recommended actions**: every case gets a plain-
  language "what to actually do about this" section (report it, verify
  the sender through another channel, change a password, etc.) —
  written for a non-technical reader, not just a technical score.
- **Campaign correlation**: cases sharing a domain, IP, or URL indicator
  are automatically grouped into a campaign via plain SQL — no graph
  database required.
- **Tamper-evident evidence ledger**: each case's evidence SHA-256 is
  chained to the previous entry's hash (`evidence_chain` table), giving a
  simple, practical stand-in for the "Blockchain" theme requirement
  without integrating a real blockchain.
- **PDF forensic reports** (ReportLab) with the ML assessment, recommended
  actions, and an explicit Attribution Limitations disclaimer.
- **Privacy-aware dashboard**: PII (emails, phone numbers) is masked
  wherever raw sender/body text is displayed.
- **Audit log** on every analyze / view / report-export action.

## Tech stack

- **Frontend**: single `frontend/index.html` — vanilla JS + `fetch()`,
  no build step, no framework.
- **Backend**: Python (FastAPI), modular, with SQLite persistence.
- **ML**: scikit-learn (TF-IDF vectorizer + Logistic Regression).

## Getting started

The backend package uses relative imports (`from . import ...`), so it
**must be launched as a package from the project root** — not from
inside `backend/`. Running `cd backend && uvicorn main:app` will fail
with `ImportError: attempted relative import with no known parent
package`.

```bash
# from the project root (email-forensics-platform/)
python3 -m venv backend/venv
source backend/venv/bin/activate          # Windows: backend\venv\Scripts\activate
pip install -r backend/requirements.txt

# ML is the primary content-detection engine — install its runtime deps:
pip install -r backend/requirements-ml.txt

# Only needed if you're retraining the model (backend/ml/train.py), not
# for running the API:
#   pip install -r backend/requirements-train.txt

python -m uvicorn backend.main:app --reload --port 8000
```

The API will be available at `http://localhost:8000`. Interactive docs
at `http://localhost:8000/docs`. Check `/health` — it reports
`ml_enabled` and whether the evidence chain is intact.

Then open `frontend/index.html` directly in a browser (it talks to
`http://localhost:8000` via the `API_BASE` constant at the top of the
`<script>` block — change it there if you deploy the backend elsewhere).

A ready-to-use phishing sample is provided at
`sample_emails/sample_phishing.eml` — try uploading it from the
**Upload .eml** tab.

## Project structure

```
email-forensics-platform/
├── backend/
│   ├── main.py              # FastAPI app + route registration only
│   ├── config.py            # Feature flags, incl. ENABLE_ML
│   ├── db.py                # SQLite connection + schema migrations
│   ├── ingestion.py         # .eml / paste-text / paste-headers parsing
│   ├── header_forensics.py  # Received chain, SPF/DKIM/DMARC, alignment
│   ├── content_signals.py   # algorithmic lookalike-domain detection ONLY (no keyword lists)
│   ├── url_analysis.py      # URL risk signal extraction
│   ├── attachment_analysis.py
│   ├── intel.py             # GeoIP, WHOIS, hosting/VPN/Tor heuristics
│   ├── attribution.py       # attribution classifier (structural forensics + ML content signal)
│   ├── recommendations.py   # plain-language recommended actions per case
│   ├── scoring.py           # the aggregator — ML is the primary content signal, see ML contract below
│   ├── ml/
│   │   ├── classifier.py    # loads model.pkl/vectorizer.pkl; classify() + explain_in_plain_language()
│   │   ├── train.py         # standalone training script
│   │   ├── data/
│   │   │   ├── generate_dataset.py          # synthetic dataset generator (see note below)
│   │   │   ├── synthetic_phishing_dataset.csv
│   │   │   └── ood_eval_set.py              # hand-written generalization eval (measured, not assumed)
│   │   └── artifacts/
│   │       ├── model.pkl, vectorizer.pkl    # trained artifacts
│   │       └── metrics.json                 # accuracy + honest OOD generalization check
│   ├── correlation.py       # campaign correlation via SQL
│   ├── reports.py           # PDF forensic report generation
│   ├── privacy.py           # PII masking, retention/purge helpers
│   ├── audit.py             # audit log writes
│   ├── requirements.txt
│   ├── requirements-ml.txt      # runtime ML inference deps (scikit-learn, joblib — no pandas)
│   └── requirements-train.txt   # training-only deps (adds pandas), never installed on the API host
├── frontend/
│   └── index.html
├── sample_emails/
│   └── sample_phishing.eml
└── README.md
```

## API endpoints

| Method | Path | Description |
|---|---|---|
| POST | `/analyze/eml` | multipart file upload (`.eml`) |
| POST | `/analyze/paste` | `{ raw_text, mode }` — `mode` is `"headers"` or `"text"` |
| GET | `/cases` | list cases, newest first, optional `?verdict=` filter |
| GET | `/cases/{id}` | full case detail |
| GET | `/cases/{id}/report` | PDF forensic report download |
| GET | `/campaigns` | list detected campaigns |
| GET | `/campaigns/{id}` | cases in a campaign |
| GET | `/health` | health check + evidence-chain integrity status |

## ML integration

`ENABLE_ML` is `True` by default in `backend/config.py`, with a trained
model already in `backend/ml/artifacts/`. **ML is now the primary
content-detection engine** — if it's unavailable (model missing, load
failure), the pipeline degrades to structural-forensics-only scoring
(auth/URL/attachment/domain-identity) rather than falling back to any
keyword list, because there is no keyword list left in this codebase.
`classify()` never raises, so a missing/broken model degrades
gracefully instead of crashing the pipeline — but note it now means
"no content opinion at all" rather than "fall back to rules."

**How much the ML score matters:** in `scoring.py`, the ML contribution
is scored directly off `phishing_probability` and capped at **55 of the
100** scoring points — deliberately the single largest weight in the
additive score, since it's the primary content signal. It contributes
`0` (not a small positive number) when the model itself says
"legitimate" — a bug in the earlier version of this scorer added
`confidence × 20` points *unconditionally*, so a confident *legitimate*
classification was still pushing the threat score up; that's fixed.

**What it is:** a TF-IDF vectorizer (unigrams + bigrams, 20k features)
feeding a Logistic Regression classifier — a real trained statistical
model. Because Logistic Regression is linear, `classifier.py` can (and
does) extract exactly which n-grams in *this specific email* drove the
decision, by multiplying each feature's TF-IDF value by its learned
coefficient. `explain_in_plain_language()` turns that into a sentence
for non-technical readers, and the PDF report lists the top contributing
phrases with their weights. This is model introspection, computed fresh
per email — not a predefined keyword list being matched and reported
back.

**What it is not:** a deep semantic model. TF-IDF + Logistic Regression
is still fundamentally a bag-of-words method — it has no contextual
understanding, and its recall on wording it never saw in training will
always be weaker than on wording close to its training vocabulary.
Don't present its accuracy number as proof it "understands" phishing
intent; it recognizes statistically-associated vocabulary.

### Current training data — an important caveat

The model shipped in this repo is trained on
`backend/ml/data/synthetic_phishing_dataset.csv`, generated by
`backend/ml/data/generate_dataset.py`. This exists because the
environment this was built in could not reach `huggingface.co` or
`kaggle.com` (both blocked by the sandbox's network policy) to pull a
real-world phishing corpus.

The generator produces ~10.5k emails from a set of sentence templates
with randomized company names, amounts, and topics — it's topically
correct (genuine phishing/BEC phrasing, not 2001-era spam vocabulary),
but it is still synthetic. Two numbers are recorded in
`backend/ml/artifacts/metrics.json`:

- `accuracy`/`precision`/`recall`/`f1` (**1.00** currently) — measured
  on a held-out split from the *same* template generator as training
  data. This number is inflated and not meaningful on its own; a model
  that has seen every sentence pattern before will always score near
  100% on more of the same patterns.
- `ood_generalization_accuracy` (**0.75**, n=16) — measured (not
  assumed — run `python3 backend/ml/data/ood_eval_set.py` yourself to
  reproduce it) on `backend/ml/data/ood_eval_set.py`, a small
  hand-written set of emails using vocabulary and phrasing that do
  **not** appear in the generator. This is the more honest signal, and
  it's the number worth quoting to judges. `metrics.json` also lists the
  specific mistakes (`ood_eval_mistakes`) so you can explain exactly
  what kind of phishing the current model misses (e.g. informal
  social-engineering requests without classic "verify your account"
  phrasing) — that's a more credible, defensible talking point than a
  single inflated accuracy number.

**Before relying on this for a real demo or submission, retrain on a
real dataset.** Recommended: the Kaggle "Phishing Email Detection"
dataset or `huggingface.co/datasets/zefang-liu/phishing-email-dataset`
(both built from the Nazario phishing corpus + Enron ham — real
attacker-written text, not templates). To retrain:

```bash
cd backend/ml
pip install -r ../requirements-train.txt   # adds pandas, only needed here
python3 train.py --csv /path/to/real_dataset.csv --text-col "Email Text" --label-col "Email Type"
python3 data/ood_eval_set.py               # re-check generalization on the new model
```

`train.py` auto-detects common column names; override with
`--text-col`/`--label-col` or `--subject-col`/`--body-col` if needed.
It prints the sklearn version it trained with — **re-pin
`requirements-ml.txt` to that exact version** (see the bug below).

### Two dependency/version bugs already fixed once — watch for them again

1. **pandas blocking the entire ML install.** `requirements-ml.txt`
   used to include `pandas`, which is only needed by `train.py`. On a
   Python version without a prebuilt pandas wheel, pip would try to
   build it from source, fail without a C/C++ toolchain, and abort the
   *entire* `pip install -r requirements-ml.txt` — so `scikit-learn`
   and `joblib` never installed either, even though the running API
   never imports pandas. `pandas` now lives only in
   `requirements-train.txt`.

2. **Silent scikit-learn version mismatch.** `model.pkl`/`vectorizer.pkl`
   are pickled scikit-learn objects tied to the exact version that
   trained them. A mismatched `requirements-ml.txt` pin raises
   `AttributeError` on load — and because `classify()` catches all
   exceptions and returns `None`, this fails **silently**: `/health`
   still reports `ml_enabled: true`, but every request quietly falls
   back to structural-forensics-only scoring. The artifacts in this
   repo were retrained and re-pinned together (`scikit-learn==1.9.0`)
   to eliminate this for now, but if you retrain, re-pin
   `requirements-ml.txt` to whatever
   `python3 -c "import sklearn; print(sklearn.__version__)"` reports in
   your training environment, and check a live `/analyze/eml` response
   for `"ml_applied": true` — not just `/health` — to confirm it
   actually loaded.

## Non-goals (explicitly out of scope for this build)

Neo4j, a real blockchain integration, user authentication/login, and any
ML library import outside `ml/classifier.py`. Campaign correlation is
handled with plain SQL; the evidence hash chain is the practical
stand-in for the blockchain theme requirement. There is also,
deliberately, no hand-written keyword/phrase list anywhere in the
codebase for classifying email content — see the top of this README.

## Disclaimer

This tool produces **investigative leads**, not definitive proof.
Relay-chain IPs reflect *probable sending infrastructure*, not a
confirmed attacker identity or location. Email headers can be forged.
The ML classifier is the primary content signal but is trained on
limited (currently synthetic) data — see the caveat above — and its
"phishing"/"legitimate" label should be read alongside the structural
forensic evidence, not as a verdict on its own. Every generated report
includes an explicit Attribution Limitations section and plain-language
recommended actions — read both before acting on any conclusion.
