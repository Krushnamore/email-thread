# ml/classifier.py
#
# This is now the PRIMARY content-based detection engine for the
# platform (see scoring.py). It replaces the old urgency/credential-
# harvesting keyword lists entirely -- there is no static wordlist
# anywhere in this module. Every phrase surfaced in explain() is
# extracted dynamically from the trained TF-IDF + Logistic Regression
# model's own learned coefficients for the SPECIFIC input text, not
# from a hand-curated list. That is the actual difference between this
# and rule-based keyword matching: the "signal" is whatever the model
# learned from data, re-derived per-email, not a fixed vocabulary
# someone wrote down in advance.
#
# Contract (do not change this signature -- scoring.py depends on it):
#   classify(analysis: dict) -> dict | None
#
#   Returns None when ML is disabled or unavailable -- the caller in
#   scoring.py handles None by falling back to structural-forensics-only
#   mode (auth/URL/attachment/WHOIS signals), never to keyword guessing.
#
#   Returns {
#       "label": "phishing" | "legitimate",
#       "confidence": float 0.0-1.0,       # confidence in `label`
#       "phishing_probability": float,     # P(phishing) regardless of label
#       "top_features": [(phrase, weight), ...],  # this email's top
#                                                   # model-derived signals
#   }
#
# TO RETRAIN:
#   cd backend/ml && pip install -r ../requirements-train.txt
#   python3 train.py --csv /path/to/dataset.csv
#   python3 data/ood_eval_set.py   # sanity-check generalization

import logging
import os

from ..config import ENABLE_ML

logger = logging.getLogger("ml.classifier")

_MODEL = None
_VECTORIZER = None
ARTIFACT_DIR = os.path.join(os.path.dirname(__file__), "artifacts")

TOP_FEATURES_N = 6


def _load_model():
    global _MODEL, _VECTORIZER
    if _MODEL is not None:
        return
    model_path = os.path.join(ARTIFACT_DIR, "model.pkl")
    vectorizer_path = os.path.join(ARTIFACT_DIR, "vectorizer.pkl")
    if not (os.path.exists(model_path) and os.path.exists(vectorizer_path)):
        return  # artifacts not present yet -- stay disabled, no error
    try:
        import joblib
        _MODEL = joblib.load(model_path)
        _VECTORIZER = joblib.load(vectorizer_path)
    except Exception as exc:  # never let a bad artifact break the pipeline
        logger.warning("Failed to load ML artifacts: %s", exc)
        _MODEL, _VECTORIZER = None, None


def build_feature_text(analysis: dict) -> str:
    """
    Single source of truth for what text the model sees. Keep this in
    sync with however the model was trained -- subject + body is the
    expected minimum; extend it here (not in scoring.py) if the trained
    model expects more.
    """
    return f"{analysis.get('subject', '')} {analysis.get('body', '')}"


def _phishing_class_index() -> int:
    classes = list(_MODEL.classes_)
    return classes.index("phishing") if "phishing" in classes else int(_MODEL.classes_.argmax())


def _top_features(X, predicted_class_idx: int, top_n: int = TOP_FEATURES_N) -> list:
    """
    Extracts the n-grams from THIS email that pushed the model's decision
    toward the predicted class the hardest. Since LogisticRegression is
    linear, each feature's contribution to the decision function is just
    (tfidf_value_for_this_email * learned_coefficient_for_this_class).
    This is derived fresh per-email from the fitted model -- it is not a
    keyword list, it is model introspection.
    """
    try:
        feature_names = _VECTORIZER.get_feature_names_out()
        row = X.toarray()[0]
        if _MODEL.coef_.shape[0] == 1:
            # binary logistic regression: one coef row, class_index 1 = "positive"
            coefs = _MODEL.coef_[0] if predicted_class_idx == 1 else -_MODEL.coef_[0]
        else:
            coefs = _MODEL.coef_[predicted_class_idx]
        contributions = row * coefs
        nonzero_idx = contributions.nonzero()[0]
        ranked = sorted(nonzero_idx, key=lambda i: contributions[i], reverse=True)
        top = [(feature_names[i], float(contributions[i])) for i in ranked[:top_n] if contributions[i] > 0]
        return top
    except Exception as exc:
        logger.warning("Feature attribution failed, continuing without it: %s", exc)
        return []


def _predict(text: str) -> dict:
    """Runs inference. Isolated so classify() can wrap it in one try/except."""
    X = _VECTORIZER.transform([text])
    proba = _MODEL.predict_proba(X)[0]
    label_idx = int(proba.argmax())
    label = str(_MODEL.classes_[label_idx])
    confidence = float(proba[label_idx])

    phishing_idx = _phishing_class_index()
    phishing_probability = float(proba[phishing_idx])

    top_features = _top_features(X, label_idx)

    return {
        "label": label,
        "confidence": confidence,
        "phishing_probability": phishing_probability,
        "top_features": top_features,
    }


def classify(analysis: dict) -> dict | None:
    if not ENABLE_ML:
        return None
    try:
        _load_model()
        if _MODEL is None or _VECTORIZER is None:
            return None  # artifacts missing -- fail open, not closed
        text = build_feature_text(analysis)
        if not text.strip():
            return None  # nothing to classify
        return _predict(text)
    except Exception as exc:
        logger.warning("ML classification failed, continuing without it: %s", exc)
        return None


def explain_in_plain_language(ml_result: dict) -> str:
    """
    Turns the model's own top contributing n-grams into a human-readable
    sentence for non-technical readers (investigators, victims, judges),
    per the PS-106 requirement for human-readable output, not just
    technical scores. This describes what the trained model picked up on
    for THIS email -- it does not reference any predefined list of
    "suspicious words".
    """
    if not ml_result:
        return ""
    label = ml_result["label"]
    confidence_pct = round(ml_result["confidence"] * 100)
    phrases = [f[0] for f in ml_result.get("top_features", [])][:4]

    if label == "phishing":
        if phrases:
            phrase_list = ", ".join(f"'{p}'" for p in phrases)
            return (
                f"The machine learning model classifies this message's content as phishing "
                f"with {confidence_pct}% confidence. Its decision was driven most strongly by "
                f"phrasing patterns such as {phrase_list}, which the model has learned (from "
                f"training data) to statistically associate with phishing/social-engineering "
                f"writing, rather than by matching any fixed list of banned words."
            )
        return (
            f"The machine learning model classifies this message's content as phishing "
            f"with {confidence_pct}% confidence, based on its overall learned writing-style "
            f"patterns for this text."
        )
    else:
        return (
            f"The machine learning model classifies this message's content as legitimate "
            f"with {confidence_pct}% confidence -- its language does not statistically "
            f"resemble the phishing/social-engineering patterns it was trained to recognize."
        )
