"""
train.py — trains the phishing-detection classifier used by classifier.py.

This is a STANDALONE SCRIPT. Run it from the command line, not imported
by the running API. It produces exactly two files:

    backend/ml/artifacts/vectorizer.pkl   (a fitted TfidfVectorizer)
    backend/ml/artifacts/model.pkl        (a fitted LogisticRegression)

which is precisely the contract classifier.py already expects:
    _VECTORIZER.transform([text])   -> sparse matrix
    _MODEL.predict_proba(X)[0]      -> per-class probabilities
    _MODEL.classes_                 -> class labels

USAGE
-----
    cd backend/ml
    python3 train.py --csv /path/to/dataset.csv

The script tries to auto-detect the text column(s) and label column from
common Kaggle phishing-email dataset formats. If auto-detection picks the
wrong columns, override explicitly:

    python3 train.py --csv dataset.csv --text-col "Email Text" --label-col "Email Type"

If your dataset has separate subject/body columns instead of one combined
text column, pass both and they'll be concatenated the same way
classifier.py's build_feature_text() does at inference time:

    python3 train.py --csv dataset.csv --subject-col subject --body-col body --label-col label

WHAT IT DOES
------------
1. Loads the CSV, drops rows with missing text/label.
2. Normalizes the label column to {"phishing", "legitimate"} — edit
   LABEL_MAP below if your dataset uses different class names (e.g.
   "spam"/"ham", 1/0, "Phishing Email"/"Safe Email").
3. Splits 80/20 train/test (stratified, so class balance is preserved).
4. Fits a TF-IDF vectorizer (unigrams+bigrams, English stopwords removed,
   max 20k features — kept small on purpose: fast, explainable, no GPU).
5. Fits a Logistic Regression classifier (class_weight="balanced" so an
   imbalanced dataset doesn't just learn to predict the majority class).
6. Prints accuracy / precision / recall / F1 / confusion matrix on the
   held-out test set — copy these numbers into your SIH presentation.
7. Saves vectorizer.pkl + model.pkl into backend/ml/artifacts/.
8. Also saves metrics.json next to them, so the numbers are reproducible
   evidence, not just something you remembered from the terminal.
"""

import argparse
import json
import os
import re

import joblib
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import train_test_split

ARTIFACT_DIR = os.path.join(os.path.dirname(__file__), "artifacts")

# Edit this if your dataset's raw label values differ. Keys are lowercased
# and stripped before lookup, so "Phishing Email", "phishing", "PHISHING"
# all match the same entry.
LABEL_MAP = {
    "phishing": "phishing",
    "phishing email": "phishing",
    "spam": "phishing",
    "1": "phishing",
    "malicious": "phishing",
    "fraud": "phishing",
    "legitimate": "legitimate",
    "safe email": "legitimate",
    "ham": "legitimate",
    "0": "legitimate",
    "benign": "legitimate",
    "not spam": "legitimate",
}

CANDIDATE_TEXT_COLS = [
    "text", "email text", "email_text", "body", "message", "content",
]
CANDIDATE_LABEL_COLS = [
    "label", "email type", "email_type", "type", "class", "category",
    "target", "is_phishing", "spam",
]


def clean_text(s: str) -> str:
    s = str(s)
    s = re.sub(r"\s+", " ", s)
    return s.strip()


def autodetect_column(columns, candidates):
    lowered = {c.lower().strip(): c for c in columns}
    for cand in candidates:
        if cand in lowered:
            return lowered[cand]
    return None


def main():
    parser = argparse.ArgumentParser(description="Train the phishing-email classifier.")
    parser.add_argument("--csv", required=True, help="Path to the Kaggle CSV dataset.")
    parser.add_argument("--text-col", default=None, help="Column with combined email text.")
    parser.add_argument("--subject-col", default=None, help="Column with subject (use with --body-col).")
    parser.add_argument("--body-col", default=None, help="Column with body (use with --subject-col).")
    parser.add_argument("--label-col", default=None, help="Column with the phishing/legit label.")
    parser.add_argument("--test-size", type=float, default=0.2)
    parser.add_argument("--random-state", type=int, default=42)
    args = parser.parse_args()

    print(f"Loading {args.csv} ...")
    df = pd.read_csv(args.csv)
    print(f"  {len(df)} rows, columns: {list(df.columns)}")

    label_col = args.label_col or autodetect_column(df.columns, CANDIDATE_LABEL_COLS)
    if label_col is None:
        raise SystemExit(
            "Could not detect the label column automatically. "
            "Re-run with --label-col <name>. Columns found: " + str(list(df.columns))
        )
    print(f"  Using label column: '{label_col}'")

    if args.subject_col and args.body_col:
        df["_text"] = (
            df[args.subject_col].fillna("").map(clean_text)
            + " "
            + df[args.body_col].fillna("").map(clean_text)
        )
    else:
        text_col = args.text_col or autodetect_column(df.columns, CANDIDATE_TEXT_COLS)
        if text_col is None:
            raise SystemExit(
                "Could not detect a text column automatically. "
                "Re-run with --text-col <name>, or --subject-col/--body-col. "
                "Columns found: " + str(list(df.columns))
            )
        print(f"  Using text column: '{text_col}'")
        df["_text"] = df[text_col].fillna("").map(clean_text)

    df["_label"] = (
        df[label_col].astype(str).str.strip().str.lower().map(LABEL_MAP)
    )
    unmapped = df["_label"].isna().sum()
    if unmapped:
        raw_unmapped = df.loc[df["_label"].isna(), label_col].astype(str).str.lower().unique()
        print(
            f"  WARNING: {unmapped} rows had a label value not in LABEL_MAP and were dropped: "
            f"{list(raw_unmapped)[:10]}. Edit LABEL_MAP in train.py if these should map to a class."
        )

    df = df.dropna(subset=["_text", "_label"])
    df = df[df["_text"].str.len() > 0]
    print(f"  {len(df)} usable rows after cleaning.")
    print(f"  Class balance:\n{df['_label'].value_counts()}")

    X_train, X_test, y_train, y_test = train_test_split(
        df["_text"], df["_label"],
        test_size=args.test_size, random_state=args.random_state, stratify=df["_label"],
    )

    print("\nFitting TF-IDF vectorizer ...")
    vectorizer = TfidfVectorizer(
        max_features=20000, ngram_range=(1, 2), stop_words="english", min_df=2,
    )
    X_train_vec = vectorizer.fit_transform(X_train)
    X_test_vec = vectorizer.transform(X_test)

    print("Fitting Logistic Regression ...")
    model = LogisticRegression(max_iter=1000, class_weight="balanced")
    model.fit(X_train_vec, y_train)

    y_pred = model.predict(X_test_vec)

    metrics = {
        "accuracy": accuracy_score(y_test, y_pred),
        "precision": precision_score(y_test, y_pred, pos_label="phishing"),
        "recall": recall_score(y_test, y_pred, pos_label="phishing"),
        "f1": f1_score(y_test, y_pred, pos_label="phishing"),
        "confusion_matrix": confusion_matrix(y_test, y_pred, labels=model.classes_.tolist()).tolist(),
        "classes": model.classes_.tolist(),
        "n_train": int(len(X_train)),
        "n_test": int(len(X_test)),
    }

    print("\n=== Test set performance ===")
    print(classification_report(y_test, y_pred))
    print("Confusion matrix (rows=true, cols=pred), classes:", model.classes_.tolist())
    print(metrics["confusion_matrix"])

    os.makedirs(ARTIFACT_DIR, exist_ok=True)
    joblib.dump(vectorizer, os.path.join(ARTIFACT_DIR, "vectorizer.pkl"))
    joblib.dump(model, os.path.join(ARTIFACT_DIR, "model.pkl"))
    with open(os.path.join(ARTIFACT_DIR, "metrics.json"), "w") as f:
        json.dump(metrics, f, indent=2)

    print(f"\nSaved vectorizer.pkl, model.pkl, metrics.json to {ARTIFACT_DIR}")
    print("Next steps:")
    print("  1. Set ENABLE_ML = True in backend/config.py")
    print("  2. Uncomment scikit-learn/joblib in backend/requirements.txt")
    print("  3. Restart the API — /health should now show ml_enabled: true")


if __name__ == "__main__":
    main()
