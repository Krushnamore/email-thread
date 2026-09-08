"""
ood_eval_set.py — a small, HAND-WRITTEN evaluation set used only to
sanity-check how the trained model generalizes beyond the synthetic
generator's own template vocabulary and sentence pools.

Why this exists: accuracy/precision/recall/F1 in metrics.json come from
a held-out split of the SAME synthetic generator that produced the
training data, so a near-100% score there mostly proves the model can
recognize the generator's own patterns -- not that it generalizes to
real-world phishing phrasing. This file is deliberately written by hand,
using wording, structure, and topics NOT drawn from
backend/ml/data/generate_dataset.py's sentence pools, to give a more
honest (if smaller and less statistically robust) signal. Re-run
run_ood_eval() any time the model is retrained; do not hand-edit the
resulting number in metrics.json.
"""

OOD_EMAILS = [
    # --- phishing / BEC (hand-written, generator-vocabulary-free) ---
    ("Hi, quick one before I hop on a flight -- can you grab five iTunes "
     "gift cards and send me the codes? I'll explain the client situation "
     "when I land, just need this sorted in the next hour.", "phishing"),
    ("Notice: unusual sign-in blocked. If this wasn't you, tap below "
     "within 6 hours or the mailbox will be permanently disabled and all "
     "stored messages purged.", "phishing"),
    ("Hey, it's Priya from payroll -- HR migrated everyone to a new "
     "direct-deposit system this morning and your last update didn't go "
     "through. Update it today or you'll miss this cycle's pay run.", "phishing"),
    ("We tried to deliver your parcel twice but nobody was home. A small "
     "redelivery fee is outstanding -- settle it today or the item goes "
     "back to the depot and gets destroyed after 48 hours.", "phishing"),
    ("Congrats -- your number was drawn in our loyalty rewards draw. "
     "Claim your prize before midnight by confirming your full card "
     "details on the form below, it only takes a second.", "phishing"),
    ("This is the compliance office. Your tax filing shows a mismatch "
     "and a hold has been placed on your refund. Respond with your PAN "
     "and bank passbook photo today to avoid escalation.", "phishing"),
    ("Boss asked me to loop you in -- we're switching vendors this week "
     "and need the outstanding invoice settled through the new account "
     "details attached, please process before close of business.", "phishing"),
    ("Storage almost full -- messages will start bouncing in 24 hours. "
     "Re-validate your mailbox now using the same sign-in you use every "
     "day so nothing gets lost.", "phishing"),

    # --- legitimate (hand-written, generator-vocabulary-free) ---
    ("Hey, just circling back on the notes from Tuesday's standup -- did "
     "we ever land on who owns the migration doc? Happy to take it if "
     "nobody has grabbed it yet.", "legitimate"),
    ("Lunch on Friday? A few of us were thinking of trying that new place "
     "near the office around 12:30 if you're free.", "legitimate"),
    ("Attaching the revised slide deck for tomorrow's review -- I moved "
     "the budget section earlier since that's what leadership usually "
     "asks about first. Let me know if it needs more edits.", "legitimate"),
    ("Reminder that the dentist appointment got moved to 4pm on Thursday, "
     "not the original 2pm slot -- wanted to flag it before it slipped "
     "through the cracks.", "legitimate"),
    ("Thanks for sending over the contract draft, I've read through "
     "section 3 and left a couple of comments inline. Nothing major, "
     "should be quick to close out.", "legitimate"),
    ("The garden club meeting got pushed to next Saturday because of the "
     "forecast -- same time, same place otherwise. Bring the extra "
     "seedlings if you still have them.", "legitimate"),
    ("Quick heads up, the printer on the third floor is jammed again -- "
     "already put in a ticket with facilities so should be fixed by "
     "tomorrow.", "legitimate"),
    ("Really enjoyed catching up at the conference last week. Let's find "
     "time to actually dig into that collaboration idea once things calm "
     "down on your end.", "legitimate"),
]


def run_ood_eval(model, vectorizer) -> dict:
    texts = [t for t, _ in OOD_EMAILS]
    true_labels = [l for _, l in OOD_EMAILS]
    X = vectorizer.transform(texts)
    preds = model.predict(X)
    correct = sum(1 for p, t in zip(preds, true_labels) if p == t)
    return {
        "n": len(OOD_EMAILS),
        "correct": correct,
        "accuracy": round(correct / len(OOD_EMAILS), 4),
        "mistakes": [
            {"text": t[:80] + "...", "true": true, "predicted": str(p)}
            for (t, true), p in zip(OOD_EMAILS, preds) if p != true
        ],
    }


if __name__ == "__main__":
    import json
    import os
    import joblib

    artifact_dir = os.path.join(os.path.dirname(__file__), "..", "artifacts")
    model = joblib.load(os.path.join(artifact_dir, "model.pkl"))
    vectorizer = joblib.load(os.path.join(artifact_dir, "vectorizer.pkl"))
    result = run_ood_eval(model, vectorizer)
    print(json.dumps(result, indent=2))
