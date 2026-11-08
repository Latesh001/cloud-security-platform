"""Offline training for the Phase 2 threat detection models.

Two complementary models are produced from the same feature space:

  * Isolation Forest (unsupervised) learns the shape of normal cloud activity so
    that attack patterns absent from the training labels can still be flagged.
  * Random Forest (supervised) produces the calibrated probability that an event
    is malicious, which the platform reports as detection confidence.

Both share a StandardScaler, which is saved alongside them because inference
must apply the exact same transformation used during training.

Run once before starting the platform:
    cd backend
    python ai/train_model.py
"""
import json
import os
import sys
from datetime import datetime, timezone

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import (
    classification_report, confusion_matrix, precision_recall_fscore_support, roc_auc_score,
)
from sklearn.model_selection import cross_val_score, train_test_split
from sklearn.preprocessing import StandardScaler

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
MODELS_DIR = os.path.join(BASE_DIR, "trained_models")
DATASETS_DIR = os.path.join(BASE_DIR, "datasets")

# The order here is contractual: phase2/ai/threat_detector.py builds its feature
# vector in exactly this sequence. Changing one without the other silently
# corrupts every prediction.
FEATURE_NAMES = [
    "loginHour",
    "eventTypeEncoded",
    "failedLogin",
    "iamChange",
    "dataTransfer",
    "mfaEnabled",
    "isSuspicious",
    "bytesTransferredGB",
    "highRiskCountry",
    "statusFailure",
]

ATTACK_RATE = 0.15
N_SAMPLES = 8000
RANDOM_STATE = 42


def generate_synthetic_dataset(n_samples: int = N_SAMPLES):
    """Build a labelled dataset that mirrors the simulated cloud event stream.

    The two classes deliberately overlap. Real intrusions are hard precisely
    because a patient attacker looks like a busy engineer, and because ordinary
    staff occasionally do alarming things: night deployments, mistyped
    passwords, large authorised backups. Each attack therefore draws a
    ``stealth`` factor; stealthy ones suppress most of their tell-tale signals
    and are meant to be missed, which is what keeps the reported metrics honest
    rather than a product of separable toy data.
    """
    rng = np.random.default_rng(RANDOM_STATE)
    data = []
    labels = []

    for _ in range(n_samples):
        if rng.random() < ATTACK_RATE:
            # 0 = noisy smash-and-grab, 1 = patient low-and-slow intrusion.
            stealth = rng.beta(2, 3)
            loud = 1.0 - stealth

            off_hours = rng.random() < 0.4 + 0.35 * loud
            hour = rng.integers(0, 6) if off_hours else rng.integers(8, 20)

            # Exfiltration volume scales with how brazen the attacker is, and
            # the log-normal tail keeps quiet transfers indistinguishable from
            # an ordinary upload.
            transferred = float(rng.lognormal(mean=-2.0 + 2.2 * loud, sigma=1.1))

            features = [
                hour,
                rng.integers(0, 22),
                rng.choice([0, 1], p=[1 - (0.25 + 0.5 * loud), 0.25 + 0.5 * loud]),
                rng.choice([0, 1], p=[1 - (0.15 + 0.45 * loud), 0.15 + 0.45 * loud]),
                rng.choice([0, 1], p=[1 - (0.2 + 0.5 * loud), 0.2 + 0.5 * loud]),
                rng.choice([0, 1], p=[0.75, 0.25]),
                rng.choice([0, 1], p=[1 - (0.2 + 0.5 * loud), 0.2 + 0.5 * loud]),
                min(transferred, 8.0),
                rng.choice([0, 1], p=[1 - (0.2 + 0.35 * loud), 0.2 + 0.35 * loud]),
                rng.choice([0, 1], p=[1 - (0.2 + 0.45 * loud), 0.2 + 0.45 * loud]),
            ]
            labels.append(1)
        else:
            # 0 = routine desk work, 1 = on-call engineer doing unusual but
            # entirely legitimate things.
            unusual = rng.beta(2, 6)

            off_hours = rng.random() < 0.05 + 0.55 * unusual
            hour = rng.integers(0, 24) if off_hours else rng.integers(7, 20)

            transferred = float(rng.lognormal(mean=-3.2 + 2.0 * unusual, sigma=0.9))

            features = [
                hour,
                rng.integers(0, 14),
                rng.choice([0, 1], p=[1 - (0.05 + 0.3 * unusual), 0.05 + 0.3 * unusual]),
                rng.choice([0, 1], p=[1 - (0.02 + 0.25 * unusual), 0.02 + 0.25 * unusual]),
                rng.choice([0, 1], p=[1 - (0.04 + 0.4 * unusual), 0.04 + 0.4 * unusual]),
                rng.choice([0, 1], p=[0.12, 0.88]),
                rng.choice([0, 1], p=[1 - (0.03 + 0.25 * unusual), 0.03 + 0.25 * unusual]),
                min(transferred, 6.0),
                rng.choice([0, 1], p=[1 - (0.03 + 0.2 * unusual), 0.03 + 0.2 * unusual]),
                rng.choice([0, 1], p=[1 - (0.05 + 0.25 * unusual), 0.05 + 0.25 * unusual]),
            ]
            labels.append(0)
        data.append(features)

    return np.array(data, dtype=float), np.array(labels)


def train():
    os.makedirs(MODELS_DIR, exist_ok=True)
    os.makedirs(DATASETS_DIR, exist_ok=True)

    print("Generating synthetic cloud security dataset...")
    X, y = generate_synthetic_dataset()
    print(f"  {len(y)} events  |  {int(y.sum())} malicious  |  {len(y) - int(y.sum())} benign")

    np.savez(os.path.join(DATASETS_DIR, "cloud_security_features.npz"),
             X=X, y=y, feature_names=np.array(FEATURE_NAMES))

    # Split before scaling so the test set never influences the scaler.
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=RANDOM_STATE, stratify=y,
    )

    scaler = StandardScaler().fit(X_train)
    X_train_scaled = scaler.transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    print("\nTraining Isolation Forest (anomaly baseline)...")
    # Fit only on benign traffic so the model learns what normal looks like.
    iso_forest = IsolationForest(
        n_estimators=200, contamination=ATTACK_RATE, random_state=RANDOM_STATE, n_jobs=-1,
    )
    iso_forest.fit(X_train_scaled[y_train == 0])

    # Isolation Forest labels outliers as -1 and inliers as 1.
    iso_predictions = (iso_forest.predict(X_test_scaled) == -1).astype(int)
    iso_precision, iso_recall, iso_f1, _ = precision_recall_fscore_support(
        y_test, iso_predictions, average="binary", zero_division=0,
    )
    print(f"  precision {iso_precision:.2%}  recall {iso_recall:.2%}  f1 {iso_f1:.2%}")

    print("\nTraining Random Forest (supervised classifier)...")
    rf = RandomForestClassifier(
        n_estimators=200, max_depth=12, min_samples_leaf=2,
        class_weight="balanced", random_state=RANDOM_STATE, n_jobs=-1,
    )
    rf.fit(X_train_scaled, y_train)

    rf_predictions = rf.predict(X_test_scaled)
    rf_probabilities = rf.predict_proba(X_test_scaled)[:, 1]
    accuracy = rf.score(X_test_scaled, y_test)
    roc_auc = roc_auc_score(y_test, rf_probabilities)
    precision, recall, f1, _ = precision_recall_fscore_support(
        y_test, rf_predictions, average="binary", zero_division=0,
    )
    cv_scores = cross_val_score(rf, X_train_scaled, y_train, cv=5, scoring="f1", n_jobs=-1)

    print(f"  accuracy {accuracy:.2%}  precision {precision:.2%}  "
          f"recall {recall:.2%}  f1 {f1:.2%}  roc-auc {roc_auc:.3f}")
    print(f"  5-fold cross-validated f1: {cv_scores.mean():.2%} (+/- {cv_scores.std():.2%})")

    print("\nClassification report")
    print(classification_report(y_test, rf_predictions,
                                target_names=["Benign", "Malicious"], zero_division=0))

    tn, fp, fn, tp = confusion_matrix(y_test, rf_predictions).ravel()
    print(f"Confusion matrix: TN={tn}  FP={fp}  FN={fn}  TP={tp}")

    print("\nFeature importance")
    for name, importance in sorted(zip(FEATURE_NAMES, rf.feature_importances_),
                                   key=lambda pair: pair[1], reverse=True):
        bar = "#" * int(importance * 60)
        print(f"  {name:<20} {importance:.4f}  {bar}")

    joblib.dump(iso_forest, os.path.join(MODELS_DIR, "threat_detector.joblib"))
    joblib.dump(scaler, os.path.join(MODELS_DIR, "feature_scaler.joblib"))
    joblib.dump(rf, os.path.join(MODELS_DIR, "threat_classifier.joblib"))

    # The metadata file lets the dashboard and the viva discussion cite real
    # numbers instead of guesses.
    metadata = {
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "samples": int(len(y)),
        "attack_rate": ATTACK_RATE,
        "feature_names": FEATURE_NAMES,
        "isolation_forest": {
            "precision": round(float(iso_precision), 4),
            "recall": round(float(iso_recall), 4),
            "f1": round(float(iso_f1), 4),
        },
        "random_forest": {
            "accuracy": round(float(accuracy), 4),
            "precision": round(float(precision), 4),
            "recall": round(float(recall), 4),
            "f1": round(float(f1), 4),
            "roc_auc": round(float(roc_auc), 4),
            "cv_f1_mean": round(float(cv_scores.mean()), 4),
            "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
            "feature_importance": {
                name: round(float(value), 4)
                for name, value in zip(FEATURE_NAMES, rf.feature_importances_)
            },
        },
    }
    with open(os.path.join(MODELS_DIR, "model_metadata.json"), "w", encoding="utf-8") as handle:
        json.dump(metadata, handle, indent=2)

    print(f"\nModels and metadata saved to {MODELS_DIR}")
    print("Training complete.")


if __name__ == "__main__":
    train()
