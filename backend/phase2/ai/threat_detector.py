"""Phase 2 AI threat detection.

Models are trained offline by ai/train_model.py and only loaded for inference
here, never retrained at runtime. Two complementary models are combined:

  * Isolation Forest (unsupervised) flags events that deviate from the normal
    behaviour baseline, catching attack patterns never seen during training.
  * Random Forest (supervised) assigns a calibrated probability that the event
    is malicious, which becomes the confidence score.

When no trained model is present the detector falls back to a transparent
weighted rule set so the pipeline still functions on a fresh checkout.
"""
import os
from typing import Dict, Optional, Tuple

import joblib
import numpy as np

# Event type -> (threat category, base severity)
THREAT_CATEGORIES = {
    "ConsoleLoginFailure": ("Brute Force", "Medium"),
    "CreateAccessKey": ("Credential Theft", "Critical"),
    "LargeFileDownload": ("Data Exfiltration", "High"),
    "ModifyPolicy": ("Privilege Escalation", "High"),
    "AttachUserPolicy": ("Privilege Escalation", "High"),
    "DeleteBucket": ("Configuration Tampering", "Critical"),
    "DeleteUser": ("Configuration Tampering", "High"),
    "AssumeRole": ("Suspicious API Usage", "High"),
    "CreateUser": ("Insider Threat", "Medium"),
    "AuthorizeSecurityGroupIngress": ("Public Resource Exposure", "High"),
    "UpdateLoginProfile": ("Credential Theft", "High"),
    "ChangePassword": ("Suspicious Login", "Medium"),
    "TerminateInstances": ("Configuration Tampering", "High"),
    "DatabaseQuery": ("Reconnaissance", "Medium"),
    "APIRequest": ("Reconnaissance", "Low"),
}

EVENT_ENCODING = {event: index for index, event in enumerate([
    "ConsoleLogin", "ConsoleLoginFailure", "CreateUser", "DeleteUser",
    "CreateAccessKey", "ModifyPolicy", "AttachUserPolicy",
    "RunInstances", "StopInstances", "TerminateInstances",
    "PutObject", "GetObject", "DeleteBucket", "CreateBucket",
    "AuthorizeSecurityGroupIngress", "RevokeSecurityGroupIngress",
    "ChangePassword", "UpdateLoginProfile", "AssumeRole",
    "LargeFileDownload", "DatabaseQuery", "APIRequest",
])}

HIGH_RISK_COUNTRIES = {"Russia", "China", "Unknown", "North Korea", "Iran"}

FEATURE_NAMES = [
    "loginHour", "eventTypeEncoded", "failedLogin", "iamChange", "dataTransfer",
    "mfaEnabled", "isSuspicious", "gigabytesTransferred", "highRiskCountry", "requestFailed",
]

SEVERITY_ORDER = ["Low", "Medium", "High", "Critical"]


def _raise_severity(severity: str) -> str:
    index = SEVERITY_ORDER.index(severity) if severity in SEVERITY_ORDER else 0
    return SEVERITY_ORDER[min(index + 1, len(SEVERITY_ORDER) - 1)]


class ThreatDetector:
    _anomaly_model = None
    _classifier = None
    _scaler = None
    _loaded = False
    _confidence_threshold = 85.0

    @classmethod
    def load_model(cls, models_folder: str, confidence_threshold: float = 85.0) -> bool:
        """Load the offline-trained models. Safe to call repeatedly."""
        cls._confidence_threshold = float(confidence_threshold)

        def _load(filename):
            path = os.path.join(models_folder, filename)
            if not os.path.exists(path):
                return None
            try:
                return joblib.load(path)
            except Exception:
                return None

        cls._anomaly_model = _load("threat_detector.joblib")
        cls._classifier = _load("threat_classifier.joblib")
        cls._scaler = _load("feature_scaler.joblib")
        cls._loaded = cls._anomaly_model is not None or cls._classifier is not None
        return cls._loaded

    @classmethod
    def extract_features(cls, log: Dict) -> np.ndarray:
        """Build the feature vector in the exact order used during training."""
        features = [
            log.get("loginHour", 12),
            EVENT_ENCODING.get(log.get("eventType", "ConsoleLogin"), 0),
            log.get("failedLogin", 0),
            log.get("iamChange", 0),
            log.get("dataTransfer", 0),
            log.get("mfaEnabled", 0),
            log.get("isSuspicious", 0),
            log.get("bytesTransferred", 0) / 1e9,
            1 if log.get("country") in HIGH_RISK_COUNTRIES else 0,
            1 if log.get("status") == "Failure" else 0,
        ]
        return np.array(features, dtype=float).reshape(1, -1)

    @classmethod
    def predict(cls, log: Dict) -> Dict:
        features = cls.extract_features(log)
        model_used = "RuleBased"

        if cls._loaded:
            outcome = cls._model_inference(features)
            if outcome is not None:
                is_malicious, confidence, model_used = outcome
            else:
                is_malicious, confidence = cls._rule_based(log)
        else:
            is_malicious, confidence = cls._rule_based(log)

        threat, severity = cls._classify(log, is_malicious)

        # Only high-confidence detections are forwarded to Phase 3; everything
        # else is retained as an observation to keep false positives down.
        forward_to_response = bool(is_malicious and confidence >= cls._confidence_threshold)

        return {
            "threat": threat,
            "severity": severity,
            "confidence": round(float(confidence), 1),
            "isThreat": forward_to_response,
            "isAnomaly": bool(is_malicious),
            "modelUsed": model_used,
            "threshold": cls._confidence_threshold,
        }

    @classmethod
    def _model_inference(cls, features: np.ndarray) -> Optional[Tuple[bool, float, str]]:
        """Run the trained models, returning None if inference fails."""
        try:
            scaled = cls._scaler.transform(features) if cls._scaler is not None else features

            anomaly_detected = False
            if cls._anomaly_model is not None:
                # Isolation Forest labels outliers as -1 and inliers as 1.
                anomaly_detected = int(cls._anomaly_model.predict(scaled)[0]) == -1

            if cls._classifier is not None:
                probability = float(cls._classifier.predict_proba(scaled)[0][1])
                malicious = probability >= 0.5 or anomaly_detected
                confidence = probability * 100 if malicious else (1 - probability) * 100
                model = "RandomForest + IsolationForest" if cls._anomaly_model is not None else "RandomForest"
                return malicious, confidence, model

            if cls._anomaly_model is not None:
                # Distance from the decision boundary stands in for confidence.
                margin = abs(float(cls._anomaly_model.decision_function(scaled)[0]))
                confidence = min(99.0, 70.0 + margin * 100)
                return anomaly_detected, confidence, "IsolationForest"
        except Exception:
            return None
        return None

    @classmethod
    def _classify(cls, log: Dict, is_malicious: bool) -> Tuple[str, str]:
        """Map a malicious event onto a threat category and severity."""
        if not is_malicious:
            return "Normal", "Low"

        event_type = log.get("eventType", "ConsoleLogin")
        threat, severity = THREAT_CATEGORIES.get(event_type, ("Suspicious Activity", "Medium"))

        if log.get("dataTransfer"):
            threat, severity = "Data Exfiltration", "Critical"
        elif log.get("failedLogin") and log.get("isSuspicious"):
            threat, severity = "Brute Force", "High"
        elif log.get("iamChange") and not log.get("mfaEnabled"):
            threat, severity = "Privilege Escalation", "High"

        # An unfamiliar origin without MFA makes any event materially riskier.
        if log.get("country") in HIGH_RISK_COUNTRIES and not log.get("mfaEnabled"):
            severity = _raise_severity(severity)

        return threat, severity

    @staticmethod
    def _rule_based(log: Dict) -> Tuple[bool, float]:
        """Transparent weighted fallback used when no model is available."""
        score = 0
        if log.get("isSuspicious"):
            score += 40
        if log.get("failedLogin"):
            score += 25
        if log.get("iamChange"):
            score += 30
        if log.get("dataTransfer"):
            score += 35
        if log.get("country") in HIGH_RISK_COUNTRIES:
            score += 20
        if not log.get("mfaEnabled"):
            score += 10

        is_malicious = score >= 50
        confidence = min(99.0, 60.0 + score * 0.5) if is_malicious else max(60.0, 100.0 - score)
        return is_malicious, confidence
