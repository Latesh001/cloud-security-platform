"""Functional AI explanations (SHAP-style, LIME-style) without extra packages.

Uses the Phase 2 trained Random Forest + scaler when present. If models are
missing, a transparent weighted rule explanation is returned so the viewers
still work.
"""
from typing import Dict, List

import numpy as np

from phase2.ai.threat_detector import FEATURE_NAMES, HIGH_RISK_COUNTRIES, ThreatDetector


def _vector(log: Dict) -> np.ndarray:
    return ThreatDetector.extract_features({
        "loginHour": log.get("loginHour", 12),
        "eventType": log.get("eventType") or log.get("event_type") or "ConsoleLogin",
        "failedLogin": 1 if log.get("failedLogin") or log.get("event_type") == "ConsoleLoginFailure" else 0,
        "iamChange": 1 if log.get("iamChange") or "Policy" in str(log.get("eventType") or log.get("event_type") or "") else 0,
        "dataTransfer": 1 if log.get("dataTransfer") or (log.get("bytesTransferred") or log.get("bytes") or 0) > 0 else 0,
        "mfaEnabled": 1 if log.get("mfaEnabled") or log.get("mfa") else 0,
        "isSuspicious": 1 if log.get("isSuspicious") or log.get("is_suspicious") else 0,
        "bytesTransferred": log.get("bytesTransferred") or log.get("bytes") or 0,
        "country": log.get("country"),
        "status": log.get("status") or "Success",
    })


def shap_view(log: Dict) -> Dict:
    from flask import current_app
    ThreatDetector.load_model(current_app.config["MODELS_FOLDER"],
                              current_app.config.get("THREAT_CONFIDENCE_THRESHOLD", 85))
    features = _vector(log)
    contributions: List[Dict] = []

    if ThreatDetector._classifier is not None and hasattr(ThreatDetector._classifier, "feature_importances_"):
        importances = ThreatDetector._classifier.feature_importances_
        values = features.ravel()
        scaled = values
        if ThreatDetector._scaler is not None:
            scaled = ThreatDetector._scaler.transform(features).ravel()
        raw = importances * np.abs(scaled)
        total = float(raw.sum()) or 1.0
        for name, value, weight in zip(FEATURE_NAMES, values, raw):
            contributions.append({
                "feature": name,
                "value": round(float(value), 4),
                "contribution": round(float(weight / total * 100), 2),
            })
        method = "RandomForest feature-attribution (SHAP-style)"
    else:
        weights = {
            "isSuspicious": 40, "failedLogin": 25, "iamChange": 30,
            "dataTransfer": 35, "highRiskCountry": 20, "mfaEnabled": -10,
        }
        values = dict(zip(FEATURE_NAMES, features.ravel()))
        values["highRiskCountry"] = 1 if log.get("country") in HIGH_RISK_COUNTRIES else 0
        for name, value in values.items():
            contributions.append({
                "feature": name,
                "value": round(float(value), 4),
                "contribution": round(float(weights.get(name, 5) * (1 if value else 0.1)), 2),
            })
        method = "Rule-weight attribution (model artifacts not loaded)"

    contributions.sort(key=lambda item: item["contribution"], reverse=True)
    return {
        "method": method,
        "model": ThreatDetector._classifier is not None,
        "contributions": contributions,
        "summary": (
            f"Top drivers: {', '.join(c['feature'] for c in contributions[:3])}."
        ),
    }


def lime_view(log: Dict) -> Dict:
    """Local linear explanation by perturbing one feature at a time."""
    from flask import current_app
    ThreatDetector.load_model(current_app.config["MODELS_FOLDER"],
                              current_app.config.get("THREAT_CONFIDENCE_THRESHOLD", 85))
    base = ThreatDetector.predict(log if "eventType" in log else {
        "eventType": log.get("event_type") or "ConsoleLogin",
        "username": log.get("username"),
        "sourceIP": log.get("source_ip") or log.get("sourceIP"),
        "country": log.get("country"),
        "status": log.get("status") or "Success",
        "mfaEnabled": log.get("mfaEnabled") or log.get("mfa"),
        "isSuspicious": log.get("isSuspicious") or log.get("is_suspicious"),
        "bytesTransferred": log.get("bytesTransferred") or log.get("bytes") or 0,
    })
    base_conf = float(base.get("confidence") or 0)
    local = []
    probes = {
        "mfaEnabled": True,
        "isSuspicious": False,
        "status": "Success",
        "country": "India",
        "bytesTransferred": 0,
    }
    for key, safe_value in probes.items():
        trial = dict(log)
        trial[key] = safe_value
        if key == "bytesTransferred":
            trial["dataTransfer"] = 0
        pred = ThreatDetector.predict({
            "eventType": trial.get("eventType") or trial.get("event_type") or "ConsoleLogin",
            "country": trial.get("country"),
            "status": trial.get("status") or "Success",
            "mfaEnabled": trial.get("mfaEnabled") or trial.get("mfa"),
            "isSuspicious": trial.get("isSuspicious") or trial.get("is_suspicious"),
            "bytesTransferred": trial.get("bytesTransferred") or 0,
        })
        delta = round(base_conf - float(pred.get("confidence") or 0), 2)
        local.append({
            "feature": key,
            "perturbed_to": safe_value,
            "confidence_drop": delta,
            "interpretation": (
                f"Changing {key} to {safe_value} {'reduces' if delta > 0 else 'does not reduce'} "
                f"malicious confidence by {abs(delta)} points."
            ),
        })
    local.sort(key=lambda item: abs(item["confidence_drop"]), reverse=True)
    return {
        "method": "LIME-style local perturbation",
        "baseline_confidence": base_conf,
        "baseline_threat": base.get("threat"),
        "perturbations": local,
        "summary": local[0]["interpretation"] if local else "No local effects computed.",
    }


def risk_prediction(score: float, critical: int, high: int, threats: int, incidents: int) -> Dict:
    residual = max(0, 100 - float(score or 0))
    penalty = critical * 12 + high * 6 + threats * 4 + incidents * 8
    risk = min(99, round(residual * 0.55 + penalty, 1))
    if risk >= 75:
        level, advice = "Critical", "Do not deploy. Remediate criticals and re-scan."
    elif risk >= 55:
        level, advice = "High", "Hold production changes and start Phase 2 monitoring only after approval."
    elif risk >= 35:
        level, advice = "Medium", "Monitor continuously and close open vulnerabilities."
    else:
        level, advice = "Low", "Residual risk is acceptable with monitoring enabled."
    return {
        "risk_score": risk,
        "level": level,
        "inputs": {
            "phase1_score": score, "critical": critical, "high": high,
            "threats": threats, "incidents": incidents,
        },
        "recommendation": advice,
    }


def severity_prediction(event: Dict) -> Dict:
    pred = ThreatDetector.predict({
        "eventType": event.get("eventType") or event.get("event_type") or "APIRequest",
        "country": event.get("country"),
        "status": event.get("status") or "Success",
        "mfaEnabled": event.get("mfaEnabled") or event.get("mfa"),
        "isSuspicious": event.get("isSuspicious") or event.get("is_suspicious"),
        "bytesTransferred": event.get("bytesTransferred") or event.get("bytes") or 0,
    })
    return {
        "severity": pred.get("severity"),
        "threat": pred.get("threat"),
        "confidence": pred.get("confidence"),
        "is_incident": pred.get("isThreat"),
        "model": pred.get("modelUsed"),
    }


def summarize_incident(incident: Dict, analysis: Dict = None) -> Dict:
    analysis = analysis or {}
    vulns = (analysis.get("critical") or 0) + (analysis.get("high") or 0)
    text = (
        f"Incident {incident.get('incident_id')} on project {incident.get('project_id')} "
        f"is a {incident.get('severity')} {incident.get('threat')} detection "
        f"({incident.get('confidence')}% confidence) affecting "
        f"{incident.get('affected_user') or 'an unknown user'} from "
        f"{incident.get('source_ip') or 'an unknown IP'}. "
        f"Phase 1 residual findings: {vulns} critical/high. "
        f"Status: {incident.get('status')}."
    )
    root = (
        "Most likely root cause is a high-confidence Phase 2 event that cleared the "
        f"{incident.get('confidence')}% threshold after Phase 1 left residual risk "
        f"({analysis.get('security_score', 'n/a')}/100)."
    )
    return {"summary": text, "root_cause": root}
