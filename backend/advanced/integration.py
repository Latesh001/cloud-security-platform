"""Non-breaking hooks from Phase 1 / 2 / 3 into Advanced Features.

Each public function is safe to call from existing code: failures are swallowed
and logged so a scan or incident never fails because this module errored.
"""
from typing import Any, Dict, List, Optional

from advanced import store
from advanced.seed import seed_if_empty
from utils.logger import audit_logger

WORKFLOW_MAP = {
    "Created": "Pending",
    "Uploaded": "Pending",
    "Scanning": "Scanning",
    "Approved": "Passed",
    "Monitoring Enabled": "Monitoring",
    "Pending Remediation": "Failed",
    "Upload Failed": "Failed",
    "Rejected": "Failed",
    "Incident Detected": "Incident",
}


def _safe(fn):
    def wrapper(*args, **kwargs):
        try:
            seed_if_empty()
            return fn(*args, **kwargs)
        except Exception as exc:
            audit_logger.exception("Advanced Features hook failed: %s", exc)
            return None
    return wrapper


def workflow_status(project_status: str, has_open_incident: bool = False,
                    resolved: bool = False) -> str:
    if resolved:
        return "Resolved"
    if has_open_incident or project_status == "Incident Detected":
        return "Incident"
    return WORKFLOW_MAP.get(project_status or "", "Pending")


@_safe
def on_phase1_complete(project_id: str, user_id: Any, report_data: Dict,
                       findings: List[Dict], scoring: Dict, approval: str) -> None:
    score = float(scoring.get("score") or 0)
    counts = scoring.get("counts") or {}
    risk = scoring.get("risk_level") or "Low"
    status = "Passed" if approval == "Approved" else "Failed"
    store.upsert("phase1_analysis", {"project_id": project_id}, {
        "project_id": project_id,
        "user_id": user_id,
        "security_score": score,
        "risk_level": risk,
        "approval": approval,
        "critical": int(counts.get("Critical") or 0),
        "high": int(counts.get("High") or 0),
        "medium": int(counts.get("Medium") or 0),
        "low": int(counts.get("Low") or 0),
        "vulnerabilities": findings[:80],
        "scan_report": {
            "recommendation": report_data.get("recommendation"),
            "detector_summary": report_data.get("detector_summary"),
            "technologies": report_data.get("technologies"),
            "files_scanned": report_data.get("files_scanned"),
            "scan_duration": report_data.get("scan_duration"),
        },
        "deployment_blocked": score < 65,
        "phase2_enabled": approval == "Approved",
    })
    store.upsert("phase_integration", {"project_id": project_id}, {
        "project_id": project_id,
        "user_id": user_id,
        "status": "Monitoring" if approval == "Approved" else status,
        "security_score": score,
        "risk_level": risk,
        "phase1": "complete",
        "phase2": "enabled" if approval == "Approved" else "blocked",
        "phase3": "idle",
        "steps": _steps(phase1=True, monitoring=approval == "Approved"),
    })
    _sync_vulnerabilities(project_id, user_id, findings)
    _ensure_default_assets(project_id, user_id, report_data.get("technologies") or {})
    evaluate_compliance(project_id, user_id)


@_safe
def on_phase2_event(project_id: str, log: Dict, prediction: Optional[Dict] = None) -> None:
    raw = {
        "project_id": project_id,
        "source": "cloud",
        "raw": dict(log),
        "timestamp": log.get("timestamp") or store.utcnow(),
    }
    store.insert("raw_logs", raw)
    normalized = {
        "project_id": project_id,
        "source": log.get("logType") or "CloudTrail",
        "event_type": log.get("eventType"),
        "username": log.get("username"),
        "source_ip": log.get("sourceIP"),
        "country": log.get("country"),
        "resource": log.get("resource"),
        "severity": (prediction or {}).get("severity") or ("High" if log.get("isSuspicious") else "Low"),
        "status": log.get("status"),
        "mfa": log.get("mfaEnabled"),
        "bytes": log.get("bytesTransferred") or 0,
        "is_suspicious": bool(log.get("isSuspicious")),
        "message": log.get("message") or "",
        "timestamp": log.get("timestamp") or store.utcnow(),
    }
    store.insert("normalized_logs", normalized)
    store.insert("security_logs", dict(normalized))

    if prediction and prediction.get("isAnomaly"):
        store.insert("threat_alerts", {
            "project_id": project_id,
            "threat": prediction.get("threat"),
            "severity": prediction.get("severity"),
            "confidence": prediction.get("confidence"),
            "status": "Validated" if prediction.get("isThreat") else "Observation",
            "source_ip": log.get("sourceIP"),
            "username": log.get("username"),
        })
        _correlate(project_id, normalized, prediction)


@_safe
def on_incident_created(project_id: str, incident_id: str, threat: str,
                        severity: str, prediction: Dict, log: Dict) -> None:
    integration = store.find_one("phase_integration", {"project_id": project_id}) or {}
    store.upsert("phase_integration", {"project_id": project_id}, {
        "project_id": project_id,
        "user_id": integration.get("user_id"),
        "status": "Incident",
        "security_score": integration.get("security_score"),
        "phase1": integration.get("phase1") or "complete",
        "phase2": "alert",
        "phase3": "active",
        "latest_incident_id": incident_id,
        "latest_threat": threat,
        "latest_severity": severity,
        "steps": _steps(phase1=True, monitoring=True, incident=True),
    })
    store.insert("correlated_events", {
        "project_id": project_id,
        "incident_id": incident_id,
        "rule": "phase2_high_confidence",
        "threat": threat,
        "severity": severity,
        "confidence": prediction.get("confidence"),
        "related_event": log.get("eventType"),
        "source_ip": log.get("sourceIP"),
        "narrative": (
            f"Phase 2 detection {threat} ({severity}, {prediction.get('confidence')}% "
            f"confidence) on {project_id} opened incident {incident_id}."
        ),
    })
    _auto_execute_playbook(project_id, incident_id, threat)


@_safe
def on_incident_closed(project_id: str, incident_id: str) -> None:
    store.upsert("phase_integration", {"project_id": project_id}, {
        "status": "Resolved",
        "phase3": "resolved",
        "resolved_incident_id": incident_id,
        "steps": _steps(phase1=True, monitoring=True, incident=True, resolved=True),
    })
    evaluate_compliance(project_id, None)


def _steps(phase1=False, monitoring=False, incident=False, resolved=False) -> List[Dict]:
    return [
        {"name": "Project Upload", "done": True},
        {"name": "AI Security Scan", "done": phase1},
        {"name": "Generate Security Score", "done": phase1},
        {"name": "Store Analysis", "done": phase1},
        {"name": "Cloud Monitoring", "done": monitoring},
        {"name": "Threat Detection", "done": incident or resolved},
        {"name": "Incident Creation", "done": incident or resolved},
        {"name": "SOAR Response", "done": incident or resolved},
        {"name": "Resolved", "done": resolved},
    ]


def _sync_vulnerabilities(project_id: str, user_id: Any, findings: List[Dict]) -> None:
    existing = {v.get("fingerprint") for v in store.find("vulnerabilities", {"project_id": project_id})}
    for finding in findings[:60]:
        fingerprint = "|".join([
            str(finding.get("detector") or ""),
            str(finding.get("file") or finding.get("path") or ""),
            str(finding.get("problem") or finding.get("title") or "")[:120],
        ])
        if fingerprint in existing:
            continue
        severity = finding.get("severity") or "Medium"
        cvss = {"Critical": 9.8, "High": 7.5, "Medium": 5.3, "Low": 3.1}.get(severity, 5.0)
        store.insert("vulnerabilities", {
            "vuln_id": store.next_id("vulnerabilities", "VUL"),
            "project_id": project_id,
            "user_id": user_id,
            "title": finding.get("problem") or finding.get("title") or "Finding",
            "severity": severity,
            "cvss": cvss,
            "asset": finding.get("file") or finding.get("path") or project_id,
            "owner": "Unassigned",
            "status": "Open",
            "risk_level": severity,
            "due_date": None,
            "fingerprint": fingerprint,
            "detector": finding.get("detector"),
            "remediation": finding.get("remediation") or finding.get("fix"),
        })


def _ensure_default_assets(project_id: str, user_id: Any, tech: Dict) -> None:
    if store.count("asset_inventory", {"project_id": project_id}) > 0:
        return
    language = (tech.get("primary_language") if isinstance(tech, dict) else None) or "Application"
    defaults = [
        ("Web Application", "Compute", "us-east-1"),
        ("Object Storage", "Storage", "us-east-1"),
        ("Identity Store", "IAM", "global"),
        (f"{language} Runtime", "Compute", "us-east-1"),
    ]
    for name, kind, region in defaults:
        store.insert("asset_inventory", {
            "asset_id": store.next_id("asset_inventory", "AST"),
            "project_id": project_id,
            "user_id": user_id,
            "name": f"{project_id} {name}",
            "type": kind,
            "owner": "Platform",
            "region": region,
            "status": "Active",
            "risk_score": 40,
            "last_scan": store.utcnow(),
        })
        store.insert("cloud_assets", {
            "project_id": project_id,
            "name": f"{project_id} {name}",
            "type": kind,
            "region": region,
            "status": "Active",
        })


def _correlate(project_id: str, event: Dict, prediction: Dict) -> None:
    recent = store.find("normalized_logs", {"project_id": project_id},
                        sort=[("timestamp", -1)], limit=12)
    failed = sum(1 for item in recent if item.get("event_type") == "ConsoleLoginFailure")
    if failed >= 3 or prediction.get("isThreat"):
        store.insert("correlated_events", {
            "project_id": project_id,
            "rule": "burst_or_validated_threat",
            "threat": prediction.get("threat"),
            "severity": prediction.get("severity"),
            "related_events": failed,
            "source_ip": event.get("source_ip"),
            "narrative": (
                f"Correlated {failed} recent auth/cloud events on {project_id} "
                f"with AI threat {prediction.get('threat')}."
            ),
        })


def _auto_execute_playbook(project_id: str, incident_id: str, threat: str) -> None:
    playbooks = store.find("playbooks", {})
    matched = None
    for book in playbooks:
        types = book.get("threat_types") or []
        if threat in types or "*" in types:
            matched = book
            if threat in types:
                break
    if not matched:
        return
    store.insert("automation_history", {
        "history_id": store.next_id("automation_history", "AUTO"),
        "project_id": project_id,
        "incident_id": incident_id,
        "playbook_id": matched.get("playbook_id"),
        "playbook_name": matched.get("name"),
        "trigger": matched.get("trigger"),
        "condition": matched.get("condition"),
        "action": matched.get("action"),
        "status": "Executed",
        "result": "Simulated Successfully",
        "execution_time": store.utcnow(),
    })


def sync_existing_project(project) -> None:
    """Backfill Advanced Features records for projects scanned before this module existed."""
    if store.find_one("phase1_analysis", {"project_id": project.project_id}):
        return
    from utils.project_scope import latest_scan_log, latest_security_report
    report = latest_security_report(project)
    scan = latest_scan_log(project) or {}
    findings = scan.get("findings") or []
    scoring = scan.get("scoring") or {
        "score": project.security_score or 0,
        "risk_level": getattr(report, "risk_level", "Low"),
        "counts": {
            "Critical": getattr(report, "critical", 0) or 0,
            "High": getattr(report, "high", 0) or 0,
            "Medium": getattr(report, "medium", 0) or 0,
            "Low": getattr(report, "low", 0) or 0,
        },
    }
    from phase1.scoring.engine import DecisionEngine
    approval = DecisionEngine.decide(
        float(project.security_score or 0),
        int(getattr(report, "critical", 0) or 0),
    )
    if project.status in ("Approved", "Monitoring Enabled"):
        approval = "Approved"
    on_phase1_complete(
        project.project_id,
        project.user_id,
        {
            "recommendation": getattr(report, "recommendation", ""),
            "detector_summary": scan.get("detectorSummary") or {},
            "technologies": scan.get("technologies") or {},
            "files_scanned": scan.get("filesScanned"),
            "scan_duration": scan.get("scanDuration"),
        },
        findings,
        scoring,
        approval,
    )


def evaluate_compliance(project_id: str, user_id: Any) -> Dict:
    from advanced.seed import COMPLIANCE
    analysis = store.find_one("phase1_analysis", {"project_id": project_id}) or {}
    incidents = store.find("threat_alerts", {"project_id": project_id}, limit=20)
    vulns_open = store.count("vulnerabilities", {"project_id": project_id, "status": {"$ne": "Closed"}})
    score = float(analysis.get("security_score") or 0)
    critical = int(analysis.get("critical") or 0)
    findings = analysis.get("vulnerabilities") or []
    secret_hits = any("secret" in str(f.get("detector", "")).lower() or
                      "secret" in str(f.get("problem", "")).lower()
                      for f in findings)
    config_hits = any("config" in str(f.get("detector", "")).lower()
                      for f in findings)
    monitored = (store.find_one("phase_integration", {"project_id": project_id}) or {}).get("phase2") in (
        "enabled", "alert"
    )

    results = []
    for control in COMPLIANCE:
        kind = control["maps_to"]
        passed = True
        reason = "Control evidence is present."
        if kind == "score" and score < 65:
            passed, reason = False, f"Security score {score} is below the 65 approval gate."
        elif kind == "vuln" and (critical > 0 or vulns_open > 8):
            passed, reason = False, f"{critical} critical findings / {vulns_open} open vulnerabilities."
        elif kind == "iam" and any("IAM" in str(f) or "privilege" in str(f).lower() for f in findings):
            passed, reason = False, "IAM or privilege findings remain in Phase 1."
        elif kind == "secret" and secret_hits:
            passed, reason = False, "Hardcoded secrets or credential findings are still open."
        elif kind == "config" and config_hits:
            passed, reason = False, "Insecure configuration findings remain."
        elif kind == "monitor" and not monitored:
            passed, reason = False, "Phase 2 monitoring is not enabled for this project."
        elif kind == "incident" and not incidents and score < 50:
            passed, reason = False, "No incident process evidence and residual risk is high."
        results.append({**control, "passed": passed, "reason": reason})

    passed_n = sum(1 for r in results if r["passed"])
    summary = {
        "project_id": project_id,
        "user_id": user_id,
        "generated_at": store.utcnow(),
        "passed": passed_n,
        "failed": len(results) - passed_n,
        "percentage": round(100 * passed_n / len(results), 1) if results else 0,
        "controls": results,
    }
    store.upsert("compliance_reports", {"project_id": project_id, "live": True}, {
        **summary, "live": True, "report_id": f"COMP-{project_id}",
    })
    return summary
