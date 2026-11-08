from collections import Counter

from flask import Blueprint, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity

from database.models import Project, Incident, ThreatSummary, ProjectMonitoring
from notifications.service import NotificationService
from phase2.scheduler.monitor_scheduler import MonitoringScheduler
from utils.project_scope import belongs_to_project, latest_security_report, project_score

dashboard_bp = Blueprint("dashboard", __name__, url_prefix="/api/dashboard")

# Project IDs are reused (P001, P002, …). Threat/incident rows from an earlier
# project with the same ID must not appear on the current dashboard.


def _for_current_project(record_time, project) -> bool:
    return belongs_to_project(record_time, project)


def _latest_score(project) -> float:
    return project_score(project)


def _was_scanned(project) -> bool:
    status = project.status or ""
    if status in ("Created", "Uploaded", "Scanning"):
        return False
    return _latest_score(project) > 0 or status not in ("Created", "Uploaded")


@dashboard_bp.route("", methods=["GET"])
@dashboard_bp.route("/", methods=["GET"])
@jwt_required()
def get_dashboard():
    user_id = int(get_jwt_identity())
    projects = Project.query.filter_by(user_id=user_id).all()

    def _is_approved(project):
        status = project.status or ""
        if status in ("Pending Remediation", "Upload Failed", "Rejected"):
            return False
        if status in ("Approved", "Monitoring Enabled", "Incident Detected"):
            return True
        report = latest_security_report(project)
        critical = int(getattr(report, "critical", 0) or 0) if report else 0
        from phase1.scoring.engine import DecisionEngine
        return DecisionEngine.decide(_latest_score(project), critical) == "Approved"

    approved = len([p for p in projects if _is_approved(p)])
    pending = len([p for p in projects if p.status in ("Pending Remediation", "Scanning", "Created", "Uploaded")])
    rejected = len([p for p in projects if p.status in ("Rejected", "Upload Failed")])
    incident_projects = len([p for p in projects if p.status == "Incident Detected"])
    project_status = Counter(p.status or "Created" for p in projects)
    monitoring = len([p for p in projects if p.monitoring_enabled])
    active_monitors = set(MonitoringScheduler.get_active_monitors())

    user_projects = [p.project_id for p in projects if p.project_id]
    projects_by_id = {p.project_id: p for p in projects}

    raw_incidents = Incident.query.filter(Incident.project_id.in_(user_projects)).all() if user_projects else []
    raw_threats = ThreatSummary.query.filter(ThreatSummary.project_id.in_(user_projects)).all() if user_projects else []
    incidents = [
        item for item in raw_incidents
        if _for_current_project(getattr(item, "created_time", None), projects_by_id.get(item.project_id))
    ]
    threats = [
        item for item in raw_threats
        if _for_current_project(getattr(item, "created_date", None), projects_by_id.get(item.project_id))
    ]
    validated_threats_rows = [
        item for item in threats
        if (item.status or "") == "Validated" or float(item.confidence or 0) >= 85
    ]

    monitoring_threats = 0
    for pid in user_projects:
        mon = ProjectMonitoring.query.filter_by(project_id=pid).first()
        if mon:
            monitoring_threats += int(mon.total_threats or 0)
    # Prefer live Phase 2 records; fall back to the monitoring counter if summaries lag.
    total_threats = max(len(validated_threats_rows), monitoring_threats)

    scores = [_latest_score(p) for p in projects if _was_scanned(p)]
    avg_score = round(sum(scores) / len(scores), 1) if scores else 0.0

    score_buckets = {"90-100": 0, "75-89": 0, "65-74": 0, "40-64": 0, "0-39": 0}
    for score in scores:
        if score >= 90:
            score_buckets["90-100"] += 1
        elif score >= 75:
            score_buckets["75-89"] += 1
        elif score >= 65:
            score_buckets["65-74"] += 1
        elif score >= 40:
            score_buckets["40-64"] += 1
        else:
            score_buckets["0-39"] += 1

    finding_totals = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for project in projects:
        report = latest_security_report(project)
        if not report:
            continue
        finding_totals["Critical"] += int(report.critical or 0)
        finding_totals["High"] += int(report.high or 0)
        finding_totals["Medium"] += int(report.medium or 0)
        finding_totals["Low"] += int(report.low or 0)

    threat_by_type = Counter(t.threat_type or "Unknown" for t in validated_threats_rows)
    incident_by_status = Counter(i.status or "Open" for i in incidents)
    incident_by_severity = Counter(i.severity or "Medium" for i in incidents)

    resolved = len([i for i in incidents if (i.status or "").lower() in ("resolved", "closed")])
    open_incidents = [
        i for i in incidents
        if (i.status or "Open") not in ("Resolved", "Closed")
    ]
    threshold = 85.0
    threat_conf = [float(t.confidence or 0) for t in threats]
    validated_threats = len(validated_threats_rows)
    observation_threats = max(0, len(threats) - validated_threats)
    incident_conf = [float(i.confidence or 0) for i in incidents]
    avg_confidence = round(sum(incident_conf) / len(incident_conf), 1) if incident_conf else (
        round(sum(threat_conf) / len(threat_conf), 1) if threat_conf else 0.0
    )
    severity_rank = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    attention_queue = []
    for incident in sorted(
        open_incidents,
        key=lambda item: (severity_rank.get(item.severity or "Medium", 9), -(float(item.confidence or 0))),
    )[:6]:
        attention_queue.append({
            "incident_id": incident.incident_id,
            "project_id": incident.project_id,
            "threat": incident.threat,
            "severity": incident.severity,
            "status": incident.status,
            "confidence": incident.confidence,
        })
    pipeline = {
        "scanned": len([p for p in projects if (p.security_score or 0) > 0 or p.status not in ("Created", "Uploaded")]),
        "approved": approved,
        "monitoring": monitoring,
        "active_monitoring": len([pid for pid in user_projects if pid in active_monitors]),
        "threats": total_threats,
        "incidents": len(incidents),
        "resolved": resolved,
    }

    notifications = NotificationService.get_user_notifications(user_id, unread_only=False)[:10]

    recent_activities = []
    for p in sorted(projects, key=lambda x: x.created_date or "", reverse=True)[:5]:
        recent_activities.append({
            "type": "project",
            "message": f"Project {p.project_id} - {p.project_name} ({p.status})",
            "date": p.created_date.isoformat() if p.created_date else None,
        })

    return jsonify({
        "welcome": "Welcome back!",
        "stats": {
            "total_projects": len(projects),
            "approved_projects": approved,
            "pending_projects": pending,
            "rejected_projects": rejected,
            "incident_projects": incident_projects,
            "monitoring_enabled": monitoring,
            "active_monitoring": pipeline["active_monitoring"],
            "total_incidents": len(incidents),
            "critical_incidents": len([i for i in incidents if i.severity == "Critical"]),
            "resolved_incidents": resolved,
            "total_threats": total_threats,
            "avg_security_score": avg_score,
            "unread_notifications": len([n for n in notifications if not n.read_status]),
        },
        "analytics": {
            "project_status": dict(project_status),
            "score_distribution": score_buckets,
            "findings_by_severity": finding_totals,
            "threats_by_type": dict(threat_by_type.most_common(8)),
            "incidents_by_status": dict(incident_by_status),
            "incidents_by_severity": dict(incident_by_severity),
            "pipeline": pipeline,
        },
        "ops": {
            "phase_gate": {
                "phase1_scanned": pipeline["scanned"],
                "phase1_approved": approved,
                "phase1_pending": pending,
                "phase2_monitoring": monitoring,
                "phase2_live": pipeline["active_monitoring"],
                "phase3_open": len(open_incidents),
                "phase3_resolved": resolved,
                "approval_gate": 65,
            },
            "attention_queue": attention_queue,
            "detection_confidence": {
                "threshold": int(threshold),
                "validated_threats": validated_threats,
                "observation_threats": observation_threats,
                "open_incidents": len(open_incidents),
                "avg_confidence": avg_confidence,
                "total_threats": total_threats,
            },
        },
        "recent_activities": recent_activities,
        "notifications": [{
            "id": n.notification_id,
            "title": n.title,
            "message": n.message,
            "read": n.read_status,
            "date": n.created_date.isoformat() if n.created_date else None,
        } for n in notifications],
        "security_tips": [
            "Always use environment variables for secrets, never hardcode them.",
            "Keep dependencies updated to patch known CVEs.",
            "Review IAM permissions regularly — apply least privilege.",
            "Enable logging and monitoring for all cloud resources.",
            "Track residual risk after Phase 1 approval with continuous Phase 2 monitoring.",
        ],
    }), 200
