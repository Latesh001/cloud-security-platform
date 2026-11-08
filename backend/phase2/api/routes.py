from flask import Blueprint, jsonify, current_app
from flask_jwt_extended import jwt_required, get_jwt_identity

from database.extensions import db, mongo_find
from database.models import Project, ProjectMonitoring, ThreatSummary
from phase1.scoring.engine import DecisionEngine
from utils.project_scope import latest_security_report, project_score
from phase2.scheduler.monitor_scheduler import MonitoringScheduler
from utils.helpers import isoformat_utc
from utils.logger import audit_logger

monitor_bp = Blueprint("monitoring", __name__, url_prefix="/api/monitoring")


def _check_eligibility(project: Project) -> tuple[bool, str]:
    report = latest_security_report(project)
    if not report:
        return False, "No security report found"
    threshold = current_app.config.get("APPROVAL_SCORE_THRESHOLD", 65)
    score = project_score(project)
    critical = int(report.critical or 0)
    if DecisionEngine.decide(score, critical, threshold) != "Approved":
        return False, (
            f"Security score {score} is below the monitoring gate ({threshold}) "
            "or residual critical risk is too high. Remediate and rescan."
        )
    return True, "Eligible"


def _enable_monitoring(project: Project) -> None:
    """Mark the project eligible so Phase 2 can start after a 65+ score."""
    project.monitoring_enabled = True
    if (project.status or "") in ("Pending Remediation", "Approved", "Uploaded", "Scanning"):
        project.status = "Monitoring Enabled"
    monitoring = ProjectMonitoring.query.filter_by(project_id=project.project_id).first()
    if monitoring:
        monitoring.monitoring_enabled = True
    else:
        db.session.add(ProjectMonitoring(
            project_id=project.project_id,
            monitoring_enabled=True,
            current_state="Idle",
        ))
    db.session.commit()


@monitor_bp.route("/projects", methods=["GET"])
@jwt_required()
def monitoring_projects():
    user_id = int(get_jwt_identity())
    projects = []
    for project in Project.query.filter_by(user_id=user_id).all():
        eligible, _ = _check_eligibility(project)
        if eligible and not project.monitoring_enabled:
            _enable_monitoring(project)
        if project.monitoring_enabled or eligible:
            projects.append(project)
    result = []
    for p in projects:
        mon = ProjectMonitoring.query.filter_by(project_id=p.project_id).first()
        live = p.project_id in MonitoringScheduler.get_active_monitors()
        result.append({
            "project_id": p.project_id,
            "project_name": p.project_name,
            "status": p.status,
            "monitoring_state": "Running" if live else "Stopped",
            "total_logs": mon.total_logs if mon else 0,
            "total_threats": mon.total_threats if mon else 0,
        })
    return jsonify({"projects": result}), 200


@monitor_bp.route("/start/<project_id>", methods=["POST"])
@jwt_required()
def start_monitoring(project_id):
    user_id = int(get_jwt_identity())
    project = Project.query.filter_by(project_id=project_id, user_id=user_id).first()
    if not project:
        return jsonify({"error": "Project not found"}), 404

    eligible, msg = _check_eligibility(project)
    if not eligible:
        return jsonify({"error": msg}), 403

    _enable_monitoring(project)
    started = MonitoringScheduler.start_monitoring(project_id, current_app._get_current_object())
    if started:
        audit_logger.info(f"Monitoring started for {project_id}")
        return jsonify({"message": "Monitoring started", "project_id": project_id, "state": "Running"}), 200
    return jsonify({"error": "Monitoring could not start. Confirm the Phase 1 score is 65 or higher."}), 400


@monitor_bp.route("/stop/<project_id>", methods=["POST"])
@jwt_required()
def stop_monitoring(project_id):
    user_id = int(get_jwt_identity())
    project = Project.query.filter_by(project_id=project_id, user_id=user_id).first()
    if not project:
        return jsonify({"error": "Project not found"}), 404

    MonitoringScheduler.stop_monitoring(project_id)
    return jsonify({"message": "Monitoring stopped"}), 200


@monitor_bp.route("/status/<project_id>", methods=["GET"])
@jwt_required()
def monitoring_status(project_id):
    user_id = int(get_jwt_identity())
    project = Project.query.filter_by(project_id=project_id, user_id=user_id).first()
    if not project:
        return jsonify({"error": "Project not found"}), 404

    mon = ProjectMonitoring.query.filter_by(project_id=project_id).first()
    active = project_id in MonitoringScheduler.get_active_monitors()

    return jsonify({
        "project_id": project_id,
        "monitoring_enabled": project.monitoring_enabled,
        "current_state": "Running" if active else (mon.current_state if mon else "Stopped"),
        "total_logs": mon.total_logs if mon else 0,
        "total_threats": mon.total_threats if mon else 0,
    }), 200


@monitor_bp.route("/logs", methods=["GET"])
@monitor_bp.route("/logs/<project_id>", methods=["GET"])
@jwt_required()
def get_logs(project_id=None):
    user_id = int(get_jwt_identity())
    limit = 50

    if project_id:
        project = Project.query.filter_by(project_id=project_id, user_id=user_id).first()
        if not project:
            return jsonify({"error": "Project not found"}), 404

    if project_id:
        query = {"projectId": project_id}
    else:
        user_projects = [p.project_id for p in Project.query.filter_by(user_id=user_id).all()]
        query = {"projectId": {"$in": user_projects}}

    logs = mongo_find("cloud_logs", query, sort=[("timestamp", -1)], limit=limit)
    return jsonify({"logs": logs}), 200


@monitor_bp.route("/threats", methods=["GET"])
@monitor_bp.route("/threats/<project_id>", methods=["GET"])
@jwt_required()
def get_threats(project_id=None):
    user_id = int(get_jwt_identity())

    from dashboard.routes import _for_current_project
    if project_id:
        project = Project.query.filter_by(project_id=project_id, user_id=user_id).first()
        if not project:
            return jsonify({"error": "Project not found"}), 404
        threats = [
            item for item in ThreatSummary.query.filter_by(project_id=project_id)
            .order_by(ThreatSummary.created_date.desc()).all()
            if _for_current_project(getattr(item, "created_date", None), project)
        ][:50]
    else:
        owned = Project.query.filter_by(user_id=user_id).all()
        user_projects = [p.project_id for p in owned]
        by_id = {p.project_id: p for p in owned}
        threats = [
            item for item in (
                ThreatSummary.query.filter(ThreatSummary.project_id.in_(user_projects))
                .order_by(ThreatSummary.created_date.desc()).all() if user_projects else []
            )
            if _for_current_project(getattr(item, "created_date", None), by_id.get(item.project_id))
        ][:50]

    return jsonify({
        "threats": [{
            "id": t.id,
            "project_id": t.project_id,
            "threat_type": t.threat_type,
            "severity": t.severity,
            "confidence": t.confidence,
            "status": t.status,
            "created_date": isoformat_utc(t.created_date),
        } for t in threats]
    }), 200


@monitor_bp.route("/dashboard", methods=["GET"])
@jwt_required()
def monitoring_dashboard():
    user_id = int(get_jwt_identity())
    projects = Project.query.filter_by(user_id=user_id).all()
    project_ids = [p.project_id for p in projects]

    total_logs = 0
    total_threats = 0
    live = set(MonitoringScheduler.get_active_monitors())
    active_monitoring = len([pid for pid in project_ids if pid in live])

    for pid in project_ids:
        mon = ProjectMonitoring.query.filter_by(project_id=pid).first()
        if mon:
            total_logs += mon.total_logs
            total_threats += mon.total_threats

    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    from dashboard.routes import _for_current_project
    by_id = {p.project_id: p for p in projects}
    threats = [
        item for item in (
            ThreatSummary.query.filter(ThreatSummary.project_id.in_(project_ids)).all()
            if project_ids else []
        )
        if _for_current_project(getattr(item, "created_date", None), by_id.get(item.project_id))
    ]

    threat_categories = {}
    for t in threats:
        severity_counts[t.severity] = severity_counts.get(t.severity, 0) + 1
        threat_categories[t.threat_type] = threat_categories.get(t.threat_type, 0) + 1

    return jsonify({
        "active_projects": len([p for p in projects if p.monitoring_enabled]),
        "active_monitoring": active_monitoring,
        "total_logs": total_logs,
        "total_threats": total_threats,
        "severity_distribution": severity_counts,
        "threat_categories": threat_categories,
        "recent_threats": [{
            "project_id": t.project_id,
            "threat_type": t.threat_type,
            "severity": t.severity,
            "confidence": t.confidence,
            "created_date": isoformat_utc(t.created_date),
        } for t in sorted(threats, key=lambda x: x.created_date or "", reverse=True)[:10]],
    }), 200
