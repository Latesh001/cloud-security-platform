from flask import Blueprint, jsonify, send_file
from flask_jwt_extended import jwt_required, get_jwt_identity

from database.extensions import db, mongo_find_one
from database.models import Incident, Response, Project
from phase3.rule_engine.engine import PLAYBOOK_MAP, RuleEngine
from phase3.incident_manager.manager import IncidentManager
from phase3.playbooks.executor import PLAYBOOKS
from phase3.reports.generator import IncidentReportGenerator, PLAYBOOK_LABELS
from utils.helpers import isoformat_utc
from utils.logger import audit_logger


def _live_status(incident: Incident) -> str:
    status = incident.status or "Open"
    if status == "Closed":
        return "Closed"
    if status == "Resolved" and incident.resolved_time:
        return "Resolved"
    if status == "Resolved":
        return "In Progress"
    return status


def _response_succeeded(result) -> bool:
    text = (result or "").strip().lower()
    if not text:
        return False
    if any(token in text for token in ("fail", "error", "pending", "denied")):
        return False
    return True

incidents_bp = Blueprint("incidents", __name__, url_prefix="/api/incidents")


@incidents_bp.route("", methods=["GET"])
@incidents_bp.route("/", methods=["GET"])
@jwt_required()
def list_incidents():
    user_id = int(get_jwt_identity())
    owned = Project.query.filter_by(user_id=user_id).all()
    user_projects = [p.project_id for p in owned]
    by_id = {p.project_id: p for p in owned}
    from dashboard.routes import _for_current_project
    incidents = [
        item for item in (
            Incident.query.filter(Incident.project_id.in_(user_projects))
            .order_by(Incident.created_time.desc()).all() if user_projects else []
        )
        if _for_current_project(getattr(item, "created_time", None), by_id.get(item.project_id))
    ]

    rows = [_incident_dict(i) for i in incidents]
    open_count = len([row for row in rows if row["status"] in ("Open", "In Progress")])
    resolved_count = len([row for row in rows if row["status"] in ("Resolved", "Closed")])
    incident_ids = [item.incident_id for item in incidents]
    responses = (
        Response.query.filter(Response.incident_id.in_(incident_ids)).all()
        if incident_ids else []
    )
    succeeded = len([r for r in responses if _response_succeeded(getattr(r, "result", ""))])
    if responses:
        success_rate = round((succeeded / len(responses)) * 100)
    elif rows:
        success_rate = round((resolved_count / len(rows)) * 100)
    else:
        success_rate = 0
    return jsonify({
        "incidents": rows,
        "stats": {
            "total": len(rows),
            "open": open_count,
            "in_progress": len([row for row in rows if row["status"] == "In Progress"]),
            "resolved": resolved_count,
            "critical": len([i for i in incidents if i.severity == "Critical"]),
            "response_actions": len(responses),
            "response_succeeded": succeeded,
            "response_success_rate": success_rate,
        },
    }), 200


@incidents_bp.route("/<incident_id>", methods=["GET"])
@jwt_required()
def get_incident(incident_id):
    user_id = int(get_jwt_identity())
    incident = Incident.query.get(incident_id)
    if not incident:
        return jsonify({"error": "Incident not found"}), 404

    project = Project.query.filter_by(project_id=incident.project_id, user_id=user_id).first()
    if not project:
        return jsonify({"error": "Access denied"}), 403

    responses = Response.query.filter_by(incident_id=incident_id).order_by(
        Response.executed_time
    ).all()

    evidence = mongo_find_one("forensic_logs", {"incidentId": incident_id})
    pack = mongo_find_one("incident_evidence", {"incidentId": incident_id})
    timeline_doc = mongo_find_one("timeline_history", {"incidentId": incident_id})
    timeline = timeline_doc.get("timeline") if timeline_doc else []
    event = (evidence or {}).get("eventHistory") or (pack or {}).get("log") or {}
    prediction = (pack or {}).get("prediction") or {}
    playbook_key = PLAYBOOK_MAP.get(incident.threat, "suspicious_login")

    return jsonify({
        "incident": _incident_dict(incident),
        "project": {
            "project_id": project.project_id,
            "project_name": project.project_name,
            "category": project.category,
            "programming_language": project.programming_language,
            "framework": project.framework,
            "cloud_provider": project.cloud_provider,
            "security_score": project.security_score,
            "status": project.status,
            "monitoring_enabled": project.monitoring_enabled,
        },
        "detection": {
            "model_used": prediction.get("modelUsed") or "Rule-based / recorded",
            "confidence": prediction.get("confidence", incident.confidence),
            "threshold": prediction.get("threshold", 85),
            "is_threat": prediction.get("isThreat", True),
            "is_anomaly": prediction.get("isAnomaly", True),
            "playbook_key": playbook_key,
            "playbook_name": PLAYBOOK_LABELS.get(playbook_key, playbook_key),
            "playbook_steps": len(PLAYBOOKS.get(playbook_key, [])),
        },
        "event": event,
        "responses": [{
            "action": r.action,
            "result": r.result,
            "executed_time": r.executed_time.isoformat() if r.executed_time else None,
        } for r in responses],
        "evidence": evidence,
        "timeline": timeline,
    }), 200


@incidents_bp.route("/respond/<incident_id>", methods=["POST"])
@jwt_required()
def respond_incident(incident_id):
    user_id = int(get_jwt_identity())
    incident = Incident.query.get(incident_id)
    if not incident:
        return jsonify({"error": "Incident not found"}), 404

    project = Project.query.filter_by(project_id=incident.project_id, user_id=user_id).first()
    if not project:
        return jsonify({"error": "Access denied"}), 403

    log = {"username": incident.affected_user, "sourceIP": incident.source_ip}
    RuleEngine.process_incident(incident, log, auto_mode=True)
    return jsonify({"message": "Response executed", "incident": _incident_dict(incident)}), 200


@incidents_bp.route("/close/<incident_id>", methods=["POST"])
@jwt_required()
def close_incident(incident_id):
    user_id = int(get_jwt_identity())
    incident = Incident.query.get(incident_id)
    if not incident:
        return jsonify({"error": "Incident not found"}), 404

    project = Project.query.filter_by(project_id=incident.project_id, user_id=user_id).first()
    if not project:
        return jsonify({"error": "Access denied"}), 403

    IncidentManager.close_incident(incident_id)
    return jsonify({"message": "Incident closed"}), 200


@incidents_bp.route("/timeline/<incident_id>", methods=["GET"])
@jwt_required()
def get_timeline(incident_id):
    user_id = int(get_jwt_identity())
    incident = Incident.query.get(incident_id)
    if not incident:
        return jsonify({"error": "Incident not found"}), 404

    project = Project.query.filter_by(project_id=incident.project_id, user_id=user_id).first()
    if not project:
        return jsonify({"error": "Access denied"}), 403

    timeline_doc = mongo_find_one("timeline_history", {"incidentId": incident_id})
    timeline = timeline_doc.get("timeline", []) if timeline_doc else []
    return jsonify({"timeline": timeline}), 200


@incidents_bp.route("/report/<incident_id>", methods=["GET"])
@jwt_required()
def download_report(incident_id):
    user_id = int(get_jwt_identity())
    incident = Incident.query.get(incident_id)
    if not incident:
        return jsonify({"error": "Incident not found"}), 404

    project = Project.query.filter_by(project_id=incident.project_id, user_id=user_id).first()
    if not project:
        return jsonify({"error": "Access denied"}), 403

    report_path = IncidentReportGenerator.generate(incident)
    return send_file(
        report_path,
        as_attachment=True,
        download_name=f"incident_{incident_id}_full_report.pdf",
    )


def _incident_dict(incident: Incident) -> dict:
    return {
        "incident_id": incident.incident_id,
        "project_id": incident.project_id,
        "threat": incident.threat,
        "severity": incident.severity,
        "confidence": incident.confidence,
        "affected_user": incident.affected_user,
        "source_ip": incident.source_ip,
        "status": _live_status(incident),
        "created_time": isoformat_utc(incident.created_time),
        "resolved_time": isoformat_utc(incident.resolved_time),
    }
