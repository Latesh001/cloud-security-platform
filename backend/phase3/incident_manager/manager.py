from datetime import datetime, timezone

from database.extensions import db, mongo_insert
from database.models import Incident, Response, Project
from utils.helpers import generate_incident_id
from notifications.service import NotificationService
from utils.logger import audit_logger


class IncidentManager:
    @staticmethod
    def create_from_threat(project_id: str, log: dict, prediction: dict) -> Incident:
        last = Incident.query.order_by(Incident.incident_id.desc()).first()
        incident_id = generate_incident_id(last.incident_id if last else None)

        incident = Incident(
            incident_id=incident_id,
            project_id=project_id,
            threat=prediction.get("threat", "Unknown"),
            severity=prediction.get("severity", "Medium"),
            confidence=prediction.get("confidence", 0),
            affected_user=log.get("username"),
            source_ip=log.get("sourceIP"),
            status="Open",
        )
        db.session.add(incident)
        db.session.commit()

        project = Project.query.get(project_id)
        if project:
            project.status = "Incident Detected"
            db.session.commit()

        mongo_insert("incident_evidence", {
            "incidentId": incident_id,
            "projectId": project_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "log": dict(log),
            "prediction": dict(prediction),
        })

        from phase3.rule_engine.engine import RuleEngine
        RuleEngine.process_incident(incident, log, auto_mode=True)

        try:
            from advanced.integration import on_incident_created
            on_incident_created(project_id, incident_id, incident.threat, incident.severity, prediction, log)
        except Exception as exc:
            audit_logger.error("Advanced Features incident hook skipped: %s", exc)

        audit_logger.info(f"Incident created: {incident_id} for {project_id}")
        return incident

    @staticmethod
    def get_incident(incident_id: str) -> Incident:
        return Incident.query.get(incident_id)

    @staticmethod
    def close_incident(incident_id: str):
        incident = Incident.query.get(incident_id)
        if incident:
            incident.status = "Closed"
            incident.resolved_time = datetime.now(timezone.utc)
            db.session.commit()
            try:
                from advanced.integration import on_incident_closed
                on_incident_closed(incident.project_id, incident_id)
            except Exception:
                pass
        return incident
