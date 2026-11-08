from datetime import datetime, timezone
from database.extensions import mongo_insert
from database.models import Incident


class EvidenceCollector:
    @staticmethod
    def collect(incident: Incident, log: dict, actions: list):
        evidence = {
            "incidentId": incident.incident_id,
            "projectId": incident.project_id,
            "threat": incident.threat,
            "severity": incident.severity,
            "confidence": incident.confidence,
            "affectedUser": incident.affected_user,
            "sourceIP": incident.source_ip,
            "country": log.get("country"),
            "browser": log.get("browser"),
            "eventType": log.get("eventType"),
            "resource": log.get("resource"),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "responseActions": actions,
            "eventHistory": log,
        }
        mongo_insert("forensic_logs", dict(evidence))
        return evidence
