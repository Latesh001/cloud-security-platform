from datetime import datetime, timezone

from database.extensions import db
from database.models import Incident, Response, Project
from phase3.playbooks.executor import PlaybookExecutor
from phase3.evidence.collector import EvidenceCollector
from phase3.timeline.builder import TimelineBuilder
from notifications.service import NotificationService
from utils.logger import audit_logger


PLAYBOOK_MAP = {
    "Credential Theft": "credential_theft",
    "Brute Force": "brute_force",
    "Brute Force Attack": "brute_force",
    "Data Exfiltration": "data_exfiltration",
    "Privilege Escalation": "privilege_escalation",
    "Malware Activity": "malware",
    "Suspicious Login": "suspicious_login",
    "Configuration Tampering": "config_tampering",
    "Public Resource Exposure": "public_exposure",
    "Insider Threat": "insider_threat",
    "Suspicious Activity": "suspicious_login",
    "Suspicious API Usage": "privilege_escalation",
}


class RuleEngine:
    @staticmethod
    def process_incident(incident: Incident, log: dict, auto_mode: bool = True):
        playbook_key = PLAYBOOK_MAP.get(incident.threat, "suspicious_login")

        if auto_mode:
            actions = PlaybookExecutor.execute(playbook_key, incident, log)
        else:
            actions = [{"action": f"Recommended: {playbook_key}", "result": "Pending Approval"}]

        for action in actions:
            response = Response(
                incident_id=incident.incident_id,
                action=action["action"],
                result=action.get("result", "Success"),
            )
            db.session.add(response)

        incident.status = "In Progress"
        db.session.commit()

        EvidenceCollector.collect(incident, log, actions)
        TimelineBuilder.build(incident, log, actions)

        project = Project.query.get(incident.project_id)
        if project:
            NotificationService.create(
                project.user_id,
                f"Incident {incident.incident_id} - {incident.severity}",
                f"Threat: {incident.threat}. Actions executed: {len(actions)}",
                send_email=True,
            )

        from phase3.reports.generator import IncidentReportGenerator
        IncidentReportGenerator.generate(incident)

        # Stay Open/In Progress until an analyst closes the case so Phase 3
        # Open filter and the Open counter actually show live incidents.
        incident.status = "In Progress"
        db.session.commit()
        audit_logger.info(f"Incident processed: {incident.incident_id}")
