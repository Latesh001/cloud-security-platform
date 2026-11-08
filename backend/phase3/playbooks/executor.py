from typing import Dict, List
from database.models import Incident


PLAYBOOKS = {
    "credential_theft": [
        {"action": "Lock User Account (Simulation)", "step": 1},
        {"action": "Disable Active Sessions (Simulation)", "step": 2},
        {"action": "Force Password Reset (Simulation)", "step": 3},
        {"action": "Rotate Access Keys (Simulation)", "step": 4},
        {"action": "Generate Incident Report", "step": 5},
    ],
    "brute_force": [
        {"action": "Temporarily Lock Account (Simulation)", "step": 1},
        {"action": "Record Source IP (Simulation)", "step": 2},
        {"action": "Increase Risk Score", "step": 3},
        {"action": "Notify User", "step": 4},
    ],
    "malware": [
        {"action": "Quarantine Resource (Simulation)", "step": 1},
        {"action": "Save Forensic Evidence", "step": 2},
        {"action": "Generate Incident Report", "step": 3},
    ],
    "suspicious_login": [
        {"action": "Flag High-Risk Login", "step": 1},
        {"action": "Require MFA Re-verification (Simulation)", "step": 2},
        {"action": "Record Login Details", "step": 3},
        {"action": "Notify User", "step": 4},
    ],
    "data_exfiltration": [
        {"action": "Suspend Download Session (Simulation)", "step": 1},
        {"action": "Record Transfer Evidence", "step": 2},
        {"action": "Block Source IP (Simulation)", "step": 3},
        {"action": "Generate Incident Report", "step": 4},
    ],
    "privilege_escalation": [
        {"action": "Revoke Elevated Permissions (Simulation)", "step": 1},
        {"action": "Audit IAM Changes", "step": 2},
        {"action": "Notify Security Team", "step": 3},
    ],
    "config_tampering": [
        {"action": "Restore Configuration (Simulation)", "step": 1},
        {"action": "Enable Enhanced Logging", "step": 2},
        {"action": "Generate Incident Report", "step": 3},
    ],
    "public_exposure": [
        {"action": "Disable Public Access (Simulation)", "step": 1},
        {"action": "Mark Resource Critical", "step": 2},
        {"action": "Generate Remediation Report", "step": 3},
    ],
    "insider_threat": [
        {"action": "Restrict User Permissions (Simulation)", "step": 1},
        {"action": "Enable Activity Monitoring", "step": 2},
        {"action": "Collect Evidence", "step": 3},
    ],
}


class PlaybookExecutor:
    @staticmethod
    def execute(playbook_key: str, incident: Incident, log: dict) -> List[Dict]:
        steps = PLAYBOOKS.get(playbook_key, PLAYBOOKS["suspicious_login"])
        results = []
        for step in steps:
            results.append({
                "action": step["action"],
                "result": "Simulated Successfully",
                "step": step["step"],
                "incident_id": incident.incident_id,
                "target_user": log.get("username"),
                "source_ip": log.get("sourceIP"),
            })
        return results
