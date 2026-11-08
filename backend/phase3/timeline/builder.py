from datetime import datetime, timezone
from database.extensions import mongo_insert
from database.models import Incident


class TimelineBuilder:
    @staticmethod
    def build(incident: Incident, log: dict, actions: list):
        now = datetime.now(timezone.utc)
        timeline = [
            {"time": log.get("timestamp", now.isoformat()), "event": "Security Event Detected", "details": log.get("eventType")},
            {"time": now.isoformat(), "event": "AI Threat Prediction", "details": f"{incident.threat} ({incident.confidence}% confidence)"},
            {"time": now.isoformat(), "event": "Incident Created", "details": incident.incident_id},
        ]
        for action in actions:
            timeline.append({
                "time": now.isoformat(),
                "event": "Response Executed",
                "details": action.get("action"),
            })
        timeline.append({"time": now.isoformat(), "event": "Evidence Stored", "details": "Forensic data preserved"})
        timeline.append({"time": now.isoformat(), "event": "Notification Sent", "details": "Developer alerted"})

        mongo_insert("timeline_history", {
            "incidentId": incident.incident_id,
            "projectId": incident.project_id,
            "timeline": list(timeline),
        })
        return timeline
