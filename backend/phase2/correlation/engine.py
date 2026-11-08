from datetime import datetime, timezone, timedelta
from typing import Dict, List


class EventCorrelationEngine:
    CORRELATION_WINDOW_MINUTES = 30

    @staticmethod
    def correlate(events: List[Dict]) -> List[Dict]:
        if len(events) < 2:
            return []

        incidents = []
        sorted_events = sorted(events, key=lambda x: x.get("timestamp", ""))

        attack_chains = [
            (["ConsoleLoginFailure", "ConsoleLoginFailure", "ConsoleLogin"], "Brute Force Attack"),
            (["ConsoleLogin", "CreateAccessKey", "LargeFileDownload"], "Credential Theft & Data Exfiltration"),
            (["ConsoleLogin", "ModifyPolicy", "DeleteBucket"], "Privilege Escalation & Sabotage"),
            (["AssumeRole", "CreateUser", "AttachUserPolicy"], "Insider Threat Pattern"),
        ]

        event_types = [e.get("eventType") for e in sorted_events[-10:]]

        for pattern, incident_type in attack_chains:
            if EventCorrelationEngine._contains_sequence(event_types, pattern):
                related = sorted_events[-len(pattern):]
                incidents.append({
                    "incidentType": incident_type,
                    "events": related,
                    "severity": "Critical",
                    "confidence": 95.0,
                    "description": f"Correlated attack pattern detected: {incident_type}",
                })

        return incidents

    @staticmethod
    def _contains_sequence(events: List[str], pattern: List[str]) -> bool:
        if len(pattern) > len(events):
            return False
        for i in range(len(events) - len(pattern) + 1):
            if events[i:i + len(pattern)] == pattern:
                return True
        return False
