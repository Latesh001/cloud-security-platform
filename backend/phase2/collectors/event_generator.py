import random
from datetime import datetime, timezone
from typing import Dict, List


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


EVENT_TYPES = [
    "ConsoleLogin", "ConsoleLoginFailure", "CreateUser", "DeleteUser",
    "CreateAccessKey", "ModifyPolicy", "AttachUserPolicy",
    "RunInstances", "StopInstances", "TerminateInstances",
    "PutObject", "GetObject", "DeleteBucket", "CreateBucket",
    "AuthorizeSecurityGroupIngress", "RevokeSecurityGroupIngress",
    "ChangePassword", "UpdateLoginProfile", "AssumeRole",
    "LargeFileDownload", "DatabaseQuery", "APIRequest",
]

RESOURCES = ["IAM", "EC2", "S3", "VPC", "RDS", "Lambda", "CloudWatch", "SecurityHub"]
USERS = ["admin", "developer", "analyst", "devops", "guest", "service-account"]
COUNTRIES = ["India", "USA", "Germany", "Russia", "China", "Brazil", "UK", "Japan"]
BROWSERS = ["Chrome", "Firefox", "Safari", "Edge"]
STATUSES = ["Success", "Failure"]

THREAT_SEQUENCES = [
    ["ConsoleLoginFailure", "ConsoleLoginFailure", "ConsoleLoginFailure", "ConsoleLogin"],
    ["ConsoleLogin", "CreateAccessKey", "LargeFileDownload"],
    ["ConsoleLogin", "ModifyPolicy", "DeleteBucket"],
    ["AssumeRole", "CreateUser", "AttachUserPolicy"],
]


class CloudEventGenerator:
    def __init__(self, project_id: str):
        self.project_id = project_id
        self.event_counter = 0
        self.threat_mode = False
        self.sequence_index = 0

    def generate(self, force_threat: bool = False) -> Dict:
        self.event_counter += 1

        if force_threat or (self.event_counter % 15 == 0):
            return self._generate_threat_sequence_event()

        event_type = random.choice(EVENT_TYPES)
        is_suspicious = event_type in (
            "ConsoleLoginFailure", "DeleteBucket", "LargeFileDownload",
            "ModifyPolicy", "CreateAccessKey", "AssumeRole",
        )

        return {
            "projectId": self.project_id,
            "timestamp": _now(),
            "username": random.choice(USERS),
            "eventType": event_type,
            "resource": random.choice(RESOURCES),
            "sourceIP": f"182.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}",
            "country": random.choice(COUNTRIES),
            "browser": random.choice(BROWSERS),
            "status": "Failure" if "Failure" in event_type else random.choice(STATUSES),
            "logType": random.choice(["CloudTrail", "CloudWatch", "IAM", "VPC Flow", "GuardDuty"]),
            "bytesTransferred": random.randint(0, 5000000000) if event_type == "LargeFileDownload" else 0,
            "mfaEnabled": random.choice([True, False]),
            "isSuspicious": is_suspicious,
        }

    def _generate_threat_sequence_event(self) -> Dict:
        seq = random.choice(THREAT_SEQUENCES)
        event_type = seq[self.sequence_index % len(seq)]
        self.sequence_index += 1

        return {
            "projectId": self.project_id,
            "timestamp": _now(),
            "username": "admin",
            "eventType": event_type,
            "resource": random.choice(["IAM", "S3", "EC2"]),
            "sourceIP": f"185.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}",
            "country": random.choice(["Russia", "China", "Unknown"]),
            "browser": random.choice(["Firefox", "Tor Browser"]),
            "status": "Success" if "Failure" not in event_type else "Failure",
            "logType": "CloudTrail",
            "bytesTransferred": random.randint(1000000000, 5000000000) if event_type == "LargeFileDownload" else 0,
            "mfaEnabled": False,
            "isSuspicious": True,
        }
