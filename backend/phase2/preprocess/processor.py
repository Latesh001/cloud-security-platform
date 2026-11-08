import re
from datetime import datetime, timezone
from typing import Dict, List, Optional


class LogValidator:
    REQUIRED_FIELDS = ["projectId", "timestamp", "eventType", "sourceIP"]

    @staticmethod
    def validate(log: Dict) -> tuple[bool, str]:
        for field in LogValidator.REQUIRED_FIELDS:
            if field not in log or not log[field]:
                return False, f"Missing required field: {field}"
        if not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", str(log.get("sourceIP", "")).split("/")[0]):
            if log.get("sourceIP") != "Unknown":
                pass
        return True, "Valid"


class LogPreprocessor:
    seen_hashes = set()

    @staticmethod
    def process(log: Dict) -> Optional[Dict]:
        valid, msg = LogValidator.validate(log)
        if not valid:
            return None

        log_hash = f"{log['projectId']}_{log['timestamp']}_{log['eventType']}_{log.get('username','')}"
        if log_hash in LogPreprocessor.seen_hashes:
            return None
        LogPreprocessor.seen_hashes.add(log_hash)
        if len(LogPreprocessor.seen_hashes) > 10000:
            LogPreprocessor.seen_hashes.clear()

        ts = log.get("timestamp") or datetime.now(timezone.utc).isoformat()
        try:
            login_hour = datetime.fromisoformat(ts.replace("Z", "+00:00")).hour
        except (ValueError, AttributeError):
            login_hour = 12

        processed = {
            "projectId": log["projectId"],
            "timestamp": ts,
            "username": log.get("username", "unknown"),
            "eventType": log["eventType"],
            "resource": log.get("resource", "Unknown"),
            "sourceIP": log.get("sourceIP", "0.0.0.0"),
            "country": log.get("country", "Unknown"),
            "browser": log.get("browser", "Unknown"),
            "status": log.get("status", "Unknown"),
            "logType": log.get("logType", "CloudTrail"),
            "bytesTransferred": log.get("bytesTransferred", 0),
            "mfaEnabled": 1 if log.get("mfaEnabled") else 0,
            "loginHour": login_hour,
            "isSuspicious": 1 if log.get("isSuspicious") else 0,
            "failedLogin": 1 if "Failure" in log.get("eventType", "") else 0,
            "iamChange": 1 if log.get("eventType") in ("ModifyPolicy", "CreateUser", "AttachUserPolicy") else 0,
            "dataTransfer": 1 if log.get("bytesTransferred", 0) > 100000000 else 0,
        }
        return processed
