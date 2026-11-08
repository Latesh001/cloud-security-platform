"""Keep Project-ID reuse from mixing leftover reports into the current project."""
from datetime import datetime, timedelta, timezone
from typing import Optional

from database.extensions import mongo_find_one
from database.models import SecurityReport

_STALE_GRACE = timedelta(seconds=5)


def as_dt(value) -> Optional[datetime]:
    if value is None:
        return None
    if isinstance(value, datetime):
        if value.tzinfo is not None:
            return value.astimezone(timezone.utc).replace(tzinfo=None)
        return value
    if isinstance(value, str):
        text = value.strip().replace("Z", "").replace("T", " ")
        for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
            try:
                return datetime.strptime(text[:26], fmt)
            except ValueError:
                continue
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00")).replace(tzinfo=None)
        except ValueError:
            return None
    return None


def belongs_to_project(record_time, project) -> bool:
    created = as_dt(getattr(project, "created_date", None))
    when = as_dt(record_time)
    if created is None or when is None:
        return True
    return when >= (created - _STALE_GRACE)


def latest_security_report(project) -> Optional[SecurityReport]:
    if project is None:
        return None
    reports = SecurityReport.query.filter_by(project_id=project.project_id).order_by(
        SecurityReport.created_date.desc()
    ).all()
    for report in reports:
        if belongs_to_project(getattr(report, "created_date", None), project):
            return report
    return None


def current_reports(project):
    reports = SecurityReport.query.filter_by(project_id=project.project_id).order_by(
        SecurityReport.created_date.desc()
    ).all()
    return [r for r in reports if belongs_to_project(getattr(r, "created_date", None), project)]


def latest_scan_log(project) -> Optional[dict]:
    if project is None:
        return None
    log = mongo_find_one(
        "scan_logs",
        {"projectId": project.project_id},
        sort=[("timestamp", -1)],
    )
    if not log:
        return None
    if belongs_to_project(log.get("timestamp"), project):
        return log
    return None


def project_score(project) -> float:
    """Score shown on project cards, scan results, and dashboard average."""
    report = latest_security_report(project)
    if report is not None and report.score is not None:
        return float(report.score)
    return float(getattr(project, "security_score", 0) or 0)
