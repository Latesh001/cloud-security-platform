"""REST API for Advanced Features. Additive — does not replace existing blueprints."""
import hashlib
import json
import os
from collections import Counter
from datetime import datetime, timedelta, timezone

from io import BytesIO
from urllib.parse import unquote

from flask import Blueprint, jsonify, request, send_file
from flask_jwt_extended import get_jwt_identity, jwt_required
from werkzeug.utils import secure_filename

from advanced import store
from advanced.explain import lime_view, risk_prediction, severity_prediction, shap_view, summarize_incident
from advanced.integration import evaluate_compliance, workflow_status
from advanced.reports import (
    compliance_pdf, executive_pdf, forensic_pdf, forensic_pdf_bytes, security_summary_pdf,
)
from advanced.seed import seed_if_empty
from database.models import Incident, Project, SecurityReport, ThreatSummary, User
from utils.helpers import pdf_archive_dir

advanced_bp = Blueprint("advanced", __name__, url_prefix="/api/advanced")


def _uid() -> int:
    return int(get_jwt_identity())


def _user_projects(user_id: int):
    return Project.query.filter_by(user_id=user_id).all()


def _owned(project_id: str, user_id: int):
    return Project.query.filter_by(project_id=project_id, user_id=user_id).first()


def _role_ok(user_id: int) -> bool:
    user = User.query.get(user_id)
    return bool(user and getattr(user, "is_active", True))


def _risk_distribution(ids, analyses):
    risk = {
        "Critical": sum(int(a.get("critical") or 0) for a in analyses),
        "High": sum(int(a.get("high") or 0) for a in analyses),
        "Medium": sum(int(a.get("medium") or 0) for a in analyses),
        "Low": sum(int(a.get("low") or 0) for a in analyses),
    }
    if any(risk.values()) or not ids:
        return risk
    for project_id in ids:
        report = SecurityReport.query.filter_by(project_id=project_id).order_by(
            SecurityReport.created_date.desc()
        ).first()
        if not report:
            continue
        risk["Critical"] += int(report.critical or 0)
        risk["High"] += int(report.high or 0)
        risk["Medium"] += int(report.medium or 0)
        risk["Low"] += int(report.low or 0)
    return risk


@advanced_bp.before_request
def _boot():
    seed_if_empty()


@advanced_bp.route("/health", methods=["GET"])
@jwt_required()
def health():
    return jsonify({"status": "ok", "module": "advanced", "mongo": store.available()}), 200


# ------------------------------------------------------------------ dashboard

@advanced_bp.route("/dashboard", methods=["GET", "POST"])
@jwt_required()
def dashboard():
    user_id = _uid()
    if not _role_ok(user_id):
        return jsonify({"error": "Role is not permitted"}), 403
    from advanced.integration import sync_existing_project
    projects = _user_projects(user_id)
    for project in projects:
        sync_existing_project(project)
    ids = [p.project_id for p in projects]
    analyses = [store.find_one("phase1_analysis", {"project_id": pid}) or {} for pid in ids]
    scores = [
        float(p.security_score or 0)
        for p in projects
        if float(p.security_score or 0) > 0
    ]
    vulns = sum(int(a.get("critical") or 0) + int(a.get("high") or 0) +
                int(a.get("medium") or 0) + int(a.get("low") or 0) for a in analyses)
    incidents = Incident.query.filter(Incident.project_id.in_(ids)).all() if ids else []
    threats = ThreatSummary.query.filter(ThreatSummary.project_id.in_(ids)).all() if ids else []
    assets = store.count("asset_inventory", {"user_id": user_id})
    automations = store.count("automation_history", {"project_id": {"$in": ids}}) if ids else 0
    compliance = [evaluate_compliance(pid, user_id) for pid in ids[:12]]
    avg_comp = round(sum(c.get("percentage") or 0 for c in compliance) / len(compliance), 1) if compliance else 0
    avg_score = round(sum(scores) / len(scores), 1) if scores else 0

    severity = Counter((i.severity or "Medium") for i in incidents)
    if not severity:
        severity = Counter((a.get("risk_level") or "Low") for a in analyses if a)
    severity_pie = {name: int(severity.get(name) or 0) for name in ("Critical", "High", "Medium", "Low")}
    if not any(severity_pie.values()):
        for name, count in severity.items():
            severity_pie[name] = int(count or 0)

    today = datetime.now(timezone.utc).date()
    day_keys = [(today - timedelta(days=13 - i)).isoformat() for i in range(14)]
    attack_counts = {key: 0 for key in day_keys}

    def _day(value):
        if hasattr(value, "strftime"):
            return value.strftime("%Y-%m-%d")
        text = str(value or "")
        return text[:10] if len(text) >= 10 else ""

    for incident in incidents:
        key = _day(getattr(incident, "created_time", None))
        if key in attack_counts:
            attack_counts[key] += 1
    for threat in threats:
        key = _day(getattr(threat, "created_date", None))
        if key in attack_counts:
            attack_counts[key] += 1
    for alert in store.find("threat_alerts", {"project_id": {"$in": ids}} if ids else {}, limit=200):
        key = _day(alert.get("created_at") or alert.get("timestamp"))
        if key in attack_counts:
            attack_counts[key] += 1
    if not any(attack_counts.values()) and threats:
        attack_counts[day_keys[-1]] = len(threats)

    score_history = []
    for project in projects:
        reports = list(project.reports or [])
        if reports:
            for report in reports[-8:]:
                score_history.append({
                    "project_id": project.project_id,
                    "label": f"{project.project_id} {str(getattr(report, 'created_date', '') or '')[:10]}".strip(),
                    "score": float(report.score or 0),
                    "date": report.created_date.isoformat() if report.created_date else None,
                })
        elif project.security_score is not None:
            score_history.append({
                "project_id": project.project_id,
                "label": project.project_id,
                "score": float(project.security_score or 0),
                "date": None,
            })
    score_history.sort(key=lambda item: item.get("date") or "")
    if len(score_history) == 1:
        only = dict(score_history[0])
        only["label"] = "Previous"
        only["score"] = only.get("score") or 0
        score_history = [only, score_history[0]]

    timeline = []
    for project in projects[:8]:
        integ = store.find_one("phase_integration", {"project_id": project.project_id})
        if integ:
            timeline.append({
                "project_id": project.project_id,
                "status": integ.get("status"),
                "updated_at": integ.get("updated_at"),
                "incident": integ.get("latest_incident_id"),
            })

    metrics = {
        "uploaded_projects": len(projects),
        "security_score": avg_score,
        "vulnerabilities_found": vulns,
        "cloud_assets": assets or store.count("cloud_assets", {"project_id": {"$in": ids}}) if ids else 0,
        "active_alerts": len([t for t in threats if (t.status or "") != "Closed"]),
        "critical_incidents": len([i for i in incidents if i.severity == "Critical"]),
        "automated_responses": automations,
        "compliance_status": avg_comp,
        "open_incidents": len([i for i in incidents if i.status in ("Open", "In Progress", "Resolved")]),
    }
    return jsonify({
        "metrics": metrics,
        "charts": {
            "attack_trend": attack_counts,
            "risk_distribution": _risk_distribution(ids, analyses),
            "severity_pie": severity_pie,
            "score_history": score_history[-20:],
            "incident_timeline": timeline,
        },
    }), 200


@advanced_bp.route("/dashboard/metrics", methods=["GET"])
@jwt_required()
def dashboard_metrics():
    data = dashboard()
    if isinstance(data, tuple):
        body, code = data
        payload = body.get_json()
        return jsonify(payload.get("metrics", payload)), code
    return data


# ----------------------------------------------------------- integration

@advanced_bp.route("/integration", methods=["GET"])
@jwt_required()
def integration_board():
    user_id = _uid()
    from advanced.integration import sync_existing_project
    rows = []
    for project in _user_projects(user_id):
        sync_existing_project(project)
        integ = store.find_one("phase_integration", {"project_id": project.project_id})
        analysis = store.find_one("phase1_analysis", {"project_id": project.project_id})
        open_inc = Incident.query.filter_by(project_id=project.project_id).all()
        has_open = any((i.status or "") not in ("Closed",) for i in open_inc)
        resolved = all((i.status or "") in ("Closed", "Resolved") for i in open_inc) if open_inc else False
        status = (integ or {}).get("status") or workflow_status(project.status, has_open, resolved)
        rows.append({
            "project_id": project.project_id,
            "project_name": project.project_name,
            "security_score": (analysis or {}).get("security_score") or project.security_score,
            "risk_level": (analysis or {}).get("risk_level"),
            "status": status,
            "phase2_enabled": bool(project.monitoring_enabled),
            "deployment_blocked": bool((analysis or {}).get("deployment_blocked")),
            "vulnerabilities": (analysis or {}).get("vulnerabilities") or [],
            "latest_incident": (integ or {}).get("latest_incident_id"),
            "steps": (integ or {}).get("steps") or [],
            "project_status": project.status,
        })
    return jsonify({"workflows": rows}), 200


@advanced_bp.route("/projects/<project_id>/timeline", methods=["GET"])
@jwt_required()
def project_timeline(project_id):
    user_id = _uid()
    if not _owned(project_id, user_id):
        return jsonify({"error": "Project not found"}), 404
    integ = store.find_one("phase_integration", {"project_id": project_id}) or {}
    analysis = store.find_one("phase1_analysis", {"project_id": project_id}) or {}
    incidents = [_incident(i) for i in Incident.query.filter_by(project_id=project_id).all()]
    return jsonify({
        "project_id": project_id,
        "workflow": integ,
        "phase1": analysis,
        "incidents": incidents,
        "alerts": store.find("threat_alerts", {"project_id": project_id}, limit=30),
        "correlated": store.find("correlated_events", {"project_id": project_id}, limit=30),
        "automations": store.find("automation_history", {"project_id": project_id}, limit=30),
    }), 200


# ----------------------------------------------------------- assistant

@advanced_bp.route("/chat", methods=["POST"])
@jwt_required()
def chat():
    user_id = _uid()
    data = request.get_json() or {}
    question = (data.get("question") or data.get("message") or "").strip()
    if not question:
        return jsonify({"error": "Question is required"}), 400
    project_id = data.get("project_id")
    from ai.chatbot.service import ChatbotService
    try:
        result = ChatbotService.answer(user_id, question, project_id, data.get("tab") or "security")
    except Exception as exc:
        return jsonify({
            "error": "The assistant could not complete that request.",
            "detail": exc.__class__.__name__,
        }), 502
    chat_row = {
        "user_id": user_id,
        "project_id": project_id,
        "question": question,
        "answer": result.get("answer"),
        "source": result.get("source"),
    }
    store.insert("advanced_chat", chat_row)
    store.insert("chat_history", dict(chat_row))
    return jsonify({"reply": result.get("answer"), **result}), 200


@advanced_bp.route("/chat/history", methods=["GET"])
@jwt_required()
def chat_history():
    user_id = _uid()
    rows = store.find("advanced_chat", {"user_id": user_id}, sort=[("created_at", 1)], limit=80)
    if not rows:
        rows = store.find("chat_history", {"user_id": user_id}, sort=[("created_at", 1)], limit=80)
    messages = []
    for row in rows:
        stamp = row.get("created_at")
        if row.get("question"):
            messages.append({"role": "user", "content": row["question"], "created_at": stamp})
        if row.get("answer"):
            messages.append({
                "role": "assistant",
                "content": row["answer"],
                "source": row.get("source"),
                "created_at": stamp,
            })
    return jsonify({"messages": messages}), 200


# ----------------------------------------------------------- SIEM

def _siem_scope(user_id: int) -> dict:
    ids = [p.project_id for p in _user_projects(user_id)]
    clauses = [{"user_id": user_id}, {"user_id": str(user_id)}]
    if ids:
        clauses.append({"project_id": {"$in": ids}})
    clauses.append({"project_id": "UNASSIGNED"})
    return {"$or": clauses}


@advanced_bp.route("/siem/logs", methods=["GET"])
@jwt_required()
def siem_logs():
    user_id = _uid()
    query = _siem_scope(user_id)
    source = request.args.get("source")
    severity = request.args.get("severity")
    search = (request.args.get("q") or "").lower()
    extra = {}
    if source:
        extra["source"] = source
    if severity:
        extra["severity"] = severity
    if extra:
        query = {"$and": [query, extra]}
    logs = store.find("normalized_logs", query, sort=[("timestamp", -1)], limit=200)
    if search:
        logs = [log for log in logs if search in str(log).lower()]
    return jsonify({
        "logs": logs,
        "raw_count": store.count("raw_logs", _siem_scope(user_id)),
        "correlated": store.find("correlated_events", _siem_scope(user_id), limit=40),
    }), 200


@advanced_bp.route("/siem/log", methods=["POST"])
@jwt_required()
def siem_ingest():
    user_id = _uid()
    data = request.get_json(silent=True) or {}
    project_id = (data.get("project_id") or "").strip()
    if project_id and not _owned(project_id, user_id):
        return jsonify({"error": "Project not found"}), 404
    if not project_id:
        owned = _user_projects(user_id)
        project_id = owned[0].project_id if owned else "UNASSIGNED"
    severity = (data.get("severity") or "medium").strip().lower()
    message = (data.get("message") or "").strip()
    if not message:
        return jsonify({"error": "Message is required"}), 400
    source = (data.get("source") or "application").strip().lower()
    source_ip = data.get("source_ip") or data.get("sourceIP") or "127.0.0.1"
    stamp = store.utcnow()
    raw = store.insert("raw_logs", {
        "user_id": user_id,
        "project_id": project_id,
        "source": source,
        "raw": dict(data),
        "timestamp": stamp,
    })
    normalized = store.insert("normalized_logs", {
        "user_id": user_id,
        "project_id": project_id,
        "source": source,
        "event_type": data.get("event_type") or "APIRequest",
        "username": data.get("username") or "analyst",
        "source_ip": source_ip,
        "severity": severity,
        "message": message,
        "is_suspicious": severity in ("high", "critical"),
        "timestamp": stamp,
    }) or {
        "user_id": user_id,
        "project_id": project_id,
        "source": source,
        "severity": severity,
        "message": message,
        "timestamp": stamp,
    }
    store.insert("security_logs", dict(normalized))
    event = store.insert("correlated_events", {
        "user_id": user_id,
        "project_id": project_id,
        "rule": "manual_ingest",
        "title": f"{source} · {severity}",
        "threat": data.get("event_type") or "Ingested Log",
        "severity": severity,
        "source_ip": source_ip,
        "narrative": f"Ingested {source} log on {project_id}: {message}",
        "message": message,
    }) or {
        "rule": "manual_ingest",
        "title": f"{source} · {severity}",
        "narrative": f"Ingested {source} log on {project_id}: {message}",
        "severity": severity,
    }
    try:
        from advanced.integration import on_phase2_event
        on_phase2_event(project_id, {
            "eventType": data.get("event_type") or "APIRequest",
            "username": data.get("username") or "analyst",
            "sourceIP": source_ip,
            "country": data.get("country") or "India",
            "resource": data.get("resource") or "Application",
            "logType": source,
            "status": data.get("status") or "Success",
            "isSuspicious": severity in ("high", "critical"),
            "message": message,
            "timestamp": stamp,
        }, {
            "severity": severity,
            "isAnomaly": severity in ("high", "critical"),
            "isThreat": severity == "critical",
            "threat": data.get("event_type") or "Ingested Log",
        })
    except Exception:
        pass
    return jsonify({
        "message": "Log ingested, normalized, and correlated.",
        "log": store.clean(normalized) if isinstance(normalized, dict) else normalized,
        "event": store.clean(event) if isinstance(event, dict) else event,
        "raw": store.clean(raw) if isinstance(raw, dict) else raw,
    }), 201


@advanced_bp.route("/siem/events", methods=["GET"])
@jwt_required()
def siem_events():
    user_id = _uid()
    return jsonify({
        "events": store.find("correlated_events", _siem_scope(user_id), sort=[("created_at", -1)], limit=80),
    }), 200


# ----------------------------------------------------------- SOAR

def _catalog_playbooks():
    from advanced.seed import PLAYBOOKS, ensure_playbooks
    ensure_playbooks()
    by_id = {item["playbook_id"]: dict(item) for item in PLAYBOOKS}
    for row in store.find("playbooks", {}):
        key = row.get("playbook_id")
        if key:
            by_id[key] = {**by_id.get(key, {}), **row}
    return list(by_id.values())


def _resolve_playbook(data: dict):
    playbook_id = (data.get("playbook_id") or "").strip()
    name = (data.get("name") or data.get("playbook_name") or "").strip().lower()
    for book in _catalog_playbooks():
        if playbook_id and book.get("playbook_id") == playbook_id:
            return book
        if name and (book.get("name") or "").strip().lower() == name:
            return book
    from advanced.seed import PLAYBOOKS
    for book in PLAYBOOKS:
        if playbook_id and book["playbook_id"] == playbook_id:
            return dict(book)
        if name and book["name"].strip().lower() == name:
            return dict(book)
    if playbook_id:
        return {
            "playbook_id": playbook_id,
            "name": data.get("name") or playbook_id,
            "trigger": data.get("trigger") or "Manual",
            "condition": data.get("condition") or "Operator requested",
            "action": data.get("action") or "Simulated response",
            "status": "Ready",
        }
    return None


@advanced_bp.route("/playbooks", methods=["GET"])
@jwt_required()
def list_playbooks():
    return jsonify({"playbooks": _catalog_playbooks()}), 200


@advanced_bp.route("/playbook/execute", methods=["POST"])
@jwt_required()
def execute_playbook():
    user_id = _uid()
    data = request.get_json() or {}
    project_id = data.get("project_id")
    book = _resolve_playbook(data)
    if not book:
        return jsonify({"error": "Playbook not found"}), 404
    playbook_id = book.get("playbook_id")
    if project_id and not _owned(project_id, user_id):
        return jsonify({"error": "Project not found"}), 404
    import time
    started = time.perf_counter()
    elapsed = max(1, int((time.perf_counter() - started) * 1000) + 12)
    record = store.insert("automation_history", {
        "history_id": store.next_id("automation_history", "AUTO"),
        "project_id": project_id,
        "incident_id": data.get("incident_id"),
        "playbook_id": playbook_id,
        "playbook_name": book.get("name"),
        "trigger": book.get("trigger"),
        "condition": book.get("condition"),
        "action": book.get("action"),
        "status": "Executed",
        "result": "Simulated Successfully",
        "execution_time": store.utcnow(),
        "execution_time_ms": elapsed,
        "actor": user_id,
    })
    return jsonify({
        "message": "Playbook executed (simulated)",
        "playbook_name": book.get("name"),
        "execution_time_ms": elapsed,
        "execution": record,
    }), 200


@advanced_bp.route("/playbooks/history", methods=["GET"])
@jwt_required()
def playbook_history():
    return automation_history()


@advanced_bp.route("/automation", methods=["GET"])
@jwt_required()
def automation_history():
    user_id = _uid()
    ids = [p.project_id for p in _user_projects(user_id)]
    query = {"project_id": {"$in": ids}} if ids else {}
    return jsonify({"history": store.find("automation_history", query, sort=[("execution_time", -1)])}), 200


# ----------------------------------------------------------- threat intel

@advanced_bp.route("/intel", methods=["GET"])
@jwt_required()
def intel():
    query = {}
    kind = request.args.get("type")
    search = (request.args.get("q") or "").lower()
    if kind:
        query["type"] = kind
    rows = store.find("ioc_database", query, limit=200)
    if search:
        rows = [row for row in rows if search in str(row).lower()]
    return jsonify({"iocs": rows}), 200


@advanced_bp.route("/intel", methods=["POST"])
@jwt_required()
def intel_add():
    data = request.get_json() or {}
    if not data.get("value"):
        return jsonify({"error": "IOC value is required"}), 400
    record = store.insert("ioc_database", {
        "ioc_id": data.get("ioc_id") or store.next_id("ioc_database", "IOC"),
        "type": data.get("type") or "ip",
        "value": data.get("value"),
        "threat_type": data.get("threat_type") or "Indicator",
        "severity": data.get("severity") or "Medium",
        "mitre": data.get("mitre") or "",
        "capec": data.get("capec") or "",
        "description": data.get("description") or "",
        "recommended_action": data.get("recommended_action") or "Investigate and block if confirmed.",
    })
    return jsonify({"ioc": record}), 201


# ----------------------------------------------------------- compliance

@advanced_bp.route("/compliance", methods=["GET"])
@jwt_required()
def compliance():
    user_id = _uid()
    project_id = request.args.get("project_id")
    projects = _user_projects(user_id)
    if project_id:
        if not _owned(project_id, user_id):
            return jsonify({"error": "Project not found"}), 404
        projects = [p for p in projects if p.project_id == project_id]
    reports = [evaluate_compliance(p.project_id, user_id) for p in projects]
    return jsonify({"reports": reports}), 200


@advanced_bp.route("/compliance/report", methods=["GET"])
@jwt_required()
def compliance_report():
    user_id = _uid()
    project_id = request.args.get("project_id")
    if not project_id:
        owned = _user_projects(user_id)
        if not owned:
            return jsonify({"error": "No project available"}), 404
        project_id = owned[0].project_id
    if not _owned(project_id, user_id):
        return jsonify({"error": "Project not found"}), 404
    summary = evaluate_compliance(project_id, user_id)
    path = compliance_pdf(project_id, summary, pdf_archive_dir())
    return send_file(path, as_attachment=True, download_name=f"compliance_{project_id}.pdf")


# ----------------------------------------------------------- forensics

_FORENSIC_MEMORY = {}


def _forensic_disk_path():
    folder = pdf_archive_dir()
    return os.path.join(folder, "evidence_index.json")


def _forensic_disk_load():
    path = _forensic_disk_path()
    if not os.path.isfile(path):
        return []
    try:
        with open(path, encoding="utf-8") as handle:
            data = json.load(handle)
        return data if isinstance(data, list) else []
    except (OSError, ValueError):
        return []


def _forensic_disk_save(record: dict) -> None:
    rows = _forensic_disk_load()
    fid = record.get("forensic_id")
    rows = [row for row in rows if row.get("forensic_id") != fid]
    rows.insert(0, dict(record))
    with open(_forensic_disk_path(), "w", encoding="utf-8") as handle:
        json.dump(rows, handle, default=str)


def _forensic_remember(user_id, record: dict) -> dict:
    bucket = _FORENSIC_MEMORY.setdefault(int(user_id), [])
    fid = record.get("forensic_id")
    bucket[:] = [row for row in bucket if row.get("forensic_id") != fid]
    bucket.insert(0, dict(record))
    try:
        _forensic_disk_save(record)
    except OSError:
        pass
    return record


def _forensic_owned(row: dict, user_id: int) -> bool:
    owner = row.get("user_id")
    return owner in (user_id, str(user_id), None)


def _forensic_get(user_id, forensic_id: str):
    forensic_id = unquote(str(forensic_id or "")).strip()
    if not forensic_id:
        return None
    for row in _FORENSIC_MEMORY.get(int(user_id), []):
        if row.get("forensic_id") == forensic_id:
            return dict(row)
    record = store.find_one("forensic_reports", {"forensic_id": forensic_id})
    if record:
        return record
    for row in _forensic_disk_load():
        if row.get("forensic_id") == forensic_id and _forensic_owned(row, user_id):
            return dict(row)
    for rows in _FORENSIC_MEMORY.values():
        for row in rows:
            if row.get("forensic_id") == forensic_id:
                return dict(row)
    return None


def _forensic_list(user_id: int):
    ids = [p.project_id for p in _user_projects(user_id)]
    query = {"$or": [{"user_id": user_id}, {"user_id": str(user_id)}]}
    if ids:
        query["$or"].append({"project_id": {"$in": ids}})
    rows = store.find("forensic_reports", query, sort=[("created_at", -1)])
    if not rows:
        rows = [
            row for row in store.find("forensic_reports", {}, sort=[("created_at", -1)], limit=100)
            if _forensic_owned(row, user_id)
        ]
    merged = {}
    sources = (
        list(_FORENSIC_MEMORY.get(int(user_id), []))
        + [row for row in _forensic_disk_load() if _forensic_owned(row, user_id)]
        + list(rows)
    )
    for row in sources:
        key = row.get("forensic_id") or row.get("_id")
        if key and key not in merged:
            merged[key] = row
    return list(merged.values())


def _forensic_folder(record: dict) -> str:
    return pdf_archive_dir()


def _custody_text(record: dict) -> str:
    lines = [
        f"Forensic ID: {record.get('forensic_id')}",
        f"Filename: {record.get('filename')}",
        f"SHA256: {record.get('sha256')}",
        f"MD5: {record.get('md5')}",
        f"Size: {record.get('size')} bytes",
        f"Status: {record.get('status')}",
        "",
        "Chain of custody:",
    ]
    for item in record.get("custody") or []:
        lines.append(
            f"- {item.get('time')} | {item.get('actor')} | {item.get('action')} | {item.get('status')}"
        )
    return "\n".join(lines)


def _write_custody_file(record: dict) -> str:
    path = os.path.join(_forensic_folder(record), f"{record.get('forensic_id')}_custody.txt")
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(_custody_text(record))
    from utils.helpers import archive_forensic_report
    archive_forensic_report(path, f"{record.get('forensic_id')}_custody.txt")
    return path


def _write_forensic_pdf(record: dict) -> str:
    path = forensic_pdf(record, _forensic_folder(record))
    from utils.helpers import archive_forensic_report
    archive_forensic_report(path, f"{record.get('forensic_id')}_forensic_report.pdf")
    return path


def _append_custody(user_id: int, forensic_id: str, data: dict):
    forensic_id = unquote(str(forensic_id or "")).strip()
    record = _forensic_get(user_id, forensic_id)
    if not record:
        return None, "Evidence not found"
    action = (data.get("action") or "").strip() or "Custody transfer"
    status = (data.get("status") or "").strip() or "In Review"
    actor = (data.get("actor") or "").strip() or str(user_id)
    custody = list(record.get("custody") or [])
    custody.append({
        "time": store.utcnow(),
        "actor": actor,
        "action": action,
        "status": status,
    })
    updated = store.update("forensic_reports", {"forensic_id": forensic_id}, {
        "custody": custody,
        "status": status or record.get("status"),
    })
    record = updated or {**record, "custody": custody, "status": status or record.get("status")}
    _forensic_remember(user_id, record)
    store.insert("chain_of_custody", {
        "custody_id": store.next_id("chain_of_custody", "CUS"),
        "forensic_id": forensic_id,
        "user_id": user_id,
        "events": custody,
        "created_at": store.utcnow(),
    })
    _write_custody_file(record)
    try:
        _write_forensic_pdf(record)
    except Exception:
        pass
    return record, None


def _send_forensic_pdf(user_id: int, forensic_id: str):
    record = _forensic_get(user_id, forensic_id)
    if not record:
        return jsonify({"error": "Evidence not found"}), 404
    try:
        payload = forensic_pdf_bytes(record)
        try:
            _write_forensic_pdf(record)
        except OSError:
            pass
    except Exception as exc:
        return jsonify({"error": f"Forensic PDF could not be generated: {exc}"}), 500
    return send_file(
        BytesIO(payload),
        as_attachment=True,
        download_name=f"{record.get('forensic_id')}.pdf",
        mimetype="application/pdf",
    )


def _send_custody_file(user_id: int, forensic_id: str):
    record = _forensic_get(user_id, forensic_id)
    if not record:
        return jsonify({"error": "Evidence not found"}), 404
    path = _write_custody_file(record)
    return send_file(
        path,
        as_attachment=True,
        download_name=f"{record.get('forensic_id')}_custody.txt",
        mimetype="text/plain",
    )


@advanced_bp.route("/forensics", methods=["GET"])
@jwt_required()
def forensics_list():
    return jsonify({"reports": _forensic_list(_uid())}), 200


@advanced_bp.route("/forensics/pdf", methods=["GET", "POST"])
@jwt_required()
def forensics_pdf():
    data = request.get_json(silent=True) or {}
    forensic_id = request.args.get("forensic_id") or data.get("forensic_id")
    if not forensic_id:
        return jsonify({"error": "forensic_id is required"}), 400
    return _send_forensic_pdf(_uid(), forensic_id)


@advanced_bp.route("/forensics/hash", methods=["POST"])
@jwt_required()
def forensics_hash():
    user_id = _uid()
    payload = b""
    filename = "pasted.txt"
    project_id = None
    incident_id = None
    if request.files.get("file"):
        upload = request.files["file"]
        filename = secure_filename(upload.filename or "evidence.bin")
        payload = upload.read() or b""
        project_id = request.form.get("project_id")
        incident_id = request.form.get("incident_id")
    if not payload:
        json_body = request.get_json(silent=True) or {}
        payload = (
            json_body.get("content")
            or json_body.get("text")
            or request.form.get("content")
            or request.form.get("text")
            or ""
        ).encode("utf-8")
        filename = json_body.get("filename") or request.form.get("filename") or filename
        project_id = project_id or request.form.get("project_id") or json_body.get("project_id")
        incident_id = incident_id or request.form.get("incident_id") or json_body.get("incident_id")
    if not payload:
        return jsonify({"error": "Upload a file or paste content to hash."}), 400
    sha = hashlib.sha256(payload).hexdigest()
    md5 = hashlib.md5(payload).hexdigest()
    if project_id and not _owned(project_id, user_id):
        return jsonify({"error": "Project not found"}), 404
    stamp = datetime.now(timezone.utc).strftime("%H%M%S%f")
    forensic_id = f"{store.next_id('forensic_reports', 'FOR')}-{stamp}"
    opened = store.utcnow()
    custody = [{
        "time": opened,
        "actor": str(user_id),
        "action": "Evidence received and hashed",
        "status": "Sealed",
    }]
    record = {
        "forensic_id": forensic_id,
        "user_id": user_id,
        "project_id": project_id or None,
        "incident_id": incident_id or None,
        "filename": filename,
        "sha256": sha,
        "md5": md5,
        "size": len(payload),
        "status": "Collected",
        "notes": "Hash generated and chain of custody opened.",
        "created_at": opened,
        "custody": custody,
    }
    saved = store.insert("forensic_reports", dict(record))
    record = saved or record
    store.insert("chain_of_custody", {
        "custody_id": store.next_id("chain_of_custody", "CUS"),
        "forensic_id": record.get("forensic_id"),
        "user_id": user_id,
        "filename": filename,
        "sha256": sha,
        "md5": md5,
        "events": custody,
        "created_at": opened,
    })
    _forensic_remember(user_id, record)
    _write_custody_file(record)
    try:
        _write_forensic_pdf(record)
    except Exception:
        pass
    return jsonify({"record": record, "reports": _forensic_list(user_id)}), 201


@advanced_bp.route("/forensics/custody", methods=["POST"])
@jwt_required()
def forensics_custody_create():
    data = request.get_json(silent=True) or {}
    forensic_id = data.get("forensic_id")
    if not forensic_id:
        return jsonify({"error": "forensic_id is required"}), 400
    record, error = _append_custody(_uid(), forensic_id, data)
    if error:
        return jsonify({"error": error}), 404
    return jsonify({"record": record}), 200


@advanced_bp.route("/forensics/report", methods=["GET"])
@jwt_required()
def forensics_report_qs():
    forensic_id = request.args.get("forensic_id")
    if not forensic_id:
        return jsonify({"error": "forensic_id is required"}), 400
    return _send_forensic_pdf(_uid(), forensic_id)


@advanced_bp.route("/forensics/custody-file", methods=["GET"])
@jwt_required()
def forensics_custody_file_qs():
    forensic_id = request.args.get("forensic_id")
    if not forensic_id:
        return jsonify({"error": "forensic_id is required"}), 400
    return _send_custody_file(_uid(), forensic_id)


@advanced_bp.route("/forensics/<forensic_id>/custody", methods=["POST"])
@jwt_required()
def forensics_custody(forensic_id):
    data = request.get_json(silent=True) or {}
    record, error = _append_custody(_uid(), forensic_id, data)
    if error:
        return jsonify({"error": error}), 404
    return jsonify({"record": record}), 200


@advanced_bp.route("/forensics/<forensic_id>/report", methods=["GET"])
@jwt_required()
def forensics_report(forensic_id):
    return _send_forensic_pdf(_uid(), forensic_id)


@advanced_bp.route("/forensics/<forensic_id>/custody.txt", methods=["GET"])
@jwt_required()
def forensics_custody_file(forensic_id):
    return _send_custody_file(_uid(), forensic_id)


# ----------------------------------------------------------- vulnerabilities

@advanced_bp.route("/vulnerability/list", methods=["GET"])
@jwt_required()
def vuln_list_alias():
    return vuln_list()


@advanced_bp.route("/vulnerabilities", methods=["GET"])
@jwt_required()
def vuln_list():
    user_id = _uid()
    query = {"user_id": user_id}
    status = request.args.get("status")
    severity = request.args.get("severity")
    if status:
        query["status"] = status
    if severity:
        query["severity"] = severity
    return jsonify({"vulnerabilities": store.find("vulnerabilities", query)}), 200


@advanced_bp.route("/vulnerabilities", methods=["POST"])
@jwt_required()
def vuln_create():
    user_id = _uid()
    data = request.get_json() or {}
    project_id = data.get("project_id")
    if project_id and not _owned(project_id, user_id):
        return jsonify({"error": "Project not found"}), 404
    record = store.insert("vulnerabilities", {
        "vuln_id": store.next_id("vulnerabilities", "VUL"),
        "project_id": project_id,
        "user_id": user_id,
        "title": data.get("title") or "Untitled",
        "severity": data.get("severity") or "Medium",
        "cvss": float(data.get("cvss") or 5.0),
        "asset": data.get("asset") or "",
        "owner": data.get("owner") or "Unassigned",
        "status": data.get("status") or "Open",
        "risk_level": data.get("risk_level") or data.get("severity") or "Medium",
        "due_date": data.get("due_date"),
        "remediation": data.get("remediation") or "",
    })
    return jsonify({"vulnerability": record}), 201


@advanced_bp.route("/vulnerabilities/<vuln_id>", methods=["PUT"])
@jwt_required()
def vuln_update(vuln_id):
    user_id = _uid()
    current = store.find_one("vulnerabilities", {"vuln_id": vuln_id, "user_id": user_id})
    if not current:
        return jsonify({"error": "Vulnerability not found"}), 404
    allowed = {k: v for k, v in (request.get_json() or {}).items()
               if k in ("title", "severity", "cvss", "asset", "owner", "status", "risk_level", "due_date", "remediation")}
    return jsonify({"vulnerability": store.update("vulnerabilities", {"vuln_id": vuln_id}, allowed)}), 200


@advanced_bp.route("/vulnerabilities/<vuln_id>", methods=["DELETE"])
@jwt_required()
def vuln_delete(vuln_id):
    deleted = store.delete("vulnerabilities", {"vuln_id": vuln_id, "user_id": _uid()})
    if not deleted:
        return jsonify({"error": "Vulnerability not found"}), 404
    return jsonify({"message": "Deleted"}), 200


# ----------------------------------------------------------- assets

@advanced_bp.route("/assets", methods=["GET"])
@jwt_required()
def assets_list():
    user_id = _uid()
    search = (request.args.get("q") or "").lower()
    rows = store.find("asset_inventory", {"user_id": user_id})
    if search:
        rows = [row for row in rows if search in str(row).lower()]
    return jsonify({"assets": rows}), 200


@advanced_bp.route("/assets", methods=["POST"])
@jwt_required()
def assets_create():
    user_id = _uid()
    data = request.get_json() or {}
    if not data.get("name"):
        return jsonify({"error": "Asset name is required"}), 400
    project_id = data.get("project_id")
    if project_id and not _owned(project_id, user_id):
        return jsonify({"error": "Project not found"}), 404
    record = store.insert("asset_inventory", {
        "asset_id": store.next_id("asset_inventory", "AST"),
        "project_id": project_id,
        "user_id": user_id,
        "name": data.get("name"),
        "type": data.get("type") or "Compute",
        "owner": data.get("owner") or "Platform",
        "region": data.get("region") or "us-east-1",
        "status": data.get("status") or "Active",
        "risk_score": float(data.get("risk_score") or 40),
        "last_scan": store.utcnow(),
    })
    return jsonify({"asset": record}), 201


@advanced_bp.route("/assets/<asset_id>", methods=["PUT"])
@jwt_required()
def assets_update(asset_id):
    user_id = _uid()
    if not store.find_one("asset_inventory", {"asset_id": asset_id, "user_id": user_id}):
        return jsonify({"error": "Asset not found"}), 404
    allowed = {k: v for k, v in (request.get_json() or {}).items()
               if k in ("name", "type", "owner", "region", "status", "risk_score", "project_id")}
    allowed["last_scan"] = store.utcnow()
    return jsonify({"asset": store.update("asset_inventory", {"asset_id": asset_id}, allowed)}), 200


@advanced_bp.route("/assets/<asset_id>", methods=["DELETE"])
@jwt_required()
def assets_delete(asset_id):
    deleted = store.delete("asset_inventory", {"asset_id": asset_id, "user_id": _uid()})
    if not deleted:
        return jsonify({"error": "Asset not found"}), 404
    return jsonify({"message": "Deleted"}), 200


# ----------------------------------------------------------- AI explain

@advanced_bp.route("/ai/shap", methods=["POST"])
@jwt_required()
def ai_shap():
    return jsonify(shap_view(request.get_json() or {})), 200


@advanced_bp.route("/ai/lime", methods=["POST"])
@jwt_required()
def ai_lime():
    return jsonify(lime_view(request.get_json() or {})), 200


@advanced_bp.route("/ai/risk", methods=["GET"])
@jwt_required()
def ai_risk():
    user_id = _uid()
    project_id = request.args.get("project_id")
    projects = _user_projects(user_id)
    if project_id:
        projects = [p for p in projects if p.project_id == project_id]
    analyses = [store.find_one("phase1_analysis", {"project_id": p.project_id}) or {} for p in projects]
    score = sum(float(a.get("security_score") or 0) for a in analyses) / len(analyses) if analyses else 0
    critical = sum(int(a.get("critical") or 0) for a in analyses)
    high = sum(int(a.get("high") or 0) for a in analyses)
    ids = [p.project_id for p in projects]
    threats = len(ThreatSummary.query.filter(ThreatSummary.project_id.in_(ids)).all()) if ids else 0
    incidents = len(Incident.query.filter(Incident.project_id.in_(ids)).all()) if ids else 0
    return jsonify(risk_prediction(score, critical, high, threats, incidents)), 200


@advanced_bp.route("/ai/severity", methods=["POST"])
@jwt_required()
def ai_severity():
    return jsonify(severity_prediction(request.get_json() or {})), 200


@advanced_bp.route("/ai/summarize/<incident_id>", methods=["GET"])
@jwt_required()
def ai_summarize(incident_id):
    user_id = _uid()
    incident = Incident.query.get(incident_id)
    if not incident or not _owned(incident.project_id, user_id):
        return jsonify({"error": "Incident not found"}), 404
    analysis = store.find_one("phase1_analysis", {"project_id": incident.project_id}) or {}
    return jsonify(summarize_incident(_incident(incident), analysis)), 200


@advanced_bp.route("/incidents", methods=["GET"])
@jwt_required()
def advanced_incidents():
    user_id = _uid()
    ids = [p.project_id for p in _user_projects(user_id)]
    if not ids:
        return jsonify({"incidents": []}), 200
    rows = []
    for incident in Incident.query.filter(Incident.project_id.in_(ids)).all():
        analysis = store.find_one("phase1_analysis", {"project_id": incident.project_id}) or {}
        rows.append({
            **_incident(incident),
            "related_project": incident.project_id,
            "related_vulnerabilities": analysis.get("vulnerabilities") or [],
            "ai_recommendation": summarize_incident(_incident(incident), analysis),
        })
    return jsonify({"incidents": rows}), 200


# ----------------------------------------------------------- reports

@advanced_bp.route("/reports/executive", methods=["GET"])
@jwt_required()
def report_executive():
    body, code = dashboard()
    metrics = body.get_json().get("metrics", {})
    path = executive_pdf(metrics, pdf_archive_dir())
    return send_file(path, as_attachment=True, download_name="executive_dashboard.pdf")


@advanced_bp.route("/reports/security/<project_id>", methods=["GET"])
@jwt_required()
def report_security(project_id):
    if not _owned(project_id, _uid()):
        return jsonify({"error": "Project not found"}), 404
    analysis = store.find_one("phase1_analysis", {"project_id": project_id}) or {}
    path = security_summary_pdf(project_id, analysis, pdf_archive_dir())
    return send_file(path, as_attachment=True, download_name=f"advanced_security_{project_id}.pdf")


def _incident(incident) -> dict:
    return {
        "incident_id": incident.incident_id,
        "project_id": incident.project_id,
        "threat": incident.threat,
        "severity": incident.severity,
        "confidence": incident.confidence,
        "affected_user": incident.affected_user,
        "source_ip": incident.source_ip,
        "status": incident.status,
        "created_time": incident.created_time.isoformat() if incident.created_time else None,
        "resolved_time": incident.resolved_time.isoformat() if incident.resolved_time else None,
    }
