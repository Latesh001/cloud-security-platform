import os
import shutil
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from flask import Blueprint, jsonify, send_file, current_app
from flask_jwt_extended import jwt_required, get_jwt_identity

from database.extensions import db, mongo_insert
from database.models import Project, SecurityReport, ProjectMonitoring
from utils.project_scope import current_reports, latest_scan_log, latest_security_report
from phase1.upload.validator import ZipValidator, ZipExtractor
from phase1.extractor.tech_detector import TechnologyDetector
from phase1.detectors.base import deduplicate
from phase1.detectors.code.static_analyzer import StaticAnalyzer
from phase1.detectors.secrets.scanner import SecretScanner
from phase1.detectors.configs.analyzer import ConfigAnalyzer
from phase1.detectors.infrastructure.analyzer import InfrastructureAnalyzer
from phase1.detectors.dependencies.analyzer import DependencyAnalyzer
from phase1.scoring.engine import ScoringEngine, DecisionEngine
from phase1.recommendations.engine import RecommendationEngine
from phase1.reports.pdf_generator import PDFReportGenerator
from notifications.service import NotificationService
from authentication.email_service import EmailService
from database.models import User
from utils.logger import audit_logger
from utils.helpers import pdf_output_path, locate_pdf

phase1_bp = Blueprint("phase1", __name__, url_prefix="/api/phase1")


def trigger_scan(project_id: str) -> dict:
    start = time.time()
    project = Project.query.get(project_id)
    if not project or not project.upload_path:
        return {"error": "Project or upload not found"}

    project.status = "Scanning"
    db.session.commit()

    valid, msg = ZipValidator.validate(
        project.upload_path,
        max_size_mb=current_app.config.get("MAX_UPLOAD_SIZE_MB", 1000),
    )
    if not valid:
        project.status = "Upload Failed"
        db.session.commit()
        return {"error": msg}

    extract_dir = os.path.join(current_app.config["UPLOAD_FOLDER"], project_id, "extracted")
    # Clear any previous extraction so a rescan never reports stale files.
    shutil.rmtree(extract_dir, ignore_errors=True)
    extraction = ZipExtractor.extract(project.upload_path, extract_dir)
    tech = TechnologyDetector.detect(extract_dir, extraction["files"])

    project.programming_language = tech["primary_language"]
    project.framework = tech["frameworks"][0] if tech["frameworks"] else "General"

    findings = []
    with ThreadPoolExecutor(max_workers=5) as pool:
        jobs = [
            pool.submit(SecretScanner.analyze_directory, extract_dir, project.category),
            pool.submit(StaticAnalyzer.analyze_directory, extract_dir, project.category),
            pool.submit(ConfigAnalyzer.analyze_directory, extract_dir, project.category),
            pool.submit(InfrastructureAnalyzer.analyze_directory, extract_dir, project.category),
            pool.submit(DependencyAnalyzer.analyze, extract_dir, extraction["files"]),
        ]
        for job in jobs:
            findings.extend(job.result())
    findings = deduplicate(findings)

    scoring = ScoringEngine.calculate(findings, project.category)
    approval = DecisionEngine.decide(
        scoring["score"],
        scoring["counts"]["Critical"],
        current_app.config.get("APPROVAL_SCORE_THRESHOLD", 65),
    )

    recommendation = RecommendationEngine.generate(findings, scoring["score"], project.category)

    detector_summary = {}
    for finding in findings:
        detector_summary[finding["detector"]] = detector_summary.get(finding["detector"], 0) + 1

    report_data = {
        "project_id": project_id,
        "project_name": project.project_name,
        "category": project.category,
        "score": scoring["score"],
        "risk_level": scoring["risk_level"],
        "approval_status": approval,
        "counts": scoring["counts"],
        "recommendation": recommendation,
        "findings": findings,
        "top_risks": RecommendationEngine.top_risks(findings),
        "detector_summary": detector_summary,
        "technologies": tech,
        "scan_duration": round(time.time() - start, 2),
        "files_scanned": extraction["file_count"],
        "folders": extraction["folders"],
    }

    report_path = pdf_output_path(
        f"{project_id}_security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    )
    PDFReportGenerator.generate(report_data, report_path)

    report = SecurityReport(
        project_id=project_id,
        critical=scoring["counts"]["Critical"],
        high=scoring["counts"]["High"],
        medium=scoring["counts"]["Medium"],
        low=scoring["counts"]["Low"],
        score=scoring["score"],
        risk_level=scoring["risk_level"],
        recommendation=recommendation,
        approval_status=approval,
        report_path=report_path,
    )
    db.session.add(report)

    project.security_score = scoring["score"]
    project.status = approval if approval == "Approved" else "Pending Remediation"
    monitoring_started = False
    if approval == "Approved":
        project.monitoring_enabled = True
        project.status = "Monitoring Enabled"
        monitoring = ProjectMonitoring.query.filter_by(project_id=project_id).first()
        if monitoring:
            monitoring.monitoring_enabled = True
        else:
            monitoring = ProjectMonitoring(
                project_id=project_id,
                monitoring_enabled=True,
                current_state="Idle",
            )
            db.session.add(monitoring)

    db.session.commit()

    # Phase 1 → Phase 2: start continuous monitoring automatically on approval.
    if approval == "Approved":
        try:
            from phase2.scheduler.monitor_scheduler import MonitoringScheduler
            monitoring_started = bool(
                MonitoringScheduler.start_monitoring(project_id, current_app._get_current_object())
            )
        except Exception as exc:
            audit_logger.error(f"Auto-start monitoring failed for {project_id}: {exc}")
            monitoring_started = False

    mongo_insert("scan_logs", {
        "projectId": project_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "findings": findings[:800],
        "technologies": tech,
        "scoring": scoring,
        "detectorSummary": detector_summary,
        "filesScanned": extraction["file_count"],
        "scanDuration": report_data["scan_duration"],
        "monitoringStarted": monitoring_started,
    })

    user = User.query.get(project.user_id)
    NotificationService.create(
        project.user_id,
        "Scan Completed",
        f"Security scan completed for {project_id}. Score: {scoring['score']}/100",
    )
    if approval == "Approved":
        NotificationService.create(
            project.user_id,
            "Project Approved",
            (
                f"Project {project_id} approved. Phase 2 monitoring "
                f"{'started automatically' if monitoring_started else 'is enabled — start it from Monitoring'}."
            ),
            send_email=True,
        )
    else:
        NotificationService.create(
            project.user_id,
            "Remediation Required",
            f"Project {project_id} needs security improvements.",
        )

    audit_logger.info(f"Phase1 scan complete: {project_id} score={scoring['score']}")
    report_data["monitoring_started"] = monitoring_started
    report_data["approval_status"] = approval
    try:
        from advanced.integration import on_phase1_complete
        on_phase1_complete(project_id, project.user_id, report_data, findings, scoring, approval)
    except Exception as exc:
        audit_logger.error("Advanced Features Phase 1 hook skipped: %s", exc)
    return report_data


@phase1_bp.route("/scan/<project_id>", methods=["POST"])
@jwt_required()
def scan_project(project_id):
    user_id = int(get_jwt_identity())
    project = Project.query.filter_by(project_id=project_id, user_id=user_id).first()
    if not project:
        return jsonify({"error": "Project not found"}), 404
    result = trigger_scan(project_id)
    if "error" in result:
        return jsonify(result), 400
    return jsonify({"message": "Scan completed", "result": result}), 200


@phase1_bp.route("/result/<project_id>", methods=["GET"])
@jwt_required()
def get_result(project_id):
    user_id = int(get_jwt_identity())
    project = Project.query.filter_by(project_id=project_id, user_id=user_id).first()
    if not project:
        return jsonify({"error": "Project not found"}), 404

    reports = current_reports(project)
    report = reports[0] if reports else None
    scan_log = latest_scan_log(project)
    display_score = float(report.score) if report and report.score is not None else float(project.security_score or 0)
    threshold = current_app.config.get("APPROVAL_SCORE_THRESHOLD", 65)
    live_approval = None
    if report:
        live_approval = DecisionEngine.decide(
            display_score, int(report.critical or 0), threshold,
        )

    return jsonify({
        "project": {
            "project_id": project.project_id,
            "project_name": project.project_name,
            "category": project.category,
            "programming_language": project.programming_language,
            "framework": project.framework,
            "security_score": display_score,
            "status": project.status,
            "monitoring_enabled": project.monitoring_enabled,
        },
        "report": {
            "report_id": report.report_id if report else None,
            "score": display_score if report else 0,
            "critical": report.critical if report else 0,
            "high": report.high if report else 0,
            "medium": report.medium if report else 0,
            "low": report.low if report else 0,
            "risk_level": report.risk_level if report else None,
            "approval_status": live_approval if report else None,
            "recommendation": report.recommendation if report else None,
            "created_date": report.created_date.isoformat() if report and report.created_date else None,
        },
        "findings": scan_log.get("findings", []) if scan_log else [],
        "technologies": scan_log.get("technologies", {}) if scan_log else {},
        "detector_summary": scan_log.get("detectorSummary", {}) if scan_log else {},
        "files_scanned": scan_log.get("filesScanned", 0) if scan_log else 0,
        "scan_duration": scan_log.get("scanDuration", 0) if scan_log else 0,
        "history": [{
            "report_id": r.report_id,
            "score": r.score,
            "critical": r.critical,
            "high": r.high,
            "medium": r.medium,
            "low": r.low,
            "approval_status": r.approval_status,
            "created_date": r.created_date.isoformat() if r.created_date else None,
        } for r in reports],
    }), 200


@phase1_bp.route("/report/<project_id>", methods=["GET"])
@jwt_required()
def download_report(project_id):
    user_id = int(get_jwt_identity())
    project = Project.query.filter_by(project_id=project_id, user_id=user_id).first()
    if not project:
        return jsonify({"error": "Project not found"}), 404

    report = latest_security_report(project)
    path = locate_pdf(report.report_path if report else None)
    if not path:
        return jsonify({"error": "Report not found"}), 404

    return send_file(path, as_attachment=True, download_name=f"security_report_{project_id}.pdf")


@phase1_bp.route("/rescan/<project_id>", methods=["POST"])
@jwt_required()
def rescan(project_id):
    user_id = int(get_jwt_identity())
    project = Project.query.filter_by(project_id=project_id, user_id=user_id).first()
    if not project:
        return jsonify({"error": "Project not found"}), 404
    if not project.upload_path:
        return jsonify({"error": "No uploaded file. Upload again first."}), 400

    result = trigger_scan(project_id)
    return jsonify({"message": "Rescan completed", "result": result}), 200
