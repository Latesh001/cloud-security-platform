import threading
from datetime import datetime, timezone

from database.extensions import db, mongo_insert
from database.models import Project, ProjectMonitoring, ThreatSummary
from phase2.collectors.event_generator import CloudEventGenerator
from phase2.preprocess.processor import LogPreprocessor
from phase2.ai.threat_detector import ThreatDetector
from phase2.correlation.engine import EventCorrelationEngine
from notifications.service import NotificationService
from utils.logger import audit_logger

_active_monitors = {}
_generators = {}
_lock = threading.Lock()


class MonitoringScheduler:
    @staticmethod
    def _thread_alive(project_id: str) -> bool:
        entry = _active_monitors.get(project_id)
        thread = (entry or {}).get("thread")
        return bool(thread and thread.is_alive())

    @staticmethod
    def start_monitoring(project_id: str, app):
        with _lock:
            if MonitoringScheduler._thread_alive(project_id):
                return True
            _active_monitors.pop(project_id, None)
            _generators.pop(project_id, None)

            project = Project.query.get(project_id)
            if not project:
                return False
            if not project.monitoring_enabled:
                project.monitoring_enabled = True
                db.session.commit()

            from phase1.scoring.engine import DecisionEngine
            from utils.project_scope import latest_security_report, project_score
            report = latest_security_report(project)
            threshold = app.config.get("APPROVAL_SCORE_THRESHOLD", 65)
            critical = int(getattr(report, "critical", 0) or 0) if report else 0
            if DecisionEngine.decide(project_score(project), critical, threshold) != "Approved":
                return False

            _generators[project_id] = CloudEventGenerator(project_id)
            stop_event = threading.Event()

            interval = app.config.get("MONITORING_INTERVAL_SECONDS", 5)

            def monitor_loop():
                with app.app_context():
                    ThreatDetector.load_model(
                        app.config["MODELS_FOLDER"],
                        app.config.get("THREAT_CONFIDENCE_THRESHOLD", 85),
                    )
                    monitoring = ProjectMonitoring.query.filter_by(project_id=project_id).first()
                    if monitoring:
                        monitoring.current_state = "Running"
                        db.session.commit()

                    recent_events = []
                    escalated_chains = set()
                    while not stop_event.is_set():
                        try:
                            MonitoringScheduler._process_event(
                                project_id, app, recent_events, escalated_chains
                            )
                        except Exception as e:
                            db.session.rollback()
                            audit_logger.error(f"Monitor error {project_id}: {e}")
                        stop_event.wait(interval)

                    if monitoring:
                        monitoring.current_state = "Stopped"
                        db.session.commit()

            thread = threading.Thread(target=monitor_loop, daemon=True)
            _active_monitors[project_id] = {"thread": thread, "stop": stop_event}
            thread.start()
            audit_logger.info(f"Monitoring started: {project_id}")
            return True

    @staticmethod
    def stop_monitoring(project_id: str):
        with _lock:
            if project_id in _active_monitors:
                _active_monitors[project_id]["stop"].set()
                del _active_monitors[project_id]
                _generators.pop(project_id, None)
                monitoring = ProjectMonitoring.query.filter_by(project_id=project_id).first()
                if monitoring:
                    monitoring.current_state = "Stopped"
                    db.session.commit()
                return True
        return False

    @staticmethod
    def _process_event(project_id: str, app, recent_events: list, escalated_chains=None):
        if escalated_chains is None:
            escalated_chains = set()
        generator = _generators.get(project_id)
        if not generator:
            return

        raw_log = generator.generate()
        processed = LogPreprocessor.process(raw_log)
        if not processed:
            return

        mongo_insert("cloud_logs", {**processed, "raw": raw_log})

        monitoring = ProjectMonitoring.query.filter_by(project_id=project_id).first()
        if monitoring:
            monitoring.total_logs += 1
            monitoring.last_updated = datetime.now(timezone.utc)
            db.session.commit()

        prediction = ThreatDetector.predict(processed)
        recent_events.append({**processed, **prediction})
        if len(recent_events) > 50:
            recent_events.pop(0)

        mongo_insert("ai_inference", {
            "projectId": project_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "prediction": prediction,
            "log": processed,
        })
        try:
            from advanced.integration import on_phase2_event
            on_phase2_event(project_id, processed, prediction)
        except Exception:
            pass

        if prediction.get("isAnomaly"):
            threat = ThreatSummary(
                project_id=project_id,
                threat_type=prediction["threat"],
                severity=prediction["severity"],
                confidence=prediction["confidence"],
                status="Validated" if prediction.get("isThreat") else "Observation",
            )
            db.session.add(threat)
            if prediction.get("isThreat") and monitoring:
                monitoring.total_threats += 1
            db.session.commit()

        if prediction.get("isThreat"):
            project = Project.query.get(project_id)
            if project:
                NotificationService.create(
                    project.user_id,
                    "Threat Detected",
                    f"Threat: {prediction['threat']} ({prediction['severity']}) - "
                    f"Confidence: {prediction['confidence']}%",
                    send_email=True,
                )

            from phase3.incident_manager.manager import IncidentManager
            IncidentManager.create_from_threat(project_id, processed, prediction)

        correlated = EventCorrelationEngine.correlate(recent_events)
        for inc in correlated:
            chain_name = inc.get("incidentType") or inc.get("pattern") or "Correlated Attack"
            if chain_name in escalated_chains:
                continue
            escalated_chains.add(chain_name)

            mongo_insert("threat_history", {
                "projectId": project_id,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                **inc,
            })
            project = Project.query.get(project_id)
            if project:
                NotificationService.create(
                    project.user_id,
                    "Correlated Attack Chain",
                    f"Correlated pattern detected: {chain_name}",
                    send_email=True,
                )
                from phase3.incident_manager.manager import IncidentManager
                chain_prediction = {
                    "threat": chain_name,
                    "severity": inc.get("severity", "Critical"),
                    "confidence": float(inc.get("confidence", 95)),
                    "isThreat": True,
                    "isAnomaly": True,
                    "source": "correlation",
                }
                IncidentManager.create_from_threat(project_id, processed, chain_prediction)

    @staticmethod
    def get_active_monitors():
        with _lock:
            live = []
            for project_id, entry in list(_active_monitors.items()):
                thread = (entry or {}).get("thread")
                if thread and thread.is_alive():
                    live.append(project_id)
                else:
                    _active_monitors.pop(project_id, None)
                    _generators.pop(project_id, None)
            return live

    @staticmethod
    def resume_all(app) -> int:
        """Restart Phase 2 loops after a Flask process restart."""
        started = 0
        with app.app_context():
            projects = Project.query.filter_by(monitoring_enabled=True).all()
            for project in projects:
                try:
                    if MonitoringScheduler.start_monitoring(project.project_id, app):
                        started += 1
                except Exception as exc:
                    audit_logger.error("Resume monitoring failed for %s: %s", project.project_id, exc)
        return started
