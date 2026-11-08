"""Cloud Security Monitoring and Automated Incident Response using AI.

Application entry point. Wires the configuration, MongoDB database, and the
blueprints for all three phases, then exposes the Flask app for local execution.

    cd backend
    python app.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from flask import Flask, jsonify
from flask_cors import CORS
from werkzeug.exceptions import HTTPException, RequestEntityTooLarge

from config.settings import Config
from database.extensions import db, mail, jwt, init_mongo, mongo_available
from database.models import (
    User, Project, SecurityReport, Notification, Incident, Response,
    ProjectMonitoring, ThreatSummary, ChatHistory, OTPRecord, EmailVerification,
)

from authentication.routes import auth_bp
from projects.routes import projects_bp
from phase1.api.routes import phase1_bp
from phase2.api.routes import monitor_bp
from phase3.api.routes import incidents_bp
from ai.chatbot.routes import chatbot_bp
from dashboard.routes import dashboard_bp
from notifications.routes import notifications_bp
from advanced.routes import advanced_bp
from utils.logger import audit_logger

BLUEPRINTS = (
    auth_bp, projects_bp, phase1_bp, monitor_bp,
    incidents_bp, chatbot_bp, dashboard_bp, notifications_bp,
    advanced_bp,
)


def create_app(config_object=Config) -> Flask:
    app = Flask(__name__)
    app.config.from_object(config_object)

    CORS(
        app,
        origins=[app.config["FRONTEND_URL"], "http://localhost:5173", "http://127.0.0.1:5173"],
        supports_credentials=True,
    )

    db.init_app(app)
    mail.init_app(app)
    jwt.init_app(app)
    init_mongo(app)
    try:
        from advanced.seed import seed_if_empty
        seed_if_empty()
    except Exception:
        pass

    for folder in (app.config["UPLOAD_FOLDER"], app.config["REPORTS_FOLDER"],
                   app.config["MODELS_FOLDER"], app.config["LOGS_FOLDER"],
                   app.config["DATASETS_FOLDER"], app.config.get("INCIDENT_REPORTS_FOLDER")):
        if folder:
            try:
                os.makedirs(folder, exist_ok=True)
            except OSError:
                pass

    for blueprint in BLUEPRINTS:
        app.register_blueprint(blueprint)

    _register_error_handlers(app)
    _register_jwt_handlers(app)

    @app.route("/api/health", methods=["GET"])
    def health():
        mongo_status = "connected" if mongo_available() else "unavailable"
        return jsonify({
            "status": "healthy" if mongo_available() else "degraded",
            "service": "Cloud Security Monitoring and Automated Incident Response",
            "database": mongo_status,
            "mongodb": mongo_status,
        }), 200

    return app


def _register_error_handlers(app: Flask) -> None:
    @app.errorhandler(RequestEntityTooLarge)
    def payload_too_large(_error):
        limit = app.config["MAX_UPLOAD_SIZE_MB"]
        return jsonify({"error": f"Upload exceeds the {limit} MB limit"}), 413

    @app.errorhandler(HTTPException)
    def http_error(error):
        return jsonify({"error": error.description}), error.code

    @app.errorhandler(Exception)
    def unhandled_error(error):
        db.session.rollback()
        audit_logger.exception("Unhandled error: %s", error)
        return jsonify({"error": "An internal error occurred"}), 500


def _register_jwt_handlers(app: Flask) -> None:
    @jwt.expired_token_loader
    def expired_token(_header, _payload):
        return jsonify({"error": "Session expired. Please log in again."}), 401

    @jwt.invalid_token_loader
    def invalid_token(_reason):
        return jsonify({"error": "Invalid authentication token"}), 401

    @jwt.unauthorized_loader
    def missing_token(_reason):
        return jsonify({"error": "Authentication required"}), 401


app = create_app()

if __name__ == "__main__":
    with app.app_context():
        try:
            from phase2.scheduler.monitor_scheduler import MonitoringScheduler
            resumed = MonitoringScheduler.resume_all(app)
            if resumed:
                audit_logger.info("Resumed %s Phase 2 monitor(s) after startup", resumed)
        except Exception as exc:
            audit_logger.error("Could not resume monitors at startup: %s", exc)
    app.run(host="0.0.0.0", port=5000, debug=True, use_reloader=False, threaded=True)
