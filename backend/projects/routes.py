import os
from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import jwt_required, get_jwt_identity
from werkzeug.utils import secure_filename

from database.extensions import db
from database.models import Project, SecurityReport, ProjectMonitoring
from utils.helpers import generate_project_id
from utils.security import sanitize_input
from notifications.service import NotificationService
from utils.logger import audit_logger

projects_bp = Blueprint("projects", __name__, url_prefix="/api/projects")

ALLOWED_EXTENSIONS = {"zip"}


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


@projects_bp.route("/categories", methods=["GET"])
def get_categories():
    return jsonify({"categories": current_app.config["PROJECT_CATEGORIES"]}), 200


@projects_bp.route("/create", methods=["POST"])
@jwt_required()
def create_project():
    user_id = int(get_jwt_identity())
    data = request.get_json() or {}

    name = sanitize_input(data.get("project_name", ""), 200)
    if not name:
        return jsonify({"error": "Project name is required"}), 400

    last = Project.query.order_by(Project.project_id.desc()).first()
    project_id = generate_project_id(last.project_id if last else None)

    project = Project(
        project_id=project_id,
        user_id=user_id,
        project_name=name,
        description=sanitize_input(data.get("description", ""), 2000),
        category=data.get("category", "General Software"),
        programming_language=data.get("programming_language"),
        framework=data.get("framework"),
        version=data.get("version"),
        cloud_provider=data.get("cloud_provider"),
        status="Created",
    )
    db.session.add(project)

    monitoring = ProjectMonitoring(project_id=project_id, monitoring_enabled=False)
    db.session.add(monitoring)
    db.session.commit()

    NotificationService.create(
        user_id,
        "Project Created",
        f"Project {project_id} - {name} has been created.",
    )
    audit_logger.info(f"Project created: {project_id} by user {user_id}")

    return jsonify({"message": "Project created", "project": _project_dict(project)}), 201


@projects_bp.route("", methods=["GET"])
@projects_bp.route("/", methods=["GET"])
@jwt_required()
def list_projects():
    user_id = int(get_jwt_identity())
    projects = Project.query.filter_by(user_id=user_id).order_by(Project.created_date.desc()).all()
    return jsonify({"projects": [_project_dict(p) for p in projects]}), 200


@projects_bp.route("/<project_id>", methods=["GET"])
@jwt_required()
def get_project(project_id):
    user_id = int(get_jwt_identity())
    project = Project.query.filter_by(project_id=project_id, user_id=user_id).first()
    if not project:
        return jsonify({"error": "Project not found"}), 404
    return jsonify({"project": _project_dict(project)}), 200


@projects_bp.route("/upload/<project_id>", methods=["POST"])
@jwt_required()
def upload_project(project_id):
    user_id = int(get_jwt_identity())
    project = Project.query.filter_by(project_id=project_id, user_id=user_id).first()
    if not project:
        return jsonify({"error": "Project not found"}), 404

    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    file = request.files["file"]
    if not file or file.filename == "":
        return jsonify({"error": "No file selected"}), 400
    if not allowed_file(file.filename):
        return jsonify({"error": "Only ZIP files are allowed"}), 400

    max_size = current_app.config["MAX_UPLOAD_SIZE_MB"] * 1024 * 1024
    file.seek(0, os.SEEK_END)
    size = file.tell()
    file.seek(0)
    if size > max_size:
        return jsonify({"error": f"File exceeds {current_app.config['MAX_UPLOAD_SIZE_MB']}MB limit"}), 400

    upload_dir = os.path.join(current_app.config["UPLOAD_FOLDER"], project_id)
    os.makedirs(upload_dir, exist_ok=True)

    filename = secure_filename(file.filename)
    filepath = os.path.join(upload_dir, "original.zip")
    file.save(filepath)

    project.upload_path = filepath
    project.status = "Uploaded"
    db.session.commit()

    NotificationService.create(
        user_id,
        "Project Uploaded",
        f"ZIP file uploaded for project {project_id}. Ready for security scan.",
    )

    from phase1.api.routes import trigger_scan
    scan_result = trigger_scan(project_id)

    return jsonify({
        "message": "File uploaded and scan initiated",
        "project": _project_dict(project),
        "scan": scan_result,
    }), 200


def _project_dict(project: Project) -> dict:
    return {
        "project_id": project.project_id,
        "user_id": project.user_id,
        "project_name": project.project_name,
        "description": project.description,
        "category": project.category,
        "programming_language": project.programming_language,
        "framework": project.framework,
        "version": project.version,
        "cloud_provider": project.cloud_provider,
        "security_score": project.security_score,
        "status": project.status,
        "monitoring_enabled": project.monitoring_enabled,
        "created_date": project.created_date.isoformat() if project.created_date else None,
    }
