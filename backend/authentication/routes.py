import secrets

from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

from database.extensions import db
from database.models import User, EmailVerification
from utils.security import (
    hash_password, verify_password, validate_email,
    validate_password_strength, sanitize_input,
)
from utils.helpers import is_expired
from notifications.service import NotificationService
from authentication.email_service import EmailService
from utils.logger import audit_logger

auth_bp = Blueprint("auth", __name__, url_prefix="/api/auth")

ALLOWED_ROLES = (
    "Developer",
    "Security Analyst",
    "Incident Responder",
    "Student",
    "Researcher",
    "Project Manager",
)


def _normalize_role(value: str) -> str:
    text = sanitize_input(value or "", 80)
    for role in ALLOWED_ROLES:
        if role.lower() == text.lower():
            return role
    return "Developer"


@auth_bp.route("/register", methods=["POST"])
def register():
    """Register with email only. Account is ready immediately; a welcome mail is sent."""
    data = request.get_json() or {}
    name = sanitize_input(data.get("name") or data.get("username") or "", 150)
    email = sanitize_input(data.get("email", ""), 150).lower()
    location = sanitize_input(data.get("location") or data.get("country") or "", 150)
    role = _normalize_role(data.get("role", "Developer"))

    if not name:
        return jsonify({"error": "User name is required"}), 400
    if not email:
        return jsonify({"error": "Email address is required"}), 400
    if not validate_email(email):
        return jsonify({"error": "Invalid email format"}), 400
    if not location:
        return jsonify({"error": "Location is required"}), 400
    if User.query.filter_by(email=email).first():
        return jsonify({"error": "Email already registered"}), 409

    user = User(
        name=name,
        email=email,
        phone=None,
        password_hash=hash_password(secrets.token_urlsafe(32)),
        country=location,
        state="",
        organization="",
        profession=role,
        role=role,
        mfa_enabled=False,
        verification_status="verified",
    )
    db.session.add(user)
    db.session.commit()
    audit_logger.info(f"User registered: {email}")

    welcome = (
        f"Welcome {name}. Your Cloud Security Monitoring and Automated Incident "
        "Response account is ready. Sign in with this email to scan projects, "
        "monitor threats, and run incident playbooks."
    )
    NotificationService.create(
        user.user_id,
        "Welcome to Cloud Security Platform",
        welcome,
        send_email=False,
    )
    email_sent = EmailService.send_welcome_email(user)
    message = (
        f"Registration successful. A welcome email was sent to {email}."
        if email_sent else
        "Registration successful, but the welcome email could not be sent. You can still sign in with your email."
    )

    return jsonify({
        "message": message,
        "user_id": user.user_id,
        "verification_type": "none",
        "auto_verified": True,
        "email_sent": email_sent,
    }), 201


@auth_bp.route("/verify-email", methods=["POST"])
def verify_email():
    data = request.get_json() or {}
    token = data.get("token")
    if not token:
        return jsonify({"error": "Token is required"}), 400

    record = EmailVerification.query.filter_by(token=token, used=False).first()
    if not record:
        return jsonify({"error": "Invalid verification token"}), 400
    if is_expired(record.expires_at):
        return jsonify({"error": "Verification token expired"}), 400

    user = User.query.get(record.user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404

    user.verification_status = "verified"
    record.used = True
    db.session.commit()

    NotificationService.create(
        user.user_id,
        "Account Activated",
        "Your email has been verified. You can now log in.",
    )
    return jsonify({"message": "Email verified successfully"})


@auth_bp.route("/login", methods=["POST"])
def login():
    data = request.get_json() or {}
    email = sanitize_input(data.get("email") or data.get("identifier") or "", 150).lower()

    if not email:
        return jsonify({"error": "Email address is required"}), 400
    if not validate_email(email):
        return jsonify({"error": "Enter a valid email address"}), 400

    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({"error": "No account found for this email"}), 401

    if user.verification_status != "verified":
        user.verification_status = "verified"
        db.session.commit()

    if not user.is_active:
        return jsonify({"error": "Account is deactivated"}), 403

    if user.mfa_enabled:
        user.mfa_enabled = False
        db.session.commit()

    token = create_access_token(identity=str(user.user_id))
    NotificationService.create(user.user_id, "Login Detected", "Successful login to your account.")
    audit_logger.info(f"User login: {user.email}")
    return jsonify({
        "message": "Login successful",
        "access_token": token,
        "user": _user_dict(user),
    }), 200


@auth_bp.route("/forgot-password", methods=["POST"])
def forgot_password():
    data = request.get_json() or {}
    email = sanitize_input(data.get("email", ""), 150).lower()
    if not email or not validate_email(email):
        return jsonify({"error": "Valid email is required"}), 400

    user = User.query.filter_by(email=email).first()
    if user:
        EmailService.send_password_reset(user)

    return jsonify({"message": "If the email exists, a reset link has been sent."}), 200


@auth_bp.route("/reset-password", methods=["POST"])
def reset_password():
    data = request.get_json() or {}
    token = data.get("token")
    password = data.get("password", "")
    confirm = data.get("confirm_password", "")

    if password != confirm:
        return jsonify({"error": "Passwords do not match"}), 400
    valid, msg = validate_password_strength(password)
    if not valid:
        return jsonify({"error": msg}), 400

    s = URLSafeTimedSerializer(current_app.config["SECRET_KEY"])
    try:
        user_id = s.loads(token, salt="password-reset", max_age=3600)
    except (BadSignature, SignatureExpired):
        return jsonify({"error": "Invalid or expired reset token"}), 400

    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404

    user.password_hash = hash_password(password)
    db.session.commit()
    return jsonify({"message": "Password reset successful"})


@auth_bp.route("/me", methods=["GET"])
@jwt_required()
def me():
    user_id = int(get_jwt_identity())
    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404
    return jsonify({"user": _user_dict(user)}), 200


@auth_bp.route("/profile", methods=["PUT"])
@jwt_required()
def update_profile():
    user_id = int(get_jwt_identity())
    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404

    data = request.get_json() or {}
    editable = {
        "name": 150, "country": 100, "state": 100,
        "organization": 150, "profession": 100,
    }
    if "location" in data and "country" not in data:
        data["country"] = data.get("location")
    for field, max_length in editable.items():
        if field in data:
            setattr(user, field, sanitize_input(data.get(field, ""), max_length))
    if "role" in data:
        user.role = _normalize_role(data.get("role"))

    if not user.name:
        return jsonify({"error": "Full name cannot be empty"}), 400

    db.session.commit()
    audit_logger.info(f"Profile updated: user {user_id}")
    return jsonify({"message": "Profile updated", "user": _user_dict(user)}), 200


@auth_bp.route("/change-password", methods=["POST"])
@jwt_required()
def change_password():
    user_id = int(get_jwt_identity())
    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404

    data = request.get_json() or {}
    current = data.get("current_password", "")
    new_password = data.get("new_password", "")
    confirm = data.get("confirm_password", "")

    if not verify_password(current, user.password_hash):
        return jsonify({"error": "Current password is incorrect"}), 401
    if new_password != confirm:
        return jsonify({"error": "New passwords do not match"}), 400
    if verify_password(new_password, user.password_hash):
        return jsonify({"error": "New password must differ from the current one"}), 400

    valid, msg = validate_password_strength(new_password)
    if not valid:
        return jsonify({"error": msg}), 400

    user.password_hash = hash_password(new_password)
    db.session.commit()

    NotificationService.create(
        user_id, "Password Changed",
        "Your account password was changed. If this was not you, reset it immediately.",
        send_email=True,
    )
    audit_logger.info(f"Password changed: user {user_id}")
    return jsonify({"message": "Password changed successfully"}), 200


@auth_bp.route("/resend-verification", methods=["POST"])
def resend_verification():
    data = request.get_json() or {}
    email = sanitize_input(data.get("email", ""), 150).lower()

    user = User.query.filter_by(email=email).first()
    if user and user.verification_status != "verified":
        EmailService.send_verification_email(user)

    return jsonify({"message": "If the account exists, a verification email has been sent."}), 200


def _user_dict(user: User) -> dict:
    return {
        "user_id": user.user_id,
        "name": user.name,
        "email": user.email,
        "phone": user.phone,
        "country": user.country,
        "state": user.state,
        "organization": user.organization,
        "profession": user.profession,
        "role": user.role,
        "mfa_enabled": False,
        "verification_status": user.verification_status,
    }
