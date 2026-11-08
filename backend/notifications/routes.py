from flask import Blueprint, jsonify, request
from flask_jwt_extended import jwt_required, get_jwt_identity

from database.extensions import db
from database.models import Notification
from notifications.service import NotificationService

notifications_bp = Blueprint("notifications", __name__, url_prefix="/api/notifications")


def _serialize(notification: Notification) -> dict:
    return {
        "id": notification.notification_id,
        "title": notification.title,
        "message": notification.message,
        "read": notification.read_status,
        "date": notification.created_date.isoformat() if notification.created_date else None,
    }


@notifications_bp.route("", methods=["GET"])
@notifications_bp.route("/", methods=["GET"])
@jwt_required()
def list_notifications():
    user_id = int(get_jwt_identity())
    unread_only = request.args.get("unread", "false").lower() == "true"
    notifications = NotificationService.get_user_notifications(user_id, unread_only=unread_only)

    return jsonify({
        "notifications": [_serialize(n) for n in notifications],
        "unread_count": sum(1 for n in notifications if not n.read_status),
    }), 200


@notifications_bp.route("/<int:notification_id>/read", methods=["POST"])
@jwt_required()
def mark_read(notification_id):
    user_id = int(get_jwt_identity())
    notification = NotificationService.mark_read(notification_id, user_id)
    if not notification:
        return jsonify({"error": "Notification not found"}), 404
    return jsonify({"message": "Marked as read"}), 200


@notifications_bp.route("/read-all", methods=["POST"])
@jwt_required()
def mark_all_read():
    user_id = int(get_jwt_identity())
    NotificationService.mark_all_read(user_id)
    return jsonify({"message": "All notifications marked as read"}), 200


@notifications_bp.route("/<int:notification_id>", methods=["DELETE"])
@jwt_required()
def delete_notification(notification_id):
    user_id = int(get_jwt_identity())
    notification = Notification.query.filter_by(
        notification_id=notification_id, user_id=user_id
    ).first()
    if not notification:
        return jsonify({"error": "Notification not found"}), 404

    db.session.delete(notification)
    db.session.commit()
    return jsonify({"message": "Notification deleted"}), 200
