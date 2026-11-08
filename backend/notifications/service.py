from database.extensions import db
from database.models import Notification
from authentication.email_service import EmailService
from database.models import User


class NotificationService:
    @staticmethod
    def create(user_id: int, title: str, message: str, send_email: bool = False):
        notification = Notification(
            user_id=user_id,
            title=title,
            message=message,
        )
        db.session.add(notification)
        db.session.commit()

        if send_email:
            user = User.query.get(user_id)
            if user and user.email:
                EmailService.send_email(user.email, title, message)

        return notification

    @staticmethod
    def get_user_notifications(user_id: int, unread_only: bool = False):
        query = Notification.query.filter_by(user_id=user_id)
        if unread_only:
            query = query.filter_by(read_status=False)
        return query.order_by(Notification.created_date.desc()).all()

    @staticmethod
    def mark_read(notification_id: int, user_id: int):
        n = Notification.query.filter_by(
            notification_id=notification_id, user_id=user_id
        ).first()
        if n:
            n.read_status = True
            db.session.commit()
        return n

    @staticmethod
    def mark_all_read(user_id: int):
        Notification.query.filter_by(user_id=user_id, read_status=False).update(
            {"read_status": True}
        )
        db.session.commit()
