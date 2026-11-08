from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import smtplib

from flask import current_app
from flask_mail import Message
from itsdangerous import URLSafeTimedSerializer
from datetime import datetime, timedelta, timezone

from database.extensions import db, mail
from database.models import EmailVerification
from utils.helpers import generate_token
from utils.logger import audit_logger


class EmailService:
    @staticmethod
    def mail_configured() -> bool:
        username = (current_app.config.get("MAIL_USERNAME") or "").strip()
        password = (current_app.config.get("MAIL_PASSWORD") or "").strip()
        return bool(username and password)

    @staticmethod
    def send_welcome_email(user) -> bool:
        """Notify a newly registered user that their project workspace is ready."""
        login_url = f"{current_app.config['FRONTEND_URL']}/login"
        subject = "Welcome to Cloud Security Monitoring and Automated Incident Response"
        name = getattr(user, "name", None) or "there"
        to = getattr(user, "email", None) or ""
        body = (
            f"Hello {name},\n\n"
            "Your account on Cloud Security Monitoring and Automated Incident Response using AI is ready.\n\n"
            "Sign in with this email address to:\n"
            "- Scan project ZIP files and review the Phase 1 security score\n"
            "- Enable AI monitoring for live threat detection (Phase 2)\n"
            "- Investigate incidents and run automated response playbooks (Phase 3)\n\n"
            f"Sign in: {login_url}\n\n"
            "If you did not create this account, you can ignore this message.\n\n"
            "Best regards,\n"
            "Cloud Security Platform Team\n"
        )
        html = f"""
        <div style="font-family:Segoe UI,Arial,sans-serif;max-width:560px;margin:0 auto;padding:24px;background:#0f172a;color:#e5e7eb;border-radius:12px;">
          <h2 style="color:#38bdf8;margin-top:0;">Cloud Security Platform</h2>
          <p>Hello {name},</p>
          <p>Your account on <strong>Cloud Security Monitoring and Automated Incident Response using AI</strong> is ready.</p>
          <p>Sign in with this email address to:</p>
          <ul>
            <li>Scan project ZIP files and review the Phase 1 security score</li>
            <li>Enable AI monitoring for live threat detection (Phase 2)</li>
            <li>Investigate incidents and run automated response playbooks (Phase 3)</li>
          </ul>
          <p><a href="{login_url}" style="display:inline-block;background:#2563eb;color:#fff;padding:10px 18px;border-radius:8px;text-decoration:none;">Open the platform</a></p>
          <p style="color:#94a3b8;font-size:12px;">If you did not create this account, you can ignore this message.</p>
        </div>
        """
        return EmailService._send(to, subject, body, html)

    @staticmethod
    def send_verification_email(user) -> str:
        """Create a verification token, notify the user, and return the verify URL."""
        token = generate_token()
        record = EmailVerification(
            user_id=user.user_id,
            token=token,
            expires_at=datetime.now(timezone.utc) + timedelta(hours=24),
        )
        db.session.add(record)
        db.session.commit()

        verify_url = f"{current_app.config['FRONTEND_URL']}/verify-email?token={token}"
        subject = "Verify Your Cloud Security Platform Account"
        body = f"""
Hello {user.name},

Welcome to Cloud Security Monitoring and Automated Incident Response Platform!

Please verify your email by clicking the link below:
{verify_url}

This link expires in 24 hours.

Best regards,
Cloud Security Platform Team
"""
        EmailService._send(user.email, subject, body)
        return verify_url

    @staticmethod
    def send_password_reset(user):
        s = URLSafeTimedSerializer(current_app.config["SECRET_KEY"])
        token = s.dumps(user.user_id, salt="password-reset")
        reset_url = f"{current_app.config['FRONTEND_URL']}/reset-password?token={token}"
        subject = "Password Reset Request"
        body = f"""
Hello {user.name},

Click the link below to reset your password:
{reset_url}

This link expires in 1 hour.

If you did not request this, ignore this email.
"""
        EmailService._send(user.email, subject, body)

    @staticmethod
    def send_email(to: str, subject: str, body: str):
        return EmailService._send(to, subject, body)

    @staticmethod
    def _smtp_settings():
        username = (current_app.config.get("MAIL_USERNAME") or "").strip()
        password = (current_app.config.get("MAIL_PASSWORD") or "").replace(" ", "")
        sender = current_app.config.get("MAIL_DEFAULT_SENDER") or username or ""
        if isinstance(sender, (tuple, list)):
            sender = sender[-1]
        sender = (sender or username or "").strip()
        return {
            "server": current_app.config.get("MAIL_SERVER") or "smtp.gmail.com",
            "port": int(current_app.config.get("MAIL_PORT") or 587),
            "use_tls": bool(current_app.config.get("MAIL_USE_TLS", True)),
            "username": username,
            "password": password,
            "sender": sender or username,
        }

    @staticmethod
    def _send(to: str, subject: str, body: str, html: str | None = None) -> bool:
        if not to:
            audit_logger.warning(f"Email not sent (no recipient): {subject}")
            return False
        if not EmailService.mail_configured():
            audit_logger.info(f"[EMAIL SIMULATION] To: {to} | Subject: {subject}\n{body}")
            return False

        settings = EmailService._smtp_settings()
        try:
            message = MIMEMultipart("alternative")
            message["Subject"] = subject
            message["From"] = f"Cloud Security Platform <{settings['sender']}>"
            message["To"] = to
            message["Reply-To"] = settings["sender"]
            message.attach(MIMEText(body, "plain", "utf-8"))
            if html:
                message.attach(MIMEText(html, "html", "utf-8"))
            with smtplib.SMTP(settings["server"], settings["port"], timeout=30) as smtp:
                smtp.ehlo()
                if settings["use_tls"]:
                    smtp.starttls()
                    smtp.ehlo()
                smtp.login(settings["username"], settings["password"])
                refused = smtp.sendmail(settings["sender"], [to], message.as_string())
            if refused:
                audit_logger.error(f"Email refused for {to}: {refused}")
                return False
            audit_logger.info(f"Email sent to {to}: {subject}")
            return True
        except Exception as smtp_error:
            audit_logger.warning(f"SMTP send failed to {to}: {smtp_error}; trying Flask-Mail")
            try:
                msg = Message(
                    subject=subject,
                    recipients=[to],
                    body=body,
                    html=html,
                    sender=("Cloud Security Platform", settings["sender"]),
                    reply_to=settings["sender"],
                )
                mail.send(msg)
                audit_logger.info(f"Email sent via Flask-Mail to {to}: {subject}")
                return True
            except Exception as flask_mail_error:
                audit_logger.error(f"Email failed to {to}: {flask_mail_error}")
                return False
