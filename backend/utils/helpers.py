import os
import random
import shutil
import string
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional


def generate_otp(length: int = 6) -> str:
    return "".join(random.choices(string.digits, k=length))


def generate_token(length: int = 32) -> str:
    return secrets.token_urlsafe(length)


def generate_project_id(last_id: str = None) -> str:
    if not last_id:
        return "P001"
    num = int(last_id[1:]) + 1
    return f"P{num:03d}"


def generate_incident_id(last_id: str = None) -> str:
    if not last_id:
        return "INC0001"
    num = int(last_id[3:]) + 1
    return f"INC{num:04d}"


def isoformat_utc(value) -> Optional[str]:
    """Serialize datetimes as UTC so the browser shows the correct local clock time.

    MongoDB returns naive UTC datetimes. `isoformat()` on those has no offset, so
    JavaScript treats them as local time and the hour is wrong (date stays right).
    """
    if value is None:
        return None
    if isinstance(value, str):
        raw = value.strip()
        if not raw:
            return None
        if raw.endswith("Z") or raw.endswith("z") or "+" in raw[10:] or raw.count("-") > 2:
            return raw
        return raw.replace(" ", "T") + ("Z" if "T" in raw.replace(" ", "T") else "Z")
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc).isoformat()
    return str(value)


_DEFAULT_PDF_DIR = r"D:\mainproject papers\Documents\Incident reports"


def pdf_archive_dir() -> str:
    """Directory for every downloadable PDF. Never C:\\prashanth or the repo tree."""
    folder = _DEFAULT_PDF_DIR
    try:
        from flask import current_app
        folder = current_app.config.get("INCIDENT_REPORTS_FOLDER") or folder
    except RuntimeError:
        pass
    os.makedirs(folder, exist_ok=True)
    return folder


def pdf_output_path(filename: str) -> str:
    safe = "".join(ch if ch.isalnum() or ch in "-_." else "_" for ch in str(filename or "report.pdf"))
    if "." not in os.path.basename(safe):
        safe = f"{safe}.pdf"
    return os.path.join(pdf_archive_dir(), safe)


def archive_forensic_report(source_path: str, filename: str = None) -> Optional[str]:
    """Copy a generated report into INCIDENT_REPORTS_FOLDER (no-op if already there)."""
    if not source_path or not os.path.isfile(source_path):
        return None
    dest = pdf_output_path(filename or os.path.basename(source_path))
    try:
        if os.path.abspath(source_path) != os.path.abspath(dest):
            shutil.copy2(source_path, dest)
        return dest
    except OSError:
        return None


def locate_pdf(stored_path: str = None, filename: str = None) -> Optional[str]:
    """Serve a PDF from the Documents archive, copying any legacy C: path into it."""
    folder = pdf_archive_dir()
    candidates = []
    if filename:
        candidates.append(os.path.join(folder, os.path.basename(filename)))
    if stored_path:
        candidates.append(stored_path)
        candidates.append(os.path.join(folder, os.path.basename(stored_path)))
    for path in candidates:
        if path and os.path.isfile(path):
            archived = archive_forensic_report(path, os.path.basename(path))
            return archived or path
    return None


def otp_expiry(minutes: int = 5) -> datetime:
    return datetime.now(timezone.utc) + timedelta(minutes=minutes)


def is_expired(expires_at: datetime) -> bool:
    now = datetime.now(timezone.utc)
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    return now > expires_at
