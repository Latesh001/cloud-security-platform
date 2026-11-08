import os
from datetime import timedelta
from dotenv import load_dotenv

_BACKEND_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
load_dotenv(os.path.join(_BACKEND_DIR, ".env"))
load_dotenv()


class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-key-change-in-production")
    JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "jwt-secret-key-change-in-production")
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(minutes=int(os.getenv("SESSION_TIMEOUT_MINUTES", 60)))
    JWT_TOKEN_LOCATION = ["headers"]
    JWT_HEADER_NAME = "Authorization"
    JWT_HEADER_TYPE = "Bearer"

    MONGO_URI = os.getenv("MONGO_URI", "mongodb://127.0.0.1:27017/cloud_security_db")

    MAIL_SERVER = os.getenv("MAIL_SERVER", "smtp.gmail.com")
    MAIL_PORT = int(os.getenv("MAIL_PORT", 587))
    MAIL_USE_TLS = os.getenv("MAIL_USE_TLS", "True").strip().rstrip(".").lower() == "true"
    MAIL_USERNAME = os.getenv("MAIL_USERNAME", "").strip()
    MAIL_PASSWORD = os.getenv("MAIL_PASSWORD", "").replace(" ", "")
    MAIL_DEFAULT_SENDER = (
        "Cloud Security Platform",
        os.getenv("MAIL_DEFAULT_SENDER", "").strip() or MAIL_USERNAME,
    )

    FRONTEND_URL = os.getenv("FRONTEND_URL", "http://localhost:5173")
    GEMINI_API_KEY = os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY", "")
    GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-3.5-flash-lite")
    OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
    OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
    LLM_PROVIDER = os.getenv("LLM_PROVIDER", "auto").strip().lower()

    MAX_UPLOAD_SIZE_MB = int(os.getenv("MAX_UPLOAD_SIZE_MB", 1000))
    # Werkzeug rejects oversized requests before they reach the view. The small
    # headroom covers multipart boundaries and form fields.
    MAX_CONTENT_LENGTH = (MAX_UPLOAD_SIZE_MB + 5) * 1024 * 1024

    BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
    # All downloadable PDFs (Phase 1, Phase 3, forensics, compliance, executive)
    # are written only here — never under C:\prashanth or the repo reports/ folder.
    INCIDENT_REPORTS_FOLDER = os.getenv(
        "INCIDENT_REPORTS_FOLDER",
        r"D:\mainproject papers\Documents\Incident reports",
    )
    REPORTS_FOLDER = os.getenv("REPORTS_FOLDER", INCIDENT_REPORTS_FOLDER)
    MODELS_FOLDER = os.path.join(BASE_DIR, "trained_models")
    LOGS_FOLDER = os.path.join(BASE_DIR, "logs")
    DATASETS_FOLDER = os.path.join(BASE_DIR, "datasets")

    PROJECT_CATEGORIES = [
        "Hospital Management", "Educational System", "Financial Application",
        "Banking System", "Government", "E-Commerce", "Retail", "Manufacturing",
        "Insurance", "Travel", "Transportation", "Agriculture", "IoT",
        "Healthcare", "Social Media", "General Software", "Custom Category",
    ]

    # Phase 1 approval gate: a project reaches Phase 2 monitoring when it
    # scores at or above this value (a small residual critical count is allowed).
    APPROVAL_SCORE_THRESHOLD = int(os.getenv("APPROVAL_SCORE_THRESHOLD", 65))

    # Phase 2 forwards a prediction to Phase 3 only above this confidence,
    # which keeps low-confidence anomalies as observations instead of incidents.
    THREAT_CONFIDENCE_THRESHOLD = float(os.getenv("THREAT_CONFIDENCE_THRESHOLD", 85))

    # Seconds between simulated cloud events during monitoring.
    MONITORING_INTERVAL_SECONDS = int(os.getenv("MONITORING_INTERVAL_SECONDS", 5))
