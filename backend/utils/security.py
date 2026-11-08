import re
import bcrypt


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))


def validate_email(email: str) -> bool:
    pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    return bool(re.match(pattern, email or ""))


def validate_phone(phone: str) -> bool:
    cleaned = re.sub(r"[\s\-()]", "", phone or "")
    return bool(re.match(r"^\+?[1-9]\d{9,14}$", cleaned))


COUNTRY_DIAL_CODES = {
    "india": "91",
    "in": "91",
    "united states": "1",
    "usa": "1",
    "us": "1",
    "united kingdom": "44",
    "uk": "44",
    "uae": "971",
    "united arab emirates": "971",
    "singapore": "65",
    "australia": "61",
    "canada": "1",
    "germany": "49",
    "france": "33",
}


def normalize_phone(phone: str, country: str = "") -> str:
    """Return an E.164 phone number (+<country><subscriber>)."""
    raw = re.sub(r"[\s\-()]", "", (phone or "").strip())
    if not raw:
        return ""

    if raw.startswith("00"):
        raw = "+" + raw[2:]

    if raw.startswith("+"):
        digits = re.sub(r"\D", "", raw)
        return f"+{digits}" if digits else ""

    digits = re.sub(r"\D", "", raw)
    if not digits:
        return ""

    if len(digits) >= 11:
        return f"+{digits}"

    dial = COUNTRY_DIAL_CODES.get((country or "").strip().lower(), "")
    if dial:
        return f"+{dial}{digits}"

    if len(digits) == 10:
        return f"+91{digits}"

    return f"+{digits}"


def validate_password_strength(password: str) -> tuple[bool, str]:
    if len(password) < 8:
        return False, "Password must be at least 8 characters"
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain an uppercase letter"
    if not re.search(r"[a-z]", password):
        return False, "Password must contain a lowercase letter"
    if not re.search(r"\d", password):
        return False, "Password must contain a number"
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False, "Password must contain a special character"
    return True, "Valid"


def sanitize_input(text: str, max_length: int = 500) -> str:
    if not text:
        return ""
    text = text.strip()[:max_length]
    return re.sub(r"[<>\"']", "", text)
