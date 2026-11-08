"""Configuration analysis: debug flags, weak defaults, and unsafe framework settings."""
from typing import Dict, List

from phase1.detectors.base import deduplicate, iter_files, read_lines, scan_lines

DETECTOR_NAME = "Configuration"

CONFIG_EXTENSIONS = [".env", ".ini", ".cfg", ".conf", ".properties", ".toml"]
CONFIG_FILENAMES = [
    ".env", ".env.local", ".env.production", ".env.development", ".env.staging",
    "config.py", "settings.py", "config.js", "config.json", "configuration.php",
    "application.properties", "application.yml", "application.yaml",
    "web.config", "appsettings.json", "appsettings.development.json",
    "wp-config.php", "database.yml", "local_settings.py",
]
CONFIG_NAME_HINTS = ["config", "settings", "appsettings"]

# Settings keys are almost always namespaced: DATABASE_PASSWORD, DJANGO_DEBUG,
# app.security.csrf.enabled. A plain \b will not match the tail of those names
# because `_` and `.` behave differently at a word boundary, so every rule opens
# with this prefix instead.
KEY = r"(?:^|[^A-Za-z0-9])(?:[A-Za-z0-9]+[._-])*"

CONFIG_RULES = [
    (rf"(?i){KEY}debug\s*[:=]\s*[\"']?(?:true|1|on)\b", "Debug Enabled", "High",
     "Disable debug mode outside development. Debug pages leak stack traces, "
     "environment variables, and source code to attackers."),
    (r"(?i)\bapp\.run\([^)]*debug\s*=\s*True", "Debug Enabled", "High",
     "Never run Flask with debug=True in production; the Werkzeug debugger allows remote code execution."),
    (rf"(?i){KEY}secret[_-]?key\s*[:=]\s*[\"']?(?:dev|test|secret|changeme|abc|123|key)\b",
     "Weak Secret", "High",
     "Replace the placeholder secret with a cryptographically random value supplied at deploy time."),
    (rf"(?i){KEY}(?:password|passwd|pwd)\s*[:=]\s*[\"']?(?:admin|root|password|123456|toor|guest|letmein)\b",
     "Default Password", "Critical",
     "Change all default credentials and enforce a strong password policy."),
    (rf"(?i){KEY}allow[_-]?origins?\s*[:=]\s*[\[\"']?\s*\*", "Permissive CORS", "Medium",
     "Restrict CORS to an explicit list of trusted origins instead of a wildcard."),
    (r"(?i)Access-Control-Allow-Origin\s*[:=]\s*[\"']?\*", "Permissive CORS", "Medium",
     "Restrict CORS to an explicit list of trusted origins instead of a wildcard."),
    (rf"(?i){KEY}ssl[_-]?verify\s*[:=]\s*[\"']?(?:false|0|off)\b", "Missing Certificate Validation", "High",
     "Enable TLS certificate verification; disabling it allows man-in-the-middle attacks."),
    (r"(?i)\bverify\s*=\s*False\b", "Missing Certificate Validation", "High",
     "Enable TLS certificate verification on outbound requests."),
    (rf"(?i){KEY}(?:session_cookie_secure|cookie_secure|secure_cookie)\s*[:=]\s*[\"']?(?:false|0)\b",
     "Insecure Cookie", "Medium",
     "Set the Secure flag so session cookies are only transmitted over HTTPS."),
    (rf"(?i){KEY}csrf(?:[_-]?protection)?[_-]?(?:enabled|check)?\s*[:=]\s*[\"']?(?:false|0|off)\b",
     "CSRF Protection Disabled", "High",
     "Re-enable CSRF protection for all state-changing requests."),
    (rf"(?i){KEY}allowed[_-]?hosts\s*[:=]\s*\[?\s*[\"']?\*", "Permissive Host Header", "Medium",
     "List the exact hostnames the application serves instead of a wildcard."),
    (rf"(?i){KEY}(?:ssl|tls|https)[_-]?(?:enabled|required)\s*[:=]\s*[\"']?(?:false|0|off)\b",
     "Missing Encryption", "High",
     "Require TLS for all client and service-to-service traffic."),
    (rf"(?i){KEY}expose[_-]?(?:secrets|env)\s*[:=]\s*[\"']?(?:true|1)\b", "Sensitive Data Exposure", "High",
     "Do not expose environment variables or secrets to the client."),
]


class ConfigAnalyzer:
    """Detects insecure application configuration."""

    @staticmethod
    def analyze_directory(root_path: str, category: str = "General Software") -> List[Dict]:
        findings: List[Dict] = []
        for abs_path, rel_path in iter_files(
            root_path,
            extensions=CONFIG_EXTENSIONS,
            filenames=CONFIG_FILENAMES,
            filename_contains=CONFIG_NAME_HINTS,
        ):
            lines = read_lines(abs_path)
            if not lines:
                continue
            findings.extend(scan_lines(lines, CONFIG_RULES, rel_path, DETECTOR_NAME, category))
        return deduplicate(findings)
