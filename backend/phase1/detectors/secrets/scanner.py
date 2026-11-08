"""Secret detection: hardcoded credentials, cloud keys, and private key material."""
import re
from typing import Dict, List

from phase1.detectors.base import (
    build_finding, deduplicate, iter_files, read_lines,
)

DETECTOR_NAME = "Secret Detection"

SCAN_EXTENSIONS = [
    ".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".php", ".cs", ".rb", ".go",
    ".env", ".yaml", ".yml", ".json", ".xml", ".properties", ".ini", ".cfg",
    ".tf", ".tfvars", ".sh", ".ps1", ".config", ".pem", ".key",
]
SCAN_FILENAMES = [".env", ".env.local", ".env.production", ".env.development",
                  "dockerfile", "docker-compose.yml", "credentials", "settings.py"]

# High confidence rules: the token format itself proves it is a real secret.
PROVIDER_RULES = [
    (r"AKIA[0-9A-Z]{16}", "AWS Access Key", "Critical",
     "Revoke the key immediately and load credentials from AWS Secrets Manager or environment variables."),
    (r"ASIA[0-9A-Z]{16}", "AWS Access Key", "Critical",
     "Revoke the temporary key and use IAM roles instead of embedded credentials."),
    (r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----", "Private Key", "Critical",
     "Remove the private key from the repository, rotate the key pair, and store it in a secrets manager."),
    (r"sk-[A-Za-z0-9]{32,}", "Hardcoded API Key", "Critical",
     "Revoke the OpenAI key and read it from an environment variable at runtime."),
    (r"gh[pousr]_[A-Za-z0-9]{36}", "Hardcoded API Key", "Critical",
     "Revoke the GitHub token and use encrypted CI secrets instead."),
    (r"AIza[0-9A-Za-z_\-]{35}", "Hardcoded API Key", "Critical",
     "Revoke the Google API key and restrict it by referrer or IP."),
    (r"xox[baprs]-[0-9A-Za-z\-]{10,}", "Hardcoded API Key", "Critical",
     "Revoke the Slack token and store it outside source control."),
    (r"(?i)mongodb(?:\+srv)?://[^:\s'\"]+:[^@\s'\"]+@", "Hardcoded Password", "Critical",
     "Move the database connection string into an environment variable."),
    (r"(?i)(?:postgres(?:ql)?|mysql|redis)://[^:\s'\"]+:[^@\s'\"]+@", "Hardcoded Password", "Critical",
     "Move the database connection string into an environment variable."),
]

# Credential names are usually namespaced (MYAPP_DB_PASSWORD, stripe.api_key),
# and `_` is a word character, so a leading \b would miss the tail of those
# names. This prefix consumes any number of leading name segments instead.
KEY = r"(?:^|[^A-Za-z0-9])(?:[A-Za-z0-9]+[._-])*"

# Assignment rules: `name = "value"`. The value is validated separately so that
# placeholders and environment lookups are not reported.
ASSIGNMENT_RULES = [
    (rf"(?i){KEY}(?:aws_secret_access_key|aws_secret)\b", "AWS Secret Key", "Critical",
     "Store AWS secrets in AWS Secrets Manager or environment variables, never in code."),
    (rf"(?i){KEY}(?:jwt_secret|jwt_secret_key|token_secret)\b", "Hardcoded JWT Secret", "Critical",
     "Generate a strong random JWT secret at deploy time and inject it via configuration."),
    (rf"(?i){KEY}(?:api_key|apikey|api_token|access_token|auth_token|bearer_token)\b",
     "Hardcoded API Key", "Critical",
     "Load API keys from environment variables or a managed secret store."),
    (rf"(?i){KEY}(?:password|passwd|pwd)\b",
     "Hardcoded Password", "Critical",
     "Remove the credential from source and read it from an environment variable."),
    (rf"(?i){KEY}(?:smtp_password|mail_password|email_password)\b", "Hardcoded Password", "High",
     "Store mail credentials in environment variables and use an app-specific password."),
    (rf"(?i){KEY}(?:client_secret|oauth_secret|consumer_secret)\b", "Hardcoded API Key", "High",
     "Move the OAuth client secret into a secret store."),
    (rf"(?i){KEY}(?:private_key|encryption_key|signing_key)\b", "Private Key", "High",
     "Store key material in a dedicated key management service."),
    # Last, because it is the broadest: anything still unmatched that assigns a
    # literal to a name ending in `secret` or `secret_key`.
    (rf"(?i){KEY}(?:secret_key|secret)\b", "Weak Secret", "High",
     "Load the application secret from configuration and rotate the exposed value."),
]

ASSIGNMENT_VALUE = re.compile(
    r"""[:=]\s*["']([^"']{4,})["']"""
)

# Values that look like secrets but are not: placeholders, templates, and
# references that resolve at runtime.
PLACEHOLDER_VALUE = re.compile(
    r"""^(?:
        (?:your|my|the)[-_ ]|
        change[-_ ]?(?:me|this)|
        placeholder|example|sample|dummy|test|fake|redacted|
        xxx+|\.\.\.|todo|none|null|undefined|
        \$\{|\{\{|%\(|<[a-z_]+>|\*{3,}
    )""",
    re.IGNORECASE | re.VERBOSE,
)

RUNTIME_LOOKUP = re.compile(
    r"(?i)(os\.environ|os\.getenv|process\.env|System\.getenv|dotenv|"
    r"config\.get|getenv\(|env\[|ENV\[|secrets_manager|vault|"
    r"@Value\(|\$\{env)"
)

COMMENT_LINE = re.compile(r"^\s*(#|//|/\*|\*|<!--)")


def _is_real_secret(line: str) -> bool:
    """Return True when the assignment holds a literal value worth reporting."""
    if RUNTIME_LOOKUP.search(line):
        return False
    match = ASSIGNMENT_VALUE.search(line)
    if not match:
        return False
    value = match.group(1).strip()
    if len(value) < 6 or PLACEHOLDER_VALUE.match(value):
        return False
    return True


class SecretScanner:
    """Detects credentials committed into the project source tree."""

    @staticmethod
    def analyze_directory(root_path: str, category: str = "General Software") -> List[Dict]:
        findings: List[Dict] = []
        provider = [(re.compile(p), problem, sev, fix)
                    for p, problem, sev, fix in PROVIDER_RULES]
        assignment = [(re.compile(p), problem, sev, fix)
                      for p, problem, sev, fix in ASSIGNMENT_RULES]

        for abs_path, rel_path in iter_files(
            root_path, extensions=SCAN_EXTENSIONS, filenames=SCAN_FILENAMES,
        ):
            for line_no, line in enumerate(read_lines(abs_path), 1):
                if not line.strip() or len(line) > 1000:
                    continue

                matched = False
                for regex, problem, severity, solution in provider:
                    if regex.search(line):
                        findings.append(build_finding(rel_path, line_no, problem, severity,
                                                      DETECTOR_NAME, solution, line, category))
                        matched = True
                        break
                if matched or COMMENT_LINE.match(line):
                    continue

                for regex, problem, severity, solution in assignment:
                    if regex.search(line) and _is_real_secret(line):
                        findings.append(build_finding(rel_path, line_no, problem, severity,
                                                      DETECTOR_NAME, solution, line, category))
                        break

        return deduplicate(findings)
