"""Static source code analysis for insecure coding patterns."""
import os
from typing import Dict, List

from phase1.detectors.base import deduplicate, iter_files, read_lines, scan_lines

DETECTOR_NAME = "Code Analysis"

PYTHON_EXTENSIONS = {".py"}
WEB_EXTENSIONS = {".js", ".jsx", ".ts", ".tsx", ".vue", ".svelte", ".html"}
JVM_EXTENSIONS = {".java", ".kt", ".scala"}
PHP_EXTENSIONS = {".php"}
DOTNET_EXTENSIONS = {".cs"}

ALL_CODE_EXTENSIONS = list(
    PYTHON_EXTENSIONS | WEB_EXTENSIONS | JVM_EXTENSIONS | PHP_EXTENSIONS
    | DOTNET_EXTENSIONS | {".rb", ".go", ".sh", ".bash", ".ps1", ".bat", ".cmd", ".sql"}
)

# Rules that apply to every language.
COMMON_RULES = [
    (r"(?i)\bmd5\s*\(", "Weak Hashing", "Medium",
     "MD5 is collision-prone. Use SHA-256 for integrity and bcrypt or Argon2 for passwords."),
    (r"(?i)\bsha1\s*\(", "Weak Hashing", "Medium",
     "SHA-1 is deprecated. Use SHA-256 or stronger."),
    (r"(?i)\b(?:DES|RC4|ECB)\b\s*(?:\.|\(|mode)", "Weak Encryption", "High",
     "DES, RC4, and ECB mode are broken. Use AES-256 in GCM mode."),
]

PYTHON_RULES = [
    (r"cursor\.execute\s*\(\s*f[\"']", "SQL Injection", "Critical",
     "Pass query parameters as a tuple to execute() instead of interpolating them with an f-string."),
    (r"(?:execute|executemany)\s*\(\s*[\"'][^\"']*[\"']\s*(?:%|\+)", "SQL Injection", "Critical",
     "Use parameterized queries: cursor.execute(\"SELECT ... WHERE id = %s\", (value,))."),
    (r"(?:execute|raw|filter)\s*\(\s*.*%\s*\(", "SQL Injection", "Critical",
     "Use the database driver's parameter binding rather than string formatting."),
    (r"\beval\s*\(", "Code Injection", "Critical",
     "Remove eval(). Use ast.literal_eval() for data or an explicit dispatch table for behaviour."),
    (r"\bexec\s*\(", "Code Injection", "Critical",
     "Remove exec(). Executing constructed strings allows arbitrary code execution."),
    (r"os\.system\s*\(", "Command Injection", "High",
     "Use subprocess.run([...], shell=False) with an argument list."),
    (r"(?:subprocess\.(?:run|call|Popen|check_output))\s*\([^)]*shell\s*=\s*True",
     "Command Injection", "High",
     "Set shell=False and pass the command as a list to avoid shell interpretation."),
    (r"(?:os\.popen|commands\.getoutput)\s*\(", "Command Injection", "High",
     "Use the subprocess module with an argument list instead."),
    (r"pickle\.loads?\s*\(", "Insecure Deserialization", "High",
     "Never unpickle untrusted data. Use JSON for data interchange."),
    (r"yaml\.load\s*\((?![^)]*Loader\s*=\s*yaml\.SafeLoader)", "Insecure Deserialization", "High",
     "Use yaml.safe_load() so arbitrary Python objects cannot be constructed."),
    (r"\brandom\.(?:random|randint|choice|randrange)\s*\(", "Weak Random", "Medium",
     "Use the secrets module for tokens, passwords, and anything security relevant."),
    (r"open\s*\([^)]*(?:request\.|input\(|argv)", "Path Traversal", "High",
     "Validate the path against an allowlist and resolve it under a fixed base directory."),
    (r"(?:redirect|HttpResponseRedirect)\s*\([^)]*request\.", "Open Redirect", "Medium",
     "Validate the redirect target against a list of permitted destinations."),
    (r"verify\s*=\s*False", "Missing Certificate Validation", "High",
     "Enable TLS certificate verification on outbound HTTP requests."),
    (r"@app\.route\([^)]*\)(?!.*(?:login_required|jwt_required|authenticate))",
     "Missing Authentication", "Low",
     "Confirm the endpoint requires authentication if it exposes sensitive data."),
]

WEB_RULES = [
    (r"\.innerHTML\s*=", "XSS", "High",
     "Use textContent, or sanitize the HTML with DOMPurify before insertion."),
    (r"dangerouslySetInnerHTML", "XSS", "High",
     "Sanitize the HTML with DOMPurify before passing it to dangerouslySetInnerHTML."),
    (r"document\.write\s*\(", "XSS", "High",
     "Replace document.write() with safe DOM construction methods."),
    (r"\beval\s*\(", "Code Injection", "Critical",
     "Remove eval(). Parse JSON with JSON.parse() and avoid dynamic code execution."),
    (r"new\s+Function\s*\(", "Code Injection", "Critical",
     "Avoid the Function constructor; it executes strings as code."),
    (r"(?:setTimeout|setInterval)\s*\(\s*[\"']", "Code Injection", "Medium",
     "Pass a function reference to setTimeout instead of a string to be evaluated."),
    (r"child_process\.exec\s*\(", "Command Injection", "High",
     "Use execFile() or spawn() with an argument array instead of exec()."),
    (r"(?:query|execute)\s*\(\s*[`\"'][^`\"']*\$\{", "SQL Injection", "Critical",
     "Use parameterized queries; template literals interpolate user input directly into SQL."),
    (r"\bMath\.random\s*\(\)", "Weak Random", "Medium",
     "Use crypto.randomUUID() or crypto.getRandomValues() for security-sensitive randomness."),
    (r"localStorage\.setItem\s*\(\s*[\"'](?:token|jwt|password|secret)", "Sensitive Data Exposure", "Medium",
     "Storing tokens in localStorage exposes them to XSS. Prefer httpOnly cookies."),
    (r"rejectUnauthorized\s*:\s*false", "Missing Certificate Validation", "High",
     "Enable TLS certificate validation for outbound connections."),
]

JVM_RULES = [
    (r"(?:createStatement\(\)|Statement\s+\w+)\s*[\s\S]{0,80}?execute(?:Query|Update)?\s*\(\s*[\"'][^\"']*\"\s*\+",
     "SQL Injection", "Critical",
     "Use PreparedStatement with bind parameters instead of concatenating SQL."),
    (r"execute(?:Query|Update)\s*\(\s*[\"'][^\"']*[\"']\s*\+", "SQL Injection", "Critical",
     "Use PreparedStatement with bind parameters instead of concatenating SQL."),
    (r"Runtime\.getRuntime\(\)\.exec\s*\(", "Command Injection", "High",
     "Use ProcessBuilder with an argument list and validate all inputs."),
    (r"new\s+ObjectInputStream\s*\(", "Insecure Deserialization", "High",
     "Avoid Java native deserialization of untrusted data; use JSON with a strict schema."),
    (r"new\s+Random\s*\(", "Weak Random", "Medium",
     "Use java.security.SecureRandom for security-sensitive values."),
    (r"printStackTrace\s*\(\)", "Sensitive Data Exposure", "Low",
     "Log through the application logger rather than printing stack traces to stdout."),
    (r"setAllowedOrigins?\s*\(\s*[\"']\*", "Permissive CORS", "Medium",
     "List the exact allowed origins instead of a wildcard."),
]

PHP_RULES = [
    (r"(?:mysql_query|mysqli_query)\s*\([^)]*\$", "SQL Injection", "Critical",
     "Use PDO prepared statements with bound parameters."),
    (r"\$_(?:GET|POST|REQUEST|COOKIE)\s*\[[^\]]+\][^;]*(?:query|exec|include|require)",
     "SQL Injection", "Critical",
     "Never pass superglobals directly into queries or includes; validate and bind them."),
    (r"\b(?:eval|assert)\s*\(", "Code Injection", "Critical",
     "Remove eval() and assert() on dynamic strings."),
    (r"\b(?:shell_exec|passthru|system|popen|proc_open)\s*\(", "Command Injection", "High",
     "Avoid shell execution; if unavoidable, use escapeshellarg() on every argument."),
    (r"\bunserialize\s*\(", "Insecure Deserialization", "High",
     "Use json_decode() instead of unserialize() for untrusted input."),
    (r"(?:include|require)(?:_once)?\s*\(?\s*\$", "Path Traversal", "High",
     "Never build include paths from user input; use an allowlist of permitted files."),
    (r"\bmd5\s*\(\s*\$(?:password|pass|pwd)", "Weak Hashing", "Critical",
     "Use password_hash() with PASSWORD_BCRYPT or PASSWORD_ARGON2ID."),
]

DOTNET_RULES = [
    (r"new\s+Sql(?:Command|DataAdapter)\s*\(\s*[\"'][^\"']*[\"']\s*\+", "SQL Injection", "Critical",
     "Use SqlParameter bindings instead of concatenating SQL strings."),
    (r"\$\"\s*SELECT[\s\S]{0,120}?\{", "SQL Injection", "Critical",
     "Interpolated SQL strings are injectable. Use parameterized commands."),
    (r"Process\.Start\s*\(", "Command Injection", "High",
     "Validate all arguments and avoid passing user input to Process.Start."),
    (r"BinaryFormatter", "Insecure Deserialization", "Critical",
     "BinaryFormatter is unsafe and deprecated. Use System.Text.Json."),
    (r"ServerCertificateValidationCallback\s*(?:\+)?=\s*(?:delegate|\()", "Missing Certificate Validation", "High",
     "Do not override certificate validation to always return true."),
    (r"new\s+Random\s*\(", "Weak Random", "Medium",
     "Use RandomNumberGenerator for security-sensitive values."),
]

RULES_BY_EXTENSION = {}
for _ext in PYTHON_EXTENSIONS:
    RULES_BY_EXTENSION[_ext] = PYTHON_RULES + COMMON_RULES
for _ext in WEB_EXTENSIONS:
    RULES_BY_EXTENSION[_ext] = WEB_RULES + COMMON_RULES
for _ext in JVM_EXTENSIONS:
    RULES_BY_EXTENSION[_ext] = JVM_RULES + COMMON_RULES
for _ext in PHP_EXTENSIONS:
    RULES_BY_EXTENSION[_ext] = PHP_RULES + COMMON_RULES
for _ext in DOTNET_EXTENSIONS:
    RULES_BY_EXTENSION[_ext] = DOTNET_RULES + COMMON_RULES


class StaticAnalyzer:
    """Applies language-specific insecure coding rules to project source files."""

    @staticmethod
    def analyze_directory(root_path: str, category: str = "General Software") -> List[Dict]:
        findings: List[Dict] = []
        for abs_path, rel_path in iter_files(root_path, extensions=ALL_CODE_EXTENSIONS):
            ext = os.path.splitext(abs_path)[1].lower()
            rules = RULES_BY_EXTENSION.get(ext, COMMON_RULES)
            lines = read_lines(abs_path)
            if not lines:
                continue
            findings.extend(scan_lines(lines, rules, rel_path, DETECTOR_NAME, category))
        return deduplicate(findings)
