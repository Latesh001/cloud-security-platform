"""Shared primitives for the Phase 1 detector modules.

Every detector walks a subset of the extracted project tree, matches regex rules
against each line, and emits findings in one common shape so the scoring,
recommendation, and reporting engines can consume them interchangeably.
"""
import os
import re
from typing import Dict, Iterator, List, Optional, Sequence, Tuple

MAX_FILE_BYTES = 512 * 1024
MAX_FILE_LINES = 2500
MAX_SCAN_FILES = 4000
MAX_FINDINGS_PER_FILE = 40

SKIP_DIRECTORIES = {
    "node_modules", ".git", ".svn", "venv", ".venv", "env", "__pycache__",
    "dist", "build", ".next", ".idea", ".vscode", "vendor", "target",
    "site-packages", "bower_components", ".pytest_cache", "coverage",
    ".tox", ".mypy_cache", ".eggs", "__macosx", "pods", ".gradle",
    "deriveddata", ".cache", ".parcel-cache", ".turbo", ".nuxt", ".output",
    "htmlcov", ".yarn", "pnpm-store", "storybook-static", "out", "tmp",
    "temp", "logs", "log", ".husky", "typings", "jspm_packages",
}

BINARY_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".bmp", ".tif", ".tiff",
    ".woff", ".woff2", ".ttf", ".eot", ".otf", ".mp4", ".mp3", ".wav", ".avi",
    ".mov", ".zip", ".gz", ".tar", ".rar", ".7z", ".bz2", ".exe", ".dll",
    ".so", ".dylib", ".bin", ".class", ".jar", ".war", ".pdf", ".pyc", ".pyo",
    ".whl", ".egg", ".map", ".db", ".sqlite", ".sqlite3", ".pack",
}

SKIP_NAME_MARKERS = (".min.js", ".min.css", ".bundle.js", ".chunk.js")

_RULE_CACHE = {}

# Categories carry domain specific risk. A hardcoded credential in a banking
# application is materially worse than the same issue in a hobby project, so the
# selected category escalates the severity of the checks that matter most to it.
CATEGORY_ESCALATIONS = {
    "Financial Application": {"Hardcoded Password", "SQL Injection", "Hardcoded API Key",
                              "Weak Hashing", "Missing Encryption"},
    "Banking System": {"Hardcoded Password", "SQL Injection", "Hardcoded API Key",
                       "Weak Hashing", "Missing Encryption"},
    "Insurance": {"Hardcoded Password", "SQL Injection", "Missing Encryption"},
    "Hospital Management": {"Hardcoded Password", "Hardcoded API Key", "Missing Encryption",
                            "Public S3 Bucket", "Public Database"},
    "Healthcare": {"Hardcoded Password", "Hardcoded API Key", "Missing Encryption",
                   "Public S3 Bucket", "Public Database"},
    "Government": {"Hardcoded Password", "Weak Secret", "Default Password",
                   "Public SSH Access", "Debug Enabled"},
    "Educational System": {"Hardcoded Password", "SQL Injection", "Debug Enabled"},
    "E-Commerce": {"SQL Injection", "Hardcoded API Key", "XSS"},
    "Banking": {"Hardcoded Password", "SQL Injection"},
    "IoT": {"Default Password", "Hardcoded Password", "Public SSH Access"},
}

REFERENCES = {
    "SQL Injection": "OWASP A03:2021 Injection / CWE-89",
    "Command Injection": "OWASP A03:2021 Injection / CWE-78",
    "Code Injection": "OWASP A03:2021 Injection / CWE-94",
    "XSS": "OWASP A03:2021 Injection / CWE-79",
    "Path Traversal": "OWASP A01:2021 Broken Access Control / CWE-22",
    "Open Redirect": "OWASP A01:2021 Broken Access Control / CWE-601",
    "Insecure Deserialization": "OWASP A08:2021 Data Integrity Failures / CWE-502",
    "Weak Random": "CWE-338 Weak PRNG",
    "Weak Hashing": "OWASP A02:2021 Cryptographic Failures / CWE-327",
    "Missing Certificate Validation": "OWASP A02:2021 Cryptographic Failures / CWE-295",
    "Hardcoded Password": "CWE-798 Use of Hard-coded Credentials",
    "Hardcoded API Key": "CWE-798 Use of Hard-coded Credentials",
    "Hardcoded JWT Secret": "CWE-798 Use of Hard-coded Credentials",
    "AWS Access Key": "AWS Secrets Manager Best Practices / CWE-798",
    "AWS Secret Key": "AWS Secrets Manager Best Practices / CWE-798",
    "Private Key": "CWE-321 Hard-coded Cryptographic Key",
    "Debug Enabled": "OWASP A05:2021 Security Misconfiguration",
    "Weak Secret": "OWASP A02:2021 Cryptographic Failures",
    "Default Password": "CWE-1392 Use of Default Credentials",
    "Permissive CORS": "OWASP A05:2021 Security Misconfiguration",
    "Public SSH Access": "AWS Security Group Best Practices / CWE-284",
    "Public S3 Bucket": "AWS S3 Block Public Access Guidance",
    "Public Database": "AWS RDS Security Best Practices",
    "Excessive IAM Permissions": "AWS IAM Least Privilege Guidance / CWE-269",
    "Missing Encryption": "OWASP A02:2021 Cryptographic Failures",
    "Container Runs As Root": "CIS Docker Benchmark 4.1",
    "Privileged Container": "CIS Docker Benchmark 5.4",
    "Vulnerable Dependency": "OWASP A06:2021 Vulnerable and Outdated Components",
}


def escalate_severity(base_severity: str, problem: str, category: str) -> str:
    """Raise severity one level when the problem is critical for the category."""
    if problem not in CATEGORY_ESCALATIONS.get(category, set()):
        return base_severity
    ladder = {"Low": "Medium", "Medium": "High", "High": "Critical", "Critical": "Critical"}
    return ladder.get(base_severity, base_severity)


def reference_for(problem: str) -> str:
    return REFERENCES.get(problem, "OWASP Top 10 / CWE Database")


def build_finding(filepath: str, line_no: int, problem: str, severity: str,
                  detector: str, solution: str, snippet: str, category: str) -> Dict:
    severity = escalate_severity(severity, problem, category)
    return {
        "file": filepath,
        "line": line_no,
        "problem": problem,
        "severity": severity,
        "detector": detector,
        "explanation": f"{problem} detected in {filepath} at line {line_no}.",
        "solution": solution,
        "reference": reference_for(problem),
        "snippet": snippet.strip()[:200],
    }


def iter_files(root_path: str,
               extensions: Optional[Sequence[str]] = None,
               filenames: Optional[Sequence[str]] = None,
               filename_contains: Optional[Sequence[str]] = None) -> Iterator[Tuple[str, str]]:
    """Yield (absolute_path, path_relative_to_root) for files matching the filters.

    A file matches when its extension, exact name, or name substring is listed.
    Passing no filter at all yields every file.
    """
    ext_set = {e.lower() for e in extensions} if extensions else None
    name_set = {n.lower() for n in filenames} if filenames else None
    contains = [c.lower() for c in filename_contains] if filename_contains else None
    match_all = ext_set is None and name_set is None and contains is None
    yielded = 0

    for dirpath, dirnames, files in os.walk(root_path):
        dirnames[:] = [
            d for d in dirnames
            if d.lower() not in SKIP_DIRECTORIES and not d.startswith(".git")
        ]
        for fname in files:
            if yielded >= MAX_SCAN_FILES:
                return
            lower = fname.lower()
            ext = os.path.splitext(lower)[1]
            if ext in BINARY_EXTENSIONS or any(marker in lower for marker in SKIP_NAME_MARKERS):
                continue
            matched = (
                match_all
                or (ext_set and ext in ext_set)
                or (name_set and lower in name_set)
                or (contains and any(c in lower for c in contains))
            )
            if not matched:
                continue
            abs_path = os.path.join(dirpath, fname)
            try:
                if os.path.getsize(abs_path) > MAX_FILE_BYTES:
                    continue
            except OSError:
                continue
            yielded += 1
            yield abs_path, os.path.relpath(abs_path, root_path).replace("\\", "/")


def read_lines(abs_path: str) -> List[str]:
    lines: List[str] = []
    try:
        with open(abs_path, "r", encoding="utf-8", errors="ignore") as handle:
            for index, line in enumerate(handle):
                if index >= MAX_FILE_LINES:
                    break
                lines.append(line.rstrip("\n"))
    except (OSError, UnicodeDecodeError):
        return []
    return lines


def scan_lines(lines: List[str], rules: Sequence[Tuple], rel_path: str,
               detector: str, category: str) -> List[Dict]:
    """Apply (pattern, problem, severity, solution) rules to each line.

    Only the first rule to match a given line is reported, which keeps
    overlapping patterns (several rules recognise `secret_key`, for example)
    from inflating the finding count for a single mistake.
    """
    findings: List[Dict] = []
    compiled = _RULE_CACHE.get(id(rules))
    if compiled is None:
        compiled = [(re.compile(pattern), problem, severity, solution)
                    for pattern, problem, severity, solution in rules]
        _RULE_CACHE[id(rules)] = compiled

    for line_no, line in enumerate(lines, 1):
        if not line.strip() or len(line) > 1000:
            continue
        for regex, problem, severity, solution in compiled:
            if regex.search(line):
                findings.append(build_finding(rel_path, line_no, problem, severity,
                                              detector, solution, line, category))
                break
        if len(findings) >= MAX_FINDINGS_PER_FILE:
            break
    return findings


def deduplicate(findings: List[Dict]) -> List[Dict]:
    """Collapse findings that report the same problem at the same location."""
    seen = set()
    unique = []
    for finding in findings:
        key = (finding.get("file"), finding.get("line"), finding.get("problem"))
        if key in seen:
            continue
        seen.add(key)
        unique.append(finding)
    return unique
