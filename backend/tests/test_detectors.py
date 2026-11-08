"""Smoke test for the Phase 1 detectors.

Builds a deliberately vulnerable project in a temporary directory, runs every
detector over it, and asserts that each one finds what it is responsible for
and stays quiet about the clean control files. Run with:

    cd backend
    python tests/test_detectors.py
"""
import os
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from phase1.detectors.base import deduplicate  # noqa: E402
from phase1.detectors.code.static_analyzer import StaticAnalyzer  # noqa: E402
from phase1.detectors.configs.analyzer import ConfigAnalyzer  # noqa: E402
from phase1.detectors.dependencies.analyzer import DependencyAnalyzer  # noqa: E402
from phase1.detectors.infrastructure.analyzer import InfrastructureAnalyzer  # noqa: E402
from phase1.detectors.secrets.scanner import SecretScanner  # noqa: E402
from phase1.scoring.engine import DecisionEngine, ScoringEngine  # noqa: E402

VULNERABLE_FILES = {
    "app.py": '''
import os
import pickle
import random
import sqlite3

DB_PASSWORD = "Sup3rS3cretPr0dP@ss"
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"

def lookup(user_id):
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
    return cursor.fetchall()

def run(command):
    os.system("ping " + command)

def load(blob):
    return pickle.loads(blob)

def token():
    return random.randint(100000, 999999)
''',

    "safe.py": '''
import os
import secrets

DB_PASSWORD = os.environ["DB_PASSWORD"]
API_KEY = os.getenv("API_KEY", "")
PLACEHOLDER_TOKEN = "your-token-here"

def token():
    return secrets.token_urlsafe(32)
''',

    "static/main.js": '''
const el = document.getElementById("out");
el.innerHTML = location.hash;
eval(window.name);
const id = Math.random().toString(36);
localStorage.setItem("token", id);
''',

    ".env": '''
DEBUG=True
SECRET_KEY=dev
DATABASE_PASSWORD=admin
ALLOW_ORIGINS=*
SSL_VERIFY=false
''',

    "main.tf": '''
resource "aws_security_group_rule" "ssh" {
  cidr_blocks = ["0.0.0.0/0"]
  from_port   = 22
}

resource "aws_s3_bucket" "assets" {
  acl = "public-read"
}

resource "aws_db_instance" "primary" {
  publicly_accessible = true
  storage_encrypted   = false
}
''',

    "iam_policy.json": '''
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "*",
      "Resource": "*"
    }
  ]
}
''',

    "Dockerfile": '''
FROM python:latest
USER root
COPY . /app
CMD ["python", "app.py"]
''',

    "requirements.txt": '''
Flask==2.0.1
requests==2.25.0
PyYAML==5.1
cryptography>=41.0.6
''',

    "package.json": '''
{
  "name": "sample",
  "dependencies": {
    "lodash": "4.17.15",
    "jsonwebtoken": "8.5.1",
    "axios": "1.7.7"
  }
}
''',
}

# detector -> problems it must report on the vulnerable sample
EXPECTED = {
    "Secret Detection": {"Hardcoded Password", "AWS Access Key"},
    "Code Analysis": {"SQL Injection", "Command Injection", "Insecure Deserialization",
                      "Weak Random", "XSS", "Code Injection"},
    "Configuration": {"Debug Enabled", "Default Password", "Permissive CORS",
                      "Missing Certificate Validation"},
    "Infrastructure": {"Public SSH Access", "Public S3 Bucket", "Public Database",
                       "Missing Encryption", "Container Runs As Root",
                       "Excessive IAM Permissions"},
    "Dependency Analysis": {"Vulnerable Dependency"},
}

# Findings that would mean a detector is producing noise.
FORBIDDEN_SNIPPETS = [
    ("safe.py", "os.environ lookup reported as a hardcoded secret"),
]


def build_sample(root: str) -> None:
    for rel_path, content in VULNERABLE_FILES.items():
        target = os.path.join(root, rel_path.replace("/", os.sep))
        os.makedirs(os.path.dirname(target), exist_ok=True)
        with open(target, "w", encoding="utf-8") as handle:
            handle.write(content.strip() + "\n")


def run_detectors(root: str, category: str = "Banking System"):
    findings = []
    for detector in (SecretScanner, StaticAnalyzer, ConfigAnalyzer, InfrastructureAnalyzer):
        findings.extend(detector.analyze_directory(root, category))
    findings.extend(DependencyAnalyzer.analyze(root, list(VULNERABLE_FILES)))
    return deduplicate(findings)


def main() -> int:
    root = tempfile.mkdtemp(prefix="phase1_sample_")
    failures = []
    try:
        build_sample(root)
        findings = run_detectors(root)

        by_detector = {}
        for finding in findings:
            by_detector.setdefault(finding["detector"], set()).add(finding["problem"])

        print(f"{len(findings)} findings across {len(by_detector)} detectors\n")

        for detector, expected in EXPECTED.items():
            found = by_detector.get(detector, set())
            missing = expected - found
            status = "PASS" if not missing else "FAIL"
            print(f"[{status}] {detector}: {len(found)} distinct problems")
            for problem in sorted(found):
                count = sum(1 for f in findings
                            if f["detector"] == detector and f["problem"] == problem)
                print(f"         {problem} x{count}")
            if missing:
                failures.append(f"{detector} missed {sorted(missing)}")
                print(f"         MISSING: {sorted(missing)}")
            print()

        for filename, description in FORBIDDEN_SNIPPETS:
            noise = [f for f in findings if f["file"].endswith(filename)]
            if noise:
                failures.append(description)
                print(f"[FAIL] false positive in {filename}:")
                for finding in noise:
                    print(f"         line {finding['line']}: {finding['problem']}")
            else:
                print(f"[PASS] no false positives in {filename}")

        scoring = ScoringEngine.calculate(findings, "Banking System")
        approval = DecisionEngine.decide(scoring["score"], scoring["counts"])
        print(f"\nScore {scoring['score']}/100  risk {scoring['risk_level']}  "
              f"decision {approval}")
        print(f"Counts: {scoring['counts']}")

        if approval == "Approved":
            failures.append("a project this vulnerable must not be approved")
            print("[FAIL] this project should not have been approved")
        else:
            print("[PASS] correctly withheld from Phase 2 monitoring")

        # Every finding must be actionable for the report to be worth reading.
        incomplete = [f for f in findings
                      if not f.get("solution") or not f.get("reference")]
        if incomplete:
            failures.append(f"{len(incomplete)} findings lack a solution or reference")
            print(f"[FAIL] {len(incomplete)} findings lack remediation guidance")
        else:
            print("[PASS] every finding carries a solution and a reference")
    finally:
        shutil.rmtree(root, ignore_errors=True)

    print()
    if failures:
        print(f"{len(failures)} FAILURE(S):")
        for failure in failures:
            print(f"  - {failure}")
        return 1

    print("All detector checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
