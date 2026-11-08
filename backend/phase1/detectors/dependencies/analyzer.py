"""Dependency analysis: known-vulnerable and end-of-life package versions.

The advisory table records the first *safe* version for each package. Any
declared version below that boundary is reported, which means a single entry
covers every affected release instead of one exact version string.
"""
import json
import os
import re
from typing import Dict, List, Optional, Tuple

from phase1.detectors.base import deduplicate, iter_files, read_lines

DETECTOR_NAME = "Dependency Analysis"

# package -> (first safe version, severity, advisory)
ADVISORIES = {
    # Python
    "flask": ("2.2.5", "High", "Flask below 2.2.5 is affected by CVE-2023-30861 (session cookie disclosure via caching proxies)."),
    "django": ("4.2.0", "High", "Django below 4.2 is out of extended support and affected by multiple SQL injection and DoS CVEs."),
    "requests": ("2.31.0", "High", "requests below 2.31.0 is affected by CVE-2023-32681 (Proxy-Authorization header leak on redirect)."),
    "urllib3": ("1.26.18", "High", "urllib3 below 1.26.18 is affected by CVE-2023-45803 (request body leak on redirect)."),
    "pillow": ("10.0.1", "High", "Pillow below 10.0.1 is affected by CVE-2023-4863 (WebP heap buffer overflow)."),
    "pyyaml": ("5.4", "Critical", "PyYAML below 5.4 is affected by CVE-2020-14343 (arbitrary code execution via full_load)."),
    "cryptography": ("41.0.6", "High", "cryptography below 41.0.6 is affected by multiple OpenSSL advisories."),
    "jinja2": ("3.1.3", "Medium", "Jinja2 below 3.1.3 is affected by CVE-2024-22195 (XSS via the xmlattr filter)."),
    "werkzeug": ("3.0.1", "High", "Werkzeug below 3.0.1 is affected by CVE-2023-46136 (DoS via multipart uploads)."),
    "sqlalchemy": ("2.0.0", "Medium", "SQLAlchemy 1.x is in maintenance mode; upgrade to 2.x for continued security fixes."),
    "paramiko": ("2.10.1", "High", "paramiko below 2.10.1 is affected by CVE-2022-24302 (private key race condition)."),
    "numpy": ("1.22.0", "Medium", "numpy below 1.22 is affected by CVE-2021-33430 (buffer overflow)."),
    "lxml": ("4.9.1", "High", "lxml below 4.9.1 is affected by CVE-2022-2309 (NULL dereference)."),
    "certifi": ("2023.7.22", "Medium", "certifi below 2023.7.22 trusts the removed e-Tugra root certificates."),

    # JavaScript / Node
    "lodash": ("4.17.21", "High", "lodash below 4.17.21 is affected by CVE-2021-23337 (command injection via template)."),
    "express": ("4.19.2", "High", "Express below 4.19.2 is affected by CVE-2024-29041 (open redirect in res.location)."),
    "axios": ("1.6.0", "High", "axios below 1.6.0 is affected by CVE-2023-45857 (CSRF token leak to third-party hosts)."),
    "minimist": ("1.2.6", "High", "minimist below 1.2.6 is affected by CVE-2021-44906 (prototype pollution)."),
    "jsonwebtoken": ("9.0.0", "Critical", "jsonwebtoken below 9.0.0 is affected by CVE-2022-23529 (signature verification bypass)."),
    "moment": ("2.29.4", "High", "moment below 2.29.4 is affected by CVE-2022-31129 (ReDoS). Consider migrating to date-fns."),
    "next": ("13.5.7", "High", "Next.js below 13.5.7 is affected by multiple SSRF and cache poisoning advisories."),
    "webpack-dev-server": ("5.2.1", "Medium", "webpack-dev-server below 5.2.1 can leak source code to malicious sites."),
    "node-fetch": ("2.6.7", "High", "node-fetch below 2.6.7 is affected by CVE-2022-0235 (credential leak on redirect)."),
    "socket.io": ("4.6.2", "High", "socket.io below 4.6.2 is affected by CVE-2023-32695 (unhandled resource consumption)."),
    "vite": ("4.5.3", "Medium", "Vite below 4.5.3 is affected by CVE-2024-31207 (dev server file exposure)."),
    "semver": ("7.5.2", "Medium", "semver below 7.5.2 is affected by CVE-2022-25883 (ReDoS)."),

    # Java
    "log4j-core": ("2.17.1", "Critical", "log4j-core below 2.17.1 is affected by Log4Shell (CVE-2021-44228) allowing remote code execution."),
    "spring-core": ("5.3.18", "Critical", "spring-core below 5.3.18 is affected by Spring4Shell (CVE-2022-22965)."),
    "spring-boot": ("2.7.0", "High", "Spring Boot below 2.7 is out of support and affected by multiple CVEs."),
    "jackson-databind": ("2.13.4", "High", "jackson-databind below 2.13.4 is affected by multiple deserialization CVEs."),
    "commons-text": ("1.10.0", "Critical", "commons-text below 1.10.0 is affected by CVE-2022-42889 (Text4Shell)."),
    "snakeyaml": ("2.0", "High", "SnakeYAML below 2.0 is affected by CVE-2022-1471 (deserialization to remote code execution)."),

    # PHP
    "laravel/framework": ("9.52.16", "High", "Laravel below 9.52.16 is affected by CVE-2023-29197 and related advisories."),
    "guzzlehttp/guzzle": ("7.4.5", "High", "Guzzle below 7.4.5 is affected by CVE-2022-31090 (credential leak on redirect)."),
    "symfony/http-kernel": ("5.4.20", "High", "symfony/http-kernel below 5.4.20 is affected by multiple advisories."),
}

VERSION_TOKEN = re.compile(r"(\d+(?:\.\d+)*)")


def _parse_version(raw: str) -> Optional[Tuple[int, ...]]:
    """Extract a comparable numeric version tuple from a version specifier."""
    if not raw:
        return None
    match = VERSION_TOKEN.search(raw)
    if not match:
        return None
    try:
        return tuple(int(part) for part in match.group(1).split("."))
    except ValueError:
        return None


def _pad(version: Tuple[int, ...], length: int) -> Tuple[int, ...]:
    return version + (0,) * (length - len(version))


def _is_vulnerable(declared: str, first_safe: str) -> bool:
    current = _parse_version(declared)
    safe = _parse_version(first_safe)
    if current is None or safe is None:
        return False
    size = max(len(current), len(safe))
    return _pad(current, size) < _pad(safe, size)


def _finding(rel_path: str, line_no: int, package: str, version: str,
             severity: str, advisory: str, first_safe: str, snippet: str) -> Dict:
    return {
        "file": rel_path,
        "line": line_no,
        "problem": "Vulnerable Dependency",
        "severity": severity,
        "detector": DETECTOR_NAME,
        "explanation": f"{package} {version} is outdated. {advisory}",
        "solution": f"Upgrade {package} to {first_safe} or later.",
        "reference": "NVD / GitHub Advisory Database",
        "snippet": snippet.strip()[:200],
    }


class DependencyAnalyzer:
    """Checks declared dependencies against a known-vulnerability advisory table."""

    MANIFESTS = ["requirements.txt", "requirements-dev.txt", "package.json",
                 "pom.xml", "composer.json", "build.gradle", "pipfile"]

    @staticmethod
    def analyze(extract_path: str, files: Optional[List[str]] = None) -> List[Dict]:
        findings: List[Dict] = []
        for abs_path, rel_path in iter_files(extract_path,
                                             filenames=DependencyAnalyzer.MANIFESTS):
            basename = os.path.basename(abs_path).lower()
            if basename.startswith("requirements") or basename == "pipfile":
                findings.extend(DependencyAnalyzer._scan_requirements(abs_path, rel_path))
            elif basename == "package.json":
                findings.extend(DependencyAnalyzer._scan_package_json(abs_path, rel_path))
            elif basename == "composer.json":
                findings.extend(DependencyAnalyzer._scan_composer(abs_path, rel_path))
            elif basename in ("pom.xml", "build.gradle"):
                findings.extend(DependencyAnalyzer._scan_jvm(abs_path, rel_path))
        return deduplicate(findings)

    @staticmethod
    def _scan_requirements(abs_path: str, rel_path: str) -> List[Dict]:
        findings = []
        for line_no, line in enumerate(read_lines(abs_path), 1):
            stripped = line.strip()
            if not stripped or stripped.startswith(("#", "-")):
                continue
            match = re.match(r"([A-Za-z0-9_.\-]+)\s*(?:==|>=|~=)\s*([0-9][^\s;,]*)", stripped)
            if not match:
                continue
            package, version = match.group(1).lower(), match.group(2)
            advisory = ADVISORIES.get(package)
            if advisory and _is_vulnerable(version, advisory[0]):
                findings.append(_finding(rel_path, line_no, package, version,
                                         advisory[1], advisory[2], advisory[0], line))
        return findings

    @staticmethod
    def _scan_package_json(abs_path: str, rel_path: str) -> List[Dict]:
        findings = []
        lines = read_lines(abs_path)
        try:
            data = json.loads("\n".join(lines))
        except json.JSONDecodeError:
            return findings

        dependencies = {}
        for section in ("dependencies", "devDependencies", "peerDependencies"):
            value = data.get(section)
            if isinstance(value, dict):
                dependencies.update(value)

        for package, version in dependencies.items():
            advisory = ADVISORIES.get(package.lower())
            if not advisory or not isinstance(version, str):
                continue
            if _is_vulnerable(version, advisory[0]):
                line_no = next((i for i, text in enumerate(lines, 1)
                                if f'"{package}"' in text), 1)
                findings.append(_finding(rel_path, line_no, package, version,
                                         advisory[1], advisory[2], advisory[0],
                                         f'"{package}": "{version}"'))
        return findings

    @staticmethod
    def _scan_composer(abs_path: str, rel_path: str) -> List[Dict]:
        findings = []
        lines = read_lines(abs_path)
        try:
            data = json.loads("\n".join(lines))
        except json.JSONDecodeError:
            return findings

        dependencies = {}
        for section in ("require", "require-dev"):
            value = data.get(section)
            if isinstance(value, dict):
                dependencies.update(value)

        for package, version in dependencies.items():
            advisory = ADVISORIES.get(package.lower())
            if not advisory or not isinstance(version, str):
                continue
            if _is_vulnerable(version, advisory[0]):
                line_no = next((i for i, text in enumerate(lines, 1)
                                if f'"{package}"' in text), 1)
                findings.append(_finding(rel_path, line_no, package, version,
                                         advisory[1], advisory[2], advisory[0],
                                         f'"{package}": "{version}"'))
        return findings

    @staticmethod
    def _scan_jvm(abs_path: str, rel_path: str) -> List[Dict]:
        """Match Maven artifactId/version pairs and Gradle coordinate strings."""
        findings = []
        lines = read_lines(abs_path)
        content = "\n".join(lines)

        for match in re.finditer(
            r"<artifactId>\s*([\w.\-]+)\s*</artifactId>\s*<version>\s*([^<\s]+)\s*</version>",
            content, re.IGNORECASE,
        ):
            package, version = match.group(1).lower(), match.group(2)
            advisory = ADVISORIES.get(package)
            if advisory and _is_vulnerable(version, advisory[0]):
                line_no = content[:match.start()].count("\n") + 1
                findings.append(_finding(rel_path, line_no, package, version,
                                         advisory[1], advisory[2], advisory[0], match.group(0)))

        for line_no, line in enumerate(lines, 1):
            match = re.search(r"['\"][\w.\-]+:([\w.\-]+):([0-9][\w.\-]*)['\"]", line)
            if not match:
                continue
            package, version = match.group(1).lower(), match.group(2)
            advisory = ADVISORIES.get(package)
            if advisory and _is_vulnerable(version, advisory[0]):
                findings.append(_finding(rel_path, line_no, package, version,
                                         advisory[1], advisory[2], advisory[0], line))
        return findings
