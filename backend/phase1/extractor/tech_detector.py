import os
from typing import Dict, List


TECH_SIGNATURES = {
    "python": ["requirements.txt", "setup.py", "pyproject.toml", ".py"],
    "java": ["pom.xml", "build.gradle", ".java"],
    "javascript": ["package.json", ".js", ".jsx"],
    "typescript": ["tsconfig.json", ".ts", ".tsx"],
    "php": ["composer.json", ".php"],
    "csharp": [".csproj", ".cs"],
    "react": ["package.json"],
    "node": ["package.json", "node_modules"],
    "flask": ["app.py", "requirements.txt"],
    "django": ["manage.py", "settings.py"],
    "spring": ["pom.xml", "application.properties"],
    "laravel": ["artisan", "composer.json"],
    "terraform": [".tf", "terraform.tfvars"],
    "docker": ["Dockerfile", "docker-compose.yml"],
}


FRAMEWORK_HINTS = {
    "requirements.txt": "Python",
    "package.json": "Node.js",
    "pom.xml": "Spring Boot",
    "composer.json": "PHP/Laravel",
    "manage.py": "Django",
    "artisan": "Laravel",
    "Dockerfile": "Docker",
}


class TechnologyDetector:
    @staticmethod
    def detect(extract_path: str, files: List[str]) -> Dict:
        detected_langs = set()
        detected_frameworks = set()
        package_managers = set()
        databases = set()
        cloud_configs = set()

        all_names = " ".join(files).lower()
        basename_map = {os.path.basename(f).lower(): f for f in files}

        for lang, sigs in TECH_SIGNATURES.items():
            for sig in sigs:
                if sig.startswith(".") and sig in all_names:
                    detected_langs.add(lang)
                elif any(sig.lower() in f.lower() for f in files):
                    if sig.endswith(".txt") or sig.endswith(".json") or sig.endswith(".xml"):
                        detected_langs.add(lang)

        for hint_file, framework in FRAMEWORK_HINTS.items():
            if hint_file.lower() in basename_map:
                detected_frameworks.add(framework)

        if "requirements.txt" in basename_map:
            package_managers.add("pip")
        if "package.json" in basename_map:
            package_managers.add("npm")
        if "pom.xml" in basename_map:
            package_managers.add("maven")
        if "composer.json" in basename_map:
            package_managers.add("composer")

        db_hints = ["postgresql", "mysql", "mongodb", "sqlite", "redis"]
        for f in files:
            fl = f.lower()
            for db in db_hints:
                if db in fl:
                    databases.add(db)

        cloud_hints = ["terraform", "cloudformation", "aws", "azure", "gcp", ".tf"]
        for f in files:
            fl = f.lower()
            for c in cloud_hints:
                if c in fl:
                    cloud_configs.add(c)

        primary_lang = TechnologyDetector._primary_language(detected_langs)

        return {
            "languages": list(detected_langs) or ["unknown"],
            "primary_language": primary_lang,
            "frameworks": list(detected_frameworks) or ["General"],
            "package_managers": list(package_managers),
            "databases": list(databases),
            "cloud_configs": list(cloud_configs),
        }

    @staticmethod
    def _primary_language(langs: set) -> str:
        priority = ["python", "java", "javascript", "typescript", "php", "csharp"]
        for p in priority:
            if p in langs:
                return p
        return list(langs)[0] if langs else "unknown"
