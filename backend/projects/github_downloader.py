"""GitHub Repository Downloader Helper.

Parses public GitHub repository URLs and streams branch zipball archives directly
to the project upload directory for security assessment.
"""
import os
import re
import urllib.parse
import urllib.request
from typing import Tuple


class GitHubDownloader:
    @staticmethod
    def parse_url(github_url: str) -> Tuple[bool, str, str]:
        """Extract (owner, repo) from a GitHub repository URL."""
        if not github_url or not isinstance(github_url, str):
            return False, "", "GitHub URL is required"

        url = github_url.strip()
        if not url.startswith("http://") and not url.startswith("https://"):
            url = "https://" + url

        parsed = urllib.parse.urlparse(url)
        if "github.com" not in parsed.netloc.lower():
            return False, "", "Must be a valid github.com repository URL"

        path_parts = [p for p in parsed.path.strip("/").split("/") if p]
        if len(path_parts) < 2:
            return False, "", "Invalid GitHub repository URL structure. Use format: https://github.com/owner/repository"

        owner = path_parts[0]
        repo = path_parts[1]
        if repo.endswith(".git"):
            repo = repo[:-4]

        # Sanitize owner and repo names
        if not re.match(r"^[A-Za-z0-9_.-]+$", owner) or not re.match(r"^[A-Za-z0-9_.-]+$", repo):
            return False, "", "Invalid repository or owner name in GitHub URL"

        return True, owner, repo

    @staticmethod
    def download(github_url: str, save_path: str, timeout: int = 30) -> Tuple[bool, str]:
        """Download public repository zip archive into save_path."""
        valid, owner, repo = GitHubDownloader.parse_url(github_url)
        if not valid:
            return False, owner  # owner contains error message

        os.makedirs(os.path.dirname(save_path), exist_ok=True)

        candidate_urls = [
            f"https://github.com/{owner}/{repo}/archive/refs/heads/main.zip",
            f"https://github.com/{owner}/{repo}/archive/refs/heads/master.zip",
            f"https://api.github.com/repos/{owner}/{repo}/zipball",
        ]

        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) CloudSecurityPlatform/1.0",
            "Accept": "application/vnd.github.v3+json, application/zip, */*",
        }

        last_error = ""
        for url in candidate_urls:
            try:
                req = urllib.request.Request(url, headers=headers)
                with urllib.request.urlopen(req, timeout=timeout) as response:
                    if response.status == 200:
                        content = response.read()
                        if len(content) == 0:
                            continue
                        with open(save_path, "wb") as out_file:
                            out_file.write(content)
                        return True, f"Successfully downloaded {owner}/{repo}"
            except Exception as exc:
                last_error = str(exc)
                continue

        return False, (
            f"Unable to download repository from '{github_url}'. "
            f"Ensure the repository is public and accessible. Details: {last_error or 'HTTP Error'}"
        )
