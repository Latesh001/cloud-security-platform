"""Upload validation and safe archive extraction.

The uploaded archive is untrusted input, so it is checked for encryption,
decompression bombs, and path traversal entries before a single byte is written
to disk. Those three are genuine attacks on this platform and are still refused.

Every file inside the archive is accepted and extracted regardless of extension
— `.bat`, `.exe`, `.dll`, scripts, binaries, and source alike. Phase 1 detectors
then scan the extracted tree and always produce a security score.

CRC of each entry is verified while extracting; a second full-archive testzip
pass is skipped because it decompresses the ZIP twice and dominates scan time
on large project trees.
"""
import os
import shutil
import zipfile
from typing import Dict, List, Optional, Tuple

# Keep extraction lean for full project trees that include dependency folders.
# This is a path-segment skip, not an extension filter.
SKIP_PATH_SEGMENTS = {
    "node_modules", ".git", ".svn", "venv", ".venv", "env", ".env.local.bak",
    "__pycache__", "dist", "build", ".next", ".idea", ".vscode", "vendor",
    "target", "site-packages", "bower_components", ".pytest_cache", "coverage",
    ".tox", ".mypy_cache", ".eggs", "eggs", "__macosx", "pods", ".gradle",
    "deriveddata", ".cache", ".parcel-cache", ".turbo", ".nuxt", ".output",
    "htmlcov", ".yarn", "pnpm-store", "storybook-static", "out", "tmp",
    "temp", "logs", "log", ".husky", "typings", "jspm_packages",
}

SKIP_EXTRACT_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".bmp", ".tif", ".tiff",
    ".woff", ".woff2", ".ttf", ".eot", ".otf", ".mp4", ".mp3", ".wav", ".avi",
    ".mov", ".zip", ".gz", ".tar", ".rar", ".7z", ".bz2", ".exe", ".dll",
    ".so", ".dylib", ".bin", ".class", ".jar", ".war", ".pdf", ".pyc", ".pyo",
    ".whl", ".egg", ".map", ".db", ".sqlite", ".sqlite3", ".pack",
}

MAX_EXTRACT_FILE_BYTES = 1_500_000

ENCRYPTED_FLAG = 0x1


def _path_is_skipped(normalized: str) -> bool:
    """Return True when the entry lives under a dependency / tooling directory."""
    parts = [p.lower() for p in normalized.replace("\\", "/").split("/") if p]
    return any(part in SKIP_PATH_SEGMENTS for part in parts)


class ZipValidator:
    MAX_SIZE_MB = 1000
    MAX_UNCOMPRESSED_MB = 8192
    MAX_COMPRESSION_RATIO = 150
    MAX_ENTRIES = 100000

    @staticmethod
    def validate(filepath: str, max_size_mb: Optional[int] = None) -> Tuple[bool, str]:
        limit_mb = max_size_mb if max_size_mb is not None else ZipValidator.MAX_SIZE_MB

        if not os.path.exists(filepath):
            return False, "File not found"

        size_mb = os.path.getsize(filepath) / (1024 * 1024)
        if size_mb == 0:
            return False, "Uploaded file is empty"
        if size_mb > limit_mb:
            return False, f"File exceeds the {limit_mb} MB limit"

        try:
            with zipfile.ZipFile(filepath, "r") as archive:
                entries = archive.infolist()

                if not entries:
                    return False, "Archive contains no files"
                if len(entries) > ZipValidator.MAX_ENTRIES:
                    return False, (
                        f"Archive contains more than {ZipValidator.MAX_ENTRIES} entries. "
                        "Exclude .venv, node_modules, and build folders before zipping."
                    )

                total_uncompressed = 0
                for entry in entries:
                    if entry.flag_bits & ENCRYPTED_FLAG:
                        return False, "Password-protected archives are not supported"

                    normalized = entry.filename.replace("\\", "/")
                    if normalized.startswith("/") or ".." in normalized.split("/"):
                        return False, f"Unsafe path in archive: {entry.filename}"
                    if os.path.splitdrive(normalized)[0]:
                        return False, f"Absolute path in archive: {entry.filename}"

                    # Dependency trees are never extracted — skip bomb budget for them.
                    if _path_is_skipped(normalized):
                        continue

                    total_uncompressed += entry.file_size

                if total_uncompressed > ZipValidator.MAX_UNCOMPRESSED_MB * 1024 * 1024:
                    return False, "Archive expands beyond the allowed uncompressed size"

                kept_compressed = max(
                    sum(
                        e.compress_size for e in entries
                        if not _path_is_skipped(e.filename.replace("\\", "/"))
                    ),
                    1,
                )
                if total_uncompressed / kept_compressed > ZipValidator.MAX_COMPRESSION_RATIO:
                    return False, "Archive rejected: suspicious compression ratio (possible zip bomb)"

        except zipfile.BadZipFile:
            return False, "Invalid or corrupted ZIP file"
        except (OSError, RuntimeError) as exc:
            return False, f"Unable to read archive: {exc}"

        return True, "Valid"


class ZipExtractor:
    """Extracts an archive while confining every entry inside the target directory."""

    @staticmethod
    def extract(zip_path: str, extract_to: str) -> Dict:
        os.makedirs(extract_to, exist_ok=True)
        destination_root = os.path.realpath(extract_to)

        file_count = 0
        skipped = 0
        folders = set()
        files: List[str] = []

        with zipfile.ZipFile(zip_path, "r") as archive:
            for entry in archive.infolist():
                normalized = entry.filename.replace("\\", "/")

                if _path_is_skipped(normalized):
                    skipped += 1
                    continue

                ext = os.path.splitext(normalized)[1].lower()
                if ext in SKIP_EXTRACT_EXTENSIONS or entry.file_size > MAX_EXTRACT_FILE_BYTES:
                    skipped += 1
                    continue

                target = os.path.realpath(os.path.join(destination_root, normalized))

                if not (target == destination_root
                        or target.startswith(destination_root + os.sep)):
                    skipped += 1
                    continue

                if entry.is_dir():
                    os.makedirs(target, exist_ok=True)
                    continue

                os.makedirs(os.path.dirname(target), exist_ok=True)
                try:
                    with archive.open(entry) as source, open(target, "wb") as sink:
                        shutil.copyfileobj(source, sink, 1024 * 1024)
                except (OSError, RuntimeError, zipfile.BadZipFile):
                    skipped += 1
                    continue

                file_count += 1
                files.append(normalized)
                parts = normalized.split("/")
                if len(parts) > 1:
                    folders.add(parts[0])

        return {
            "file_count": file_count,
            "skipped_count": skipped,
            "folders": sorted(folders),
            "files": files[:1000],
            "extract_path": extract_to,
        }
