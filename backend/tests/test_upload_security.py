"""Security tests for ZIP validation and extraction.

The uploaded archive is untrusted input from a browser, so these tests build
genuinely malicious archives and assert that the platform refuses them. Run with:

    cd backend
    python tests/test_upload_security.py
"""
import os
import shutil
import sys
import tempfile
import zipfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from phase1.upload.validator import ZipExtractor, ZipValidator  # noqa: E402

results = []


def check(name: str, passed: bool, detail: str = "") -> None:
    results.append((name, passed, detail))
    print(f"[{'PASS' if passed else 'FAIL'}] {name}" + (f" - {detail}" if detail else ""))


def make_zip(path: str, entries) -> str:
    """entries: iterable of (arcname, content)."""
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        for arcname, content in entries:
            archive.writestr(arcname, content)
    return path


def test_valid_archive(workdir: str) -> None:
    path = make_zip(os.path.join(workdir, "clean.zip"), [
        ("src/app.py", "print('hello')\n"),
        ("README.md", "# Sample\n"),
        ("requirements.txt", "flask==3.0.3\n"),
    ])
    ok, message = ZipValidator.validate(path)
    check("a clean archive is accepted", ok, message)

    extract_to = os.path.join(workdir, "clean_out")
    result = ZipExtractor.extract(path, extract_to)
    check("clean archive extracts every file",
          result["file_count"] == 3 and result["skipped_count"] == 0,
          f"extracted {result['file_count']}, skipped {result['skipped_count']}")


def test_zip_slip(workdir: str) -> None:
    """The classic path traversal: an entry that escapes the extraction root."""
    path = os.path.join(workdir, "slip.zip")
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("safe.py", "ok\n")
        archive.writestr("../../../pwned.txt", "escaped\n")

    ok, message = ZipValidator.validate(path)
    check("validator rejects a traversal entry", not ok, message)

    # Even if validation were bypassed, extraction must confine the entry.
    extract_to = os.path.join(workdir, "slip_out")
    result = ZipExtractor.extract(path, extract_to)
    escaped = os.path.exists(os.path.join(workdir, "pwned.txt")) or \
        os.path.exists(os.path.join(os.path.dirname(workdir), "pwned.txt"))
    check("extractor confines traversal entries",
          not escaped and result["skipped_count"] >= 1,
          f"skipped {result['skipped_count']}")


def test_absolute_path(workdir: str) -> None:
    path = os.path.join(workdir, "absolute.zip")
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("/etc/passwd", "root:x:0:0\n")
    ok, message = ZipValidator.validate(path)
    check("validator rejects an absolute path entry", not ok, message)


def test_executable(workdir: str) -> None:
    """Any extension is accepted, extracted, and available for scanning."""
    path = make_zip(os.path.join(workdir, "exe.zip"), [
        ("app.py", "print(1)\n"),
        ("payload.exe", "MZ\x90\x00binary"),
        ("phishing/start.bat", "@echo off\r\npython app.py\r\n"),
    ])
    ok, message = ZipValidator.validate(path)
    check("archive with any extensions is accepted", ok, message)

    extract_to = os.path.join(workdir, "exe_out")
    result = ZipExtractor.extract(path, extract_to)
    exe_written = os.path.exists(os.path.join(extract_to, "payload.exe"))
    bat_written = os.path.exists(os.path.join(extract_to, "phishing", "start.bat"))
    py_written = os.path.exists(os.path.join(extract_to, "app.py"))
    check("every extension is extracted for scanning",
          exe_written and bat_written and py_written and result["file_count"] == 3,
          f"files={result['file_count']} skipped={result['skipped_count']}")


def test_venv_dll_allowed(workdir: str) -> None:
    """Python virtualenvs ship native .dll files; those must not block upload."""
    path = make_zip(os.path.join(workdir, "venv.zip"), [
        ("app.py", "print(1)\n"),
        ("phishing/.venv/Lib/site-packages/numpy.libs/openblas.dll", "MZ\x00dll"),
        ("node_modules/some-pkg/native.so", "\x7fELFfake"),
    ])
    ok, message = ZipValidator.validate(path)
    check("validator allows binaries inside .venv / node_modules", ok, message)

    extract_to = os.path.join(workdir, "venv_out")
    result = ZipExtractor.extract(path, extract_to)
    extracted_app = os.path.exists(os.path.join(extract_to, "app.py"))
    venv_landed = os.path.exists(os.path.join(
        extract_to, "phishing", ".venv", "Lib", "site-packages", "numpy.libs", "openblas.dll",
    ))
    check("extractor keeps source and skips dependency trees",
          extracted_app and not venv_landed and result["file_count"] == 1,
          f"files={result['file_count']} skipped={result['skipped_count']}")


def test_zip_bomb(workdir: str) -> None:
    """A highly compressible file expands far beyond its stored size."""
    path = os.path.join(workdir, "bomb.zip")
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        archive.writestr("bomb.txt", "A" * (60 * 1024 * 1024))
    ok, message = ZipValidator.validate(path)
    check("validator rejects a decompression bomb", not ok, message)


def test_empty_archive(workdir: str) -> None:
    path = os.path.join(workdir, "empty.zip")
    with zipfile.ZipFile(path, "w"):
        pass
    ok, message = ZipValidator.validate(path)
    check("validator rejects an empty archive", not ok, message)


def test_not_a_zip(workdir: str) -> None:
    path = os.path.join(workdir, "fake.zip")
    with open(path, "wb") as handle:
        handle.write(b"this is definitely not a zip file")
    ok, message = ZipValidator.validate(path)
    check("validator rejects a non-ZIP file", not ok, message)


def test_missing_file(workdir: str) -> None:
    ok, message = ZipValidator.validate(os.path.join(workdir, "does_not_exist.zip"))
    check("validator rejects a missing file", not ok, message)


def test_nested_directories(workdir: str) -> None:
    """Legitimate deep nesting must still extract correctly."""
    path = make_zip(os.path.join(workdir, "nested.zip"), [
        ("a/b/c/d/deep.py", "x = 1\n"),
        ("a/b/other.js", "const y = 2;\n"),
    ])
    ok, _ = ZipValidator.validate(path)
    extract_to = os.path.join(workdir, "nested_out")
    result = ZipExtractor.extract(path, extract_to)
    landed = os.path.exists(os.path.join(extract_to, "a", "b", "c", "d", "deep.py"))
    check("nested directories extract correctly",
          ok and result["file_count"] == 2 and landed)


def main() -> int:
    workdir = tempfile.mkdtemp(prefix="upload_security_")
    try:
        test_valid_archive(workdir)
        test_zip_slip(workdir)
        test_absolute_path(workdir)
        test_executable(workdir)
        test_venv_dll_allowed(workdir)
        test_zip_bomb(workdir)
        test_empty_archive(workdir)
        test_not_a_zip(workdir)
        test_missing_file(workdir)
        test_nested_directories(workdir)
    finally:
        shutil.rmtree(workdir, ignore_errors=True)

    failed = [name for name, passed, _ in results if not passed]
    print()
    if failed:
        print(f"{len(failed)} of {len(results)} checks FAILED:")
        for name in failed:
            print(f"  - {name}")
        return 1

    print(f"All {len(results)} upload security checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
