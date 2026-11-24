from __future__ import annotations

import os
from collections.abc import Iterator
from pathlib import Path

from ragsentry.checks.fake_remediation import check_fake_remediation
from ragsentry.checks.hidden_payload import check_hidden_payload
from ragsentry.checks.instruction_injection import check_instruction_injection
from ragsentry.checks.retrieval_manipulation import check_retrieval_manipulation
from ragsentry.document import Document
from ragsentry.findings import Finding, Severity

_ALL_CHECKS = [
    check_instruction_injection,
    check_hidden_payload,
    check_retrieval_manipulation,
    check_fake_remediation,
]

_SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
}


def scan_document(doc: Document) -> list[Finding]:
    findings: list[Finding] = []
    for check in _ALL_CHECKS:
        findings.extend(check(doc))
    findings.sort(key=lambda f: (_SEVERITY_ORDER[f.severity], f.line, f.check))
    return findings


# Directories that never hold retrievable documents: VCS internals, dependency trees, tool caches and build output.
# Hidden directories in general are NOT skipped; a knowledge base can live under any name.
_SKIP_DIRS = frozenset({
    ".git", ".hg", ".svn", "node_modules", "venv", ".venv", "__pycache__",
    ".ruff_cache", ".pytest_cache", ".mypy_cache", ".tox", ".nox", "dist", "build",
})


def _is_binary(path: Path) -> bool:
    """A NUL byte in the first 8 KiB (the heuristic git uses). Unreadable files count as binary: nothing to scan."""
    try:
        with path.open("rb") as fh:
            return b"\0" in fh.read(8192)
    except OSError:
        return True


def _iter_text_files(root: Path) -> Iterator[Path]:
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS and not d.endswith(".egg-info")]
        for name in filenames:
            f = Path(dirpath) / name
            if f.is_file() and not _is_binary(f):
                yield f


def scan_path(path: str) -> dict[str, list[Finding]]:
    """Scan one document, or every text file under a directory.

    Directory scans skip VCS/dependency/cache/build directories and binary files, so pointing the scanner at a
    repository root does not report git pack files or bytecode as "documents". A file named explicitly is
    always scanned.
    """
    p = Path(path)
    files = sorted(_iter_text_files(p)) if p.is_dir() else [p]
    return {str(f): scan_document(Document.load(str(f))) for f in files}
