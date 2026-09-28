from __future__ import annotations

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


def scan_path(path: str) -> dict[str, list[Finding]]:
    p = Path(path)
    files = sorted(f for f in p.rglob("*") if f.is_file()) if p.is_dir() else [p]
    return {str(f): scan_document(Document.load(str(f))) for f in files}
