"""
Same structural-trick detection as memsentry's hidden_payload, applied to
RAG source documents: zero-width/invisible Unicode (can hide text inside
a chunk that still gets embedded and later surfaced to a model), and
suspicious base64-shaped blobs (a way to stage or smuggle payload data
inside content that otherwise reads as an ordinary document).
"""

from __future__ import annotations

import re

from ragsentry.document import Document
from ragsentry.findings import Finding, Severity

_ZERO_WIDTH_CHARS = {"​", "‌", "‍", "⁠", "﻿"}
_BASE64_BLOB = re.compile(r"\b[A-Za-z0-9+/]{80,}={0,2}\b")


def check_hidden_payload(doc: Document) -> list[Finding]:
    findings: list[Finding] = []

    for line_no, line in enumerate(doc.lines, start=1):
        zw_found = [ch for ch in line if ch in _ZERO_WIDTH_CHARS]
        if zw_found:
            findings.append(Finding(
                check="hidden_payload",
                severity=Severity.HIGH,
                title="Zero-width/invisible Unicode characters in document",
                detail=(
                    f"Line {line_no} contains {len(zw_found)} invisible Unicode character(s) "
                    f"({', '.join(sorted(set(f'U+{ord(c):04X}' for c in zw_found)))}). Invisible "
                    f"to a human reviewing the source document, but still tokenized once the "
                    f"chunk is retrieved and fed to a model."
                ),
                file=doc.path,
                line=line_no,
                snippet=repr(line.strip()[:200]),
            ))

        blob = _BASE64_BLOB.search(line)
        if blob:
            findings.append(Finding(
                check="hidden_payload",
                severity=Severity.MEDIUM,
                title="Suspicious base64-shaped blob in document",
                detail=(
                    f"Line {line_no} contains a long base64-shaped token "
                    f"({len(blob.group(0))} chars) inside what otherwise reads as ordinary "
                    f"document content."
                ),
                file=doc.path,
                line=line_no,
                snippet=blob.group(0)[:60] + "...",
            ))

    return findings
