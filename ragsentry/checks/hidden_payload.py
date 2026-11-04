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
from ragsentry.normalize import mixed_script_words

_ZERO_WIDTH_CHARS = {"​", "‌", "‍", "⁠", "﻿"}
_BASE64_BLOB = re.compile(r"\b[A-Za-z0-9+/]{80,}={0,2}\b")


def _is_emoji_char(ch: str) -> bool:
    o = ord(ch)
    return 0x1F300 <= o <= 0x1FAFF or 0x2600 <= o <= 0x27BF or 0x2B00 <= o <= 0x2BFF or o in (0xFE0F, 0x2764)


def _legit_emoji_zwj(line: str, i: int) -> bool:
    """A ZWJ (U+200D) directly joining emoji (family, flag, profession sequences) is not hidden text.

    Same rule memsentry adopted in v1.1 after its 170-file scan found emoji ZWJ sequences were most zero-width hits.
    """
    if line[i] != "\u200d":
        return False
    return i > 0 and i + 1 < len(line) and _is_emoji_char(line[i - 1]) and _is_emoji_char(line[i + 1])


def check_hidden_payload(doc: Document) -> list[Finding]:
    findings: list[Finding] = []

    for line_no, line in enumerate(doc.lines, start=1):
        zw_found = [ch for i, ch in enumerate(line) if ch in _ZERO_WIDTH_CHARS and not _legit_emoji_zwj(line, i)]
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

        mixed = mixed_script_words(line)
        if mixed:
            findings.append(Finding(
                check="hidden_payload",
                severity=Severity.HIGH,
                title="Look-alike letters from another script mixed into words",
                detail=(
                    f"Line {line_no} has {len(mixed)} word(s) mixing Latin letters with look-alikes from another "
                    f"script (e.g. {mixed[0]!r}). They read normally to a human but defeat plain-text phrase "
                    f"matching; ordinary multilingual text keeps each word in one script."
                ),
                file=doc.path,
                line=line_no,
                snippet=line.strip()[:200],
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
