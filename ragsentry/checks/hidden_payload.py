"""
Same structural-trick detection as memsentry's hidden_payload, applied to
RAG source documents: zero-width/invisible Unicode, including Unicode tag
characters that can spell out a whole instruction (they hide text inside a
chunk that still gets embedded and later surfaced to a model), and
suspicious base64-shaped blobs (a way to stage or smuggle payload data
inside content that otherwise reads as an ordinary document).
"""

from __future__ import annotations

import re

from ragsentry.document import Document
from ragsentry.findings import Finding, Severity
from ragsentry.normalize import mixed_script_words

# Characters that render as nothing (or reorder what is shown) while a model still reads them: zero-width
# spaces/joiners, the BOM, invisible maths operators and bidi embedding/override/isolate controls ("Trojan Source").
_ZERO_WIDTH_CHARS = frozenset(
    "\u200b\u200c\u200d\u2060\ufeff"
    "\u2061\u2062\u2063\u2064"
    "\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069"
)
_BLACK_FLAG = "\U0001f3f4"
_CANCEL_TAG = "\U000e007f"
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


def _is_tag(ch: str) -> bool:
    return 0xE0000 <= ord(ch) <= 0xE007F


def _hidden_chars(line: str) -> list[str]:
    """Invisible characters on a line, skipping legitimate emoji constructions.

    Unicode tag characters (U+E0000-U+E007F) are reported as a run: they can spell out a complete hidden
    instruction ("ASCII smuggling"). The one legitimate use, a subdivision flag such as Scotland's (black flag +
    tag letters + CANCEL TAG), is not reported; nor is a zero-width joiner between two emoji.
    """
    found: list[str] = []
    i, n = 0, len(line)
    while i < n:
        ch = line[i]
        if _is_tag(ch):
            j = i
            while j < n and _is_tag(line[j]):
                j += 1
            run = line[i:j]
            if not (i > 0 and line[i - 1] == _BLACK_FLAG and len(run) >= 2 and run.endswith(_CANCEL_TAG)):
                found.extend(run)
            i = j
            continue
        if ch in _ZERO_WIDTH_CHARS and not _legit_emoji_zwj(line, i):
            found.append(ch)
        i += 1
    return found


def check_hidden_payload(doc: Document) -> list[Finding]:
    findings: list[Finding] = []

    for line_no, line in enumerate(doc.lines, start=1):
        zw_found = _hidden_chars(line) if not line.isascii() else []
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
