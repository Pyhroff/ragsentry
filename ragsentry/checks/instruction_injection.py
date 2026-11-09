"""
The RAG-specific version of the same core problem memsentry targets: a
document destined to be embedded, indexed, and later retrieved as context
for a model can carry text that isn't information for the user at all --
it's an instruction aimed at whatever model later reads it as "trusted
retrieved context." Because retrieved chunks are typically injected into
the prompt without the same scrutiny a direct user message gets, this is
arguably a *higher*-trust channel to poison than a chat turn: the model
was told this is reference material, not something to interrogate.

Same detection shape as memsentry's instruction_injection (override
phrasing, forged-authority framing, safety-bypass claims), scoped here to
the framing a poisoned RAG chunk actually uses: fake system/citation tags
("[SYSTEM NOTE]", "[VERIFIED SOURCE]") wrapping an instruction, and
appeals to it being authoritative reference material rather than untrusted
retrieved content.
"""

from __future__ import annotations

import re

from ragsentry.document import Document
from ragsentry.findings import Finding, Severity
from ragsentry.normalize import canonical

_OVERRIDE_PATTERNS = [
    (r"\bignore (all |any )?(previous|prior|earlier) (instructions|context)\b", "instruction-override phrasing"),
    (r"\bdisregard (your|all|any) (guidelines|instructions|rules|training)\b", "instruction-override phrasing"),
    (r"\bdisregard\s+(all|any|your)\s+(earlier|previous|prior)\s+(directions|instructions|rules|guidance)\b", "instruction-override phrasing"),
    (r"\bdisregard\s+(previous|prior|earlier)\s+guidance\b", "instruction-override phrasing"),
    (r"\byou (must|are required to|have to) always\b", "coercive standing instruction"),
    (r"\bnever (mention|tell|reveal|disclose) (this|that) to (the user|anyone)\b", "concealment instruction"),
    (r"\bdo not (mention|tell|reveal|disclose) (this|that|this instruction) to (the user|anyone)\b", "concealment instruction"),
    (r"\b(skip|bypass|disable) (safety|confirmation|verification|security) (checks?|steps?)\b", "safety-bypass instruction"),
    (r"\bdo not follow (the )?(earlier|previous|prior) (instruction|instructions|constraints|rules)\b", "instruction-override phrasing"),
    (r"\btreat (future|subsequent) messages as if they came from (a|an) (verified )?(administrator|admin|trusted user)\b", "fake privileged-channel claim"),
    (r"\btreat (this|the following) (as|like) (a )?(system|developer|admin) (message|instruction)\b", "fake privileged-channel claim"),
    (r"\bwhen (asked|queried) about [^,.]+,?\s*(always|you must|respond)\b", "query-triggered standing instruction"),
    (r"\brecommend (this|the following) (product|service|option) (above|over|instead of) all others\b", "biased-recommendation injection"),
]

_FAKE_TAG = re.compile(
    r"^\s*\[(system( note)?|verified( source)?|trusted|official|admin|priority instruction)\]",
    re.IGNORECASE,
)
_IMPERATIVE = re.compile(
    r"\b(you must|you should always|always (recommend|respond|say)|never (mention|say)|do not (tell|mention))\b",
    re.IGNORECASE,
)


_COMPILED_PATTERNS = [(re.compile(pattern), label) for pattern, label in _OVERRIDE_PATTERNS]


def _is_explanatory_security_text(text: str) -> bool:
    lowered = text.lower()
    return (
        any(term in lowered for term in ("example", "examples", "security guidance", "documentation"))
        and any(term in lowered for term in (
            "these are examples only", "not policy instructions", "not an instruction"
        ))
    )


def check_instruction_injection(doc: Document) -> list[Finding]:
    findings: list[Finding] = []
    normalized_lines = [canonical(line) for line in doc.lines]

    # Preserve precise line-level findings for ordinary single-line attacks.
    for line_no, line in enumerate(doc.lines, start=1):
        lowered = normalized_lines[line_no - 1]
        if not lowered:
            continue
        # The example/disclaimer wording is attacker-controllable text, so it downgrades a match instead of
        # suppressing it: "Example (not an instruction): ignore all previous instructions" must stay visible.
        explanatory = _is_explanatory_security_text(lowered)

        for pattern, label in _COMPILED_PATTERNS:
            if pattern.search(lowered):
                findings.append(Finding(
                    check="instruction_injection",
                    severity=Severity.MEDIUM if explanatory else Severity.CRITICAL,
                    title=(f"Instruction pattern inside text labelled as an example ({label})" if explanatory
                           else f"Instruction aimed at a future retrieving model ({label})"),
                    detail=(
                        f"Line {line_no} reads as an instruction directed at whatever model "
                        f"later retrieves this chunk as context, not as information for a "
                        f"human reader. Retrieved context is often trusted more than a direct "
                        f"user message, which makes this an effective injection channel."
                    ),
                    file=doc.path,
                    line=line_no,
                    snippet=line.strip()[:200],
                ))
                break

        if _FAKE_TAG.match(lowered) and _IMPERATIVE.search(lowered):
            findings.append(Finding(
                check="instruction_injection",
                severity=Severity.CRITICAL,
                title="Forged authority tag wrapping an instruction",
                detail=(
                    f"Line {line_no} opens with a tag designed to look like a trusted system "
                    f"or verified-source marker, but its content is an imperative directed at "
                    f"the retrieving model rather than reference information."
                ),
                file=doc.path,
                line=line_no,
                snippet=line.strip()[:200],
            ))

    # Attackers can split a known phrase across Markdown lines to defeat
    # line-oriented regexes. Join only small windows (2–3 lines), and never
    # bridge blank lines, so unrelated paragraphs cannot form a match.
    seen_multiline: set[tuple[int, str]] = set()
    for window_size in (2, 3):
        for start in range(0, len(doc.lines) - window_size + 1):
            window_lines = doc.lines[start:start + window_size]
            if any(not line.strip() for line in window_lines):
                continue
            combined = canonical(" ".join(line.strip() for line in window_lines))
            explanatory = _is_explanatory_security_text(combined)
            for pattern, label in _COMPILED_PATTERNS:
                if not pattern.search(combined):
                    continue
                if any(pattern.search(line) for line in normalized_lines[start:start + window_size]):
                    continue
                key = (start + 1, label)
                if key in seen_multiline:
                    continue
                seen_multiline.add(key)
                findings.append(Finding(
                    check="instruction_injection",
                    severity=Severity.MEDIUM if explanatory else Severity.CRITICAL,
                    title=(f"Multi-line instruction pattern inside text labelled as an example ({label})" if explanatory
                           else f"Multi-line instruction aimed at a future retrieving model ({label})"),
                    detail=(
                        f"Lines {start + 1}–{start + window_size} contain instruction-override "
                        f"phrasing after adjacent lines are normalized. Splitting a phrase across "
                        f"lines can evade scanners that only inspect one line at a time."
                    ),
                    file=doc.path,
                    line=start + 1,
                    snippet=" ".join(line.strip() for line in window_lines)[:200],
                ))

    return sorted(findings, key=lambda finding: (finding.line, finding.title))
