"""RAG-source instruction-injection detection, including line-split evasions."""

from __future__ import annotations

import re

from ragsentry.document import Document
from ragsentry.findings import Finding, Severity

_OVERRIDE_PATTERNS = [
    (r"\\bignore (all |any )?(previous|prior|earlier) (instructions|context)\\b", "instruction-override phrasing"),
    (r"\\bdisregard (your|all|any) (guidelines|instructions|rules|training)\\b", "instruction-override phrasing"),
    (r"\\bdisregard\\s+(all|any|your)\\s+(earlier|previous|prior)\\s+(directions|instructions|rules|guidance)\\b", "instruction-override phrasing"),
    (r"\\bdisregard\\s+(previous|prior|earlier)\\s+guidance\\b", "instruction-override phrasing"),
    (r"\\byou (must|are required to|have to) always\\b", "coercive standing instruction"),
    (r"\\bnever (mention|tell|reveal|disclose) (this|that) to (the user|anyone)\\b", "concealment instruction"),
    (r"\\bdo not (mention|tell|reveal|disclose) (this|that|this instruction) to (the user|anyone)\\b", "concealment instruction"),
    (r"\\b(skip|bypass|disable) (safety|confirmation|verification|security) (checks?|steps?)\\b", "safety-bypass instruction"),
    (r"\\bdo not follow (the )?(earlier|previous|prior) (instruction|instructions|constraints|rules)\\b", "instruction-override phrasing"),
    (r"\\btreat (future|subsequent) messages as if they came from (a|an) (verified )?(administrator|admin|trusted user)\\b", "fake privileged-channel claim"),
    (r"\\btreat (this|the following) (as|like) (a )?(system|developer|admin) (message|instruction)\\b", "fake privileged-channel claim"),
    (r"\\bwhen (asked|queried) about [^,.]+,?\\s*(always|you must|respond)\\b", "query-triggered standing instruction"),
    (r"\\brecommend (this|the following) (product|service|option) (above|over|instead of) all others\\b", "biased-recommendation injection"),
]

_FAKE_TAG = re.compile(r"^\\s*\\[(system( note)?|verified( source)?|trusted|official|admin|priority instruction)\\]", re.IGNORECASE)
_IMPERATIVE = re.compile(r"\\b(you must|you should always|always (recommend|respond|say)|never (mention|say)|do not (tell|mention))\\b", re.IGNORECASE)


def _is_explanatory_security_text(text: str) -> bool:
    lowered = text.lower()
    return (
        any(term in lowered for term in ("example", "examples", "security guidance", "documentation"))
        and any(term in lowered for term in ("these are examples only", "not policy instructions", "not an instruction"))
    )


def check_instruction_injection(doc: Document) -> list[Finding]:
    findings: list[Finding] = []
    normalized_lines = [line.lower() for line in doc.lines]

    for line_no, line in enumerate(doc.lines, start=1):
        lowered = normalized_lines[line_no - 1]
        if _is_explanatory_security_text(lowered):
            continue
        for pattern, label in _OVERRIDE_PATTERNS:
            if re.search(pattern, lowered):
                findings.append(Finding(
                    check="instruction_injection", severity=Severity.CRITICAL,
                    title=f"Instruction aimed at a future retrieving model ({label})",
                    detail=(f"Line {line_no} reads as an instruction directed at whatever model later retrieves this chunk as context, not as information for a human reader. Retrieved context is often trusted more than a direct user message, which makes this an effective injection channel."),
                    file=doc.path, line=line_no, snippet=line.strip()[:200],
                ))
                break
        if _FAKE_TAG.match(line) and _IMPERATIVE.search(lowered):
            findings.append(Finding(
                check="instruction_injection", severity=Severity.CRITICAL,
                title="Forged authority tag wrapping an instruction",
                detail=(f"Line {line_no} opens with a tag designed to look like a trusted system or verified-source marker, but its content is an imperative directed at the retrieving model rather than reference information."),
                file=doc.path, line=line_no, snippet=line.strip()[:200],
            ))

    # Joining adjacent lines catches Markdown-wrapped phrases while keeping
    # paragraph boundaries intact and limiting accidental cross-document matches.
    seen_multiline: set[tuple[int, str]] = set()
    for window_size in (2, 3):
        for start in range(0, len(doc.lines) - window_size + 1):
            window_lines = doc.lines[start:start + window_size]
            if any(not line.strip() for line in window_lines):
                continue
            combined = " ".join(line.strip() for line in window_lines).lower()
            if _is_explanatory_security_text(combined):
                continue
            for pattern, label in _OVERRIDE_PATTERNS:
                if not re.search(pattern, combined):
                    continue
                if any(re.search(pattern, line) for line in normalized_lines[start:start + window_size]):
                    continue
                key = (start + 1, label)
                if key in seen_multiline:
                    continue
                seen_multiline.add(key)
                findings.append(Finding(
                    check="instruction_injection", severity=Severity.CRITICAL,
                    title=f"Multi-line instruction aimed at a future retrieving model ({label})",
                    detail=(f"Lines {start + 1}–{start + window_size} contain instruction-override phrasing after adjacent lines are normalized. Splitting a phrase across lines can evade scanners that only inspect one line at a time."),
                    file=doc.path, line=start + 1,
                    snippet=" ".join(line.strip() for line in window_lines)[:200],
                ))

    return sorted(findings, key=lambda finding: (finding.line, finding.title))
