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

_OVERRIDE_PATTERNS = [
    (r"\bignore (all |any )?(previous|prior|earlier) (instructions|context)\b", "instruction-override phrasing"),
    (r"\bdisregard (your|all|any) (guidelines|instructions|rules|training)\b", "instruction-override phrasing"),
    (r"\bdisregard\s+(all|any|your)\s+(earlier|previous|prior)\s+(directions|instructions|rules)\b", "instruction-override phrasing"),
    (r"\byou (must|are required to|have to) always\b", "coercive standing instruction"),
    (r"\bnever (mention|tell|reveal|disclose) (this|that) to (the user|anyone)\b", "concealment instruction"),
    (r"\b(skip|bypass|disable) (safety|confirmation|verification|security) (checks?|steps?)\b",
     "safety-bypass instruction"),
    (r"\bdo not follow (the )?(earlier|previous|prior) (instruction|instructions|constraints|rules)\b", "instruction-override phrasing"),
    (r"\btreat (future|subsequent) messages as if they came from (a|an) (verified )?(administrator|admin|trusted user)\b", "fake privileged-channel claim"),
    (r"\btreat (this|the following) (as|like) (a )?(system|developer|admin) (message|instruction)\b",
     "fake privileged-channel claim"),
    (r"\bwhen (asked|queried) about [^,.]+,?\s*(always|you must|respond)\b",
     "query-triggered standing instruction"),
    (r"\brecommend (this|the following) (product|service|option) (above|over|instead of) all others\b",
     "biased-recommendation injection"),
]

_FAKE_TAG = re.compile(
    r"^\s*\[(system( note)?|verified( source)?|trusted|official|admin|priority instruction)\]",
    re.IGNORECASE,
)
_IMPERATIVE = re.compile(
    r"\b(you must|you should always|always (recommend|respond|say)|never (mention|say)|do not (tell|mention))\b",
    re.IGNORECASE,
)


def check_instruction_injection(doc: Document) -> list[Finding]:
    findings: list[Finding] = []

    for line_no, line in enumerate(doc.lines, start=1):
        lowered = line.lower()
        explanatory_security_text = (
            any(term in lowered for term in ("example", "examples", "security guidance", "documentation"))
            and any(term in lowered for term in ("these are examples only", "not policy instructions", "not an instruction"))
        )
        if explanatory_security_text:
            continue

        for pattern, label in _OVERRIDE_PATTERNS:
            if re.search(pattern, lowered):
                findings.append(Finding(
                    check="instruction_injection",
                    severity=Severity.CRITICAL,
                    title=f"Instruction aimed at a future retrieving model ({label})",
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

        if _FAKE_TAG.match(line) and _IMPERATIVE.search(lowered):
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

    return findings
