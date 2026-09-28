"""
Grounded in a real, documented 2026 attack: "Agentjacking" (Cloud Security
Alliance, June 2026). Attackers posted malicious events to a public-facing
service ingestion API (Sentry), formatted with markdown so that, when
rendered, they "look like a legitimate Sentry remediation suggestion."
When a developer asked a coding agent to investigate the issue, the agent
retrieved and executed the embedded instructions as if they were genuine
troubleshooting guidance -- an 85% exploitation success rate, exfiltrating
real credentials, because the attack dresses up as the exact kind of
content an agent is SUPPOSED to trust and act on (a fix suggestion from a
monitoring/error-tracking tool), not as an obvious injection attempt.

This is a distinct manipulation shape from instruction_injection: it
doesn't need override phrasing ("ignore previous instructions") at all --
it just needs to look like the genre of content an agent already expects
to receive and act on from a retrieved/ingested source, paired with an
actual actionable command (run this, set this env var, use this key).
"""

from __future__ import annotations

import re

from ragsentry.document import Document
from ragsentry.findings import Finding, Severity

_REMEDIATION_FRAMING = re.compile(
    r"\b(recommended|suggested)\s+(fix|remediation|resolution)\b|"
    r"\bto\s+(resolve|fix)\s+this,?\s+(run|execute|set|use)\b|"
    r"\btroubleshooting\s+steps?:\s*$",
    re.IGNORECASE,
)

_ACTIONABLE_COMMAND = re.compile(
    r"\b(curl|wget|export|eval|bash -c)\b|"
    r"\b(api[_\s-]?key|access[_\s-]?token|credentials?|secret)\b.{0,30}\b(is|:|=)\b|"
    r"\bsend\b.{0,20}\bto\s+https?://",
    re.IGNORECASE,
)


def check_fake_remediation(doc: Document) -> list[Finding]:
    findings: list[Finding] = []

    for line_no, line in enumerate(doc.lines, start=1):
        if _REMEDIATION_FRAMING.search(line):
            # Look at this line plus a couple of following lines for an
            # actual actionable/exfiltration-shaped payload -- a genuine
            # remediation note ("recommended fix: upgrade to v2.3") is
            # common and fine on its own; it's the framing PLUS a command
            # or credential reference together that's the real signal.
            window = " ".join(doc.lines[line_no - 1: line_no + 2])
            if _ACTIONABLE_COMMAND.search(window):
                findings.append(Finding(
                    check="fake_remediation",
                    severity=Severity.CRITICAL,
                    title="Content framed as a trusted remediation suggestion, paired with an actionable command",
                    detail=(
                        f"Line {line_no} is framed as the kind of troubleshooting/remediation "
                        f"guidance an agent is expected to trust and act on from a monitoring "
                        f"or error-tracking source, and it's paired with an actual command or "
                        f"credential reference nearby. This is the documented 'Agentjacking' "
                        f"pattern (malicious content dressed as a legitimate fix suggestion, "
                        f"rather than an obvious override attempt) -- it doesn't need "
                        f"instruction-override phrasing to be dangerous."
                    ),
                    file=doc.path,
                    line=line_no,
                    snippet=window.strip()[:200],
                ))

    return findings
