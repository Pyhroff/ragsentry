# Changelog

## [1.1.0] -- fake_remediation check (Agentjacking-grounded)

New detection category: content in a retrieved RAG document that's framed
as a trusted remediation/troubleshooting suggestion (the kind of thing an
agent is supposed to trust and act on from a monitoring or error-tracking
source) paired with an actual actionable command or credential reference.

Grounded in a real, documented attack: "Agentjacking" (Cloud Security
Alliance, June 2026) -- a malicious Sentry error event formatted to look
like a legitimate remediation suggestion, achieving an 85% exploitation
success rate against real coding agents that retrieved and acted on it.
This is a distinct manipulation shape from instruction_injection: it needs
no override phrasing at all, just the genre-conventions of content an
agent already expects to trust.

6 new tests (32 total, all passing), including a false-positive guard for
genuine harmless remediation notes ("upgrade to v2.3") and a guard against
flagging an ordinary command mention with no remediation framing at all.

## [1.0.0] -- initial release

Static scanner for RAG source documents: instruction_injection (override
phrasing aimed at a future retrieving model, plus forged-authority-tag
detection), hidden_payload (zero-width Unicode, base64 blobs), and
retrieval_manipulation (keyword stuffing, query-bait). Schema-agnostic
plain-text loading, CLI with --json and --fail-on, 26 tests.
