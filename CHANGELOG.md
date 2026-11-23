# Changelog

## Unreleased

- **Security fix: instructions hidden in Unicode tag characters were not detected.** Tag characters (U+E0020-U+E007E, "ASCII smuggling") render as nothing but are read by models. `canonical()` deleted them as format characters and hidden_payload only knew five zero-width code points, so a document line carrying a complete hidden instruction scanned as clean. Tag characters are now decoded to the ASCII they mirror before the phrase rules run, and reported by hidden_payload.
- hidden_payload's invisible-character finding also covers bidi embedding/override/isolate controls ("Trojan Source") and the invisible maths operators U+2061-U+2064; subdivision-flag tag sequences (e.g. the flag of Scotland) are not reported. The finding title is unchanged.
- Directory scans skip VCS, dependency, cache and build directories (`.git`, `node_modules`, `.venv`, `__pycache__`, ...) and binary files, so a repository root no longer reports git pack files and bytecode as documents. A file named explicitly is always scanned.
- A missing path or an unknown `--fail-on` value is reported as a usage error (exit 2) before scanning.
- Packaging: SPDX `license = "MIT"` (PEP 639), Python 3.14 tested and declared, and the PyPI changelog link points at the default branch.
- Phrase rules now match on a canonical form of each line (`ragsentry/normalize.py`): NFKC, invisible format characters dropped, Cyrillic/Greek/Armenian look-alike letters folded to Latin, spaced-out letters re-joined, whitespace collapsed. Before this, doubling the spaces between words, swapping a few letters for Cyrillic look-alikes, or writing `i g n o r e` removed every high/critical finding from `samples/poisoned_doc.md`; now all of them survive.
- hidden_payload: new HIGH finding for words that mix Latin letters with look-alikes from another script (4+ characters, so maths notation like `Fβ` is not flagged).
- instruction_injection: text that labels itself as an example or disclaimer ("not an instruction") is now reported at MEDIUM instead of being dropped. The disclaimer is attacker-controllable, so it can no longer hide a real injection; use `--fail-on medium` to gate on it.
- No change in findings on 854 real README/CLAUDE.md/AGENTS.md/docs files used as a false-positive check.
- hidden_payload: emoji ZWJ sequences are no longer reported as invisible characters (the memsentry v1.2 fix, now ported).

## [1.1.0] -- fake_remediation check (Agentjacking-grounded)

New detection category: content in a retrieved RAG document that's framed
as a trusted remediation/troubleshooting suggestion (the kind of thing an
agent is supposed to trust and act on from a monitoring or error-tracking
source) paired with an actual actionable command or credential reference.

Based on the "Agentjacking" attack described in a Cloud Security Alliance
research note (June 2026): a malicious Sentry error event formatted to look
like a legitimate remediation suggestion.
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
