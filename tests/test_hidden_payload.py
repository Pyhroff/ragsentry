from ragsentry.checks.hidden_payload import check_hidden_payload
from ragsentry.document import Document


def test_clean_line_no_findings():
    assert check_hidden_payload(Document(path="x", lines=["ordinary text"])) == []


def test_flags_zero_width_chars():
    doc = Document(path="x", lines=["normal​text﻿here"])
    findings = check_hidden_payload(doc)
    assert any("Zero-width" in f.title for f in findings)


def test_flags_base64_blob():
    doc = Document(path="x", lines=["data: " + "A" * 90])
    findings = check_hidden_payload(doc)
    assert any("base64" in f.title.lower() for f in findings)
