import json

from ragsentry.findings import Finding, Severity
from ragsentry.report import max_severity, render_text, to_json


def _f(sev):
    return Finding(check="c", severity=sev, title="t", detail="d", file="x", line=1, snippet="s")


def test_render_text_clean():
    assert "No findings" in render_text({"x": []})


def test_render_text_counts():
    assert "1 finding(s)" in render_text({"x": [_f(Severity.HIGH)]})


def test_to_json_shape():
    payload = json.loads(to_json({"x": [_f(Severity.CRITICAL)]}))
    assert payload["x"][0]["severity"] == "critical"


def test_max_severity_worst():
    assert max_severity({"x": [_f(Severity.LOW), _f(Severity.CRITICAL)]}) == Severity.CRITICAL


def test_max_severity_none():
    assert max_severity({"x": []}) is None
