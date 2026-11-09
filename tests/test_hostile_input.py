"""Regression tests for hostile input (see docs/HARDENING.md). Each case runs in a subprocess with a hard timeout,
so a regex that backtracks catastrophically fails the test instead of hanging the suite."""
import subprocess
import sys

import pytest

CASES = {
    "a_run": '"a" * 80_000',
    "spaces": '" " * 80_000',
    "single_letters": '"a " * 40_000',
    "b64_bad_end": '"A" * 80_000 + "!"',
    "ignore_nospace": '"ignore" * 13_000',
    "stated_tags": '"[stated] " * 9_000',
    "zwsp": '"\\u200b" * 80_000',
    "ligature": '"\\ufb01" * 80_000',
    "nul": '"\\x00" * 80_000',
    "many_blank_lines": '"\\n" * 40_000',
    "many_paragraphs": '"\\n\\n".join(["word word"] * 7_000)',
    "require_ws": '"const " + " " * 80_000 + "= require("',
    "import_ws": '"import a" + " " * 80_000',
    "from_import_ws": '"from a import (" + " " * 80_000',
    "from_import_words": '"from a import " + "b " * 40_000 + "!"',
    "js_import_words": '"import " + "a " * 40_000 + "from"',
    "js_import_braces": '"import {" + "a," * 40_000 + "!"',
    "js_import_ws": '"import " + " " * 80_000 + "x"',
}

CHILD = """
import sys
from ragsentry.document import Document as D
from ragsentry.scanner import scan_document as scan
text = eval(sys.argv[1])
scan(D('x', text.splitlines()))
"""


@pytest.mark.parametrize("name", sorted(CASES))
def test_hostile_input_finishes(name):
    done = subprocess.run([sys.executable, "-c", CHILD, CASES[name]], capture_output=True, text=True, timeout=10)
    assert done.returncode == 0, done.stderr[-500:]
