"""Hostile-input stress harness for line-based text scanners (ragsentry, memsentry).

PRE-REGISTERED before first run:
  * Families of adversarial inputs, sizes 20k/40k/80k characters, each run in its own subprocess (10 s limit).
  * Finding = crash (any exception), timeout, > 1.0 s at 40k, or superlinear growth (t80k / t40k > 3.0 with t80k > 0.2 s).
  * Run once on the unmodified code; every finding is fixed with a regression test; the harness is then re-run once.

DEVIATION (recorded): the first run timed each case once, with 8 cases in parallel; that made sub-100 ms timings noisy
(memsentry `you_must` was reported superlinear but measures linear in-process). The harness now reports the best of 3
runs per case. Findings from the first run are listed in docs/HARDENING.md as they were.
"""
from __future__ import annotations
import importlib, json, subprocess, sys, time, itertools
from concurrent.futures import ThreadPoolExecutor

FAMILIES = {
    "a_run": lambda n: "a" * n,
    "spaces": lambda n: " " * n,
    "words": lambda n: "word " * (n // 5),
    "single_letters": lambda n: "a " * (n // 2),
    "import_words": lambda n: "import " + "aa " * (n // 3),
    "import_ws": lambda n: "import a" + " " * n,
    "import_commas": lambda n: "import " + "a," * (n // 2) + "!",
    "from_import": lambda n: "from a import " + "b," * (n // 2) + "!",
    "from_import_ws": lambda n: "from a import (" + " " * n,
    "from_import_words": lambda n: "from a import " + "b " * (n // 2) + "!",
    "js_import_braces": lambda n: "import {" + "a," * (n // 2) + "!",
    "js_import_ws": lambda n: "import " + " " * n + "x",
    "js_import_words": lambda n: "import " + "a " * (n // 2) + "from",
    "js_import_from_str": lambda n: "import x from '" + "a" * n,
    "require": lambda n: "const a = require('" + "a" * n,
    "require_ws": lambda n: "const " + " " * n + "= require(",
    "b64_ok": lambda n: "A" * n,
    "b64_bad_end": lambda n: "A" * n + "!",
    "b64_slashes": lambda n: "A/" * (n // 2) + "=",
    "stated_tags": lambda n: "[stated] " * (n // 9),
    "tag_open": lambda n: "[" * n,
    "paren_open": lambda n: "(" * n,
    "ignore_chain": lambda n: "ignore " * (n // 7),
    "ignore_prev": lambda n: "ignore previous " * (n // 16),
    "ignore_nospace": lambda n: "ignore" * (n // 6),
    "you_must": lambda n: "you must " * (n // 9),
    "always": lambda n: "always " * (n // 7),
    "questions": lambda n: "how do i " * (n // 9),
    "how_to_bait": lambda n: "how to " * (n // 7) + "x",
    "zwsp": lambda n: "​" * n,
    "zwsp_between": lambda n: "i​g​n​o​r​e " * (n // 12),
    "cyrillic": lambda n: "а" * n,
    "combining": lambda n: "é" * (n // 2),
    "ligature": lambda n: "ﬁ" * n,
    "fullwidth": lambda n: "ｉｇｎｏｒｅ " * (n // 7),
    "math_bold": lambda n: "𝐢𝐠𝐧𝐨𝐫𝐞 " * (n // 7),
    "tag_chars": lambda n: "\U000e0041" * n,
    "nul": lambda n: "\x00" * n,
    "many_short_lines": lambda n: "\n".join(["a"] * (n // 2)),
    "many_paragraphs": lambda n: "\n\n".join(["word word"] * (n // 11)),
    "many_blank_lines": lambda n: "\n" * n,
    "html_comment": lambda n: "<!--" * (n // 4),
    "backticks": lambda n: "`" * n,
    "pipes": lambda n: "|" * n,
    "curl_pipe": lambda n: "curl " + "http://a " * (n // 9) + "| sh",
    "run_this": lambda n: "run the following command " * (n // 27),
    "sudo_chain": lambda n: "sudo " * (n // 5) + "rm",
    "url_chain": lambda n: "http://" * (n // 7),
    "email_like": lambda n: "a@" * (n // 2),
    "dots": lambda n: "." * n,
    "dashes": lambda n: "-" * n,
    "digits": lambda n: "1" * n,
    "alnum_mix": lambda n: "a1" * (n // 2),
    "word_dash": lambda n: "a-" * (n // 2),
}
SIZES = (20_000, 40_000, 80_000)

CHILD = r'''
import sys, time, json
sys.path.insert(0, sys.argv[1]); sys.path.insert(0, sys.argv[5])
import hostile_inputs as hostile
pkg, fam, n = sys.argv[2], sys.argv[3], int(sys.argv[4])
text = hostile.FAMILIES[fam](n)
if pkg == "ragsentry":
    from ragsentry.document import Document as D; from ragsentry.scanner import scan_document as scan
else:
    from memsentry.memfile import MemoryFile as D; from memsentry.scanner import scan_file as scan
d = D("x", text.splitlines())
t = time.perf_counter()
try:
    r = scan(d); err = None
except Exception as e:
    r = []; err = repr(e)[:200]
print(json.dumps({"t": time.perf_counter() - t, "err": err}))
'''

def run_case(repo, pkg, fam, n):
    best = None
    for _ in range(3):
        r = _run_once(repo, pkg, fam, n)
        if r["err"]:
            return r
        best = r if best is None or r["t"] < best["t"] else best
    return best


def _run_once(repo, pkg, fam, n):
    try:
        p = subprocess.run([sys.executable, "-c", CHILD, repo, pkg, fam, str(n), __import__("os").path.dirname(__file__)],
                           capture_output=True, text=True, timeout=10)
        if p.returncode:
            return {"t": None, "err": "exit %d: %s" % (p.returncode, p.stderr[-200:])}
        return json.loads(p.stdout.strip().splitlines()[-1])
    except subprocess.TimeoutExpired:
        return {"t": 10.0, "err": "TIMEOUT"}

def main(repo, pkg):
    jobs = [(f, n) for f in FAMILIES for n in SIZES]
    with ThreadPoolExecutor(8) as ex:
        res = list(ex.map(lambda j: run_case(repo, pkg, *j), jobs))
    table = {}
    for (f, n), r in zip(jobs, res):
        table.setdefault(f, {})[n] = r
    findings = []
    for f, by in table.items():
        t = {n: by[n]["t"] for n in SIZES}
        errs = [by[n]["err"] for n in SIZES if by[n]["err"]]
        if errs: findings.append((f, "ERROR/TIMEOUT", errs[0])); continue
        if t[40_000] > 1.0: findings.append((f, "SLOW", f"{t[40_000]:.2f}s at 40k"))
        elif t[80_000] > 0.2 and t[40_000] > 0 and t[80_000] / t[40_000] > 3.0:
            findings.append((f, "SUPERLINEAR", f"40k {t[40_000]:.3f}s -> 80k {t[80_000]:.3f}s"))
    print(f"{pkg}: {len(FAMILIES)} families x {len(SIZES)} sizes; {len(findings)} findings")
    for x in findings: print("  ", *x)
    worst = sorted(((by[80_000]["t"] or 0, f) for f, by in table.items()), reverse=True)[:5]
    print("  slowest at 80k:", ", ".join(f"{f} {t:.3f}s" for t, f in worst))
    return findings

if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
