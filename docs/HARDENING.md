# Hostile-input hardening

Harness: `tools/hostile_inputs.py` (`python tools/hostile_inputs.py . ragsentry`). Regression tests: `tests/test_hostile_input.py`.

## Protocol (written before the first run)

- 54 families of adversarial text (long runs, whitespace, near-miss import/require statements, base64-like blobs, repeated trigger phrases, Unicode edge cases, NUL, huge line counts), at 20k, 40k and 80k characters.
- Each case runs in its own subprocess with a 10 s limit.
- A finding is a crash, a timeout, more than 1.0 s at 40k, or superlinear growth (80k time over 40k time above 3.0, with the 80k time above 0.2 s).
- Run once on the unmodified code, fix every finding with a regression test, then run again.

Deviation: the first run timed each case once with 8 cases in parallel, which made sub-100 ms timings noisy. The harness now reports the best of 3 runs per case.

## First run (code as merged in #25)

| Family | Result |
|---|---|
| `require_ws` | **Timeout** (over 10 s at 80k): the `require(...)` alternative of the import-line regex added in #25 backtracked catastrophically on a whitespace-heavy line. A hostile document could stall a scan. |
| `many_short_lines` | 1.68 s at 40k (20,000 lines) |
| `many_blank_lines` | 1.10 s at 40k |

## Fixes

- Import-line regex: alternatives made unambiguous (no overlapping `\s` and `[\w\s]` classes), and lines over 300 characters are never tested against it.
- `instruction_injection`: patterns are compiled once instead of through `re.search(str, ...)` for every line and window, and blank lines are skipped.

## Second run

0 timeouts or crashes. One residual item: `many_short_lines` at 1.01 s for 40k characters. Cost is linear, about 50 microseconds per line, so a file with 20,000 one-character lines takes about a second. Not changed further: the remaining cost is canonicalising each line and each 2- and 3-line window, which the multi-line rule needs.

## Checks that behaviour did not change

BIPIA and InjecAgent re-scored with the sets and detector call of `benchmarks/context_external.py` in aisec-suite: identical per item before and after (BIPIA 9/450 with 6/150 false positives; InjecAgent 1,054/2,108 with 0/17 false positives).
