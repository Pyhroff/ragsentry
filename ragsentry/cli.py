from __future__ import annotations

import sys

import typer

from ragsentry.findings import Severity
from ragsentry.report import max_severity, render_text, to_json
from ragsentry.scanner import scan_path

app = typer.Typer(name="ragsentry", help="Static scanner for injected instructions and retrieval-manipulation in RAG source documents.")

_FAIL_ORDER = {Severity.LOW: 0, Severity.MEDIUM: 1, Severity.HIGH: 2, Severity.CRITICAL: 3}


@app.command()
def scan(
    path: str = typer.Argument(..., help="A document file, or a directory to scan recursively."),
    json_out: str | None = typer.Option(None, "--json", help="Write JSON results to this path."),
    fail_on: str | None = typer.Option(None, "--fail-on", help="Exit non-zero if any finding is at or above this severity."),
) -> None:
    results = scan_path(path)
    print(render_text(results))

    if json_out:
        with open(json_out, "w", encoding="utf-8") as f:
            f.write(to_json(results))
        print(f"\nJSON written to {json_out}")

    if fail_on:
        try:
            threshold = Severity(fail_on.lower())
        except ValueError:
            print(f"\nUnknown --fail-on severity: {fail_on!r}", file=sys.stderr)
            raise typer.Exit(code=2)
        worst = max_severity(results)
        if worst is not None and _FAIL_ORDER[worst] >= _FAIL_ORDER[threshold]:
            raise typer.Exit(code=1)


def main() -> None:
    app()


if __name__ == "__main__":
    main()
