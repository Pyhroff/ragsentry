"""
ragsentry reads a candidate RAG source document as plain text plus line
numbers -- the same schema-agnostic approach as memsentry's MemoryFile,
because the threat here doesn't care whether the document is a markdown
knowledge-base article, a scraped web page, or a plain .txt export: an
injected instruction or a retrieval-manipulation trick reads the same
regardless of the source format.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass
class Document:
    path: str
    lines: list[str]

    @classmethod
    def load(cls, path: Path) -> "Document":
        text = Path(path).read_text(encoding="utf-8", errors="replace")
        return cls(path=str(path), lines=text.splitlines())

    def full_text(self) -> str:
        return "\n".join(self.lines)
