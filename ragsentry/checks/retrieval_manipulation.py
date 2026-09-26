"""
A threat class that's specific to RAG rather than borrowed from prompt
injection: a document engineered to be *retrieved* for queries it has no
real business answering. Dense embedding models score chunks by semantic
similarity, and a chunk that stuffs in a wide spread of high-value,
unrelated keywords or query-shaped phrases can get pulled into context for
searches it shouldn't win -- a way to inject a document's content (or its
instruction-injection payload) into completely unrelated conversations.

Two lightweight paragraph-level heuristics, no embeddings required:

1. KEYWORD STUFFING -- a paragraph where one non-stopword token dominates
   the word count far beyond normal prose (repeated well past what natural
   writing produces), suggesting the paragraph was padded to maximize
   similarity to queries containing that term.
2. QUERY BAIT -- a paragraph containing an unusually dense run of
   question-shaped phrases ("how do I...", "what is the best...", "why
   does...") back to back, which reads like it was built to match as many
   literal user queries as possible rather than to convey information.
"""

from __future__ import annotations

import re
from collections import Counter

from ragsentry.document import Document
from ragsentry.findings import Finding, Severity

_STOPWORDS = {
    "the", "a", "an", "and", "or", "of", "to", "in", "on", "for", "is", "are",
    "was", "were", "with", "as", "by", "at", "from", "this", "that", "it",
    "be", "you", "your", "we", "our", "can", "will", "has", "have", "not",
}
_WORD = re.compile(r"[a-zA-Z']{3,}")
_QUESTION_PHRASE = re.compile(
    r"\b(how do i|how to|what is the best|why does|where can i|when should i)\b", re.IGNORECASE
)

_STUFFING_MIN_WORDS = 25
_STUFFING_RATIO_THRESHOLD = 0.30
_QUESTION_BAIT_MIN_COUNT = 5


def _paragraphs(doc: Document) -> list[tuple[int, str]]:
    """Return (starting_line_number, paragraph_text) for each blank-line-separated block."""
    paras: list[tuple[int, str]] = []
    buf: list[str] = []
    start = 1
    for i, line in enumerate(doc.lines, start=1):
        if line.strip() == "":
            if buf:
                paras.append((start, " ".join(buf)))
                buf = []
            continue
        if not buf:
            start = i
        buf.append(line)
    if buf:
        paras.append((start, " ".join(buf)))
    return paras


def check_retrieval_manipulation(doc: Document) -> list[Finding]:
    findings: list[Finding] = []

    for start_line, para in _paragraphs(doc):
        words = [w.lower() for w in _WORD.findall(para)]
        content_words = [w for w in words if w not in _STOPWORDS]

        if len(content_words) >= _STUFFING_MIN_WORDS:
            counts = Counter(content_words)
            top_word, top_count = counts.most_common(1)[0]
            ratio = top_count / len(content_words)
            if ratio >= _STUFFING_RATIO_THRESHOLD:
                findings.append(Finding(
                    check="retrieval_manipulation",
                    severity=Severity.MEDIUM,
                    title="Possible keyword stuffing for retrieval manipulation",
                    detail=(
                        f"Paragraph starting at line {start_line} repeats the term '{top_word}' "
                        f"{top_count} times out of {len(content_words)} content words "
                        f"({ratio:.0%}), far past what normal prose produces. This pattern can "
                        f"be used to bias embedding-similarity retrieval toward matching this "
                        f"chunk for many unrelated queries containing that term."
                    ),
                    file=doc.path,
                    line=start_line,
                    snippet=para.strip()[:200],
                ))

        question_hits = _QUESTION_PHRASE.findall(para)
        if len(question_hits) >= _QUESTION_BAIT_MIN_COUNT:
            findings.append(Finding(
                check="retrieval_manipulation",
                severity=Severity.LOW,
                title="Dense run of query-shaped phrases (possible query bait)",
                detail=(
                    f"Paragraph starting at line {start_line} contains {len(question_hits)} "
                    f"question-shaped phrases in one block, which reads as engineered to match "
                    f"as many literal user queries as possible rather than to convey "
                    f"information to a human reader."
                ),
                file=doc.path,
                line=start_line,
                snippet=para.strip()[:200],
            ))

    return findings
