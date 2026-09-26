from ragsentry.checks.retrieval_manipulation import check_retrieval_manipulation
from ragsentry.document import Document


def test_ordinary_paragraph_no_findings():
    doc = Document(path="x", lines=[
        "Items can be returned within 30 days of purchase with a valid receipt.",
        "Refunds are issued to the original payment method and typically take",
        "3-5 business days to process.",
    ])
    assert check_retrieval_manipulation(doc) == []


def test_flags_keyword_stuffing():
    words = ["budget laptop"] * 20
    doc = Document(path="x", lines=[" ".join(words) + " deals reviews specs battery screen"])
    findings = check_retrieval_manipulation(doc)
    assert any("stuffing" in f.title.lower() for f in findings)


def test_flags_query_bait():
    para = (
        "How do I fix this. How to fix this. What is the best way to fix this. "
        "Why does this happen. Where can I fix this. When should I fix this."
    )
    doc = Document(path="x", lines=[para])
    findings = check_retrieval_manipulation(doc)
    assert any("query bait" in f.title.lower() for f in findings)


def test_paragraphs_split_on_blank_lines():
    doc = Document(path="x", lines=["first paragraph text here", "", "second paragraph text here"])
    # just confirm it doesn't crash and treats these as two separate paragraphs
    from ragsentry.checks.retrieval_manipulation import _paragraphs
    paras = _paragraphs(doc)
    assert len(paras) == 2
