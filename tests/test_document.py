from ragsentry.document import Document


def test_load_splits_lines(tmp_path):
    p = tmp_path / "doc.md"
    p.write_text("a\nb\nc\n", encoding="utf-8")
    doc = Document.load(str(p))
    assert doc.lines == ["a", "b", "c"]


def test_full_text_rejoins():
    doc = Document(path="x", lines=["a", "b"])
    assert doc.full_text() == "a\nb"
