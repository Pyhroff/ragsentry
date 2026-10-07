# ragsentry Evaluation Methodology

Evaluate document-injection detection on a versioned corpus of clean and intentionally poisoned documents.

Track TP, FP, TN, FN, precision, recall, F1, false-positive rate, scan latency, and rule-family coverage.

Separate development fixtures from held-out evaluation fixtures. When adding a detector rule, keep a fresh validation subset that the rule author did not use for tuning.

Important boundary: results describe the corpus and parser configuration used. They are not a universal RAG-security detection rate.

Every benchmark case should record the attack hypothesis, source format, expected severity, rationale, and whether the payload is direct, hidden, encoded, or retrieval-manipulating.