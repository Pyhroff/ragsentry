# 📚 ragsentry

<div align="center">

**Static scanner for poisoned RAG source documents.**

[![CI](https://github.com/Pyhroff/ragsentry/actions/workflows/ci.yml/badge.svg)](https://github.com/Pyhroff/ragsentry/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](pyproject.toml)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

</div>

---

## Overview

RAG turns retrieved documents into model context.

`ragsentry` checks those documents before they become trusted-looking input to an AI agent.

It is the **RAG module inside [aisec-suite](https://github.com/Pyhroff/aisec-suite)**.

## Detection surface

- direct instruction injection
- hidden payloads and suspicious encoding
- fake remediation or "trusted fix" content
- retrieval manipulation
- model-directed instructions embedded in ordinary documents

## Usage

```bash
ragsentry docs/
ragsentry docs/critical.md --fail-on high
```

## Umbrella integration

```bash
aisec scan . --rag ./docs
```

RAG findings use the same JSON/SARIF/baseline reporting path as MCP and memory findings in the umbrella.

## Static by design

Documents are treated as untrusted text. The scanner does not execute commands, load arbitrary code, or contact systems described inside the document.

## Limitations

Detection is heuristic and corpus-dependent. Novel phrasing, multimodal payloads, or attacks outside implemented rule families can evade detection.

## Development

```bash
pytest -q
```

## License

MIT
