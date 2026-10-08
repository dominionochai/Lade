# Lade

> When a pipeline breaks, a vulnerability escapes to production, or a container explodes post-merge, developers spend hours sifting through CI logs, PCAPs, and cloud artifacts. Lade brings forensic-grade multi-agent investigation to the GitLab Duo Agent platform - turning post-commit chaos into an automated, adversary-tested root-cause autopsy.

Lade is a clean-room Python 3.10+ DevSecOps post-commit forensic investigation framework. It coordinates Planner, Executor, and Analyst roles through gated phases, records tool activity in a hash-chained audit trail, and produces evidence-linked reports. The chain is tamper-evident, not tamper-proof.

## Quick start

```bash
python -m venv .venv && . .venv/bin/activate
python -m pip install -e '.[dev]'
lade setup
lade investigate ./evidence CASE-2025-001
pytest
```

The input may be a file or directory. Local indexing works without cloud credentials; external tools report unavailable until configured. See [setup](docs/setup.md), [architecture](docs/architecture.md), [tool manifest](docs/tool-manifest.md), and [GCP deployment](docs/gcp-deploy.md).

## Workflow

`CATALOG → EXTRACTION → CROSS_SYSTEM → ALTERNATIVE_NARRATIVE → REPORT` is the fixed order. Planner → Executor → Analyst run in split mode during each phase. Every phase is gated with two bounded retries by default. Catalog failures stop early; extraction requires an indexed source, cross-system requires MITRE-mapped findings, and report output must be fresh and pass evidence and coverage checks.

## Security and limitations

- Per-case SQLite uses WAL and FTS5. Append-only JSONL tool-call records are fsynced; evidence uses SHA-256, tool output uses BLAKE2b-256, and records are SHA-256 hash-chained.
- Findings require exact text slices from existing audited tool calls. Reports label analytical hypotheses and include coverage gaps.
- External integrations are adapters and do not simulate successful scans. Configure cloud credentials and scanner binaries explicitly.
- GitLab webhook and remediation APIs are opt-in functions. Lade does not create issues or merge requests automatically; remediation merge requests are drafts for human review.
- Do not store secrets in evidence. Existing MIT license file is retained unchanged.

## CLI

`lade setup`, `lade investigate <evidence> <case-id>`, `lade serve` (MCP stdio), `lade export-iocs <case-id>`, `lade export-navigator <case-id>`, and `lade report <case-id>`.

MIT License. See [LICENSE](LICENSE).