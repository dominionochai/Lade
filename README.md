# Lade

### Evidence-led post-commit forensics prototype

When a pipeline breaks, a vulnerability escapes to production, or a container explodes post-merge, developers spend hours sifting through CI logs, PCAPs, and cloud artifacts. Lade brings forensic-grade multi-agent investigation to the GitLab Duo Agent platform - turning post-commit chaos into an automated, adversary-tested root-cause autopsy.

> **Status: early prototype.** The repository currently contains Python domain models and a per-case SQLite persistence layer. It is not yet an operational investigation system. The workflow, integrations, agent behavior, reports, and deployment described as goals below are not implemented.

## What is in the repository today

- A Python package skeleton (version `0.1.0`, Python `>=3.10`) and typed domain models for investigation phases, agent configuration, evidence references, findings, and phase results.
- `lade.store.CaseStore`, which initializes per-case SQLite storage in a `cases/<case-id>/` directory. The schema includes source metadata, extracted text windows, findings, IOC values, tool-call records, evidence references, progress, and case metadata.
- SQLite WAL mode and foreign-key enforcement, plus an FTS5 virtual table and a method for searching stored text windows.

The store is a persistence foundation, not an evidence collection or analysis engine: it does not fetch artifacts, parse logs, run scanners, or orchestrate agents. Callers supply the stored records. Although the schema has fields for output digests and chain hashes, the current code does not compute or verify a cryptographic audit chain or independently validate evidence provenance.

## Using the storage prototype

Install the package in an environment with Python 3.10 or newer:

```bash
python -m pip install -e .
```

The current API can create a case, register a source, add a text window, and search that window:

```python
from lade.store import CaseStore

store = CaseStore(".lade", "demo-case")
store.add_source({
    "source_id": "build-log",
    "path": "artifacts/build.log",
    "sha256": "<source SHA-256>",
    "size": 42,
    "media_type": "text/plain",
    "text": "Build failed during packaging.",
    "indexed_at": "2026-01-01T00:00:00Z",
})
store.add_window(
    window_id="build-log-window-1",
    source_id="build-log",
    text="Build failed during packaging.",
    start_line=1,
)
matches = store.search_windows("packaging")
```

Replace the example digest and timestamp with values for the source being recorded. This demonstrates storage/search only; it does not run an investigation.

> **There is no usable Lade command-line application yet.** Although `pyproject.toml` declares a `lade` console entry point, the referenced `lade.cli` module is not present in the repository. The command surface is not available.

## Intended direction (planned, not implemented)

Lade is intended to correlate a code change with post-merge CI, security, container, and runtime evidence, then produce a traceable investigation for human review. The design is organized around five phases:

1. **Catalog** the change and relevant artifacts.
2. **Extraction** collect and normalize evidence.
3. **Cross-system analysis** connect findings across code, pipeline, and runtime signals.
4. **Alternative-narrative review** challenge the leading explanation with competing hypotheses.
5. **Report** prepare a cited incident write-up and proposed remediation for a person to review.

Planned work includes GitLab and GitLab Duo integration, evidence-source and scanner adapters, multi-agent orchestration, report generation, and deployment support. These capabilities are design goals only: this checkout does not currently provide GitLab event/API integration, a webhook receiver, MCP tools, LLM agents, scanner or cloud-runtime integrations, automated reports, or remediation merge requests. No changes are made or applied automatically.

## Development status

The package and storage code are an initial scaffold, not a production-ready tool. The repository does not yet include an end-to-end workflow or an automated test suite. The install metadata's console-script target is also unfinished. Treat the planned behavior in this README as a roadmap, not as verified functionality; setup, security properties, and integration behavior still need implementation and tests.

## License

See [LICENSE](LICENSE).
