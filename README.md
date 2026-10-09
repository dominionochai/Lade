# LADE

### DevSecOps post-commit forensics and incident-autopsy agent

> **GitLab Transcend — "Life After Code" Hackathon**
>
> "When a pipeline breaks, a vulnerability escapes to production, or a container explodes post-merge, developers spend hours sifting through CI logs, PCAPs, and cloud artifacts. LADE brings forensic-grade multi-agent investigation to the GitLab Duo Agent platform — turning post-commit chaos into an automated, adversary-tested root-cause autopsy."

**LADE is an evidence-first investigation system designed for the work that begins after code is merged.** Its intended workflow connects a commit to the pipeline, build, container, and staging-runtime evidence that follows it, then prepares a traceable incident narrative and a human-reviewable remediation proposal.

> **Status: engine foundation.** This repository currently contains the inherited investigation engine, renamed and repackaged as `lade`. The multi-phase orchestrator, MCP server, SQLite case store, audit log, CLI, and report rendering below are implemented and exercised by the test suite. The DevSecOps-specific pieces described later — the GitLab webhook receiver, commit→pipeline→container→runtime correlation, Cloud Run deployment, and draft remediation MR — are design goals, not yet built. The engine's host-forensics toolchains are retained for now and are slated to be replaced with DevSecOps tooling in a later step.

## What is in the repository today

- A `lade` console application with working `setup`, `serve`, `investigate`, `report`, `export-iocs`, and `export-navigator` commands.
- An **MCP server** exposing typed forensic tools to agent clients.
- A **multi-phase, multi-agent orchestrator** running five gated phases — CATALOG, EXTRACTION, CROSS-SYSTEM, ALTERNATIVE_NARRATIVE, REPORT — with Planner, Executor, and Analyst roles, per-role tool allowlists, quality gates, and bounded retries.
- **Per-case SQLite persistence** (`lade.db.CaseDB`): WAL mode, foreign-key enforcement, an external-content FTS5 index over extracted text windows, findings, a SHA-256 evidence-custody registry, bookmarks, progress, and a key/value store.
- An **append-only JSONL audit log** (`lade.audit.AuditLog`) with per-append `fsync`, tool-call output hashes, and provenance-chain resolution from a finding back to its cited evidence files.
- **HTML and Markdown report rendering** with evidence citations, audit summaries, and per-source window excerpts.
- **`lade setup`**, a `--verify`-able asset provisioner that downloads the toolchain, rule sets, and symbol tables pip cannot ship.
- An automated test suite covering the database, audit log, CLI, MCP tools, orchestrator, and report rendering.

The inherited engine is a **host-forensics engine** (built around the SANS SIFT Workstation). It parses disk images (Sleuth Kit), memory (Volatility 3), Windows event logs (EVTX, Hayabusa, Chainsaw, Zircolite), YARA rule hits, mobile images (ALEAPP, iLEAPP, MVT), email archives (PST), registry hives, and Office documents. **These host-forensics capabilities are the parts that will be replaced with DevSecOps tooling** — Trivy, Syft, Kubernetes log extraction, and pipeline-trace parsers — in a later step. They are kept in place now because removing them would break the tested baseline.

## Using Lade today

Install in an environment with Python 3.10 or newer:

```bash
python -m pip install -e .        # runtime
python -m pip install -e ".[dev]" # with test/lint tooling
```

The console entry point is `lade`:

```bash
lade --version
lade setup --dry-run                 # plan the asset download; nothing fetched
lade setup --verify                  # validate an existing install, no network
lade serve                           # start the MCP server (stdio or streamable-http)
lade investigate <evidence> <case-id>  # run the five-phase investigation
lade report <case-id>                # render HTML + Markdown reports
lade export-iocs <case-id>           # STIX 2.1 / CSV IOC export
lade export-navigator <case-id>      # MITRE ATT&CK Navigator layer
```

Case storage is also available as a Python API:

```python
from pathlib import Path
from lade.db import CaseDB
from lade.models import WindowRow

db = CaseDB.create(
    case_id="demo-case",
    evidence_root="/evidence",
    db_dir=Path(".lade"),
)
source_id = db.register_source(
    source_name="build-log",
    source_path="artifacts/build.log",
    source_hash="<source SHA-256>",
    extractor="text",
    line_count=1,
)
db.insert_windows(source_id, [
    WindowRow(
        source_id=source_id,
        line_start=1,
        line_end=1,
        event_time="2026-01-01T00:00:00Z",
        raw_text="Build failed during packaging.",
    )
])
matches = db.search_windows("packaging")
db.close()
```

This demonstrates storage and search only; it does not run an investigation.

## Why post-commit forensics?

A green merge is not the end of a change's story. A pipeline may fail later, a vulnerable dependency may ship, or a workload may behave unexpectedly once it reaches staging. The evidence needed to explain that outcome can be scattered across source history, CI traces, scanner output, container artifacts, Kubernetes logs, and cloud runtime signals.

LADE's proposed workflow treats that material as one case. It aims to help a team answer:

- **What changed?** Identify the merged commit and the artifacts produced from it.
- **What happened after merge?** Tie pipeline and runtime behavior back to that change.
- **How strong is the conclusion?** Require traceable evidence and explicit weakness and adversary-technique mapping.
- **What should happen next?** Prepare a post-mortem and a proposed fix for a person to review.

## Five phases mapped to the post-commit lifecycle

LADE runs five gated phases. The phase machinery itself is implemented in the inherited engine; the post-commit mapping — and the GitLab/pipeline evidence integrations that feed the phases — is the Lade-specific work that remains.

| Phase | Post-commit lifecycle stage | Responsibility | Output |
|---|---|---|---|
| **1. CATALOG** | Change and artifact inventory | Catalog the merged commit and its context: pipeline artifacts, build binaries, Docker containers, and the Cloud Run staging environment. | A case inventory linking the change to the evidence sources available for investigation. |
| **2. EXTRACTION** | Evidence acquisition and triage | Map relevant logs and evidence to extraction tasks; run approved tools and parsers; evaluate results. | Normalized observations and candidate findings with source references. |
| **3. CROSS-SYSTEM** | Correlation and hypothesis formation | Correlate static evidence from code and commits with dynamic runtime failures and security alerts. A finding must be mapped to a CWE weakness and a MITRE ATT&CK technique before it can pass this gate. | A cross-system hypothesis with explicit weakness and adversary-technique mappings, or a gated result that needs more evidence. |
| **4. ALTERNATIVE_NARRATIVE** | Adversarial validation | Test counter-hypotheses, challenge causal assumptions, and look for evidence that could falsify or qualify the leading explanation. | A more resilient narrative recording competing explanations and what evidence supports or weakens each one. |
| **5. REPORT** | Incident reporting and human-reviewed remediation | Assemble the case into a reviewable report and prepare a draft remediation proposal. | A cited, integrity-aware report and a proposed patch for human review. |

### Planner, Executor, and Analyst roles

The multi-agent orchestrator separates investigation planning, tool execution, and evidence interpretation:

- **Planner** decomposes a case, maps logs and evidence to tasks, and selects the next phase-appropriate investigation steps.
- **Executor** invokes approved tools through typed, allowlisted interfaces and returns bounded, attributable results.
- **Analyst** interprets extracted evidence, develops and challenges findings, and produces cited analysis.

Typed tool contracts, role-specific allowlists, phase gates, and bounded retries are implemented in the engine and enforced by the test suite.

### Alternative-narrative review

The **ALTERNATIVE_NARRATIVE** phase asks what else could explain the same symptoms, which assumptions are unproven, and what evidence would change the conclusion. This adversarial pass is intended to reduce confirmation bias before a root-cause narrative or remediation proposal reaches a developer.

## Evidence integrity and verification

The engine records investigation provenance:

- **Per-case SQLite** storage with an external-content FTS5 index for searchable case material and WAL mode for database journaling.
- An **append-only JSONL audit log**. Every tool call is appended with `fsync` and stores an output hash; findings must cite tool-call IDs, and the audit log resolves a finding's **provenance chain** back to the tool calls and original evidence files that support it.
- An **evidence-custody registry** recording a SHA-256 digest for each ingested evidence item.
- Per-source **BLAKE2b window hashes** computed at ingestion, with a `verify_evidence_integrity` check that recomputes them and flags any modified source.

The intended mappings are **MITRE ATT&CK v18.1** and **CWE 4.14**, consistently applied across findings and reports. These version labels describe the mapping targets; finding and report mapping is not yet uniformly enforced.

## GitLab webhook and draft-MR integration

The planned GitLab integration uses a webhook receiver for **merge** and **pipeline** events to start or update a post-commit case. At the end of a qualifying investigation, the intended workflow is to:

1. Create a **GitLab Security Post-Mortem issue** with the investigation narrative, evidence citations, integrity metadata, and ATT&CK/CWE breakdown.
2. Use the **GitLab Duo API** to prepare a draft **remediation Merge Request**.
3. Require a person to review and approve the proposed MR. LADE is not designed to merge its own remediation.

GitLab event/API integration, webhook handling, issue creation, and draft-MR creation are not present in this repository. Any future token and project permissions should be restricted to the intended projects and operations.

## GCP Cloud Run deployment target

**Google Cloud Run** is the planned cloud deployment target for webhook-driven investigations and evidence processing. Google Kubernetes Engine (GKE) is also mentioned as a possible execution target in the architecture notes. Cloud deployment is part of the plan; no GCP deployment or cloud-runtime integration is currently available from this repository.

## Demo video outline

A proposed **2:30** competition demo can make the post-commit story visible. This is a presentation outline, not a description of a working end-to-end demo:

- **0:00–0:30 — Setup:** A developer merges a PR, CI completes, and the demo scenario shows Cloud Run reporting an anomaly five minutes later.
- **0:30–1:15 — Phases 1–3:** Show the five-phase progress bar and the Planner/Executor/Analyst workflow correlating commit, pipeline, and runtime signals.
- **1:15–1:45 — Phase 4:** Show an alternative-narrative prompt and how a counter-hypothesis would challenge the leading explanation rather than accept it immediately.
- **1:45–2:30 — Output:** Present the planned GitLab issue, audit trail and ATT&CK/CWE breakdown, followed by a draft remediation MR and proposed fix. Make clear that a human must approve the MR.

## Command surface

The following commands are implemented and available today:

```text
lade setup
lade investigate <evidence> <case-id>
lade serve
lade export-iocs
lade export-navigator
lade report
```

## Development status

The engine foundation is implemented and covered by an automated test suite (run with `pytest tests/`). The test suite covers the SQLite case store and FTS5 search, the audit log and provenance resolution, the CLI, the MCP tool surface, the orchestrator phases and gates, asset setup, and report rendering.

What remains to be built for Lade:

- **DevSecOps evidence integrations**: GitLab merge and pipeline webhook receiver; extraction for Trivy/Syft output, container images, Kubernetes logs, and pipeline traces.
- **Replacing host-forensics toolchains** (disk, memory, EVTX, YARA, mobile, email) with the DevSecOps tools above.
- **CWE 4.14 / MITRE ATT&CK v18.1 mapping** enforced across findings and reports.
- **GitLab Security Post-Mortem issue creation** and **draft remediation MR** via the GitLab Duo API.
- **Cloud Run deployment** and runtime hardening.

Treat the roadmap sections of this README as plans, not implemented functionality.

## License

LADE is released under the MIT License. See [`LICENSE`](LICENSE).