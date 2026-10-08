# LADE

### DevSecOps post-commit forensics and incident-autopsy agent

> **GitLab Transcend — “Life After Code” Hackathon**
>
> “When a pipeline breaks, a vulnerability escapes to production, or a container explodes post-merge, developers spend hours sifting through CI logs, PCAPs, and cloud artifacts. LADE brings forensic-grade multi-agent investigation to the GitLab Duo Agent platform — turning post-commit chaos into an automated, adversary-tested root-cause autopsy.”

**LADE is an evidence-first investigation system designed for the work that begins after code is merged.** Its intended workflow connects a commit to the pipeline, build, container, and staging-runtime evidence that follows it, then prepares a traceable incident narrative and a human-reviewable remediation proposal.

> **Status: early prototype.** This repository currently contains Python domain models and a per-case SQLite persistence layer. It is not an operational investigation system. The agent workflow, evidence integrations, cryptographic audit chain, verification gate, GitLab integration, reports, CLI, and cloud deployment described below are design goals, not implemented functionality.

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

Replace the example digest and timestamp with values for the source being recorded. This demonstrates storage and search only; it does not run an investigation.

> **There is no usable Lade command-line application yet.** Although `pyproject.toml` declares a `lade` console entry point, the referenced `lade.cli` module is not present in the repository. The CLI commands below are a roadmap, not available commands.

## Why post-commit forensics?

A green merge is not the end of a change's story. A pipeline may fail later, a vulnerable dependency may ship, or a workload may behave unexpectedly once it reaches staging. The evidence needed to explain that outcome can be scattered across source history, CI traces, scanner output, container artifacts, Kubernetes logs, and cloud runtime signals.

LADE's proposed workflow treats that material as one case. It aims to help a team answer:

- **What changed?** Identify the merged commit and the artifacts produced from it.
- **What happened after merge?** Tie pipeline and runtime behavior back to that change.
- **How strong is the conclusion?** Require traceable evidence and explicit weakness and adversary-technique mapping.
- **What should happen next?** Prepare a post-mortem and a proposed fix for a person to review.

## Five phases mapped to the post-commit lifecycle

LADE is designed as five gated phases, moving from the merged change and its resulting artifacts through evidence collection and analysis to a reviewable response. These phases describe the planned workflow; they are not implemented in this prototype.

| Phase | Post-commit lifecycle stage | Planned responsibility | Intended output |
|---|---|---|---|
| **1. CATALOG** | Change and artifact inventory | Catalog the merged commit and its context: pipeline artifacts, build binaries, Docker containers, and the Cloud Run staging environment. | A case inventory linking the change to the evidence sources available for investigation. |
| **2. EXTRACTION** | Evidence acquisition and triage | Map relevant logs and evidence to extraction tasks; run approved tools and parsers such as Trivy, Syft, Kubernetes log extraction, and pipeline-trace parsers; evaluate results. | Normalized observations and candidate findings with source references. |
| **3. CROSS-SYSTEM** | Correlation and hypothesis formation | Correlate static evidence from code and commits with dynamic runtime failures and security alerts. A finding must be mapped to a CWE weakness and a MITRE ATT&CK technique before it can pass this planned gate. | A cross-system hypothesis with explicit weakness and adversary-technique mappings, or a gated result that needs more evidence. |
| **4. ALTERNATIVE_NARRATIVE** | Adversarial validation | Test counter-hypotheses, challenge causal assumptions, and look for evidence that could falsify or qualify the leading explanation. | A more resilient narrative recording competing explanations and what evidence supports or weakens each one. |
| **5. REPORT** | Incident reporting and human-reviewed remediation | Assemble the case into a GitLab Security Post-Mortem issue and prepare a draft remediation Merge Request. | A cited, integrity-aware report and a proposed patch for human review. |

### Planner, Executor, and Analyst roles

The planned multi-agent orchestrator separates investigation planning, tool execution, and evidence interpretation:

- **Planner** decomposes a case, maps logs and evidence to tasks, and selects the next phase-appropriate investigation steps.
- **Executor** invokes approved tools through typed, allowlisted interfaces and returns bounded, attributable results.
- **Analyst** interprets extracted evidence, develops and challenges findings, and produces cited analysis.

Typed tool contracts, role-specific allowlists, phase gates, and bounded retries are design goals intended to constrain execution and make phase transitions explicit. These controls and agent behaviors are not implemented in the current checkout.

### Alternative-narrative review

The **ALTERNATIVE_NARRATIVE** phase is designed to ask what else could explain the same symptoms, which assumptions are unproven, and what evidence would change the conclusion. This adversarial pass is intended to reduce confirmation bias before a root-cause narrative or remediation proposal reaches a developer.

## Evidence integrity and verification gate

Forensic output is useful only when its provenance can be examined. The planned case workflow includes:

- **Per-case SQLite** storage with FTS5 for searchable case material and WAL mode for database journaling.
- An **append-only JSONL audit log**. Each recorded output is intended to receive a BLAKE2b digest, with records linked by a **SHA-256 hash chain**. The chain head is intended to appear in the report so a reviewer can identify the audit-log state associated with it.
- An **evidence-custody registry** recording a SHA-256 digest for each ingested evidence item.
- An **evidence-verification gate** requiring each finding to cite the relevant tool-call ID and exact stdout slice. Findings without verifiable source locations are intended to be rejected or held for review rather than promoted as fact.

The intended mappings are **MITRE ATT&CK v18.1** and **CWE 4.14**, consistently applied across findings and reports. These standards and version labels describe the planned mapping targets; they do not imply that mappings are currently implemented.

The audit-chain and custody designs aim to make unauthorized changes detectable and establish provenance. A hash chain is tamper-evident only within its threat model; it is not an absolute guarantee against alteration. The current code does not compute or verify this chain or enforce the evidence gate, so these properties must not be treated as available safeguards.

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
- **0:30–1:15 — Phases 1–3:** Show the five-phase progress bar and the planned Planner/Executor/Analyst workflow correlating commit, pipeline, and runtime signals.
- **1:15–1:45 — Phase 4:** Show an alternative-narrative prompt and how a counter-hypothesis would challenge the leading explanation rather than accept it immediately.
- **1:45–2:30 — Output:** Present the planned GitLab issue, audit trail and ATT&CK/CWE breakdown, followed by a draft remediation MR and proposed fix. Make clear that a human must approve the MR.

## CLI roadmap

The intended command surface is listed below. **These commands are not implemented yet.** The package's declared console entry point currently points to a missing `lade.cli` module.

```text
lade setup
lade investigate <evidence> <case-id>
lade serve
lade export-iocs
lade export-navigator
lade report
```

The roadmap covers initial configuration, case investigation, webhook service, IOC and Navigator exports, and report generation. Command behavior and options remain subject to implementation.

## Development status

The package and storage code are an initial scaffold, not a production-ready tool. The repository does not yet include an end-to-end workflow or an automated test suite. The install metadata's console-script target is unfinished. Treat the planned behavior in this README as a roadmap, not verified functionality; setup, security properties, and integration behavior still need implementation and tests.

## License

LADE is released under the MIT License. See [`LICENSE`](LICENSE).
