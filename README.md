# LADE

### DevSecOps Post-Commit Forensics & Incident Autopsy Agent

> **GitLab Transcend — “Life After Code” Hackathon**
>
> “When a pipeline breaks, a vulnerability escapes to production, or a container explodes post-merge, developers spend hours sifting through CI logs, PCAPs, and cloud artifacts. LADE brings forensic-grade multi-agent investigation to your GitLab Duo Agent platform — turning post-commit chaos into an automated, adversary-tested root-cause autopsy.”

**LADE is a planned, evidence-first investigation system for the work that begins after code is merged.** It is designed to connect a commit to the pipeline, build, container, and staging-runtime evidence that follows it, then produce an auditable incident narrative and a human-reviewable remediation proposal.

> **Project status: architecture finalized; clean-room implementation in progress.** The architecture and workflows described here are documentation of the planned design. The code is not yet implemented, and none of the commands, integrations, agents, or outputs described below should be considered currently functional.

---

## Why post-commit forensics?

A green merge is not the end of a change's story. A pipeline may fail later, a vulnerable dependency may ship, or a workload may behave unexpectedly once it reaches staging. The evidence needed to explain that outcome is scattered across source history, CI traces, scanner output, container artifacts, Kubernetes logs, and cloud runtime signals.

LADE's proposed workflow treats that material as one case. It aims to help a team answer:

- **What changed?** Identify the merged commit and the artifacts produced from it.
- **What happened after merge?** Tie pipeline and runtime behavior back to that change.
- **How strong is the conclusion?** Require traceable evidence and explicit weakness / adversary-technique mapping.
- **What should happen next?** Prepare a post-mortem and a proposed fix for a person to review.

## The five post-commit phases

LADE is organized as five gated phases. The sequence is intended to move from evidence collection to a defensible, reviewable outcome rather than jump from an alert directly to a patch.

| Phase | Planned responsibility | Intended output |
|---|---|---|
| **1. CATALOG** | Catalog the merged commit and its context: pipeline artifacts, build binaries, Docker containers, and the Cloud Run staging environment. | A case inventory linking the change to the evidence sources available for investigation. |
| **2. EXTRACTION** | Automate triage. The Planner maps relevant logs and evidence to extraction tasks; the Executor runs approved tools and parsers, including Trivy, Syft, Kubernetes log extraction, and pipeline-trace parsers; the Analyst evaluates the results and submits findings tagged with applicable CVE/CWE identifiers. | Normalized observations and candidate findings with source references. |
| **3. CROSS-SYSTEM** | Correlate static evidence from code and commits with dynamic runtime failures and security alerts. This is a hard correlation gate: a finding must be mapped to a CWE weakness and a MITRE ATT&CK technique before it can pass. | A cross-system hypothesis with explicit weakness and adversary-technique mappings—or a gated result that needs more evidence. |
| **4. ALTERNATIVE_NARRATIVE** | Run an adversarial audit of the leading explanation. The agent tests counter-hypotheses, challenges causal assumptions, and looks for evidence that could falsify or qualify the proposed story. | A more resilient narrative that records competing explanations and what evidence supports or weakens each one. |
| **5. REPORT** | Assemble the case into a GitLab Security Post-Mortem issue and prepare an auto-drafted remediation Merge Request through the GitLab Duo API. | A cited, integrity-aware report and a proposed patch for human review. |

### The differentiator: alternative narratives

Many incident workflows stop once an explanation seems plausible. LADE's **ALTERNATIVE_NARRATIVE** phase is designed to ask what else could explain the same symptoms, which assumptions are unproven, and what evidence would change the conclusion. This adversarial pass is intended to reduce confirmation bias before a root-cause narrative or remediation proposal reaches a developer.

## Planned architecture

```text
GitLab merge / pipeline webhooks
                 │
                 ▼
        Multi-agent orchestrator
                 │
       ┌─────────┴─────────┐
       ▼                   ▼
    Planner             Executor ── typed, allowlisted MCP tools
       │                   │
       └─────────┬─────────┘
                 ▼
              Analyst
                 │
     phase gates + bounded retries
                 │
                 ▼
     Alternative-narrative audit
                 │
                 ▼
 GitLab issue + human-reviewed MR
```

### Agents and control plane

The planned multi-agent orchestrator assigns distinct responsibilities and model profiles:

- **Planner — Claude Opus 4.6:** decomposes a case, maps logs and evidence to tasks, and selects the next phase-appropriate investigation steps.
- **Executor — Claude Haiku 4.5:** invokes approved tools through the typed MCP layer and returns bounded, attributable results.
- **Analyst — Claude Opus 4.6:** interprets extracted evidence, develops and challenges findings, and produces cited analysis.

A provider-agnostic LLM adapter is planned to support **OpenRouter** and **GitLab Duo endpoints**, with a **LiteLLM-style proxy** approach. Typed MCP tool contracts, role-specific tool allowlists, phase gates, and bounded retries are intended to keep tool execution constrained and make phase transitions explicit. These are design goals, not implemented safeguards at this stage.

### Evidence, audit, and integrity by design

Forensic output is only useful when its provenance can be examined. The planned case store and verification path include:

- **Per-case SQLite** storage using **FTS5** for searchable case material and **WAL** mode for database journaling.
- An **append-only JSONL audit log**. Each recorded output receives a **BLAKE2b hash**, and records are linked by a **SHA-256 hash chain**. The chain head is intended to appear in the report header so a reviewer can identify the audit-log state associated with a report.
- An **evidence custody registry** that records a SHA-256 digest for each ingested evidence item.
- An **evidence-verification gate**: a finding must cite the relevant tool-call ID **and exact stdout slice**. Findings without verifiable source locations are intended to be rejected or held for review rather than silently promoted as fact.

These are core engineering highlights of the proposed design—not bugfixes or claims about a currently running system:

1. **Consistent ATT&CK v18.1 and CWE 4.14 mappings** across findings and reports.
2. **A cryptographic SHA-256 hash chain** over append-only audit records, with its chain head surfaced in the report.
3. **Evidence verification** that requires tool-call IDs and exact output excerpts for findings.

The hash chain and custody registry are intended to make unauthorized changes detectable and establish provenance; reviewers should still validate the implementation and its threat model when code becomes available.

## GitLab workflow: supervised autonomy

The planned GitLab integration uses a webhook receiver for **merge** and **pipeline** events to start or update a post-commit case. At the end of a qualifying investigation, LADE is designed to:

1. Create a **GitLab Security Post-Mortem issue** with the investigation narrative, evidence citations, integrity metadata, and ATT&CK/CWE breakdown.
2. Use the **GitLab Duo API** to prepare an auto-drafted **remediation Merge Request**.
3. Leave the decision to a person: remediation is **supervised autonomy**. A human reviews and approves the proposed MR; LADE is not designed to merge its own remediation.

Configuration is planned around a GitLab API token and the relevant GitLab project ID(s), supplied through the deployment environment. Token scope and project permissions will need to be restricted to the intended projects and operations.

## GCP execution target

The execution phase is planned for **Google Cloud Run and/or GKE**, providing a cloud deployment target for webhook-driven investigations and evidence processing. Google Cloud credits are a natural fit for running the hackathon execution environment and can contribute to the project's **Google Cloud / bonus-points** framing. Cloud deployment is part of the plan; no GCP deployment is currently available from this repository.

## Planned CLI

The command surface is planned as follows; these commands are **not implemented yet**:

```text
lade setup
lade investigate <evidence> <case-id>
lade serve
lade export-iocs
lade export-navigator
lade report
```

The intended command names cover initial configuration, case investigation, webhook service, IOC and Navigator exports, and report generation. Their behavior and options remain subject to implementation.

## Technology

| Area | Planned technology |
|---|---|
| Language | Python 3.10+ |
| Agent tool interface | MCP (Model Context Protocol) |
| Data and validation | SQLAlchemy, Pydantic |
| CLI and report rendering | Click, Jinja2 |
| Security / SBOM extraction | Trivy, Syft |
| Source-control workflow | GitLab API, including GitLab Duo API integration |
| Case search and audit storage | SQLite with FTS5 and WAL; append-only JSONL audit log |
| Runtime target | Google Cloud Run and/or GKE |

## Demo video outline

A proposed 2:30 competition demo can make the full post-commit story visible:

- **0:00–0:30 — Setup:** A developer merges a PR, CI completes, then Cloud Run reports an anomaly five minutes later.
- **0:30–1:15 — Phases 1–3:** Show the five-phase progress bar. Haiku runs MCP commands through the constrained Executor role while Opus analyzes the evidence and connects commit, pipeline, and runtime signals.
- **1:15–1:45 — Phase 4 magic moment:** Put the alternative-narrative prompt on screen and show the adversarial audit testing a counter-hypothesis instead of accepting the first explanation.
- **1:45–2:30 — Output:** Show the generated GitLab issue, its tamper-proof audit trail and MITRE/CWE breakdown, followed by the drafted remediation MR and its proposed fix. Make clear that a human must approve the MR.

## Development status

**Architecture finalized. Code pending; clean-room implementation is in progress.** This repository currently documents the intended product and architecture. There is no implemented LADE agent, CLI, webhook receiver, scanner integration, report generator, or deployment to run yet. The workflows above describe the plan, not verified behavior. As implementation lands, this README should be updated to distinguish shipped capabilities from remaining design goals and to include tested setup instructions.

## License

LADE is released under the MIT License. See [`LICENSE`](LICENSE).
