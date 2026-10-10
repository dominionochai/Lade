# Lade Architecture Audit

This document describes the actual architecture of the Lade post-commit forensics and incident-autopsy engine as implemented in the codebase. All details cite specific file paths and line numbers verified against the current repository state.

---

## 1. The Phase Machine

**Files:** `src/lade/orchestrator/phases.py` (lines 1–250), `src/lade/orchestrator/runner.py` (lines 150–550), `src/lade/orchestrator/gates.py` (lines 1–432).

### Phases and Execution Modes
Lade defines five sequential phases via `PhaseConfig` in `src/lade/orchestrator/phases.py`:
1. **CATALOG** (`phases.py:100–108`): Mode `single`. Role: `planner`. Scans and fingerprints evidence disks, directories, archives, and files. Turns: 40.
2. **EXTRACTION** (`phases.py:127–162`): Mode `split`. Processes evidence systems (optionally via a bounded concurrency worker pool in `runner.py:650–750`). Runs Planner (15 turns) -> Executor (80 turns) -> Analyst (60 turns).
3. **CROSS_SYSTEM** (`phases.py:164–192`): Mode `split`. Performs multi-source correlation across identified hosts and artifacts. Planner (15 turns) -> Executor (50 turns) -> Analyst (50 turns).
4. **ALTERNATIVE_NARRATIVE** (`phases.py:194–221`): Mode `split`. Conducts adversarial counter-analysis challenging initial findings. Planner (15 turns) -> Executor (35 turns) -> Analyst (35 turns).
5. **REPORT** (`phases.py:223–231`): Mode `single`. Role: `analyst`. Consolidates the validated findings, writes the narrative, and finalizes the case report. Turns: 25.

### Gate Definition and Enforcement
Each phase concludes with a quality gate evaluated in `src/lade/orchestrator/gates.py`:
- **Catalog Gate (`validate_catalog`, `gates.py:53–128`):** Verifies that the catalog agent emitted valid JSON containing `case_id`, a valid `evidence_root`, and a non-empty `systems` array (`len(systems) > 0`).
- **Extraction Gate (`validate_extraction`, `gates.py:131–193`):** Queries `get_investigation_summary` to verify that `sources_indexed > 0`. If the summary query fails on the first attempt, it logs an advisory warning and allows progression; on consecutive failures (`_consecutive_extraction_failures >= 1`), it fails.
- **Cross-System Gate (`validate_cross_system`, `gates.py:196–277`):** Verifies that `findings_submitted > 0` and `findings_with_mitre_ids > 0`. Consecutive query failures fail closed.
- **Alternative Narrative Gate (`validate_narrative`, `gates.py:280–370`):** Calls `check_finalize_readiness` tool. Verifies that all readiness gates passed, while deferring `narrative_submitted` to the report phase. An empty readiness response fails closed (`gates.py:350–360`).
- **Report Gate (`validate_report`, `gates.py:373–432`):** Requires that `finalize_report` was invoked AND the final Markdown report file exists on disk (`<db_dir>/<case_id>.report.md`) with a modified timestamp newer than the phase start time (`gates.py:396–410`).

### Progression Blocking and Retries
- Progression is strictly gated: in `runner.py:_run_split_phase()` and `runner.py:_run_single_phase()`, `gate_result.passed` must be `True` to proceed to the next phase.
- If a gate fails, the orchestrator triggers remediation (`runner.py:_remediate_phase()`, lines 400–480). It provides the exact `gate_result.gaps` to the agent prompt.
- Retries are bounded by `PhaseConfig.max_retries` (default `2`, `phases.py:84`). If all retries are exhausted, the investigation halts with an error (`runner.py:475–480`).
- Within split phases, the analyst can also request up to `max_follow_ups` (default `2`, `phases.py:85`) execution loops before final gate evaluation.

---

## 2. Agent Roles and Model Configuration

**Files:** `src/lade/orchestrator/roles.py` (lines 1–779), `src/lade/orchestrator/models.py` (lines 1–267), `src/lade/orchestrator/prompts/__init__.py` (lines 1–56).

### Role Implementation
- **Planner (`roles.py:run_planner`, lines 50–220):** Formulates an evidence-gathering plan. It must output a strict JSON array of tasks (`roles.py:110–135`). If the planner outputs malformed JSON or markdown commentary, `roles.py:_repair_plan_json()` uses a lightweight utility LLM query to repair the plan (`roles.py:140–180`). If repair fails, execution falls back or aborts.
- **Executor (`roles.py:run_executor`, lines 225–480):** Iterates through the plan, invoking authorized MCP tools. It enforces the role tool allowlist and logs each execution into the CaseDB and AuditLog.
- **Analyst (`roles.py:run_analyst`, lines 485–720):** Interprets the tool execution results, queries indexed text windows and timeline artifacts, submits structured findings via `submit_finding`, and determines whether follow-up execution is needed.

### Model Assignment and Configuration
Models are defined in `src/lade/orchestrator/models.py` via `RoleConfig`:
- **Defaults (`models.py:25–35`):**
  - Planner: `claude-opus-4-6` (or env `LADE_PLANNER_MODEL`)
  - Executor: `claude-haiku-4-5` (or env `LADE_EXECUTOR_MODEL`)
  - Analyst: `claude-opus-4-6` (or env `LADE_ANALYST_MODEL`)
  - Single-mode / Utility: `claude-opus-4-6` (or env `LADE_UTILITY_MODEL` / `LADE_MODEL`)
- **Overrides:** The CLI allows overriding global models via `--model <name>` or per-role models via `--role-model planner=<model> --role-model executor=<model>`.

### Prompt Loading
Prompts are loaded at runtime by `src/lade/orchestrator/prompts/__init__.py`:
- Markdown templates reside under `src/lade/orchestrator/prompts/*.md` (e.g. `catalog.md`, `extract_planner.md`, `extract_executor.md`, `extract_analyst.md`, `cross_system_planner.md`, `cross_system_executor.md`, `cross_system_analyst.md`, `narrative_planner.md`, `narrative_executor.md`, `narrative_analyst.md`, `report.md`).
- Loaded using `importlib.resources.files("lade.orchestrator.prompts").joinpath(...)` with UTF-8 decoding.

---

## 3. Tool Allowlists and MCP Registry

**Files:** `src/lade/server/tool_access.py` (lines 1–80), `src/lade/server/tools/` (all modules).

### Definition and Enforcement
- Role access is declared via the `@tool_access(*roles: Role, unthrottled: bool = False)` decorator (`tool_access.py:46–68`) placed directly below `@mcp.tool()`.
- The `Role` enum is a bitwise `Flag` (`CATALOG`, `EXTRACT_PLANNER`, `EXTRACT_EXECUTOR`, `EXTRACT_ANALYST`, `CROSS_PLANNER`, `CROSS_EXECUTOR`, `CROSS_ANALYST`, `NARRATIVE_PLANNER`, `NARRATIVE_EXECUTOR`, `NARRATIVE_ANALYST`, `REPORT`).
- `get_tools_for_role(role)` (`tool_access.py:71–75`) produces the prefixed list `mcp__lade__<tool_name>` passed to `ClaudeAgentOptions.allowed_tools` during session initialization.
- At runtime, `_wrap_sync_tool` in `src/lade/server/app.py` blocks off-role calls and enforces CPU/memory concurrency throttles unless marked `unthrottled=True`.

### MCP Server Tool Catalog (153 Registered Tools)

| Tool Name | Role Permissions | Type |
|---|---|---|
| `open_case`, `list_cases` | ALL_ROLES / CATALOG, PLANNER, REPORT | Generic |
| `list_sources`, `get_source_stats` | ALL_ROLES / CATALOG, ANALYSTS, REPORT | Generic |
| `search`, `get_timeline`, `filter_timeline` | ANALYSTS, EXECUTORS, REPORT | Generic |
| `bookmark_window`, `get_bookmarks`, `remove_bookmark` | ANALYSTS, EXECUTORS, REPORT | Generic |
| `submit_finding`, `update_finding`, `delete_finding`, `get_findings` | ANALYSTS, REPORT | Generic |
| `check_finalize_readiness`, `finalize_report`, `submit_narrative` | REPORT, NARRATIVE | Generic |
| `track_progress`, `get_investigation_summary` | ANALYSTS, REPORT | Generic |
| `run_parallel`, `wait`, `wait_all`, `check_extraction_status` | EXECUTORS, CATALOG | Generic |
| `list_directory`, `read_evidence_file` | CATALOG, EXECUTORS, ANALYSTS | Generic |
| `enrich_iocs`, `get_ioc_summary` | ANALYSTS, EXECUTORS, REPORT | Generic |
| `lookup_attack_technique` | ANALYSTS | Generic |
| `run_volatility`, `run_volatility_batch`, `list_processes_from_memory` | EXTRACT_EXECUTOR, CROSS_EXECUTOR | Host-Forensics (DFIR) |
| `run_fls`, `run_mmls`, `run_fsstat`, `extract_file_by_inode` | EXTRACT_EXECUTOR | Host-Forensics (DFIR) |
| `parse_mft`, `extract_mft_timeline`, `get_fs_timeline`, `get_deleted_files` | EXECUTORS, ANALYSTS | Host-Forensics (DFIR) |
| `parse_usn_journal`, `parse_shimcache`, `parse_amcache`, `run_amcache_parser` | EXECUTORS, ANALYSTS | Host-Forensics (DFIR) |
| `parse_prefetch`, `parse_prefetch_detailed`, `run_prefetch_parser` | EXECUTORS, ANALYSTS | Host-Forensics (DFIR) |
| `parse_srum`, `parse_shellbags`, `parse_jump_lists`, `parse_lnk_files` | EXECUTORS, ANALYSTS | Host-Forensics (DFIR) |
| `query_registry_value`, `run_registry_parser`, `run_regripper`, `get_userassist` | EXECUTORS, ANALYSTS | Host-Forensics (DFIR) |
| `index_evtx_file`, `run_evtx_parser`, `get_eventlog_anomalies` | EXTRACT_EXECUTOR, CROSS_EXECUTOR | Host-Forensics (DFIR) |
| `run_hayabusa`, `run_chainsaw`, `run_zircolite` | EXTRACT_EXECUTOR | Host-Forensics (DFIR) |
| `run_yara`, `yara_scan_files`, `yara_scan_memory`, `yara_scan_with_volatility` | EXTRACT_EXECUTOR | Host-Forensics (DFIR) |
| `run_capa`, `run_floss`, `run_strings`, `triage_binary`, `run_radare2`, `run_binwalk` | EXECUTORS, ANALYSTS | Host-Forensics (DFIR) |
| `analyze_office_document`, `analyze_pdf` | EXTRACT_EXECUTOR | Host-Forensics (DFIR) |
| `parse_pst` | EXTRACT_EXECUTOR | Host-Forensics (DFIR) |
| `run_aleapp`, `run_ileapp`, `run_mvt_android`, `run_mvt_ios` | EXTRACT_EXECUTOR | Host-Forensics (DFIR) |
| `run_pcap_analysis`, `analyze_disk_pcaps`, `correlate_pcap_with_host`, `run_zeek_analysis`, `run_suricata` | EXECUTORS | Host-Forensics / Network |
| `run_photorec`, `run_foremost`, `run_scalpel`, `run_bulk_extractor` | EXTRACT_EXECUTOR | Host-Forensics (Carving) |
| `run_plaso`, `get_plaso_stats` | EXECUTORS, ANALYSTS | Host-Forensics (Timeline) |
| `run_dislocker`, `run_bdeinfo`, `run_fvdeinfo`, `run_vshadow_info` | EXTRACT_EXECUTOR | Host-Forensics (Volume) |

---

## 4. The Audit Log

**File:** `src/lade/audit.py` (lines 1–323).

### File Format and Storage
- **Format:** JSON Lines (`.jsonl`), written with `separators=(",", ":")` (`audit.py:120`).
- **Location:** Stored per-case at `<db_dir>/<case_id>.audit.jsonl` (or configured log path).
- **Integrity:** Appends are thread-locked via `threading.Lock()` (`audit.py:46, 117–123`). Every write calls `fh.flush()` followed by `os.fsync(fh.fileno())` (`audit.py:121–122`) to guarantee crash persistence.

### Event Types and Fields
1. **Tool Invocations (`type: "tool_call"`, `audit.py:125–144`):**
   - `type`: `"tool_call"`
   - `tool_call_id`: Unique identifier (e.g. `tc_...`)
   - `tool_name`: Short MCP tool name
   - `params`: JSON serialization of passed arguments
   - `output_hash`: SHA-256 digest of the tool's raw text response
   - `duration_ms`: Execution latency in milliseconds
   - `timestamp`: UTC ISO-8601 string
   - `sub_calls` (optional): Child call IDs if dispatched via `run_parallel`
   - `batch_id` (optional): Identifier of parent batch
2. **Ingestion Steps (`type: "ingestion"`, `audit.py:160–178`):**
   - `type`: `"ingestion"`, `source_name`, `source_path`, `source_hash`, `extractor`, `window_count`, `duration_ms`, `timestamp`.
3. **Finding Submissions (`type: "finding"`, `audit.py:180–192`):**
   - `type`: `"finding"`, `finding_id`, `evidence_refs`, `timestamp`.

### Hash Chaining Status
- **Current State:** The audit log computes SHA-256 digests of individual outputs (`output_hash`). However, **no cryptographic hash chaining (`prev_hash` or Merkle tree) is currently implemented between JSONL entries**. Each entry is independent. Provenance tracing is reconstructed through `get_provenance_chain()` (`audit.py:194–220`), which maps a finding's `evidence_refs` back to indexed tool calls and source hashes in the CaseDB.

---

## 5. Evidence Handling and Finding Validation

**Files:** `src/lade/server/tools/findings.py` (lines 250–345), `src/lade/models.py` (lines 50–110), `src/lade/db.py` (lines 500–560).

### Finding Structure (`Finding` model, `models.py:53–75`)
- `finding_id`: Unique ID (e.g. `f-001`)
- `case_id`: Associated case
- `title`: Short descriptive title
- `description`: Comprehensive narrative
- `severity`: `"critical"` | `"high"` | `"medium"` | `"low"` | `"info"`
- `confidence`: `"confirmed"` (corroborated by 2+ sources) or `"inference"`
- `evidence_refs`: Array of strings referencing prior tool call IDs
- `sources`: Array of source names where evidence was extracted
- `mitre_attack_ids`: Optional list of ATT&CK technique IDs (e.g. `T1059.001`)
- `event_time_start` / `event_time_end`: Optional ISO-8601 timestamps
- `submitted_at`: UTC timestamp

### Validation Requirements for `submit_finding` (`findings.py:251–340`)
1. **Audit Log Membership:** Every element in `evidence_refs` must exist in `audit_log.tool_call_ids` (`findings.py:290–298`). Citing an invented or unreviewed tool call fails immediately.
2. **Source Existence:** Every entry in `sources` must correspond to a source registered in the CaseDB (`findings.py:300–305`).
3. **Valid Severity & Confidence:** Severity must match one of the 5 allowed levels. Confidence must be `"confirmed"` or `"inference"`.
4. **Timestamp Strictness:** Timestamps must be precise ISO-8601 strings copied from tool output; day-precision placeholders (`YYYY-MM-DD`) are rejected or auto-nullified (`findings.py:271–276`).
5. **Finalize Gate Dependency:** Any finding with severity > `"info"` must have `event_time_start` populated before `finalize_report` will clear the readiness gate (`findings.py:273–275`).

---

## 6. Persistence: CaseDB SQLite Schema

**File:** `src/lade/db.py` (lines 40–180).

Database connection uses SQLite in **WAL mode** with foreign keys enabled (`db.py:200–220`).

### Schema Tables
1. **`case_metadata` (`db.py:50–57`):**
   - `case_id` (Text, PK), `ingested_at` (Text), `evidence_root` (Text), `extractor_versions` (Text JSON), `narrative` (Text, nullable).
2. **`sources` (`db.py:59–70`):**
   - `source_id` (Integer, PK auto), `case_id` (Text, FK), `source_name` (Text, index), `source_path` (Text), `source_hash` (Text SHA-256), `extractor` (Text), `line_count` (Integer), `ingested_at` (Text), `windows_hash` (Text, nullable).
3. **`windows` (`db.py:72–80`):**
   - `window_id` (Integer, PK auto), `source_id` (Integer, FK, index), `line_start` (Integer), `line_end` (Integer), `event_time` (Text, index), `raw_text` (Text).
4. **`windows_fts` (`db.py:128–132`):**
   - SQLite FTS5 Virtual Table over `windows` (`raw_text, content=windows, content_rowid=window_id`).
5. **`findings` (`db.py:82–96`):**
   - `finding_id` (Text, PK), `case_id` (Text), `title` (Text), `description` (Text), `severity` (Text), `confidence` (Text), `evidence_refs` (Text JSON), `sources` (Text JSON), `mitre_attack_ids` (Text JSON), `event_time_start` (Text), `event_time_end` (Text), `submitted_at` (Text).
6. **`evidence_registry` (`db.py:98–105`):**
   - `id` (Integer, PK auto), `file_path` (Text), `sha256` (Text), `size_bytes` (Integer), `registered_at` (Text).
7. **`bookmarks` (`db.py:107–114`):**
   - `id` (Integer, PK auto), `window_id` (Integer, FK), `source_name` (Text), `note` (Text), `created_at` (Text).
8. **`progress` (`db.py:116–124`):**
   - `id` (Integer, PK auto), `system_name` (Text), `tools_completed` (Text JSON), `questions_addressed` (Text JSON), `notes` (Text), `recorded_at` (Text).
9. **`kv_store` (`db.py:126–131`):**
   - `key` (Text, PK), `value` (Text JSON), `updated_at` (Text).

---

## 7. The Adversarial / Alternative-Narrative Phase

**Files:** `src/lade/orchestrator/phases.py` (lines 194–221), `src/lade/orchestrator/prompts/narrative_*.md`.

### Step-by-Step Execution
1. **Planner Step (`narrative_planner.md`):**
   - Ingests the current case briefing, findings, timeline, and consistency report (`phases.py:199–203`).
   - Identifies high-severity claims and formulates counter-theories (e.g., legitimate admin activity, IT software updates, forensic artifact misattribution, clock skew).
   - Evaluates *Reverse Challenges* to confirm whether dismissed events actually form a coherent kill chain.
   - Outputs a plan of focused search and correlation queries.
2. **Executor Step (`narrative_executor.md`):**
   - Executes authorized queries (`correlate_across_sources`, `search`, `get_timeline`, `find_file_staging`, `detect_timestomping`).
3. **Analyst Step (`narrative_analyst.md`):**
   - Examines whether the counter-evidence refutes or weakens any findings.
   - Calls `update_finding` or `delete_finding` to adjust confidence, downgrade severity, or eliminate debunked hypotheses.
   - Identifies gaps via `check_finalize_readiness` and `audit_evidence_coverage`.
4. **Gate Validation (`gates.py:280–370`):**
   - Validates that readiness checks were evaluated and that no unaddressed blocking gaps remain before progressing to REPORT.

---

## 8. ATT&CK Data and Exporter

**Files:** `src/lade/report/navigator.py` (lines 1–130), `src/lade/report/data/attack_tactics.json` (lines 1–5), `src/lade/report/ioc_export.py` (lines 1–150).

### Version and Format
- **MITRE ATT&CK Navigator Layer Version:**
  - `versions`: `{"attack": "16", "navigator": "4.5", "layer": "4.5"}` (`navigator.py:91`).
  - `domain`: `"enterprise-attack"` (default) or `"ics-attack"` (`navigator.py:92`).
- **Tactics Metadata:** `src/lade/report/data/attack_tactics.json` maps ATT&CK tactic IDs to standardized display labels and matrix order.
- **Color Coding:** Color gradient based on finding severity:
  - Critical: `#ff0000` (score 100)
  - High: `#ff6600` (score 75)
  - Medium: `#ffff00` (score 50)
  - Low: `#66ccff` (score 25)
  - Info: `#ffffff` (score 10)
- **IOC Exporter (`ioc_export.py`):**
  - Exports extracted IOCs (IPs, domains, hashes, URLs) as STIX 2.1 bundles (`stix2.Bundle` with `Indicator` and `ObservedData` SDOs) or RFC 4180 CSV tables.

---

## 9. Entry Points and Invocations

**Files:** `src/lade/cli.py` (lines 1–790), `src/lade/server/app.py` (lines 1–765).

### CLI Commands (`lade.cli:cli`)
- `lade setup`: Provisions external tool binaries, rule sets (YARA, Chainsaw, Hayabusa), and symbol tables. Flags: `--dry-run`, `--verify`, `--force`, `--full`, `--inject-deps`.
- `lade serve`: Launches the MCP server. Supports `stdio` or SSE/HTTP transports (`--transport`, `--port`, `--host`). Flags: `--read-only`, `--case-id`.
- `lade investigate <evidence_path> <case_id>`: Launches the 5-phase automated multi-agent investigation. Flags: `--model`, `--role-model`, `--max-retries`, `--max-follow-ups`, `--workspace`, `--db-dir`, `--no-dashboard`.
- `lade report <case_id>`: Renders stand-alone HTML and Markdown incident reports from CaseDB.
- `lade export-iocs <case_id>`: Generates STIX 2.1 JSON or CSV IOC packages.
- `lade export-navigator <case_id>`: Generates ATT&CK Navigator layer JSON.

### Investigation Lifecycle
In `cli.py:investigate` (lines 350–450):
1. Resolves `evidence_path` and `case_id`.
2. Creates `CaseDB` and `AuditLog` in `db_dir` (default `~/.lade/cases/<case_id>`).
3. Instantiates `Orchestrator(case_id, evidence_root, db_dir=db_dir, config=...)`.
4. Runs `orchestrator.run()`, iterating CATALOG -> EXTRACTION -> CROSS_SYSTEM -> ALTERNATIVE_NARRATIVE -> REPORT.
5. On completion, generates final HTML/Markdown reports in the case directory.

---

## 10. DFIR vs. DevSecOps Tooling Transition Map

| Component / Tool | Current Implementation (Host DFIR) | DevSecOps Replacement / Future Status | Retain or Replace |
|---|---|---|---|
| **Pipeline Orchestrator** | 5 gated phases (Catalog, Extraction, Cross-System, Narrative, Report) | Same 5-phase pipeline applied to commit/CI/pipeline lifecycle | **RETAIN** (Generic) |
| **CaseDB (SQLite + FTS5)** | Source windows, findings, evidence registry, bookmarks | Unchanged schema; stores CI logs, traces, container manifests | **RETAIN** (Generic) |
| **AuditLog (JSONL)** | Append-only tool invocation logs with SHA-256 output digests | Unchanged format; audit trail for CI pipeline forensics | **RETAIN** (Generic) |
| **MCP Server Core** | FastMCP / standard MCP protocol with `@tool_access` allowlists | Unchanged server architecture; registers DevSecOps tools | **RETAIN** (Generic) |
| **Report Renderer** | Executive summary, finding tables, MITRE ATT&CK, provenance chain | Add remediation MR drafts, CI/CD impact section | **RETAIN** (Generic) |
| **Memory Analysis** | Volatility 3 (`run_volatility`, `list_processes_from_memory`) | Container runtime inspection, cgroup/OOM metrics, Falco alerts | **REPLACE** |
| **Disk & Filesystems** | The Sleuth Kit (`fls`, `mmls`, `fsstat`), MFT/USN parser | Git tree parser, Docker image layer diff, Syft SBOM extractor | **REPLACE** |
| **Windows Event Logs** | Hayabusa, Chainsaw, Zircolite, python-evtx | GitLab CI job log parser, Kubernetes pod events, Cloud Audit logs | **REPLACE** |
| **Signature Scanning** | Host YARA file/memory scanning (`yara_scan_files`) | Trivy container scanner, Gitleaks secrets scanner, Semgrep SAST | **REPLACE** |
| **Binary Triage** | Capa, FLOSS, Radare2, PE timestamp analysis | Container image vulnerability scan (GCP Artifact Registry / Trivy) | **REPLACE** |
| **Carving & Volume** | Foremost, Photorec, Dislocker, BitLocker info | Artifact bundle unpacker, OCI registry blob unpacker | **REPLACE** |
| **Mobile & PST Forensics**| ALEAPP, iLEAPP, MVT, `readpst` | Webhook event ingest, GitLab MR diff extractor, OIDC auditor | **REPLACE** |
| **Network PCAP** | Zeek, Suricata, `pcap_analysis` | VPC Flow Logs, Istio/Envoy access logs, Kubernetes ingress logs | **REPLACE / ADAPT** |
