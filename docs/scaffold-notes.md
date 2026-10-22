# Scaffold Notes (Archival Record)

This record preserves the interface design from the pre-engine scaffold (`lade/models.py` and `lade/store.py`), present prior to commit `5cc8ea3`.

## 1. Phase Enum and Ordering

Defined in `lade/models.py`:

```python
class Phase(str, Enum):
    CATALOG = "CATALOG"
    EXTRACTION = "EXTRACTION"
    CROSS_SYSTEM = "CROSS_SYSTEM"
    ALTERNATIVE_NARRATIVE = "ALTERNATIVE_NARRATIVE"
    REPORT = "REPORT"

PHASE_ORDER = tuple(Phase)
```

## 2. Default Models Configuration

Defined in `lade/models.py`:

```python
DEFAULT_MODELS = {
    "planner": "claude-opus-5-5",
    "executor": "claude-haiku-5-5",
    "analyst": "claude-opus-5-5",
}
```

Supporting structures:
- `AgentConfig(role: str, model: str)` (frozen dataclass)
- `PhaseResult(phase: Phase, success: bool, attempts: int, detail: str)`
- `EvidenceRef(call_id: str, quote: str, source_id: str)`
- `Finding(finding_id: str, title: str, narrative: str, severity: str, confidence: float, created_at: str, evidence_refs: list[EvidenceRef], mitre_techniques: list[str], cwe_ids: list[str], iocs: list[str])`

## 3. CaseStore API Shape

Defined in `lade/store.py` (`CaseStore` class wrapping SQLite WAL database and FTS5 index):

### Constructor & Lifecycle
- `CaseStore(root: str | Path, case_id: str)`: Validates `case_id` against `^[A-Za-z0-9][A-Za-z0-9_.-]{0,99}$`. Sets up `<root>/cases/<case_id>/case.sqlite3` and `<root>/cases/<case_id>/audit.jsonl`.
- `connect() -> sqlite3.Connection`: Connects with `sqlite3.Row`, `WAL` mode, and foreign keys enabled.
- `_init_db() -> None`: Initializes schema (`metadata`, `sources`, `extracted_windows`, `window_fts` FTS5 virtual table, `findings`, `evidence_registry`, `tool_calls`, `progress`, `iocs`).

### Data Operations
- `add_source(src: dict[str, Any]) -> None`: Inserts/replaces into `sources` (source_id, path, sha256, size, media_type, text, indexed_at).
- `sources() -> list[dict[str, Any]]`: Returns all sources ordered by indexed_at, source_id.
- `source(source_id: str) -> dict[str, Any] | None`: Fetches single source by ID.
- `add_window(window_id: str, source_id: str, text: str, start_line: int | None) -> None`: Inserts into `extracted_windows` and `window_fts`.
- `search_windows(query: str, limit: int = 20) -> list[dict[str, Any]]`: Executes FTS5 MATCH against `window_fts`.
- `record_call(event: dict[str, Any]) -> None`: Inserts into `tool_calls` (call_id, tool_name, params_json, output_text, output_digest, duration_ms, timestamp, hash).
- `call(call_id: str) -> dict[str, Any] | None`: Returns tool call by ID.
- `calls() -> list[dict[str, Any]]`: Lists all tool calls ordered by timestamp, call_id.
- `register_evidence(call_id: str, source_id: str, output_text: str) -> None`: Inserts into `evidence_registry`.
- `evidence_for_call(call_id: str) -> list[dict[str, Any]]`: Returns evidence items for a call ID.
- `add_finding(finding: dict[str, Any]) -> None`: Inserts finding payload into `findings`, extracts `iocs` into `iocs` table.
- `findings() -> list[dict[str, Any]]`: Returns list of parsed finding payloads.
- `record_progress(phase: str, status: str, attempts: int, detail: str, updated_at: str) -> None`: Records phase state in `progress`.
