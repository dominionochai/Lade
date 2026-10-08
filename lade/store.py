"""Per-case SQLite persistence, FTS5 indexing, and evidence registry."""
from __future__ import annotations
import json, re, sqlite3
from pathlib import Path
from typing import Any

_CASE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,99}$")

class CaseStore:
    def __init__(self, root: str | Path, case_id: str):
        if not _CASE_RE.fullmatch(case_id):
            raise ValueError("case-id must contain 1-100 safe characters")
        self.case_id = case_id
        self.directory = Path(root).expanduser().resolve() / "cases" / case_id
        self.directory.mkdir(parents=True, exist_ok=True)
        self.db_path = self.directory / "case.sqlite3"
        self.audit_path = self.directory / "audit.jsonl"
        self._init_db()

    def connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.db_path)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA foreign_keys=ON")
        return db

    def _init_db(self) -> None:
        with self.connect() as db:
            db.executescript("""
            CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS sources (source_id TEXT PRIMARY KEY, path TEXT NOT NULL, sha256 TEXT NOT NULL, size INTEGER NOT NULL, media_type TEXT NOT NULL, text TEXT NOT NULL, indexed_at TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS extracted_windows (window_id TEXT PRIMARY KEY, source_id TEXT NOT NULL, text TEXT NOT NULL, start_line INTEGER, FOREIGN KEY(source_id) REFERENCES sources(source_id));
            CREATE VIRTUAL TABLE IF NOT EXISTS window_fts USING fts5(window_id UNINDEXED, source_id UNINDEXED, text);
            CREATE TABLE IF NOT EXISTS findings (finding_id TEXT PRIMARY KEY, payload TEXT NOT NULL, created_at TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS evidence_registry (call_id TEXT NOT NULL, source_id TEXT NOT NULL, output_text TEXT NOT NULL, PRIMARY KEY(call_id, source_id));
            CREATE TABLE IF NOT EXISTS tool_calls (call_id TEXT PRIMARY KEY, tool_name TEXT NOT NULL, params_json TEXT NOT NULL, output_text TEXT NOT NULL, output_digest TEXT NOT NULL, duration_ms REAL NOT NULL, timestamp TEXT NOT NULL, chain_hash TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS progress (phase TEXT PRIMARY KEY, status TEXT NOT NULL, attempts INTEGER NOT NULL, detail TEXT NOT NULL, updated_at TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS iocs (value TEXT PRIMARY KEY, kind TEXT NOT NULL, source_id TEXT NOT NULL);
            """)
            db.execute("INSERT OR REPLACE INTO metadata(key,value) VALUES('case_id',?)", (self.case_id,))

    def add_source(self, src: dict[str, Any]) -> None:
        with self.connect() as db:
            db.execute("INSERT OR REPLACE INTO sources VALUES(?,?,?,?,?,?,?)", (src["source_id"], src["path"], src["sha256"], src["size"], src["media_type"], src["text"], src["indexed_at"]))

    def sources(self) -> list[dict[str, Any]]:
        with self.connect() as db:
            return [dict(r) for r in db.execute("SELECT * FROM sources ORDER BY indexed_at,source_id")]

    def source(self, source_id: str) -> dict[str, Any] | None:
        with self.connect() as db:
            row = db.execute("SELECT * FROM sources WHERE source_id=?", (source_id,)).fetchone()
            return dict(row) if row else None

    def add_window(self, window_id: str, source_id: str, text: str, start_line: int | None) -> None:
        with self.connect() as db:
            db.execute("INSERT OR REPLACE INTO extracted_windows VALUES(?,?,?,?)", (window_id, source_id, text, start_line))
            db.execute("INSERT INTO window_fts(window_id,source_id,text) VALUES(?,?,?)", (window_id, source_id, text))

    def search_windows(self, query: str, limit: int = 20) -> list[dict[str, Any]]:
        with self.connect() as db:
            try:
                rows = db.execute("SELECT window_id,source_id,text FROM window_fts WHERE window_fts MATCH ? LIMIT ?", (query, limit)).fetchall()
            except sqlite3.OperationalError:
                return []
            return [dict(r) for r in rows]

    def record_call(self, event: dict[str, Any]) -> None:
        with self.connect() as db:
            db.execute("INSERT INTO tool_calls VALUES(?,?,?,?,?,?,?,?)", (event["call_id"], event["tool_name"], json.dumps(event["params"], sort_keys=True), event["output_text"], event["output_digest"], event["duration_ms"], event["timestamp"], event["hash"]))

    def register_evidence(self, call_id: str, source_id: str, output_text: str) -> None:
        with self.connect() as db:
            db.execute("INSERT OR REPLACE INTO evidence_registry VALUES(?,?,?)", (call_id, source_id, output_text))

    def evidence_for_call(self, call_id: str) -> list[dict[str, Any]]:
        with self.connect() as db:
            return [dict(r) for r in db.execute("SELECT * FROM evidence_registry WHERE call_id=?", (call_id,))]

    def call(self, call_id: str) -> dict[str, Any] | None:
        with self.connect() as db:
            row = db.execute("SELECT * FROM tool_calls WHERE call_id=?", (call_id,)).fetchone()
            return dict(row) if row else None

    def add_finding(self, finding: dict[str, Any]) -> None:
        with self.connect() as db:
            db.execute("INSERT OR REPLACE INTO findings VALUES(?,?,?)", (finding["finding_id"], json.dumps(finding, sort_keys=True), finding["created_at"]))
            for ioc in finding.get("iocs", []):
                db.execute("INSERT OR IGNORE INTO iocs VALUES(?,?,?)", (ioc, "observed", finding["evidence_refs"][0]["source_id"]))

    def findings(self) -> list[dict[str, Any]]:
        with self.connect() as db:
            return [json.loads(r[0]) for r in db.execute("SELECT payload FROM findings ORDER BY created_at,finding_id")]

    def record_progress(self, phase: str, status: str, attempts: int, detail: str, updated_at: str) -> None:
        with self.connect() as db:
            db.execute("INSERT OR REPLACE INTO progress VALUES(?,?,?,?,?)", (phase, status, attempts, detail, updated_at))

    def calls(self) -> list[dict[str, Any]]:
        with self.connect() as db:
            return [dict(r) for r in db.execute("SELECT * FROM tool_calls ORDER BY timestamp,call_id")]
