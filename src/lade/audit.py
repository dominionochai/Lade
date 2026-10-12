"""Append-only JSONL audit log for a case investigation."""

from __future__ import annotations

import hashlib
import json
import logging
import os
import threading
from collections import defaultdict
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, cast

from lade.models import (
    AuditSummary,
    ProvenanceChain,
    SourceProvenance,
    ToolCallEntry,
)

if TYPE_CHECKING:
    from lade.db import CaseDB

logger = logging.getLogger(__name__)

_COST_PER_MTOK_INPUT = 3.0
_COST_PER_MTOK_OUTPUT = 15.0
_MIN_OUTPUT_TOKEN_ESTIMATE = 100


def compute_record_hash(record: Mapping[str, object]) -> str:
    """Compute SHA-256 over the canonical JSON of the record without record_hash.

    Canonical representation: json.dumps(obj, sort_keys=True, separators=(",", ":"),
    ensure_ascii=False) encoded as UTF-8.
    """
    obj = {k: v for k, v in record.items() if k != "record_hash"}
    canonical = json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


@dataclass
class AuditVerificationResult:
    """Result of verifying an audit log's SHA-256 hash chain."""

    ok: bool
    record_count: int = 0
    head_hash: str | None = None
    unchained_count: int = 0
    error_seq: int | None = None
    error_reason: str | None = None
    error_message: str | None = None

    @property
    def legacy_count(self) -> int:
        """Alias for unchained_count."""
        return self.unchained_count

    def __bool__(self) -> bool:
        return self.ok

    def __str__(self) -> str:
        if self.ok:
            head_12 = self.head_hash[:12] if self.head_hash else "0" * 12
            if self.unchained_count > 0:
                return (
                    f"OK: {self.record_count} records, head {head_12} "
                    f"({self.unchained_count} unchained)"
                )
            return f"OK: {self.record_count} records, head {head_12}"
        seq_str = f"seq {self.error_seq}: " if self.error_seq is not None else ""
        return f"FAILED: {seq_str}{self.error_reason}"


class AuditLog:
    """Append-only JSONL audit log for a case investigation.

    Each ``log_tool_call`` invocation appends a single JSON line and records
    the ``tool_call_id`` in an in-memory index for fast validation by
    ``submit_finding`` and provenance chain resolution.
    """

    def __init__(self, log_path: Path, db: CaseDB | None = None) -> None:
        """Open or create an audit log at ``log_path`` and load existing entries."""
        self._log_path = Path(log_path)
        self._db = db
        self._lock = threading.Lock()
        self._last_seq: int = -1
        self._last_hash: str = "0" * 64
        self._tool_call_ids: set[str] = set()
        self._tool_calls: dict[str, dict[str, object]] = {}
        self._finding_entries: dict[str, dict[str, object]] = {}
        self._total_tool_calls: int = 0
        self._total_findings: int = 0
        self._total_duration_ms: float = 0.0
        self._tool_call_counts: dict[str, int] = defaultdict(int)
        self._tool_durations: dict[str, float] = defaultdict(float)
        self._estimated_input_tokens: int = 0
        self._estimated_output_tokens: int = 0
        self._timestamps: list[str] = []
        self._load_existing()

    @property
    def db(self) -> CaseDB | None:
        """The CaseDB instance linked for anchor persistence, if any."""
        return self._db

    @db.setter
    def db(self, db: CaseDB | None) -> None:
        self._db = db

    @property
    def last_seq(self) -> int:
        """The sequence number of the most recent chained record."""
        return self._last_seq

    @property
    def last_hash(self) -> str:
        """The record_hash of the most recent chained record."""
        return self._last_hash

    def _load_existing(self) -> None:
        """Populate in-memory indexes from an existing JSONL file."""
        if not self._log_path.exists():
            return
        parse_errors = 0
        last_entry: dict[str, object] | None = None
        with open(self._log_path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    parse_errors += 1
                    continue
                if isinstance(entry, dict):
                    self._index_entry(cast(dict[str, object], entry))
                    last_entry = entry

        if last_entry is not None and "seq" in last_entry and "record_hash" in last_entry:
            try:
                self._last_seq = int(last_entry["seq"])  # type: ignore[arg-type]
                self._last_hash = str(last_entry["record_hash"])
            except (ValueError, TypeError):
                self._last_seq = -1
                self._last_hash = "0" * 64
        else:
            self._last_seq = -1
            self._last_hash = "0" * 64

        if parse_errors > 0:
            logger.warning(
                "Audit log %s: %d lines failed to parse (possible corruption)",
                self._log_path,
                parse_errors,
            )

    def _index_entry(self, entry: dict[str, object]) -> None:
        """Index a parsed audit entry by type and update summary accumulators."""
        ts = entry.get("timestamp")
        if isinstance(ts, str) and ts:
            self._timestamps.append(ts)

        entry_type = entry.get("type")
        if entry_type == "tool_call" and "tool_call_id" in entry:
            tcid = entry["tool_call_id"]
            if not isinstance(tcid, str):
                return
            self._tool_call_ids.add(tcid)
            self._tool_calls[tcid] = entry
            tool_name = entry.get("tool_name", "unknown")
            if isinstance(tool_name, str) and tool_name != "run_parallel":
                self._total_tool_calls += 1
                dur = entry.get("duration_ms", 0)
                dur_f = float(dur) if isinstance(dur, int | float) else 0.0
                self._tool_call_counts[tool_name] += 1
                self._tool_durations[tool_name] += dur_f
                self._total_duration_ms += dur_f
                params_str = json.dumps(entry.get("params", {}))
                self._estimated_input_tokens += len(params_str) // 4
                self._estimated_output_tokens += max(
                    len(params_str) // 2, _MIN_OUTPUT_TOKEN_ESTIMATE
                )
        elif entry_type == "finding" and "finding_id" in entry:
            fid = entry["finding_id"]
            if not isinstance(fid, str):
                return
            self._finding_entries[fid] = entry
            self._total_findings += 1

    def _append(self, entry: dict[str, object]) -> None:
        """Append ``entry`` to the JSONL log file with SHA-256 hash chaining."""
        with self._lock:
            seq = self._last_seq + 1
            prev_hash = self._last_hash
            entry["seq"] = seq
            entry["prev_hash"] = prev_hash
            record_hash = compute_record_hash(entry)
            entry["record_hash"] = record_hash
            self._last_seq = seq
            self._last_hash = record_hash

            self._log_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self._log_path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry, separators=(",", ":"), ensure_ascii=False) + "\n")
                fh.flush()
                os.fsync(fh.fileno())

            if self._db is not None:
                try:
                    self._db.set_kv(
                        "audit_head",
                        json.dumps({"seq": seq, "record_hash": record_hash}),
                    )
                except Exception:
                    logger.warning("Failed to store audit_head in CaseDB kv_store", exc_info=True)

            self._index_entry(entry)

    def log_tool_call(
        self,
        tool_call_id: str,
        tool_name: str,
        params: Mapping[str, object],
        output_hash: str,
        duration_ms: float = 0,
        sub_calls: list[str] | None = None,
        batch_id: str | None = None,
    ) -> None:
        """Record a tool invocation as one JSONL line and index ``tool_call_id``."""
        entry: dict[str, object] = {
            "type": "tool_call",
            "tool_call_id": tool_call_id,
            "tool_name": tool_name,
            "params": dict(params),
            "output_hash": output_hash,
            "duration_ms": duration_ms,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        if sub_calls is not None:
            entry["sub_calls"] = sub_calls
        if batch_id is not None:
            entry["batch_id"] = batch_id
        self._append(entry)

    def has_tool_call(self, tool_call_id: str) -> bool:
        """Return True if ``tool_call_id`` appears in this audit log."""
        return tool_call_id in self._tool_call_ids

    @property
    def tool_call_ids(self) -> set[str]:
        """All tool call IDs indexed from the log (copy of the internal set)."""
        return set(self._tool_call_ids)

    def log_ingestion_step(
        self,
        source_name: str,
        source_path: str,
        source_hash: str,
        extractor: str,
        window_count: int,
        duration_ms: float,
    ) -> None:
        """Record a source ingestion step (extractor run and window count)."""
        entry: dict[str, object] = {
            "type": "ingestion",
            "source_name": source_name,
            "source_path": source_path,
            "source_hash": source_hash,
            "extractor": extractor,
            "window_count": window_count,
            "duration_ms": duration_ms,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        self._append(entry)

    def log_finding_submission(
        self,
        finding_id: str,
        evidence_refs: list[str],
    ) -> None:
        """Record a finding submission and its evidence tool-call references."""
        entry: dict[str, object] = {
            "type": "finding",
            "finding_id": finding_id,
            "evidence_refs": evidence_refs,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        self._append(entry)

    def get_provenance_chain(self, finding_id: str, db: CaseDB) -> ProvenanceChain:
        """Trace a finding back through tool calls to original evidence files."""
        finding_entry = self._finding_entries.get(finding_id)
        if finding_entry is None:
            raise KeyError(f"No finding with id '{finding_id}' in the audit log")

        raw_refs = finding_entry.get("evidence_refs", [])
        if isinstance(raw_refs, list):
            evidence_refs = [x for x in raw_refs if isinstance(x, str)]
        else:
            evidence_refs = []
        tool_calls, queried_source_names = self._resolve_tool_calls(evidence_refs)
        sources = self._resolve_sources(queried_source_names, db)

        return ProvenanceChain(
            finding_id=finding_id,
            tool_calls=tool_calls,
            sources=sources,
        )

    def _resolve_tool_calls(
        self, evidence_refs: list[str]
    ) -> tuple[list[ToolCallEntry], set[str]]:
        """Map ``evidence_refs`` to ``ToolCallEntry`` rows and collect source names."""
        tool_calls: list[ToolCallEntry] = []
        source_names: set[str] = set()

        for ref in evidence_refs:
            tc = self._tool_calls.get(ref)
            if tc is None:
                continue
            tcid_o = tc.get("tool_call_id", "")
            tname_o = tc.get("tool_name", "")
            params_o = tc.get("params", {})
            outh_o = tc.get("output_hash", "")
            ts_o = tc.get("timestamp", "")
            dur_o = tc.get("duration_ms", 0)
            params: dict[str, object] = (
                cast(dict[str, object], params_o) if isinstance(params_o, dict) else {}
            )
            dur_f = float(dur_o) if isinstance(dur_o, int | float) else 0.0
            bid_o = tc.get("batch_id")
            tool_calls.append(
                ToolCallEntry(
                    tool_call_id=tcid_o if isinstance(tcid_o, str) else "",
                    tool_name=tname_o if isinstance(tname_o, str) else "",
                    params=params,
                    output_hash=outh_o if isinstance(outh_o, str) else "",
                    timestamp=ts_o if isinstance(ts_o, str) else "",
                    duration_ms=dur_f,
                    batch_id=bid_o if isinstance(bid_o, str) else None,
                )
            )
            source_names.update(self._extract_source_names(params))

        return tool_calls, source_names

    @staticmethod
    def _extract_source_names(params: dict[str, object]) -> set[str]:
        """Collect source identifiers from tool ``params`` (keys, channel, lists)."""
        names: set[str] = set()
        for key in ("source", "source_name"):
            val = params.get(key)
            if isinstance(val, str):
                names.add(val)
        channel = params.get("channel")
        if channel is not None:
            names.add(f"evtx.{channel}")
        sources_list = params.get("sources")
        if isinstance(sources_list, list):
            names.update(x for x in sources_list if isinstance(x, str))
        return names

    @staticmethod
    def _resolve_sources(queried_names: set[str], db: CaseDB) -> list[SourceProvenance]:
        """Look up ``SourceProvenance`` rows in the case DB for ``queried_names``."""
        db_sources = {s.source_name: s for s in db.get_sources()}
        return [
            SourceProvenance(
                source_name=src.source_name,
                source_path=src.source_path,
                source_hash=src.source_hash,
                extractor=src.extractor,
            )
            for name in sorted(queried_names)
            if (src := db_sources.get(name)) is not None
        ]

    def summary(self) -> AuditSummary:
        """Compute aggregate statistics from in-memory accumulators."""
        if not self._timestamps and self._total_tool_calls == 0:
            return AuditSummary(
                total_tool_calls=0,
                total_findings=0,
                tool_call_counts={},
                total_duration_ms=0.0,
                first_timestamp="",
                last_timestamp="",
            )

        cost_per_mtok_in = _COST_PER_MTOK_INPUT
        cost_per_mtok_out = _COST_PER_MTOK_OUTPUT
        estimated_cost = (
            self._estimated_input_tokens / 1_000_000 * cost_per_mtok_in
            + self._estimated_output_tokens / 1_000_000 * cost_per_mtok_out
        )

        wall_clock_ms = self._total_duration_ms
        if len(self._timestamps) >= 2:
            try:
                t0 = datetime.fromisoformat(self._timestamps[0])
                t1 = datetime.fromisoformat(self._timestamps[-1])
                wall_clock_ms = (t1 - t0).total_seconds() * 1000
            except (ValueError, TypeError):
                pass

        return AuditSummary(
            total_tool_calls=self._total_tool_calls,
            total_findings=self._total_findings,
            tool_call_counts=dict(self._tool_call_counts),
            tool_durations=dict(self._tool_durations),
            total_duration_ms=self._total_duration_ms,
            wall_clock_ms=wall_clock_ms,
            first_timestamp=self._timestamps[0] if self._timestamps else "",
            last_timestamp=self._timestamps[-1] if self._timestamps else "",
            estimated_input_tokens=self._estimated_input_tokens,
            estimated_output_tokens=self._estimated_output_tokens,
            estimated_cost_usd=round(estimated_cost, 4),
        )


def _resolve_anchor(anchor: object, log_path: Path) -> tuple[int, str] | None:
    """Resolve an anchor argument or companion DB into (seq, record_hash)."""
    raw_value: object = anchor
    if raw_value is None and log_path.name.endswith(".audit.jsonl"):
        case_id = log_path.name[: -len(".audit.jsonl")]
        companion = log_path.parent / f"{case_id}.db"
        if companion.is_file():
            raw_value = companion

    if isinstance(raw_value, Path) or (
        isinstance(raw_value, str) and (raw_value.endswith(".db") or Path(raw_value).is_file())
    ):
        db_file = Path(raw_value)
        if db_file.is_file():
            try:
                import sqlite3

                from lade.server.helpers import readonly_sqlite_uri

                conn = sqlite3.connect(readonly_sqlite_uri(db_file), uri=True)
                try:
                    cursor = conn.cursor()
                    cursor.execute("SELECT value FROM kv_store WHERE key = 'audit_head'")
                    row = cursor.fetchone()
                    if row and row[0]:
                        raw_value = row[0]
                    else:
                        return None
                finally:
                    conn.close()
            except Exception:
                return None

    if hasattr(raw_value, "get_kv"):
        try:
            val = raw_value.get_kv("audit_head")
            if val:
                raw_value = val
            else:
                return None
        except Exception:
            return None

    if isinstance(raw_value, str):
        raw_value = raw_value.strip()
        try:
            parsed = json.loads(raw_value)
            if isinstance(parsed, dict):
                raw_value = parsed
        except json.JSONDecodeError:
            if ":" in raw_value:
                parts = raw_value.split(":", 1)
                return int(parts[0]), parts[1]
            return None

    if isinstance(raw_value, Mapping):
        seq = raw_value.get("seq")
        rec_hash = raw_value.get("record_hash")
        if seq is not None and rec_hash is not None:
            return int(seq), str(rec_hash)

    if isinstance(raw_value, (tuple, list)) and len(raw_value) >= 2:
        return int(raw_value[0]), str(raw_value[1])

    return None


def verify_chain(
    path: str | Path,
    anchor: Mapping[str, object] | str | CaseDB | tuple[int, str] | None = None,
) -> AuditVerificationResult:
    """Verify the SHA-256 hash chain in an audit log file.

    Recomputes every hash, checks sequence continuity and previous-hash links,
    and optionally compares the chain head to an anchor stored in CaseDB kv_store.

    Args:
        path: Path to the .audit.jsonl file.
        anchor: Expected chain head as (seq, record_hash) tuple, dict, JSON string,
            or CaseDB instance. If None and a companion .db file exists, the anchor
            is loaded automatically from kv_store["audit_head"].

    Returns:
        AuditVerificationResult with ok=True or the first failure reason.
    """
    log_path = Path(path)
    if not log_path.exists():
        return AuditVerificationResult(
            ok=False,
            error_reason="file_not_found",
            error_message=f"File not found: {log_path}",
        )

    expected_anchor = _resolve_anchor(anchor, log_path)

    expected_seq = 0
    expected_prev_hash = "0" * 64
    chained_count = 0
    unchained_count = 0
    last_seq: int | None = None
    last_hash: str | None = None

    with open(log_path, encoding="utf-8") as fh:
        for line_no, raw_line in enumerate(fh, start=1):
            line = raw_line.strip()
            if not line:
                continue

            try:
                entry = json.loads(line)
            except json.JSONDecodeError as exc:
                return AuditVerificationResult(
                    ok=False,
                    error_seq=expected_seq,
                    error_reason="malformed_line",
                    error_message=f"Line {line_no}: invalid JSON ({exc})",
                    unchained_count=unchained_count,
                    record_count=chained_count,
                )

            if not isinstance(entry, dict):
                return AuditVerificationResult(
                    ok=False,
                    error_seq=expected_seq,
                    error_reason="malformed_line",
                    error_message=f"Line {line_no}: record is not a JSON object",
                    unchained_count=unchained_count,
                    record_count=chained_count,
                )

            is_chained = "seq" in entry or "record_hash" in entry or "prev_hash" in entry

            if not is_chained:
                if chained_count == 0:
                    unchained_count += 1
                    continue
                return AuditVerificationResult(
                    ok=False,
                    error_seq=expected_seq,
                    error_reason="malformed_line",
                    error_message=f"Line {line_no}: missing chain fields after chain start",
                    unchained_count=unchained_count,
                    record_count=chained_count,
                )

            seq = entry.get("seq")
            prev_hash = entry.get("prev_hash")
            record_hash = entry.get("record_hash")

            if (
                not isinstance(seq, int)
                or not isinstance(prev_hash, str)
                or not isinstance(record_hash, str)
            ):
                return AuditVerificationResult(
                    ok=False,
                    error_seq=seq if isinstance(seq, int) else expected_seq,
                    error_reason="malformed_line",
                    error_message=f"Line {line_no}: malformed chain fields",
                    unchained_count=unchained_count,
                    record_count=chained_count,
                )

            # 1. Sequence number continuity
            if seq != expected_seq:
                return AuditVerificationResult(
                    ok=False,
                    error_seq=seq,
                    error_reason="seq_gap",
                    error_message=(
                        f"Line {line_no}: sequence gap: "
                        f"expected seq {expected_seq}, got seq {seq}"
                    ),
                    unchained_count=unchained_count,
                    record_count=chained_count,
                )

            # 2. Previous hash link
            if prev_hash != expected_prev_hash:
                return AuditVerificationResult(
                    ok=False,
                    error_seq=seq,
                    error_reason="prev_mismatch",
                    error_message=(
                        f"Line {line_no}: prev_hash mismatch: "
                        f"expected {expected_prev_hash}, got {prev_hash}"
                    ),
                    unchained_count=unchained_count,
                    record_count=chained_count,
                )

            # 3. Canonical record hash verification
            computed = compute_record_hash(entry)
            if computed != record_hash:
                return AuditVerificationResult(
                    ok=False,
                    error_seq=seq,
                    error_reason="hash_mismatch",
                    error_message=(
                        f"Line {line_no}: record_hash mismatch: "
                        f"expected {computed}, got {record_hash}"
                    ),
                    unchained_count=unchained_count,
                    record_count=chained_count,
                )

            chained_count += 1
            last_seq = seq
            last_hash = record_hash
            expected_seq = seq + 1
            expected_prev_hash = record_hash

    if expected_anchor is not None:
        anchor_seq, anchor_hash = expected_anchor
        if last_seq != anchor_seq or last_hash != anchor_hash:
            return AuditVerificationResult(
                ok=False,
                record_count=chained_count,
                head_hash=last_hash,
                unchained_count=unchained_count,
                error_seq=anchor_seq,
                error_reason="anchor_mismatch",
                error_message=(
                    f"Anchor mismatch: DB anchor expects seq {anchor_seq} "
                    f"({anchor_hash[:12]}...), but file head is seq {last_seq} "
                    f"({last_hash[:12] if last_hash else None}...)"
                ),
            )

    default_head = "0" * 64 if unchained_count == 0 else None
    return AuditVerificationResult(
        ok=True,
        record_count=chained_count,
        head_hash=last_hash if last_hash is not None else default_head,
        unchained_count=unchained_count,
    )
