"""Tests for the SHA-256 hash chain in lade.audit."""

from __future__ import annotations

import json
import threading
from pathlib import Path

from click.testing import CliRunner

from lade.audit import AuditLog, verify_chain
from lade.cli import cli
from lade.db import CaseDB


def test_fresh_log_of_10_records_verifies_ok(tmp_path: Path) -> None:
    """1. A fresh log of 10 records verifies OK."""
    log_path = tmp_path / "test.audit.jsonl"
    audit = AuditLog(log_path)
    for i in range(10):
        audit.log_tool_call(
            tool_call_id=f"tc_{i}",
            tool_name="search",
            params={"query": f"item_{i}"},
            output_hash=f"hash_{i}",
            duration_ms=10.0 * i,
        )

    res = verify_chain(log_path)
    assert res.ok is True
    assert res.record_count == 10
    assert res.unchained_count == 0
    assert res.head_hash == audit.last_hash
    assert res.error_reason is None

    # CLI verification
    runner = CliRunner()
    cli_res = runner.invoke(cli, ["audit-verify", str(log_path)])
    assert cli_res.exit_code == 0
    assert f"OK: 10 records, head {audit.last_hash[:12]}" in cli_res.output


def test_editing_field_in_middle_record_detected(tmp_path: Path) -> None:
    """2. Editing a field in a middle record is detected at that seq (hash_mismatch)."""
    log_path = tmp_path / "test.audit.jsonl"
    audit = AuditLog(log_path)
    for i in range(10):
        audit.log_tool_call(
            tool_call_id=f"tc_{i}",
            tool_name="search",
            params={"query": f"item_{i}"},
            output_hash=f"hash_{i}",
            duration_ms=10.0 * i,
        )

    lines = log_path.read_text(encoding="utf-8").splitlines()
    # Edit a field in seq 4 (the 5th line)
    rec = json.loads(lines[4])
    assert rec["seq"] == 4
    rec["tool_name"] = "tampered_search"
    lines[4] = json.dumps(rec, separators=(",", ":"))
    log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    res = verify_chain(log_path)
    assert res.ok is False
    assert res.error_seq == 4
    assert res.error_reason == "hash_mismatch"

    # CLI verification
    runner = CliRunner()
    cli_res = runner.invoke(cli, ["audit-verify", str(log_path)])
    assert cli_res.exit_code == 1
    assert "seq 4" in cli_res.output
    assert "hash_mismatch" in cli_res.output


def test_deleting_middle_record_detected(tmp_path: Path) -> None:
    """3. Deleting a middle record is detected (seq_gap or prev_mismatch)."""
    log_path = tmp_path / "test.audit.jsonl"
    audit = AuditLog(log_path)
    for i in range(10):
        audit.log_tool_call(
            tool_call_id=f"tc_{i}",
            tool_name="search",
            params={"query": f"item_{i}"},
            output_hash=f"hash_{i}",
            duration_ms=10.0 * i,
        )

    lines = log_path.read_text(encoding="utf-8").splitlines()
    del lines[4]  # Remove record seq 4
    log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    res = verify_chain(log_path)
    assert res.ok is False
    assert res.error_reason in ("seq_gap", "prev_mismatch")

    runner = CliRunner()
    cli_res = runner.invoke(cli, ["audit-verify", str(log_path)])
    assert cli_res.exit_code == 1


def test_swapping_two_records_detected(tmp_path: Path) -> None:
    """4. Swapping two records is detected."""
    log_path = tmp_path / "test.audit.jsonl"
    audit = AuditLog(log_path)
    for i in range(10):
        audit.log_tool_call(
            tool_call_id=f"tc_{i}",
            tool_name="search",
            params={"query": f"item_{i}"},
            output_hash=f"hash_{i}",
            duration_ms=10.0 * i,
        )

    lines = log_path.read_text(encoding="utf-8").splitlines()
    lines[4], lines[5] = lines[5], lines[4]
    log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    res = verify_chain(log_path)
    assert res.ok is False
    assert res.error_reason in ("seq_gap", "prev_mismatch", "hash_mismatch")

    runner = CliRunner()
    cli_res = runner.invoke(cli, ["audit-verify", str(log_path)])
    assert cli_res.exit_code == 1


def test_truncating_last_two_records_detected_via_anchor(tmp_path: Path) -> None:
    """5. Truncating the last 2 records is detected via the DB anchor."""
    db = CaseDB.create(case_id="case-trunc", evidence_root="/evidence", db_dir=tmp_path)
    log_path = tmp_path / "case-trunc.audit.jsonl"
    audit = AuditLog(log_path, db=db)
    for i in range(10):
        audit.log_tool_call(
            tool_call_id=f"tc_{i}",
            tool_name="search",
            params={"query": f"item_{i}"},
            output_hash=f"hash_{i}",
            duration_ms=10.0 * i,
        )

    # Verify anchor was set in kv_store
    raw_anchor = db.get_kv("audit_head")
    assert raw_anchor is not None
    anchor_data = json.loads(raw_anchor)
    assert anchor_data["seq"] == 9
    assert anchor_data["record_hash"] == audit.last_hash

    # Truncate the last 2 records from file
    lines = log_path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 10
    lines = lines[:-2]
    log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    # Verify with explicit anchor
    res = verify_chain(log_path, anchor=db)
    assert res.ok is False
    assert res.error_reason == "anchor_mismatch"
    assert res.error_seq == 9

    # Verify with auto-detected companion DB anchor
    res_auto = verify_chain(log_path)
    assert res_auto.ok is False
    assert res_auto.error_reason == "anchor_mismatch"
    assert res_auto.error_seq == 9

    # CLI verification
    runner = CliRunner()
    cli_res = runner.invoke(cli, ["audit-verify", str(log_path), "--db-dir", str(tmp_path)])
    assert cli_res.exit_code == 1
    assert "anchor_mismatch" in cli_res.output
    assert "seq 9" in cli_res.output

    db.close()


def test_concurrent_threads_produce_valid_chain(tmp_path: Path) -> None:
    """6. 8 threads appending 50 records each still verify as one valid chain."""
    log_path = tmp_path / "concurrent.audit.jsonl"
    audit = AuditLog(log_path)

    def worker(tid: int) -> None:
        for i in range(50):
            audit.log_tool_call(
                tool_call_id=f"tc_{tid}_{i}",
                tool_name=f"tool_{tid}",
                params={"tid": tid, "i": i},
                output_hash=f"hash_{tid}_{i}",
                duration_ms=5.0,
            )

    threads = [threading.Thread(target=worker, args=(t,)) for t in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    res = verify_chain(log_path)
    assert res.ok is True
    assert res.record_count == 400
    assert res.unchained_count == 0
    assert audit.last_seq == 399
    assert res.head_hash == audit.last_hash

    runner = CliRunner()
    cli_res = runner.invoke(cli, ["audit-verify", str(log_path)])
    assert cli_res.exit_code == 0
    assert f"OK: 400 records, head {audit.last_hash[:12]}" in cli_res.output


def test_legacy_unchained_file_plus_new_records(tmp_path: Path) -> None:
    """7. A legacy unchained file plus new records verifies, with a legacy count."""
    log_path = tmp_path / "legacy.audit.jsonl"
    # Write 3 legacy unchained records without seq/prev_hash/record_hash
    legacy_lines = [
        json.dumps({
            "type": "tool_call",
            "tool_call_id": "legacy_0",
            "tool_name": "legacy_tool",
            "params": {"q": "old_0"},
            "output_hash": "h0",
            "duration_ms": 1.0,
            "timestamp": "2025-01-01T00:00:00Z",
        }),
        json.dumps({
            "type": "tool_call",
            "tool_call_id": "legacy_1",
            "tool_name": "legacy_tool",
            "params": {"q": "old_1"},
            "output_hash": "h1",
            "duration_ms": 2.0,
            "timestamp": "2025-01-01T00:00:01Z",
        }),
        json.dumps({
            "type": "tool_call",
            "tool_call_id": "legacy_2",
            "tool_name": "legacy_tool",
            "params": {"q": "old_2"},
            "output_hash": "h2",
            "duration_ms": 3.0,
            "timestamp": "2025-01-01T00:00:02Z",
        }),
    ]
    log_path.write_text("\n".join(legacy_lines) + "\n", encoding="utf-8")

    # Open existing file and verify resume
    audit = AuditLog(log_path)
    assert audit.last_seq == -1
    assert audit.last_hash == "0" * 64

    # Append 5 new records
    for i in range(5):
        audit.log_tool_call(
            tool_call_id=f"new_{i}",
            tool_name="new_tool",
            params={"q": f"new_{i}"},
            output_hash=f"h_new_{i}",
            duration_ms=10.0,
        )

    assert audit.last_seq == 4

    res = verify_chain(log_path)
    assert res.ok is True
    assert res.record_count == 5
    assert res.unchained_count == 3
    assert res.legacy_count == 3
    assert res.head_hash == audit.last_hash

    runner = CliRunner()
    cli_res = runner.invoke(cli, ["audit-verify", str(log_path)])
    assert cli_res.exit_code == 0
    assert f"OK: 5 records, head {audit.last_hash[:12]}" in cli_res.output
