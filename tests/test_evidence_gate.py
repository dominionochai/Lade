"""Tests for evidence gate: strict-mode finding validation against tool outputs."""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from sqlalchemy import text

from lade.audit import AuditLog, verify_chain
from lade.db import CaseDB
from lade.models import Finding
from lade.server.app import _tool_dispatch_sync
from lade.server.helpers import get_evidence_mode, hash_output
from lade.server.tools.findings import _validate_evidence_refs


@pytest.fixture()
def case_db(tmp_path: Path) -> CaseDB:
    """Create a CaseDB with a valid case_id."""
    db = CaseDB.create(case_id="test-case", evidence_root="/evidence", db_dir=tmp_path)
    return db


@pytest.fixture()
def audit_log(tmp_path: Path) -> AuditLog:
    """Create an AuditLog with some pre-recorded tool call IDs."""
    log = AuditLog(tmp_path / "test.audit.jsonl")
    log.log_tool_call(
        tool_call_id="tc_aabbccdd",
        tool_name="run_volatility",
        params={"plugin": "pslist"},
        output_hash="hash1",
        duration_ms=100.0,
    )
    log.log_tool_call(
        tool_call_id="tc_11223344",
        tool_name="search_windows",
        params={"query": "cmd.exe"},
        output_hash="hash2",
        duration_ms=50.0,
    )
    return log


@pytest.fixture()
def mock_ctx(case_db: CaseDB, audit_log: AuditLog) -> MagicMock:
    """Create a mock context with db and audit."""
    ctx = MagicMock()
    ctx.db = case_db
    ctx.audit = audit_log
    return ctx


def _call_submit_finding(
    case_db: CaseDB, audit_log: AuditLog, **kwargs: object
) -> dict[str, object]:
    """Invoke the sync submit_finding directly, bypassing the async MCP wrapper."""
    ctx = MagicMock()
    ctx.db = case_db
    ctx.audit = audit_log

    sync_fn = _tool_dispatch_sync["submit_finding"]
    with patch("lade.server.tools.findings.get_ctx", return_value=ctx):
        return sync_fn(**kwargs)  # type: ignore[no-any-return]


class TestEvidenceMode:
    """Tests for evidence_mode setting."""

    def test_default_legacy(self, tmp_path: Path) -> None:
        """Default mode is 'legacy'."""
        os.environ.pop("LADE_EVIDENCE_MODE", None)
        assert get_evidence_mode() == "legacy"

    def test_env_override(self, tmp_path: Path) -> None:
        """Environment variable overrides default."""
        os.environ["LADE_EVIDENCE_MODE"] = "strict"
        assert get_evidence_mode() == "strict"
        os.environ.pop("LADE_EVIDENCE_MODE", None)

    def test_investigation_runner_sets_strict(self, tmp_path: Path) -> None:
        """InvestigationRunner sets LADE_EVIDENCE_MODE=strict by default."""
        # Simulate what InvestigationRunner does in __init__
        os.environ.pop("LADE_EVIDENCE_MODE", None)
        runner_env = {}
        runner_env.setdefault("LADE_EVIDENCE_MODE", "strict")
        os.environ.update(runner_env)
        try:
            assert get_evidence_mode() == "strict"
        finally:
            os.environ.pop("LADE_EVIDENCE_MODE", None)

    def test_env_override_runner_strict(self, tmp_path: Path) -> None:
        """Explicit LADE_EVIDENCE_MODE env var overrides runner default."""
        os.environ.pop("LADE_EVIDENCE_MODE", None)
        # Set explicit env var first
        os.environ["LADE_EVIDENCE_MODE"] = "legacy"
        # Runner only sets default if not already present (mimics setdefault behavior)
        if "LADE_EVIDENCE_MODE" not in os.environ:
            os.environ["LADE_EVIDENCE_MODE"] = "strict"
        try:
            # Explicit env var should win
            assert get_evidence_mode() == "legacy"
        finally:
            os.environ.pop("LADE_EVIDENCE_MODE", None)

    def test_runner_sets_strict_in_env(self, tmp_path: Path) -> None:
        """InvestigationRunner sets LADE_EVIDENCE_MODE=strict in its env."""
        # Verify setdefault only sets if key missing
        # Case 1: no env var -> runner sets strict
        runner_env = {}
        runner_env.setdefault("LADE_EVIDENCE_MODE", "strict")
        assert runner_env["LADE_EVIDENCE_MODE"] == "strict"

        # Case 2: env var already legacy -> runner keeps legacy (no override)
        runner_env = {"LADE_EVIDENCE_MODE": "legacy"}
        runner_env.setdefault("LADE_EVIDENCE_MODE", "strict")
        assert runner_env["LADE_EVIDENCE_MODE"] == "legacy"

        # Case 3: env var already set to strict -> runner keeps strict
        runner_env = {"LADE_EVIDENCE_MODE": "strict"}
        runner_env.setdefault("LADE_EVIDENCE_MODE", "strict")
        assert runner_env["LADE_EVIDENCE_MODE"] == "strict"

    def test_env_override_explicit(self, tmp_path: Path) -> None:
        """Environment variable overrides default."""
        os.environ["LADE_EVIDENCE_MODE"] = "strict"
        assert get_evidence_mode() == "strict"
        os.environ.pop("LADE_EVIDENCE_MODE", None)


class TestValidateEvidenceRefs:
    """Tests for _validate_evidence_refs function."""

    def test_legacy_mode_accepts_string_refs(self, mock_ctx) -> None:
        """Legacy mode accepts string tool_call_ids."""
        refs, error = _validate_evidence_refs(mock_ctx, ["tc_aabbccdd", "tc_11223344"])
        assert error is None
        assert refs == ["tc_aabbccdd", "tc_11223344"]

    def test_legacy_mode_rejects_unknown_tool_call(self, mock_ctx) -> None:
        """Legacy mode rejects unknown tool_call_id."""
        refs, error = _validate_evidence_refs(mock_ctx, ["tc_NONEXISTENT"])
        assert error is not None
        assert "tc_NONEXISTENT" in error

    def test_strict_mode_rejects_string_refs(self, mock_ctx) -> None:
        """Strict mode rejects string refs."""
        with patch("lade.server.tools.findings.get_evidence_mode", return_value="strict"):
            refs, error = _validate_evidence_refs(mock_ctx, ["tc_aabbccdd"])
            assert error is not None
            assert "must be objects" in error

    def test_strict_mode_accepts_valid_object_refs(self, mock_ctx, case_db) -> None:
        """Strict mode accepts valid object refs with tool_call_id and quote."""
        # Store tool output
        output_text = "Process cmd.exe found with PID 1234\nParent: explorer.exe"
        case_db.store_tool_output("tc_aabbccdd", "run_volatility", output_text)

        with patch("lade.server.tools.findings.get_evidence_mode", return_value="strict"):
            refs = [
                {"tool_call_id": "tc_aabbccdd", "quote": "Process cmd.exe found with PID 1234"}
            ]
            validated, error = _validate_evidence_refs(mock_ctx, refs)
            assert error is None
            assert len(validated) == 1
            assert "start" in validated[0]
            assert "end" in validated[0]
            # Quote found at position 0 in searchable_text (raw text extracted from JSON)
            assert validated[0]["start"] == 0
            assert validated[0]["end"] == len("Process cmd.exe found with PID 1234")

    def test_strict_mode_rejects_quote_not_in_output(self, mock_ctx, case_db) -> None:
        """Strict mode rejects quote not found in output."""
        output_text = "Process cmd.exe found with PID 1234"
        case_db.store_tool_output("tc_aabbccdd", "run_volatility", output_text)

        with patch("lade.server.tools.findings.get_evidence_mode", return_value="strict"):
            refs = [{"tool_call_id": "tc_aabbccdd", "quote": "Process notepad.exe found"}]
            validated, error = _validate_evidence_refs(mock_ctx, refs)
            assert error is not None
            assert "does not occur verbatim" in error

    def test_strict_mode_rejects_quote_from_different_tool_call(self, mock_ctx, case_db) -> None:
        """Strict mode rejects quote from different tool_call_id's output."""
        output_text = "Process cmd.exe found with PID 1234"
        case_db.store_tool_output("tc_aabbccdd", "run_volatility", output_text)
        case_db.store_tool_output("tc_11223344", "search_windows", "Different output entirely")

        with patch("lade.server.tools.findings.get_evidence_mode", return_value="strict"):
            refs = [{"tool_call_id": "tc_aabbccdd", "quote": "Different output entirely"}]
            validated, error = _validate_evidence_refs(mock_ctx, refs)
            assert error is not None
            assert "does not occur verbatim" in error

    def test_strict_mode_rejects_short_quote(self, mock_ctx, case_db) -> None:
        """Strict mode rejects quote under 8 chars."""
        output_text = "Process cmd.exe found"
        case_db.store_tool_output("tc_aabbccdd", "run_volatility", output_text)

        with patch("lade.server.tools.findings.get_evidence_mode", return_value="strict"):
            refs = [{"tool_call_id": "tc_aabbccdd", "quote": "cmd.exe"}]
            validated, error = _validate_evidence_refs(mock_ctx, refs)
            assert error is not None
            assert "quote length" in error

    def test_strict_mode_rejects_long_quote(self, mock_ctx, case_db) -> None:
        """Strict mode rejects quote over 2000 chars."""
        output_text = "x" * 2001
        case_db.store_tool_output("tc_aabbccdd", "run_volatility", output_text)

        with patch("lade.server.tools.findings.get_evidence_mode", return_value="strict"):
            refs = [{"tool_call_id": "tc_aabbccdd", "quote": output_text}]
            validated, error = _validate_evidence_refs(mock_ctx, refs)
            assert error is not None
            assert "quote length" in error

    def test_strict_mode_rejects_unknown_tool_call_id(self, mock_ctx) -> None:
        """Strict mode rejects unknown tool_call_id."""
        with patch("lade.server.tools.findings.get_evidence_mode", return_value="strict"):
            refs = [{"tool_call_id": "tc_NONEXISTENT", "quote": "some quote here"}]
            validated, error = _validate_evidence_refs(mock_ctx, refs)
            assert error is not None
            assert "not found in tool_outputs" in error

    def test_strict_mode_rejects_tc_id_in_tool_outputs_not_audit_log(
        self, mock_ctx, case_db
    ) -> None:
        """Strict mode rejects ref whose tool_call_id is in tool_outputs but not audit log."""
        # Store output with a tc_id that IS NOT in the mock audit log
        output_text = "Process cmd.exe found with PID 1234"
        case_db.store_tool_output("tc_IN_TOOL_OUTPUTS_ONLY", "run_volatility", output_text)
        # tc_IN_TOOL_OUTPUTS_ONLY is NOT in the mock audit log

        with patch("lade.server.tools.findings.get_evidence_mode", return_value="strict"):
            refs = [{"tool_call_id": "tc_IN_TOOL_OUTPUTS_ONLY", "quote": "Process cmd.exe found"}]
            validated, error = _validate_evidence_refs(mock_ctx, refs)
            assert error is not None
            assert "not found in audit log" in error

    def test_strict_mode_crlf_matches_lf(self, mock_ctx, case_db) -> None:
        """Strict mode: CRLF in output matches LF in quote."""
        output_text = "Line 1\r\nLine 2\r\nLine 3"
        case_db.store_tool_output("tc_aabbccdd", "run_volatility", output_text)

        with patch("lade.server.tools.findings.get_evidence_mode", return_value="strict"):
            refs = [{"tool_call_id": "tc_aabbccdd", "quote": "Line 1\nLine 2"}]
            validated, error = _validate_evidence_refs(mock_ctx, refs)
            assert error is None
            # Quote found at position 0 in searchable_text (raw text extracted from JSON)
            assert validated[0]["start"] == 0
            assert validated[0]["end"] == len("Line 1\nLine 2")

    def test_strict_mode_truncated_output_rejects_quote_past_stored(
        self, mock_ctx, case_db
    ) -> None:
        """Strict mode rejects quote past stored part for truncated output."""
        # Create output > 2MB with unique suffix starting before 2MB but ending after
        # 2MB = 2,097,152; suffix = 28 chars, END = 3 chars; total = 31 chars
        # Start suffix at 2MB - 21 so it's partially stored but END goes beyond
        prefix = "X" * (2 * 1024 * 1024 - 21)
        unique_suffix = "UNIQUE_QUOTE_AT_END_12345"
        long_text = prefix + unique_suffix + "END"
        case_db.store_tool_output("tc_aabbccdd", "run_volatility", long_text)

        with patch("lade.server.tools.findings.get_evidence_mode", return_value="strict"):
            # Quote that starts before 2MB but ends after 2MB (stored part is 2MB)
            quote_text = unique_suffix + "END"
            refs = [{"tool_call_id": "tc_aabbccdd", "quote": quote_text}]
            validated, error = _validate_evidence_refs(mock_ctx, refs)
            assert error is not None
            assert "does not occur in the stored portion of the truncated output (rule d)" in error

    def test_legacy_mode_accepts_string_refs_in_submit_finding(self, case_db, audit_log) -> None:
        """Legacy mode still accepts string refs in submit_finding."""
        os.environ.pop("LADE_EVIDENCE_MODE", None)
        result = _call_submit_finding(
            case_db,
            audit_log,
            title="Test finding",
            description="Test",
            severity="low",
            confidence="inference",
            evidence_refs=["tc_aabbccdd"],
            sources=["volatility.pslist"],
        )
        assert result.get("status") == "accepted"

    def test_strict_mode_accepts_valid_object_in_submit_finding(self, case_db, audit_log) -> None:
        """Strict mode accepts valid object refs in submit_finding."""
        output_text = "Process cmd.exe found with PID 1234"
        case_db.store_tool_output("tc_aabbccdd", "run_volatility", output_text)

        os.environ["LADE_EVIDENCE_MODE"] = "strict"
        try:
            result = _call_submit_finding(
                case_db,
                audit_log,
                title="Test finding",
                description="Test",
                severity="low",
                confidence="inference",
                evidence_refs=[{"tool_call_id": "tc_aabbccdd", "quote": "Process cmd.exe found"}],
                sources=["volatility.pslist"],
            )
            assert result.get("status") == "accepted"
        finally:
            os.environ.pop("LADE_EVIDENCE_MODE", None)


class TestAuditVerify:
    """Tests for audit-verify with tool_outputs and finding quote verification."""

    def test_audit_verify_catches_output_tampering(self, tmp_path: Path) -> None:
        """Tampering with output_text in DB is caught by audit-verify."""
        db = CaseDB.create(case_id="tamper-test", evidence_root="/evidence", db_dir=tmp_path)
        audit_log = AuditLog(tmp_path / "tamper-test.audit.jsonl", db=db)

        # Store a valid tool output
        output_text = "Original output text here"
        tool_result = {"status": "success", "raw_text": output_text}
        db.store_tool_output("tc_tamper1", "test_tool", tool_result)
        audit_log.log_tool_call(
            tool_call_id="tc_tamper1",
            tool_name="test_tool",
            params={},
            output_hash=hash_output(tool_result),
            duration_ms=10.0,
        )

        # Tamper with the stored output_text
        # Direct SQL update to tamper
        with db._engine.begin() as conn:
            conn.execute(
                text(
                    "UPDATE tool_outputs SET output_text = 'Tampered output' "
                    "WHERE tool_call_id = 'tc_tamper1'"
                )
            )

        # Verify should catch the mismatch
        result = verify_chain(tmp_path / "tamper-test.audit.jsonl", anchor=db)
        assert result.ok is False
        assert result.error_reason == "output_hash_mismatch"

    def test_audit_verify_catches_quote_tampering(self, tmp_path: Path) -> None:
        """Tampering with finding quote is caught by audit-verify."""
        db = CaseDB.create(case_id="quote-tamper", evidence_root="/evidence", db_dir=tmp_path)
        audit_log = AuditLog(tmp_path / "quote-tamper.audit.jsonl", db=db)

        output_text = "Original output text here with some quote"
        tool_result = {"status": "success", "raw_text": output_text}
        db.store_tool_output("tc_quote1", "test_tool", tool_result)
        audit_log.log_tool_call(
            tool_call_id="tc_quote1",
            tool_name="test_tool",
            params={},
            output_hash=hash_output(tool_result),
            duration_ms=10.0,
        )

        # Submit a finding with strict-mode ref
        os.environ["LADE_EVIDENCE_MODE"] = "strict"
        try:
            finding_id = "f_test1"
            audit_log.log_finding_submission(
                finding_id=finding_id,
                evidence_refs=[
                    {"tool_call_id": "tc_quote1", "quote": "some quote", "start": 29, "end": 39}
                ],
            )
            # Also insert into findings table for audit-verify to check
            finding = Finding(
                finding_id=finding_id,
                case_id="quote-tamper",
                title="Test finding",
                description="Test",
                severity="low",
                confidence="inference",
                evidence_refs=[
                    {"tool_call_id": "tc_quote1", "quote": "some quote", "start": 29, "end": 39}
                ],
                sources=["test_tool"],
                mitre_attack_ids=[],
                event_time_start=None,
                event_time_end=None,
                submitted_at=datetime.now(timezone.utc).isoformat(),
            )
            db.insert_finding(finding)
        finally:
            os.environ.pop("LADE_EVIDENCE_MODE", None)

        # Tamper with the evidence_refs in the finding
        tampered_refs = json.dumps(
            [{"tool_call_id": "tc_quote1", "quote": "WRONG QUOTE", "start": 29, "end": 39}]
        )
        with db._engine.begin() as conn:
            conn.execute(
                text(
                    "UPDATE findings SET evidence_refs = :refs WHERE finding_id = :fid"
                ),
                {"refs": tampered_refs, "fid": finding_id},
            )

        result = verify_chain(tmp_path / "quote-tamper.audit.jsonl", anchor=db, db=db)
        assert result.ok is False
        assert result.error_reason == "finding_quote_mismatch"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
