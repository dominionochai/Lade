"""Tests for CWE support and migration."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from lade.db import CaseDB, _migrate_add_cwe_ids
from lade.orchestrator.gates import validate_cross_system
from lade.server.app import _tool_dispatch_sync, init_server


@pytest.fixture()
def case_env(tmp_path: Path):
    db_dir = tmp_path / "cases"
    db_dir.mkdir()
    init_server(db_dir=db_dir)
    return db_dir


def test_cwe_only_finding_passes_gate() -> None:
    summary = {
        "findings_submitted": 1,
        "findings_with_mitre_ids": 0,
        "findings_with_cwe_ids": 1,
        "findings_classified": 1,
    }
    result = validate_cross_system(summary)
    assert result.passed
    assert not result.gaps


def test_attack_only_finding_passes_gate() -> None:
    summary = {
        "findings_submitted": 1,
        "findings_with_mitre_ids": 1,
        "findings_with_cwe_ids": 0,
        "findings_classified": 1,
    }
    result = validate_cross_system(summary)
    assert result.passed
    assert not result.gaps


def test_neither_fails_gate() -> None:
    summary = {
        "findings_submitted": 1,
        "findings_with_mitre_ids": 0,
        "findings_with_cwe_ids": 0,
        "findings_classified": 0,
    }
    result = validate_cross_system(summary)
    assert not result.passed
    assert any("mapped to CWE or ATT&CK" in gap for gap in result.gaps)


def test_invalid_cwe_rejected(case_env: Path) -> None:
    # Create a test case and try to submit a finding with invalid CWE ID
    res = _tool_dispatch_sync["scan_evidence"](
        evidence_path="fixtures/incident-001",
        case_id="cwe-test",
        replace=True,
    )
    assert res["status"] == "success"

    # Submit finding with invalid CWE
    out = _tool_dispatch_sync["submit_finding"](
        title="Test finding",
        description="Test description with enough detail for validation",
        severity="medium",
        confidence="inference",
        evidence_refs=[],
        sources=[],
        cwe_ids=["CWE-ABC", "INVALID"],
    )
    assert out["status"] == "error"
    msg = str(out.get("error_message", ""))
    err_type = str(out.get("error_type", ""))
    assert "validation" in err_type or "Invalid CWE" in msg


def test_migration_on_db_without_cwe_column(tmp_path: Path) -> None:
    # Create raw SQLite DB without cwe_ids column in findings table
    db_path = tmp_path / "mig_test.db"
    conn = sqlite3.connect(db_path)
    conn.execute(
        """
        CREATE TABLE findings (
            finding_id TEXT PRIMARY KEY,
            case_id TEXT NOT NULL,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            severity TEXT NOT NULL,
            confidence TEXT NOT NULL,
            evidence_refs TEXT NOT NULL,
            sources TEXT NOT NULL,
            mitre_attack_ids TEXT,
            event_time_start TEXT,
            event_time_end TEXT,
            submitted_at TEXT NOT NULL
        )
        """
    )
    conn.commit()
    conn.close()

    # Now open with CaseDB, which runs migrations including _migrate_add_cwe_ids
    db = CaseDB(db_path)
    with db._engine.begin() as conn:
        _migrate_add_cwe_ids(conn)
    db.close()

    # Verify column exists and can read/write findings with cwe_ids
    db2 = CaseDB(db_path)
    from lade.models import Finding
    f = Finding(
        finding_id="f_test1",
        case_id="mig_test",
        title="Test migration finding",
        description="Testing cwe migration storage",
        severity="low",
        confidence="inference",
        evidence_refs=["tc_123"],
        sources=["source1"],
        cwe_ids=["CWE-770"],
        submitted_at="2026-10-19T00:00:00Z",
    )
    db2.insert_finding(f)
    loaded = db2.get_finding("f_test1")
    assert loaded is not None
    assert loaded.cwe_ids == ["CWE-770"]
    db2.close()
