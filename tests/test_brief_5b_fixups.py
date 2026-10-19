"""Tests for brief 5b addendum fixups."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from lade.extractors.classifier import ClassifierConfig, EvidenceClassifier
from lade.orchestrator.runner import Orchestrator
from lade.server.app import _tool_dispatch_sync, init_server
from lade.server.tool_access import Profile, Role, get_active_profile, get_tools_for_role


@pytest.fixture(autouse=True)
def clean_env():
    old = os.environ.pop("LADE_PROFILE", None)
    yield
    if old is not None:
        os.environ["LADE_PROFILE"] = old
    else:
        os.environ.pop("LADE_PROFILE", None)


def test_expected_folder_excluded(tmp_path: Path) -> None:
    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir()
    expected_dir = evidence_dir / "expected"
    expected_dir.mkdir()
    (expected_dir / "trivy-image.json").write_text('{"SchemaVersion": 2, "Results": []}')
    (evidence_dir / "real_file.txt").write_text("some log data")

    classifier = EvidenceClassifier()
    results = classifier.classify(evidence_dir)
    rel_paths = [Path(r.path).relative_to(evidence_dir).parts for r in results]
    assert not any("expected" in parts for parts in rel_paths)
    assert any("real_file.txt" in parts for parts in rel_paths)


def test_default_profile_is_devsecops(tmp_path: Path) -> None:
    assert get_active_profile() == Profile.DEVSECOPS
    orch = Orchestrator(str(Path("fixtures/incident-001")), cwd=str(tmp_path))
    assert orch.env.get("LADE_PROFILE") == "devsecops"


def test_content_based_classification_generic_names(tmp_path: Path) -> None:
    d = tmp_path / "gen_evidence"
    d.mkdir()

    # data1.json with Trivy content
    trivy_file = d / "data1.json"
    trivy_file.write_text('{"SchemaVersion": 2, "Results": [{"Target": "x"}]}')

    # data2.jsonl with severity
    jsonl_file = d / "data2.jsonl"
    jsonl_file.write_text('{"severity": "INFO", "msg": "test"}\n')

    # data3.csv with memory_mib header
    csv_file = d / "data3.csv"
    csv_file.write_text("timestamp_utc,revision,instance_id,memory_mib,requests_per_sec\n2026-10-09,rev,inst,185.9,10\n")

    classifier = EvidenceClassifier()
    results = classifier.classify(d)
    types = {r.artifact_type for r in results}

    assert "trivy_report" in types
    assert "cloud_logs" in types
    assert "metrics_csv" in types


def test_incident_001_scan_evidence_registers_all_non_expected(tmp_path: Path) -> None:
    evidence_path = Path("fixtures/incident-001").resolve()
    init_server(db_dir=tmp_path)
    res = _tool_dispatch_sync["scan_evidence"](evidence_path=str(evidence_path), case_id="test-incident-001-scan", replace=True)
    assert res["status"] == "success"
    tree = str(res.get("evidence_tree", ""))
    assert "expected" not in tree
    assert "ANSWER_KEY.md" not in tree
    assert "trivy-image.json" in tree
    assert "metrics_per_minute.csv" in tree
    assert "cloud_logging.jsonl" in tree
