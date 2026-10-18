"""Tests for DevSecOps evidence reading tools.

Tests run against static fixtures under ``fixtures/incident-001`` (the
case evidence directory at the repository root).  No network access is
required; the path-containment policy is exercised including the refusal
of any folder named ``expected``.
"""

from __future__ import annotations

import re
from pathlib import Path
from types import SimpleNamespace

import pytest

import lade.server.tools.devsecops  # noqa: F401 -- register tools
from lade.audit import AuditLog
from lade.db import CaseDB
from lade.server.app import _tool_dispatch_sync

_FIXTURES = Path(__file__).parent.parent / "fixtures" / "incident-001"
_EXPECTED = _FIXTURES / "expected" / "ANSWER_KEY.md"

_DEVSECOPS_TOOLS = [
    "trivy_report",
    "dependency_diff",
    "ci_job_log",
    "git_diff",
    "cloud_logs",
    "memory_metrics",
    "heap_trace",
    "status_page",
]


@pytest.fixture()
def incident_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Set up a CaseDB with incident-001 evidence and patch the server context."""
    db = CaseDB.create(
        case_id="test-case", evidence_root=str(_FIXTURES), db_dir=tmp_path
    )
    audit = AuditLog(tmp_path / "test.audit.jsonl")
    ctx = SimpleNamespace(db=db, audit=audit)

    import lade.server.app as _app

    monkeypatch.setattr(_app, "_ctx", ctx)
    monkeypatch.setattr(_app, "_cfg", SimpleNamespace(db_dir=tmp_path))

    yield ctx, db, audit
    db.close()


def _call(tool_name: str, **kwargs: object) -> dict[str, object]:
    """Invoke a devsecops tool through the dispatch table."""
    fn = _tool_dispatch_sync[tool_name]
    return fn(**kwargs)  # type: ignore[no-any-return]


class TestTrivyReport:
    def test_contains_cve_streamcache_high(self, incident_env):
        _ctx, _db, _audit = incident_env
        result = _call("trivy_report", path=str(_FIXTURES / "scans" / "trivy-image.json"))
        assert result["status"] == "success"
        text = result["result"]
        assert "CVE-2026-90001" in text
        assert "streamcache" in text
        assert "HIGH" in text

    def test_header_has_counts(self, incident_env):
        _ctx, _db, _audit = incident_env
        result = _call("trivy_report", path=str(_FIXTURES / "scans" / "trivy-image.json"))
        assert "2 vulnerabilities found" in result["result"]

    def test_cwes_listed(self, incident_env):
        _ctx, _db, _audit = incident_env
        result = _call("trivy_report", path=str(_FIXTURES / "scans" / "trivy-image.json"))
        assert "CWE-770" in result["result"]
        assert "CWE-401" in result["result"]


class TestDependencyDiff:
    def test_reports_streamcache_version_change(self, incident_env):
        _ctx, _db, _audit = incident_env
        result = _call("dependency_diff", path=str(_FIXTURES / "scans" / "dependency-diff.txt"))
        assert result["status"] == "success"
        assert "streamcache: 2.3.4 -> 2.4.1 (changed)" in result["result"]


class TestCiJobLog:
    def test_trivy_scan_job_passed_with_warnings(self, incident_env):
        _ctx, _db, _audit = incident_env
        result = _call("ci_job_log", path=str(_FIXTURES / "pipeline" / "job_trivy-scan.log"))
        assert result["status"] == "success"
        assert result["result"].endswith("JOB RESULT: passed with warnings")

    def test_build_job_succeeded(self, incident_env):
        _ctx, _db, _audit = incident_env
        result = _call("ci_job_log", path=str(_FIXTURES / "pipeline" / "job_build.log"))
        assert result["status"] == "success"
        assert result["result"].endswith("JOB RESULT: succeeded")

    def test_deploy_job_succeeded(self, incident_env):
        _ctx, _db, _audit = incident_env
        result = _call("ci_job_log", path=str(_FIXTURES / "pipeline" / "job_deploy-staging.log"))
        assert result["status"] == "success"
        assert result["result"].endswith("JOB RESULT: succeeded")

    def test_line_numbers_present(self, incident_env):
        _ctx, _db, _audit = incident_env
        result = _call("ci_job_log", path=str(_FIXTURES / "pipeline" / "job_trivy-scan.log"))
        first_line = result["result"].splitlines()[0]
        assert re.match(r"^\d{4}: ", first_line)


class TestGitDiff:
    def test_lists_changed_file(self, incident_env):
        _ctx, _db, _audit = incident_env
        result = _call("git_diff", path=str(_FIXTURES / "git" / "mr_482.diff"))
        assert result["status"] == "success"
        assert "FILE app/routes/export.py" in result["result"]

    def test_line_numbers_present(self, incident_env):
        _ctx, _db, _audit = incident_env
        result = _call("git_diff", path=str(_FIXTURES / "git" / "mr_482.diff"))
        first_line = result["result"].splitlines()[0]
        assert re.match(r"^\d{4}: ", first_line)


class TestCloudLogs:
    def test_severity_error_contains_memory_message(self, incident_env):
        _ctx, _db, _audit = incident_env
        result = _call(
            "cloud_logs",
            path=str(_FIXTURES / "cloudrun" / "cloud_logging.jsonl"),
            severity="ERROR",
        )
        assert result["status"] == "success"
        assert "Memory limit of 512 MiB exceeded" in result["result"]
        assert "ERROR" in result["result"]

    def test_contains_max_entries_shows_none(self, incident_env):
        _ctx, _db, _audit = incident_env
        result = _call(
            "cloud_logs",
            path=str(_FIXTURES / "cloudrun" / "cloud_logging.jsonl"),
            contains="max_entries",
        )
        assert result["status"] == "success"
        assert "max_entries=None" in result["result"]

    def test_limit_caps_output(self, incident_env):
        _ctx, _db, _audit = incident_env
        result = _call(
            "cloud_logs", path=str(_FIXTURES / "cloudrun" / "cloud_logging.jsonl"), limit=1
        )
        lines = result["result"].splitlines()
        assert len(lines) <= 1

    def test_revision_name_rendered(self, incident_env):
        _ctx, _db, _audit = incident_env
        result = _call(
            "cloud_logs", path=str(_FIXTURES / "cloudrun" / "cloud_logging.jsonl")
        )
        assert "revision=orders-api-00042-kqz" in result["result"]

    def test_instance_id_rendered(self, incident_env):
        _ctx, _db, _audit = incident_env
        result = _call(
            "cloud_logs", path=str(_FIXTURES / "cloudrun" / "cloud_logging.jsonl")
        )
        assert "instance=0070a1" in result["result"]

    def test_httprequest_rendered(self, incident_env):
        _ctx, _db, _audit = incident_env
        result = _call(
            "cloud_logs",
            path=str(_FIXTURES / "cloudrun" / "cloud_logging.jsonl"),
            contains="export",
        )
        assert "httpMethod=GET" in result["result"]
        assert "requestUrl=" in result["result"]


class TestMemoryMetrics:
    def test_slope_in_range_for_0070a1(self, incident_env):
        _ctx, _db, _audit = incident_env
        result = _call(
            "memory_metrics",
            path=str(_FIXTURES / "cloudrun" / "metrics_per_minute.csv"),
        )
        assert result["status"] == "success"
        text = result["result"]
        assert "0070a1" in text

        match = re.search(r"slope=([\d.]+)_mib_per_min", text)
        assert match is not None
        slope = float(match.group(1))
        assert 5.5 <= slope <= 6.5

    def test_mib_per_1000_requests_present(self, incident_env):
        _ctx, _db, _audit = incident_env
        result = _call(
            "memory_metrics",
            path=str(_FIXTURES / "cloudrun" / "metrics_per_minute.csv"),
        )
        assert "MiB per 1000 requests:" in result["result"]

    def test_revision_filter_excludes_other_revisions(self, incident_env):
        _ctx, _db, _audit = incident_env
        result = _call(
            "memory_metrics",
            path=str(_FIXTURES / "cloudrun" / "metrics_per_minute.csv"),
            revision="orders-api-00041-fxd",
        )
        assert result["status"] == "success"
        text = result["result"]
        assert "00a1f0" in text
        assert "0070a1" not in text


class TestHeapTrace:
    def test_contains_store_py_118(self, incident_env):
        _ctx, _db, _audit = incident_env
        result = _call("heap_trace", path=str(_FIXTURES / "runtime" / "heap_trace_top.txt"))
        assert result["status"] == "success"
        assert "streamcache/store.py:118" in result["result"]

    def test_line_numbers_present(self, incident_env):
        _ctx, _db, _audit = incident_env
        result = _call("heap_trace", path=str(_FIXTURES / "runtime" / "heap_trace_top.txt"))
        first_line = result["result"].splitlines()[0]
        assert re.match(r"^\d{4}: ", first_line)


class TestStatusPage:
    def test_returns_text_with_line_numbers(self, incident_env):
        _ctx, _db, _audit = incident_env
        result = _call("status_page", path=str(_FIXTURES / "infra" / "gcp_status.txt"))
        assert result["status"] == "success"
        first_line = result["result"].splitlines()[0]
        assert re.match(r"^\d{4}: ", first_line)
        assert "no incidents" in result["result"]


class TestExpectedFolderRefused:
    """Every tool must refuse a path that contains an 'expected' folder."""

    @pytest.mark.parametrize("tool_name", _DEVSECOPS_TOOLS)
    def test_expected_path_refused(self, incident_env, tool_name: str):
        _ctx, _db, _audit = incident_env
        kwargs: dict[str, object] = {"path": str(_EXPECTED)}
        result = _call(tool_name, **kwargs)
        assert result["status"] == "error"
        assert "expected" in result["error_message"].lower()


class TestAuditAndToolOutputs:
    """Each tool's call is written to the audit log and stored in tool_outputs."""

    def test_trivy_report_audit_and_output(self, incident_env):
        ctx, db, audit = incident_env
        result = _call("trivy_report", path=str(_FIXTURES / "scans" / "trivy-image.json"))
        tc_id = result["tool_call_id"]
        assert isinstance(tc_id, str)

        # Audit log has the tool call
        assert audit.has_tool_call(tc_id)

        # Output stored in tool_outputs
        row = db.get_tool_output(tc_id)
        assert row is not None
        assert row["tool_name"] == "trivy_report"
        assert "CVE-2026-90001" in row["searchable_text"]


class TestRoleAccess:
    def test_all_tools_visible_to_executor_and_analyst(self):
        from lade.server.tool_access import ANALYSTS, EXECUTORS, get_tools_for_role

        for tool in _DEVSECOPS_TOOLS:
            assert f"mcp__lade__{tool}" in get_tools_for_role(EXECUTORS)
            assert f"mcp__lade__{tool}" in get_tools_for_role(ANALYSTS)
