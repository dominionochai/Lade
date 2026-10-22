"""Tests for lade.server.tool_access — profile allowlists."""

from __future__ import annotations

import os

import pytest

from lade.server.tool_access import (
    _DEVSECOPS_ALLOWLIST,
    Profile,
    Role,
    _registry,
    get_active_profile,
    get_tools_for_role,
)


@pytest.fixture(autouse=True)
def reset_profile_env():
    """Ensure LADE_PROFILE doesn't leak between tests."""
    old = os.environ.pop("LADE_PROFILE", None)
    yield
    if old is not None:
        os.environ["LADE_PROFILE"] = old
    else:
        os.environ.pop("LADE_PROFILE", None)


class TestAllowlistValidation:
    """Every name in the DEVSECOPS allowlist must be a registered tool."""

    def test_all_allowlisted_names_are_registered(self):
        missing = _DEVSECOPS_ALLOWLIST - set(_registry)
        assert not missing, f"Allowlist names not registered as tools: {sorted(missing)}"


class TestDEVSECOPSCoverage:
    """Every tool returned under DEVSECOPS must be in the allowlist."""

    @pytest.mark.parametrize("role", list(Role))
    def test_all_returned_tools_are_allowlisted(self, role: Role):
        os.environ.pop("LADE_PROFILE", None)
        tools = get_tools_for_role(role)
        bare_names = {t.replace("mcp__lade__", "") for t in tools}
        assert bare_names <= _DEVSECOPS_ALLOWLIST, (
            f"Tools in {role} not in allowlist: {bare_names - _DEVSECOPS_ALLOWLIST}"
        )


class TestExtractExecutorDEVSECOPS:
    """EXTRACT_EXECUTOR under DEVSECOPS must have exactly the 8 evidence tools
    plus open_case, and must NOT contain any DFIR-binary tools."""

    def setup_method(self):
        os.environ.pop("LADE_PROFILE", None)
        self.tools = set(
            t.replace("mcp__lade__", "")
            for t in get_tools_for_role(Role.EXTRACT_EXECUTOR)
        )

    def test_has_all_8_devsecops_evidence_tools(self):
        expected = {
            "trivy_report",
            "dependency_diff",
            "ci_job_log",
            "git_diff",
            "cloud_logs",
            "memory_metrics",
            "heap_trace",
            "status_page",
        }
        assert expected.issubset(self.tools)

    def test_has_open_case(self):
        assert "open_case" in self.tools

    def test_submit_finding_not_in_executor(self):
        assert "submit_finding" not in self.tools

    def test_no_dfir_binary_tools(self):
        dfir_only = {
            "run_volatility",
            "run_fls",
            "run_zeek_analysis",
            "run_regripper",
            "parse_prefetch",
            "query_registry_value",
            "run_plaso",
            "yara_scan_files",
            "run_hayabusa",
            "run_chainsaw",
            "run_zircolite",
            "parse_mft",
            "run_hindsight",
            "run_mvt_android",
            "run_mvt_ios",
            "triage_binary",
            "run_capa",
            "run_floss",
            "run_detect_it_easy",
            "list_partitions",
            "list_files",
            "get_deleted_files",
            "get_fs_timeline",
            "extract_file_by_inode",
            "get_file_metadata",
            "get_plaso_stats",
            "filter_timeline",
            "export_timeline_slice",
            "yara_scan_memory",
            "yara_scan_with_volatility",
            "run_ileapp",
            "run_aleapp",
            "carve_sqlite_from_raw",
            "parse_android_artifacts",
            "parse_ios_artifacts",
            "decrypt_app_data",
        }
        leaked = self.tools & dfir_only
        assert not leaked, (
            f"DFIR binary tools leaked into DEVSECOPS EXTRACT_EXECUTOR: {sorted(leaked)}"
        )


class TestDFIRProfile:
    """DFIR profile must include everything, including run_volatility."""

    def test_dfir_has_run_volatility(self):
        os.environ["LADE_PROFILE"] = "dfir"
        tools = get_tools_for_role(Role.EXTRACT_EXECUTOR, profile=Profile.DFIR)
        bare_names = {t.replace("mcp__lade__", "") for t in tools}
        assert "run_volatility" in bare_names

    def test_dfir_allows_all_role_tools(self):
        os.environ["LADE_PROFILE"] = "dfir"
        for role in Role:
            tools = get_tools_for_role(role, profile=Profile.DFIR)
            bare_names = {t.replace("mcp__lade__", "") for t in tools}
            assert bare_names <= set(_registry)


class TestProfileEnvVar:
    """LADE_PROFILE env var controls the active profile."""

    def test_default_is_devsecops(self):
        os.environ.pop("LADE_PROFILE", None)
        assert get_active_profile() == Profile.DEVSECOPS

    def test_dfir_env(self):
        os.environ["LADE_PROFILE"] = "dfir"
        assert get_active_profile() == Profile.DFIR

    def test_full_alias(self):
        os.environ["LADE_PROFILE"] = "full"
        assert get_active_profile() == Profile.DFIR

    def test_unknown_defaults_to_devsecops(self):
        os.environ["LADE_PROFILE"] = "unknown"
        assert get_active_profile() == Profile.DEVSECOPS
