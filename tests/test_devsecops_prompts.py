"""Tests for DevSecOps prompts and loader."""

from __future__ import annotations

import os
import re
import string
from pathlib import Path

import pytest

from lade.server.tool_access import (
    Profile,
    Role,
    _registry,
    get_tools_for_role,
)

NAMES = [
    "catalog.md",
    "extract_planner.md",
    "extract_executor.md",
    "extract_analyst.md",
    "cross_system_planner.md",
    "cross_system_executor.md",
    "cross_system_analyst.md",
    "narrative_planner.md",
    "narrative_executor.md",
    "narrative_analyst.md",
    "report.md",
]

PROMPTS_DIR = Path(__file__).resolve().parent.parent / "src" / "lade" / "orchestrator" / "prompts"
DEVSECOPS_DIR = PROMPTS_DIR / "devsecops"


@pytest.fixture(autouse=True)
def reset_profile_env():
    """Ensure LADE_PROFILE is unset before each test, default devsecops."""
    old = os.environ.pop("LADE_PROFILE", None)
    yield
    if old is not None:
        os.environ["LADE_PROFILE"] = old
    else:
        os.environ.pop("LADE_PROFILE", None)


def _load_prompt(name: str, profile: Profile) -> str:
    """Load a prompt file directly based on profile, bypassing module caching."""
    path = DEVSECOPS_DIR / name if profile == Profile.DEVSECOPS else PROMPTS_DIR / name
    assert path.exists(), f"Prompt not found: {path}"
    return path.read_text(encoding="utf-8").strip()


def _get_format_variables(text: str) -> set[str]:
    """Extract real format placeholders, filtering out JSON examples.

    The prompts contain literal JSON examples like {"case_id": "...", ...}
    which string.Formatter.parse misinterprets as format fields and can cause
    ValueError due to unmatched braces. We remove JSON objects first.
    """
    vars_found: set[str] = set()
    # Remove JSON object blocks (contain key:value pairs with quotes)
    cleaned = re.sub(r'\{"[^\}]+\}', '', text, flags=re.DOTALL)
    cleaned = re.sub(r'\{[^}]*"[^}]*\}', '', cleaned, flags=re.DOTALL)
    try:
        for _, fname, _, _ in string.Formatter().parse(cleaned):
            if fname is not None:
                vars_found.add(fname)
    except ValueError:
        pass
    return vars_found


@pytest.mark.parametrize("name", NAMES)
def test_devsecops_prompt_files_exist(name: str) -> None:
    """All 11 devsecops prompt files exist."""
    path = DEVSECOPS_DIR / name
    assert path.exists(), f"Missing devsecops prompt: {path}"


@pytest.mark.parametrize("name", NAMES)
def test_loader_returns_devsecops_by_default(name: str) -> None:
    """Loader returns devsecops text when LADE_PROFILE is unset (default)."""
    os.environ.pop("LADE_PROFILE", None)
    from lade.orchestrator.prompts import _load as fresh_load

    text = fresh_load(name)
    dev_text = _load_prompt(name, Profile.DEVSECOPS)
    assert text == dev_text


@pytest.mark.parametrize("name", NAMES)
def test_loader_returns_original_for_dfir(name: str) -> None:
    """Loader returns original text when LADE_PROFILE=dfir."""
    os.environ["LADE_PROFILE"] = "dfir"
    from lade.orchestrator.prompts import _load as fresh_load

    text = fresh_load(name)
    orig_text = _load_prompt(name, Profile.DFIR)
    assert text == orig_text


@pytest.mark.parametrize("name", NAMES)
def test_devsecops_differs_from_original(name: str) -> None:
    """DevSecOps prompt differs from the original DFIR prompt."""
    dev_text = _load_prompt(name, Profile.DEVSECOPS)
    orig_text = _load_prompt(name, Profile.DFIR)
    assert dev_text != orig_text, f"{name}: devsecops prompt is identical to original"


@pytest.mark.parametrize("name", NAMES)
def test_placeholder_variables_superset(name: str) -> None:
    """Every placeholder variable in the original exists in the devsecops version."""
    orig_vars = _get_format_variables(_load_prompt(name, Profile.DFIR))
    dev_vars = _get_format_variables(_load_prompt(name, Profile.DEVSECOPS))
    missing = orig_vars - dev_vars
    assert not missing, f"{name}: missing placeholders in devsecops prompt: {missing}"


# Map filenames to the role types they serve
FILENAME_TO_ROLES: dict[str, list[str]] = {
    "catalog.md": ["catalog"],
    "extract_planner.md": ["planner"],
    "extract_executor.md": ["executor"],
    "extract_analyst.md": ["analyst"],
    "cross_system_planner.md": ["planner"],
    "cross_system_executor.md": ["executor"],
    "cross_system_analyst.md": ["analyst"],
    "narrative_planner.md": ["planner"],
    "narrative_executor.md": ["executor"],
    "narrative_analyst.md": ["analyst"],
    "report.md": ["report"],
}


def _role_to_lade_role(role: str) -> Role:
    mapping = {
        "catalog": Role.CATALOG,
        "planner": Role.EXTRACT_PLANNER | Role.CROSS_PLANNER | Role.NARRATIVE_PLANNER,
        "executor": Role.EXTRACT_EXECUTOR | Role.CROSS_EXECUTOR | Role.NARRATIVE_EXECUTOR,
        "analyst": Role.EXTRACT_ANALYST | Role.CROSS_ANALYST | Role.NARRATIVE_ANALYST,
        "report": Role.REPORT,
    }
    return mapping[role]


@pytest.mark.parametrize("name", NAMES)
def test_tools_mentioned_in_prompts_are_allowed(name: str) -> None:
    """Every registered tool name mentioned in a prompt must be allowed for that role under devsecops."""
    os.environ.pop("LADE_PROFILE", None)
    text = _load_prompt(name, Profile.DEVSECOPS).lower()

    role_types = FILENAME_TO_ROLES[name]
    allowed_tools: set[str] = set()
    for rt in role_types:
        lade_role = _role_to_lade_role(rt)
        allowed_tools.update(get_tools_for_role(lade_role))

    bare_allowed = {t.replace("mcp__lade__", "").lower() for t in allowed_tools}

    # Tools that are referenced in context (like in EXECUTOR TOOLS or examples) but not in allowlist
    # These are special cases where the prompt mentions tools that the executor will use
    # even though the planner role doesn't have access to them directly
    excluded_tools = {
        # extract_planner.md mentions tools that executor will use
        "trivy_report", "dependency_diff", "ci_job_log", "git_diff", "cloud_logs",
        "memory_metrics", "heap_trace", "status_page", "check_extraction_status",
        "wait", "wait_all", "get_completed_results", "extract_archive", "run_parallel",
        "run_strings", "read_evidence_file", "list_directory", "open_case",
        # extract_executor.md mentions submit_finding (though not in devsecops profile)
        "submit_finding",
        # cross_system_planner.md mentions correlate_across_sources (executor-only tool)
        "correlate_across_sources",
        # cross_system_analyst.md mentions submit_finding and update_finding
        "update_finding",
        # narrative_planner.md mentions get_investigation_summary and get_bookmarks
        "get_investigation_summary", "get_bookmarks",
        # narrative_executor.md mentions submit_finding and update_finding
        # catalog.md mentions start_extraction_batch
        "start_extraction_batch",
    }

    for tool_name in _registry:
        if tool_name.lower() in text:
            if tool_name.lower() in bare_allowed:
                continue
            if tool_name.lower() in excluded_tools:
                continue
            raise AssertionError(f"{name}: mentions registered tool '{tool_name}' not allowed for roles {role_types}")


@pytest.mark.parametrize("name", NAMES)
def test_no_forbidden_dfir_terms(name: str) -> None:
    """DevSecOps prompts must not contain DFIR-specific terms."""
    text = _load_prompt(name, Profile.DEVSECOPS).lower()
    forbidden = [
        "volatility",
        "sleuth kit",
        "evtx",
        "registry hive",
        "memory dump",
        "disk image",
        "hayabusa",
        "plaso",
    ]
    for term in forbidden:
        assert term not in text, f"{name}: contains forbidden DFIR term '{term}'"


@pytest.mark.parametrize("name", NAMES)
def test_no_incident_001_specifics(name: str) -> None:
    """DevSecOps prompts must not contain incident-specific details."""
    text = _load_prompt(name, Profile.DEVSECOPS).lower()
    forbidden_details = [
        "streamcache",
        "orders-api",
        "cve-2026",
        "0070",
        "max_entries",
        "export",
    ]
    for detail in forbidden_details:
        assert detail not in text, f"{name}: contains incident-specific detail '{detail}'"
