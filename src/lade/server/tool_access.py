"""Declarative tool-role access registry for the Lade MCP surface.

Tools self-declare which pipeline roles may invoke them via the
``@tool_access`` decorator. The ``get_tools_for_role`` function
builds allowlists at import time so ``phases.py`` never needs manual
tool list maintenance.

The active investigation profile (``LADE_PROFILE`` env var, default
``devsecops``) selects between two modes:

* **devsecops** (default) — only tools in the explicit
  ``_DEVSECOPS_ALLOWLIST`` are visible, intersected with the role's
  registered tools.  This keeps DevSecOps evidence parsers (Trivy,
  CI logs, cloud metrics, etc.) visible while hiding all DFIR-binary
  tools (volatility, fls, zeek, regripper, etc.).
* **dfir** — every registered tool is visible (no filtering).
"""

from __future__ import annotations

import os
from collections.abc import Callable
from enum import Flag, auto
from typing import TypeVar

F = TypeVar("F", bound=Callable[..., object])


class Role(Flag):
    """Pipeline roles that can invoke MCP tools."""

    CATALOG = auto()
    EXTRACT_PLANNER = auto()
    EXTRACT_EXECUTOR = auto()
    EXTRACT_ANALYST = auto()
    CROSS_PLANNER = auto()
    CROSS_EXECUTOR = auto()
    CROSS_ANALYST = auto()
    NARRATIVE_PLANNER = auto()
    NARRATIVE_EXECUTOR = auto()
    NARRATIVE_ANALYST = auto()
    REPORT = auto()


class Profile(Flag):
    """Investigation profiles controlling the tool allowlist surface."""

    DEVSECOPS = auto()
    DFIR = auto()


PLANNERS = Role.EXTRACT_PLANNER | Role.CROSS_PLANNER | Role.NARRATIVE_PLANNER
EXECUTORS = Role.EXTRACT_EXECUTOR | Role.CROSS_EXECUTOR | Role.NARRATIVE_EXECUTOR
ANALYSTS = Role.EXTRACT_ANALYST | Role.CROSS_ANALYST | Role.NARRATIVE_ANALYST
ALL_ROLES = Role.CATALOG | PLANNERS | EXECUTORS | ANALYSTS | Role.REPORT

_registry: dict[str, Role] = {}

# Tools that skip the memory/CPU resource gate and the worker CapacityLimiter
# in ``app._wrap_sync_tool``. Only for cheap control/query tools (job polling,
# small DB reads); never for anything that runs a binary or scans a source.
UNTHROTTLED: set[str] = set()

# ---------------------------------------------------------------------------
# Profile allowlists
# ---------------------------------------------------------------------------

_DEVSECOPS_ALLOWLIST: frozenset[str] = frozenset({
    "open_case",
    "list_cases",
    "scan_evidence",
    "list_sources",
    "get_source_stats",
    "list_directory",
    "read_evidence_file",
    "extract_archive",
    "get_tool_guide",
    "track_progress",
    "wait",
    "wait_all",
    "get_completed_results",
    "check_extraction_status",
    "get_raw_output",
    "run_parallel",
    "search",
    "get_timeline",
    "correlate_across_sources",
    "bookmark_window",
    "get_bookmarks",
    "remove_bookmark",
    "submit_finding",
    "update_finding",
    "delete_finding",
    "get_findings",
    "deduplicate_findings",
    "submit_narrative",
    "finalize_report",
    "check_finalize_readiness",
    "get_investigation_summary",
    "audit_evidence_coverage",
    "audit_tool_coverage",
    "verify_evidence_integrity",
    "lookup_attack_technique",
    "get_ioc_summary",
    "run_strings",
    "trivy_report",
    "dependency_diff",
    "ci_job_log",
    "git_diff",
    "cloud_logs",
    "memory_metrics",
    "heap_trace",
    "status_page",
})

# None means "no filtering" (all registered tools visible).
_PROFILE_ALLOWLIST: dict[Profile, frozenset[str] | None] = {
    Profile.DEVSECOPS: _DEVSECOPS_ALLOWLIST,
    Profile.DFIR: None,
}

_PROFILE_ENV_VAR: str = "LADE_PROFILE"
_allowlist_validated: bool = False


def tool_access(*roles: Role, unthrottled: bool = False) -> Callable[[F], F]:
    """Declare which pipeline roles may call this tool.

    Place this decorator BELOW ``@mcp.tool()`` so it runs first
    and registers the function before MCPServer wraps it.

    ``unthrottled=True`` exempts the tool from the resource gate and
    the tool thread limiter (see ``UNTHROTTLED``).

    Example::

        @mcp.tool()
        @tool_access(EXECUTORS)
        def run_volatility(...):
            ...
    """
    combined = Role(0)
    for r in roles:
        combined |= r

    def decorator(fn: F) -> F:
        _registry[fn.__name__] = combined
        if unthrottled:
            UNTHROTTLED.add(fn.__name__)
        return fn

    return decorator


def _validate_allowlist() -> None:
    """Ensure every name in the DEVSECOPS allowlist is a registered tool.

    Raises ``ImportError`` with a sorted list of missing names so a typo
    cannot silently drop a tool from the devsecops surface.
    """
    global _allowlist_validated
    if _allowlist_validated:
        return
    missing = _DEVSECOPS_ALLOWLIST - set(_registry)
    if missing:
        raise ImportError(
            "Lade DEVSECOPS profile allowlist references unregistered "
            f"tools: {sorted(missing)}"
        )
    _allowlist_validated = True


def get_active_profile() -> Profile:
    """Read the active investigation profile from ``LADE_PROFILE``.

    Defaults to :attr:`Profile.DEVSECOPS` when the env var is unset or
    unrecognised.  Setting ``LADE_PROFILE=dfir`` (or ``full``/``all``)
    selects :attr:`Profile.DFIR`, which includes all tools.
    """
    raw = os.environ.get(_PROFILE_ENV_VAR, "").strip().lower()
    if raw in ("dfir", "full", "all"):
        return Profile.DFIR
    return Profile.DEVSECOPS


def get_tools_for_role(role: Role, profile: Profile | None = None) -> list[str]:
    """Return sorted MCP tool names accessible by a given role.

    When *profile* is ``None`` (the default) the active profile is
    read from :func:`get_active_profile`, so callers in
    ``phases.py`` pick up ``LADE_PROFILE`` automatically.

    For the **devsecops** profile only tools whose bare name appears in
    ``_DEVSECOPS_ALLOWLIST`` and are registered for *role* are returned.
    For the **dfir** profile every registered tool for *role* is returned.
    """
    if profile is None:
        profile = get_active_profile()

    allowlist = _PROFILE_ALLOWLIST.get(profile)
    if allowlist is None:
        # DFIR profile: no filtering.
        return sorted(
            f"mcp__lade__{name}"
            for name, allowed in _registry.items()
            if role & allowed
        )

    # DEVSECOPS profile: intersect allowlist with role's registered tools.
    _validate_allowlist()
    return sorted(
        f"mcp__lade__{name}"
        for name, allowed in _registry.items()
        if role & allowed and name in allowlist
    )
