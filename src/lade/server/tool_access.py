"""Declarative tool-role access registry for the Lade MCP surface.

Tools self-declare which pipeline roles may invoke them via the
``@tool_access`` decorator. The ``get_tools_for_role`` function
builds allowlists at import time so ``phases.py`` never needs manual
tool list maintenance.

The active investigation profile (``LADE_PROFILE`` env var, default
``devsecops``) further filters the allowlist: the *devsecops* profile
excludes tools that only run DFIR binaries (tsk, plaso, yara,
hayabusa, chainsaw, zircolite, eztools, hindsight, mvt, phone,
binary), so they are invisible to agents in that profile.
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

# Tool function names excluded from the *devsecops* profile allowlist.
# These tools only invoke external DFIR binaries (disk-image, memory,
# mobile, binary-analysis toolkits).
_PROFILE_EXCLUSIONS: dict[Profile, set[str]] = {
    Profile.DEVSECOPS: {
        # tsk.py
        "list_partitions",
        "list_files",
        "get_deleted_files",
        "get_fs_timeline",
        "extract_file_by_inode",
        "get_file_metadata",
        # plaso.py
        "get_plaso_stats",
        "filter_timeline",
        "export_timeline_slice",
        # yara.py
        "yara_scan_files",
        "yara_scan_memory",
        "yara_scan_with_volatility",
        # hayabusa.py
        "run_hayabusa",
        # chainsaw.py
        "run_chainsaw",
        # zircolite.py
        "run_zircolite",
        # eztools.py
        "parse_mft",
        "parse_usn_journal",
        # hindsight.py
        "run_hindsight",
        # mvt.py
        "run_mvt_android",
        "run_mvt_ios",
        # phone.py
        "carve_sqlite_from_raw",
        "parse_android_artifacts",
        "parse_ios_artifacts",
        "decrypt_app_data",
        "run_aleapp",
        "run_ileapp",
        # binary.py
        "triage_binary",
        "run_capa",
        "run_floss",
        "run_detect_it_easy",
    },
    Profile.DFIR: set(),
}

_PROFILE_ENV_VAR: str = "LADE_PROFILE"


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
    """
    if profile is None:
        profile = get_active_profile()
    excluded = _PROFILE_EXCLUSIONS.get(profile, set())
    return sorted(
        f"mcp__lade__{name}"
        for name, allowed in _registry.items()
        if role & allowed and name not in excluded
    )
