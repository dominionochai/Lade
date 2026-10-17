"""DevSecOps evidence parsing tools for Lade.

Read-only tools that parse common DevSecOps artifact formats (Trivy reports,
dependency diffs, CI job logs, and git diffs) found in the case evidence
directory.

All tools enforce the standard Lade path-containment policy and refuse any
path containing a folder named ``expected`` (which holds answer keys).
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from lade.path_policy import PathPolicyError, resolve_allowed_path
from lade.server.app import get_cfg, get_ctx, mcp
from lade.server.helpers import audited_tool
from lade.server.tool_access import ANALYSTS, EXECUTORS, tool_access

__all__ = [
    "trivy_report",
    "dependency_diff",
    "ci_job_log",
    "git_diff",
]


def _resolve_evidence_path(target: Path) -> Path:
    """Resolve *target* within the active evidence or case-storage root.

    Uses the same containment policy as the rest of Lade (``resolve_allowed_path``
    with ``db_dir`` and the case ``evidence_root`` as allowed roots).  Additionally
    refuses any path that contains a folder component named ``expected``.
    """
    cfg = get_cfg()
    allowed_roots: list[Path] = [Path(cfg.db_dir)]
    ctx = get_ctx()
    meta = ctx.db.get_case_metadata()
    if meta and meta.evidence_root:
        allowed_roots.append(Path(meta.evidence_root))

    resolved = resolve_allowed_path(target, allowed_roots)

    if "expected" in resolved.parts:
        raise PathPolicyError(
            "Access denied: path contains a folder named 'expected' (answer key)"
        )
    return resolved


def _read_evidence_text(path: str) -> tuple[str | None, str | None]:
    """Read a text file from evidence via the path policy.

    Returns ``(text, error_message)``.  Exactly one is non-None.
    """
    try:
        target = _resolve_evidence_path(Path(path))
    except PathPolicyError as exc:
        return None, str(exc)

    if not target.exists():
        return None, f"File not found: {path}"
    if not target.is_file():
        return None, f"Not a file: {path}"

    try:
        raw = target.read_bytes()
        return raw.decode("utf-8", errors="replace"), None
    except OSError as exc:
        return None, f"Failed to read file: {exc}"


def _numbered_lines(text: str) -> str:
    """Prefix every line of *text* with a zero-padded line number."""
    lines = text.splitlines()
    return "\n".join(f"{i + 1:04d}: {line}" for i, line in enumerate(lines))


@mcp.tool()
@tool_access(EXECUTORS | ANALYSTS)
@audited_tool("trivy_report")
def trivy_report(path: str) -> dict[str, object]:
    """Parse a Trivy JSON vulnerability report.

    Args:
        path: Path to the Trivy JSON report inside the case evidence.
    """
    text, error = _read_evidence_text(path)
    if error is not None:
        return {"status": "error", "error_message": error}

    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        return {"status": "error", "error_message": f"Invalid JSON: {exc}"}

    artifact = data.get("ArtifactName", "<unknown>")
    artifact_type = data.get("ArtifactType", "")
    results = data.get("Results", []) or []

    vulns: list[dict[str, Any]] = []
    severity_counts: dict[str, int] = {}
    for res in results:
        for v in res.get("Vulnerabilities", []) or []:
            vulns.append(v)
            sev = v.get("Severity", "UNKNOWN")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

    lines: list[str] = []
    count = len(vulns)
    sev_summary = ", ".join(f"{s}: {c}" for s, c in sorted(severity_counts.items()))
    lines.append(
        f"Trivy report for {artifact} ({artifact_type}): "
        f"{count} vulnerability{'s' if count != 1 else ''} found"
        + (f" ({sev_summary})" if sev_summary else "")
    )

    for v in vulns:
        cve = v.get("VulnerabilityID", "")
        pkg = v.get("PkgName", "")
        installed = v.get("InstalledVersion", "")
        fixed = v.get("FixedVersion", "")
        severity = v.get("Severity", "UNKNOWN")
        cwes_raw = v.get("CWEs", []) or []
        cwe_ids: list[str] = []
        for cwe in cwes_raw:
            if isinstance(cwe, dict):
                cwe_ids.append(cwe.get("ID", ""))
            elif isinstance(cwe, str):
                cwe_ids.append(cwe)
        cwe_str = ", ".join(c for c in cwe_ids if c)
        title = v.get("Title", "")
        lines.append(
            f"{cve} | {pkg} {installed} -> {fixed} | {severity} | {cwe_str} | {title}"
        )

    return {"status": "success", "result": "\n".join(lines)}


@mcp.tool()
@tool_access(EXECUTORS | ANALYSTS)
@audited_tool("dependency_diff")
def dependency_diff(path: str) -> dict[str, object]:
    """Return a dependency diff with one summary line per changed package.

    Args:
        path: Path to the dependency diff file inside the case evidence.
    """
    text, error = _read_evidence_text(path)
    if error is not None:
        return {"status": "error", "error_message": error}

    removed: dict[str, str] = {}
    added: dict[str, str] = {}
    pkg_version_re = re.compile(r"^[-+]\s*([A-Za-z0-9_.-]+)==\s*([\w.+-]+)")

    for raw_line in text.splitlines():
        line = raw_line.rstrip()
        if line.startswith("---") or line.startswith("+++"):
            continue
        stripped = line.strip()
        if stripped.startswith("+ ") or stripped.startswith("+"):
            m = pkg_version_re.match(stripped)
            if m:
                added[m.group(1).lower()] = m.group(2)
        elif stripped.startswith("- ") or stripped.startswith("-"):
            m = pkg_version_re.match(stripped)
            if m:
                removed[m.group(1).lower()] = m.group(2)

    changed_lines: list[str] = []
    for pkg in sorted(removed):
        if pkg in added and removed[pkg] != added[pkg]:
            changed_lines.append(f"{pkg}: {removed[pkg]} -> {added[pkg]} (changed)")

    result = text.rstrip()
    if changed_lines:
        result += "\n" + "\n".join(changed_lines)

    return {"status": "success", "result": result}


@mcp.tool()
@tool_access(EXECUTORS | ANALYSTS)
@audited_tool("ci_job_log")
def ci_job_log(path: str) -> dict[str, object]:
    """Return a CI job log with line numbers and a derived job result.

    The job result is derived from the log text: "failed" if the log
    contains failure indicators, "passed with warnings" if it contains
    warnings but no failures, otherwise "succeeded".

    Args:
        path: Path to the CI job log file inside the case evidence.
    """
    text, error = _read_evidence_text(path)
    if error is not None:
        return {"status": "error", "error_message": error}

    numbered = _numbered_lines(text)
    job_result = _derive_job_result(text)

    return {"status": "success", "result": f"{numbered}\nJOB RESULT: {job_result}"}


def _derive_job_result(text: str) -> str:
    """Derive a job result string from CI log text (deterministic heuristic)."""
    lowered = text.lower()
    if "fail" in lowered:
        return "failed"
    if "warn" in lowered:
        return "passed with warnings"
    if "succeed" in lowered or "pass" in lowered:
        return "succeeded"
    return "succeeded"


@mcp.tool()
@tool_access(EXECUTORS | ANALYSTS)
@audited_tool("git_diff")
def git_diff(path: str) -> dict[str, object]:
    """Return a git diff with line numbers and one summary line per changed file.

    Args:
        path: Path to the git diff file inside the case evidence.
    """
    text, error = _read_evidence_text(path)
    if error is not None:
        return {"status": "error", "error_message": error}

    numbered = _numbered_lines(text)

    file_re = re.compile(r"^diff --git\s+a/(.+?)\s+b/")
    file_stats: dict[str, list[int]] = {}

    current_file: str | None = None
    for line in text.splitlines():
        m = file_re.match(line)
        if m:
            current_file = m.group(1)
            file_stats.setdefault(current_file, [0, 0])
        if current_file and line.startswith("+") and not line.startswith("+++"):
            file_stats[current_file][0] += 1
        elif current_file and line.startswith("-") and not line.startswith("---"):
            file_stats[current_file][1] += 1

    summary_lines = [
        f"FILE {f} +{adds} -{dels}" for f, (adds, dels) in sorted(file_stats.items())
    ]

    result = numbered
    if summary_lines:
        result += "\n" + "\n".join(summary_lines)

    return {"status": "success", "result": result}
