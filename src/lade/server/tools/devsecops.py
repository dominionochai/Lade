"""DevSecOps evidence parsing tools for Lade.

Read-only tools that parse common DevSecOps artifact formats (Trivy reports,
dependency diffs, CI job logs, git diffs, cloud logs, memory metrics, heap
traces, and status pages) found in the case evidence directory.

All tools enforce the standard Lade path-containment policy and refuse any
path containing a folder named ``expected`` (which holds answer keys).
"""

from __future__ import annotations

import csv
import io
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
    "cloud_logs",
    "memory_metrics",
    "heap_trace",
    "status_page",
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
    assert text is not None

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
    noun = "vulnerability" if count == 1 else "vulnerabilities"
    lines.append(
        f"Trivy report for {artifact} ({artifact_type}): "
        f"{count} {noun} found"
        + (f" ({sev_summary})" if sev_summary else "")
    )

    for v in vulns:
        cve = v.get("VulnerabilityID", "")
        pkg = v.get("PkgName", "")
        installed = v.get("InstalledVersion", "")
        fixed = v.get("FixedVersion", "")
        severity = v.get("Severity", "UNKNOWN")
        cwes_raw = v.get("CweIDs", []) or []
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
    assert text is not None

    removed: dict[str, str] = {}
    added: dict[str, str] = {}
    pkg_version_re = re.compile(r"^[-+]\s*([A-Za-z0-9_.-]+)\s+(\S+)")

    for raw_line in text.splitlines():
        line = raw_line.rstrip()
        if line.startswith("---") or line.startswith("+++"):
            continue
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
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

    The job result is derived from the log text: "passed with warnings"
    if the log mentions ``allow_failure`` and contains a ``WARNING`` line
    (the job was allowed to fail but completed with warnings), otherwise
    the result is determined by the last ``Job succeeded`` or ``Job failed``
    line, defaulting to ``succeeded``.

    Args:
        path: Path to the CI job log file inside the case evidence.
    """
    text, error = _read_evidence_text(path)
    if error is not None:
        return {"status": "error", "error_message": error}
    assert text is not None

    numbered = _numbered_lines(text)
    job_result = _derive_job_result(text)

    return {"status": "success", "result": f"{numbered}\nJOB RESULT: {job_result}"}


def _derive_job_result(text: str) -> str:
    """Derive a job result string from CI log text (deterministic heuristic)."""
    lowered = text.lower()
    if "allow_failure" in lowered and "warning" in lowered:
        return "passed with warnings"
    for line in reversed(text.splitlines()):
        line_lower = line.lower()
        if "job succeeded" in line_lower:
            return "succeeded"
        if "job failed" in line_lower:
            return "failed"
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
    assert text is not None

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


@mcp.tool()
@tool_access(EXECUTORS | ANALYSTS)
@audited_tool("cloud_logs")
def cloud_logs(
    path: str,
    severity: str | None = None,
    contains: str | None = None,
    start: str | None = None,
    end: str | None = None,
    limit: int = 200,
) -> dict[str, object]:
    """Filter Cloud Logging JSONL entries.

    Each entry is rendered as one line:
    ``timestamp SEVERITY revision=NAME instance=ID ...`` where
    ``resource.labels`` (revision_name), ``labels.instanceId``,
    ``httpRequest``, ``textPayload``, and ``jsonPayload`` fields are all
    included (null renders as ``None``).

    Args:
        path: Path to the Cloud Logging JSONL file inside the case evidence.
        severity: Filter to entries with this severity level.
        contains: Substring filter on the rendered line text.
        start: ISO-8601 timestamp; only entries at or after this time are kept.
        end: ISO-8601 timestamp; only entries before this time are kept.
        limit: Maximum number of entries to return.
    """
    text, error = _read_evidence_text(path)
    if error is not None:
        return {"status": "error", "error_message": error}
    assert text is not None

    out_lines: list[str] = []
    for raw_line in text.splitlines():
        raw_line = raw_line.strip()
        if not raw_line:
            continue
        try:
            entry = json.loads(raw_line)
        except json.JSONDecodeError:
            continue

        entry_severity = entry.get("severity", "DEFAULT")
        if severity is not None and entry_severity != severity:
            continue

        ts = entry.get("timestamp", "")
        if start is not None and ts < start:
            continue
        if end is not None and ts > end:
            continue

        parts: list[str] = [ts, entry_severity]

        resource = entry.get("resource", {}) or {}
        rev = (resource.get("labels", {}) or {}).get("revision_name", "")
        if rev:
            parts.append(f"revision={rev}")

        entry_labels = entry.get("labels", {}) or {}
        inst = entry_labels.get("instanceId", "")
        if inst:
            parts.append(f"instance={inst}")

        http = entry.get("httpRequest", {}) or {}
        if http:
            if http.get("requestMethod"):
                parts.append(f"httpMethod={http['requestMethod']}")
            if http.get("requestUrl"):
                parts.append(f"requestUrl={http['requestUrl']}")
            if http.get("status"):
                parts.append(f"status={http['status']}")
            if http.get("latency"):
                parts.append(f"latency={http['latency']}")

        if entry.get("textPayload"):
            parts.append(entry["textPayload"])

        payload = entry.get("jsonPayload", {}) or {}
        if isinstance(payload, dict):
            for k, v in payload.items():
                parts.append(_kv(k, v))
        elif isinstance(payload, str):
            parts.append(payload)

        rendered = " ".join(parts)
        if contains is not None and contains not in rendered:
            continue

        out_lines.append(rendered)
        if len(out_lines) >= limit:
            break

    return {"status": "success", "result": "\n".join(out_lines)}


def _kv(key: str, value: Any) -> str:
    """Render a key/value pair from a Cloud Logging payload."""
    if isinstance(value, bool):
        return f"{key}={value}"
    if value is None:
        return f"{key}=None"
    if isinstance(value, (dict, list)):
        return f"{key}={json.dumps(value, default=str)}"
    return f"{key}={value}"


@mcp.tool()
@tool_access(EXECUTORS | ANALYSTS)
@audited_tool("memory_metrics")
def memory_metrics(path: str, revision: str | None = None) -> dict[str, object]:
    """Analyze per-minute memory metrics from a CSV file.

    Produces one summary line per instance with first/last timestamp,
    start/end MiB, slope (MiB/min via least squares), and requests/sec
    statistics.  Adds a ``MiB per 1000 requests`` line per instance.

    Args:
        path: Path to the per-minute memory metrics CSV file.
        revision: Optional revision name filter (e.g. ``orders-api-00042-kqz``);
            when provided, only rows matching this revision are included.
    """
    text, error = _read_evidence_text(path)
    if error is not None:
        return {"status": "error", "error_message": error}
    assert text is not None

    reader = csv.DictReader(io.StringIO(text))
    by_instance: dict[str, list[dict[str, str]]] = {}
    for row in reader:
        if revision is not None:
            row_rev = (row.get("revision") or "").strip()
            if row_rev != revision:
                continue
        inst = (row.get("instance_id") or "").strip()
        if not inst:
            continue
        by_instance.setdefault(inst, []).append(row)

    lines: list[str] = []
    for inst in sorted(by_instance):
        rows = by_instance[inst]
        rows.sort(key=lambda r: r.get("timestamp_utc", ""))
        first_ts = rows[0].get("timestamp_utc", "")
        last_ts = rows[-1].get("timestamp_utc", "")

        mibs: list[float] = []
        reqs: list[float] = []
        for r in rows:
            try:
                mibs.append(float(r.get("memory_mib", 0)))
            except (TypeError, ValueError):
                mibs.append(0.0)
            try:
                reqs.append(float(r.get("requests_per_sec", 0)))
            except (TypeError, ValueError):
                reqs.append(0.0)

        slope = _least_squares_slope(mibs)

        req_mean = sum(reqs) / len(reqs) if reqs else 0.0
        req_min = min(reqs) if reqs else 0.0
        req_max = max(reqs) if reqs else 0.0

        lines.append(
            f"instance={inst} first={first_ts} last={last_ts} "
            f"start_mib={mibs[0]:.1f} end_mib={mibs[-1]:.1f} "
            f"slope={slope:.2f}_mib_per_min "
            f"reqs_per_sec mean={req_mean:.1f} min={req_min:.1f} max={req_max:.1f}"
        )

        if req_mean > 0:
            mib_per_1k = slope * 1000.0 / (req_mean * 60.0)
            lines.append(f"MiB per 1000 requests: {mib_per_1k:.2f}")
        else:
            lines.append("MiB per 1000 requests: N/A")

    return {"status": "success", "result": "\n".join(lines)}


def _least_squares_slope(values: list[float]) -> float:
    """Return the least-squares linear regression slope of *values*.

    The independent variable is the 0-based index (one point per minute),
    so the slope is in units-per-step where each step is one minute.
    """
    n = len(values)
    if n < 2:
        return 0.0
    xs = list(range(n))
    sum_x = sum(xs)
    sum_y = sum(values)
    sum_xy = sum(x * y for x, y in zip(xs, values, strict=True))
    sum_xx = sum(x * x for x in xs)
    denom = n * sum_xx - sum_x * sum_x
    if denom == 0:
        return 0.0
    return (n * sum_xy - sum_x * sum_y) / denom


@mcp.tool()
@tool_access(EXECUTORS | ANALYSTS)
@audited_tool("heap_trace")
def heap_trace(path: str) -> dict[str, object]:
    """Return a heap trace dump with line numbers.

    Args:
        path: Path to the heap trace file inside the case evidence.
    """
    text, error = _read_evidence_text(path)
    if error is not None:
        return {"status": "error", "error_message": error}
    assert text is not None

    return {"status": "success", "result": _numbered_lines(text)}


@mcp.tool()
@tool_access(EXECUTORS | ANALYSTS)
@audited_tool("status_page")
def status_page(path: str) -> dict[str, object]:
    """Return a service status page with line numbers.

    Args:
        path: Path to the status page file inside the case evidence.
    """
    text, error = _read_evidence_text(path)
    if error is not None:
        return {"status": "error", "error_message": error}
    assert text is not None

    return {"status": "success", "result": _numbered_lines(text)}
