"""GitLab webhook receiver with background investigation queue."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import os
import sqlite3
import time
from collections.abc import Callable
from contextlib import asynccontextmanager, suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, PlainTextResponse
from starlette.routing import Route

MAX_BODY_SIZE = 1_000_000
DB_PATH = Path(os.getenv("LADE_DB_DIR", "/tmp/lade")) / "webhook.db"
EVIDENCE_ROOT = Path(os.getenv("LADE_EVIDENCE_ROOT", "/app/evidence"))


@dataclass
class WebhookSettings:
    gitlab_webhook_secret: str
    evidence_root: Path
    db_path: Path


def get_settings() -> WebhookSettings:
    secret = os.getenv("GITLAB_WEBHOOK_SECRET")
    if not secret:
        raise RuntimeError("GITLAB_WEBHOOK_SECRET is not set")
    return WebhookSettings(
        gitlab_webhook_secret=secret,
        evidence_root=EVIDENCE_ROOT,
        db_path=DB_PATH,
    )


class BodyLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, max_size: int = MAX_BODY_SIZE):
        super().__init__(app)
        self.max_size = max_size

    async def dispatch(self, request: Request, call_next: Callable):
        content_length = request.headers.get("content-length")
        if content_length and int(content_length) > self.max_size:
            return JSONResponse({"error": "body too large"}, status_code=413)
        return await call_next(request)


def init_db(db_path: Path) -> None:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(db_path) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS processed_events (
                event_uuid TEXT PRIMARY KEY,
                received_at INTEGER
            )
        """)


def is_duplicate(db_path: Path, event_uuid: str) -> bool:
    with sqlite3.connect(db_path) as conn:
        cur = conn.execute(
            "SELECT 1 FROM processed_events WHERE event_uuid = ?", (event_uuid,)
        )
        return cur.fetchone() is not None


def mark_processed(db_path: Path, event_uuid: str) -> None:
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            "INSERT OR IGNORE INTO processed_events (event_uuid, received_at) VALUES (?, ?)",
            (event_uuid, int(time.time())),
        )


def verify_token(secret: str, provided: str | None) -> bool:
    if not provided:
        return False
    return hmac.compare_digest(provided, secret)


def truncate_field(value: Any, max_len: int = 200) -> str:
    s = str(value)
    return s[:max_len]


def build_context_summary(payload: dict, event_type: str) -> dict:
    summary = {"event_type": event_type}
    if "project" in payload:
        summary["project"] = truncate_field(payload["project"].get("path_with_namespace"))
    if "ref" in payload:
        summary["ref"] = truncate_field(payload["ref"])
    if "checkout_sha" in payload:
        summary["commit_sha"] = truncate_field(payload["checkout_sha"])
    if "after" in payload:
        summary["commit_sha"] = truncate_field(payload["after"])
    if "merge_request" in payload:
        mr = payload["merge_request"]
        summary["mr_iid"] = truncate_field(mr.get("iid"))
    if "pipeline" in payload:
        pl = payload["pipeline"]
        summary["pipeline_id"] = truncate_field(pl.get("id"))
        summary["pipeline_status"] = truncate_field(pl.get("status"))
    # Pipeline Hook uses object_attributes for pipeline info
    if "object_attributes" in payload:
        obj = payload["object_attributes"]
        if "id" in obj:
            summary["pipeline_id"] = truncate_field(obj.get("id"))
        if "status" in obj:
            summary["pipeline_status"] = truncate_field(obj.get("status"))
    if "deployment" in payload:
        dep = payload["deployment"]
        summary["deployment_id"] = truncate_field(dep.get("id"))
    return summary


def sanitize_case_for_public(payload: dict, case_dir: Path) -> dict:
    """Return only allowed public fields, never raw payload or paths."""
    ctx = {}
    # Determine event_type from payload
    if "event_type" in payload:
        ctx["event_type"] = str(payload.get("event_type", ""))
    elif "object_kind" in payload:
        ctx["event_type"] = str(payload.get("object_kind", "unknown"))
    else:
        ctx["event_type"] = "unknown"

    if "project" in payload:
        proj = payload["project"].get("path_with_namespace", "")
        ctx["project"] = str(proj)[:100]
    if "ref" in payload:
        ref = str(payload.get("ref", ""))
        ctx["ref"] = ref[:100]
    if "checkout_sha" in payload:
        sha = str(payload.get("checkout_sha", ""))
        ctx["short_sha"] = sha[:7]
    if "after" in payload:
        sha = str(payload.get("after", ""))
        ctx["short_sha"] = sha[:7]
    if "object_attributes" in payload:
        obj = payload["object_attributes"]
        if "status" in obj:
            ctx["status"] = str(obj.get("status", ""))
        if "id" in obj:
            ctx["pipeline_id"] = str(obj.get("id", ""))
    if "checkout_sha" in payload and "short_sha" not in ctx:
        ctx["short_sha"] = str(payload.get("checkout_sha", ""))[:7]

    return {
        "case_id": case_dir.name,
        "status": ctx.get("status", "running"),
        "phase": "running",
        "updated_at": int(case_dir.stat().st_mtime * 1000),
        "event_type": ctx.get("event_type", "unknown"),
        "project": ctx.get("project", ""),
        "short_sha": ctx.get("short_sha", ""),
        "finding_count": 0,
        "audit_head": "pending",
        "report_ready": False,
    }


async def run_investigation_background(
    case_id: str,
    evidence_root: Path,
    context: dict,
    runner_factory: Callable,
) -> None:
    try:
        runner = runner_factory(case_id, evidence_root, context)
        await runner.run()
    except Exception as e:
        print(f"Investigation failed for {case_id}: {e}")


class InvestigationQueue:
    def __init__(self, runner_factory: Callable, sync_mode: bool = False):
        self._queue: asyncio.Queue = asyncio.Queue()
        self._runner_factory = runner_factory
        self._sync_mode = sync_mode
        self._worker_task: asyncio.Task | None = None

    async def start(self) -> None:
        if not self._sync_mode:
            self._worker_task = asyncio.create_task(self._worker())

    async def stop(self) -> None:
        if self._worker_task:
            self._worker_task.cancel()
            with suppress(asyncio.CancelledError):
                await self._worker_task

    async def enqueue(self, case_id: str, evidence_root: Path, context: dict) -> None:
        if self._sync_mode:
            runner = self._runner_factory(case_id, evidence_root, context)
            if hasattr(runner, 'run') and callable(runner.run):
                await runner.run()
            elif callable(runner):
                if asyncio.iscoroutinefunction(runner):
                    await runner(case_id, evidence_root, context)
                else:
                    runner(case_id, evidence_root, context)
        else:
            await self._queue.put((case_id, evidence_root, context))

    async def _worker(self) -> None:
        while True:
            case_id, evidence_root, context = await self._queue.get()
            await run_investigation_background(
                case_id, evidence_root, context, self._runner_factory
            )
            self._queue.task_done()


def create_app(
    runner_factory: Callable | None = None,
    settings: WebhookSettings | None = None,
    sync_mode: bool = False,
) -> Starlette:
    if settings is None:
        settings = get_settings()

    init_db(settings.db_path)
    queue = InvestigationQueue(runner_factory, sync_mode=sync_mode) if runner_factory else None

    @asynccontextmanager
    async def lifespan(app: Starlette):
        if queue:
            await queue.start()
        yield
        if queue:
            await queue.stop()

    async def gitlab_webhook(request: Request) -> JSONResponse:
        token = request.headers.get("X-Gitlab-Token")
        if not verify_token(settings.gitlab_webhook_secret, token):
            return JSONResponse({"error": "unauthorized"}, status_code=401)

        event_type = request.headers.get("X-Gitlab-Event", "")
        event_uuid = request.headers.get("X-Gitlab-Event-UUID", "")

        if event_uuid and is_duplicate(settings.db_path, event_uuid):
            return JSONResponse({"duplicate": True})

        try:
            body = await request.body()
        except Exception:
            return JSONResponse({"error": "invalid body"}, status_code=400)

        if len(body) > MAX_BODY_SIZE:
            return JSONResponse({"error": "body too large"}, status_code=413)

        try:
            payload = json.loads(body)
        except json.JSONDecodeError:
            return JSONResponse({"error": "invalid json"}, status_code=400)

        accepted = False
        if event_type == "Pipeline Hook":
            obj_kind = payload.get("object_kind")
            status = payload.get("object_attributes", {}).get("status")
            if obj_kind == "pipeline" and status in ("success", "failed"):
                accepted = True
        elif event_type == "Merge Request Hook":
            state = payload.get("object_attributes", {}).get("state")
            if state == "merged":
                accepted = True
        elif event_type == "Deployment Hook":
            accepted = True

        if not accepted:
            return JSONResponse({"ignored": True})

        if event_uuid:
            mark_processed(settings.db_path, event_uuid)

        case_id = hashlib.sha256(f"{event_uuid}{time.time()}".encode()).hexdigest()[:16]
        case_dir = settings.evidence_root / case_id
        case_dir.mkdir(parents=True, exist_ok=True)
        trigger_dir = case_dir / "trigger"
        trigger_dir.mkdir(exist_ok=True)

        trigger_file = trigger_dir / "gitlab_event.json"
        trigger_file.write_text(json.dumps(payload, indent=2))

        context = build_context_summary(payload, event_type)

        if queue:
            await queue.enqueue(case_id, settings.evidence_root, context)

        return JSONResponse({"case_id": case_id, "status": "queued"}, status_code=202)

    async def manual_trigger(request: Request) -> JSONResponse:
        token = request.headers.get("X-Gitlab-Token")
        if not verify_token(settings.gitlab_webhook_secret, token):
            return JSONResponse({"error": "unauthorized"}, status_code=401)

        try:
            body = await request.body()
            payload = json.loads(body) if body else {}
        except json.JSONDecodeError:
            return JSONResponse({"error": "invalid json"}, status_code=400)

        case_id = hashlib.sha256(f"manual{time.time()}".encode()).hexdigest()[:16]
        case_dir = settings.evidence_root / case_id
        case_dir.mkdir(parents=True, exist_ok=True)
        trigger_dir = case_dir / "trigger"
        trigger_dir.mkdir(exist_ok=True)

        trigger_file = trigger_dir / "gitlab_event.json"
        trigger_file.write_text(json.dumps(payload, indent=2))

        context = {"event_type": "Manual Trigger", **payload}
        if queue:
            await queue.enqueue(case_id, settings.evidence_root, context)

        return JSONResponse({"case_id": case_id, "status": "queued"}, status_code=202)

    async def case_status(request: Request) -> JSONResponse:
        case_id = request.path_params["case_id"]
        case_dir = settings.evidence_root / case_id
        if not case_dir.exists():
            return JSONResponse({"error": "not found"}, status_code=404)

        trigger_file = case_dir / "trigger" / "gitlab_event.json"
        payload = {}
        if trigger_file.exists():
            with suppress(Exception):
                payload = json.loads(trigger_file.read_text())

        return JSONResponse(sanitize_case_for_public(payload, case_dir))

    async def list_cases(request: Request) -> JSONResponse:
        cases = []
        if not settings.evidence_root.exists():
            return JSONResponse([])
        for case_dir in settings.evidence_root.iterdir():
            if not case_dir.is_dir():
                continue
            trigger_file = case_dir / "trigger" / "gitlab_event.json"
            payload = {}
            if trigger_file.exists():
                with suppress(Exception):
                    payload = json.loads(trigger_file.read_text())
            cases.append(sanitize_case_for_public(payload, case_dir))
        cases.sort(key=lambda c: c.get("updated_at", 0), reverse=True)
        return JSONResponse(cases)

    async def healthz(request: Request) -> PlainTextResponse:
        return PlainTextResponse("ok")

    async def dashboard(request: Request) -> HTMLResponse:
        return HTMLResponse("""
<!DOCTYPE html>
<html>
<head>
  <title>Lade Webhook Dashboard</title>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace; background: #0d1117; color: #e6edf3; line-height: 1.4; padding: 20px; }
    .container { max-width: 900px; margin: 0 auto; }
    header { border-bottom: 1px solid #30363d; padding-bottom: 16px; margin-bottom: 24px; }
    h1 { font-size: 1.5rem; font-weight: 600; color: #58a6ff; }
    .subtitle { color: #8b949e; margin-top: 4px; }
    .status-bar { display: flex; gap: 16px; margin-bottom: 24px; flex-wrap: wrap; }
    .stat { background: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 12px 16px; min-width: 120px; }
    .stat-label { color: #8b949e; font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.5px; }
    .stat-value { font-size: 1.5rem; font-weight: 600; color: #58a6ff; }
    .case-list { background: #161b22; border: 1px solid #30363d; border-radius: 6px; overflow: hidden; }
    .case-header { display: grid; grid-template-columns: 2fr 1fr 1fr 1fr 2fr; padding: 12px 16px; background: #21262d; border-bottom: 1px solid #30363d; font-size: 0.75rem; text-transform: uppercase; color: #8b949e; letter-spacing: 0.5px; }
    .case-row { display: grid; grid-template-columns: 2fr 1fr 1fr 1fr 2fr; padding: 12px 16px; border-bottom: 1px solid #21262d; transition: background 0.15s; }
    .case-row:hover { background: #1f2428; }
    .case-row:last-child { border-bottom: none; }
    .case-id { font-family: monospace; color: #58a6ff; word-break: break-all; }
    .status { display: inline-flex; align-items: center; gap: 6px; font-weight: 500; }
    .status::before { content: ''; width: 8px; height: 8px; border-radius: 50%; }
    .status-queued::before { background: #d29922; }
    .status-running::before { background: #58a6ff; animation: pulse 1.5s infinite; }
    .status-done::before { background: #3fb950; }
    .status-failed::before { background: #f85149; }
    @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.4; } }
    .phase { color: #8b949e; font-size: 0.875rem; }
    .timestamp { color: #8b949e; font-size: 0.75rem; font-family: monospace; }
    .actions button { background: #238636; color: white; border: none; border-radius: 4px; padding: 4px 12px; font-family: inherit; font-size: 0.75rem; cursor: pointer; transition: background 0.15s; }
    .actions button:hover { background: #2ea043; }
    .actions button:disabled { background: #30363d; color: #8b949e; cursor: not-allowed; }
    .empty { padding: 48px; text-align: center; color: #8b949e; }
    .footer { margin-top: 24px; padding-top: 16px; border-top: 1px solid #30363d; color: #8b949e; font-size: 0.75rem; text-align: center; }
    .flash { animation: flash 0.5s ease-out; }
    @keyframes flash { 0% { background: #238636; } 100% { background: #161b22; } }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <h1>▲ LADE Webhook Dashboard</h1>
      <p class="subtitle">GitLab webhook receiver · investigation queue</p>
    </header>

    <div class="status-bar">
      <div class="stat">
        <div class="stat-label">Queued</div>
        <div class="stat-value" id="stat-queued">0</div>
      </div>
      <div class="stat">
        <div class="stat-label">Running</div>
        <div class="stat-value" id="stat-running">0</div>
      </div>
      <div class="stat">
        <div class="stat-label">Done</div>
        <div class="stat-value" id="stat-done">0</div>
      </div>
      <div class="stat">
        <div class="stat-label">Failed</div>
        <div class="stat-value" id="stat-failed">0</div>
      </div>
      <div class="stat">
        <div class="stat-label">Last Update</div>
        <div class="stat-value" id="stat-last">—</div>
      </div>
    </div>

    <div class="case-list" id="case-list">
      <div class="case-header">
        <div>Case ID</div>
        <div>Status</div>
        <div>Phase</div>
        <div>Updated</div>
        <div>Actions</div>
      </div>
      <div id="case-rows"></div>
    </div>

    <footer class="footer">
      <code>GET /cases/{id}</code> · <code>POST /webhook/gitlab</code> · <code>POST /trigger/manual</code> · <code>GET /healthz</code>
      <br>Webhook secret: <code>GITLAB_WEBHOOK_SECRET</code> · Evidence root: <code>LADE_EVIDENCE_ROOT</code>
    </footer>
  </div>

  <script>
    const rowsEl = document.getElementById('case-rows');
    const statEls = {
      queued: document.getElementById('stat-queued'),
      running: document.getElementById('stat-running'),
      done: document.getElementById('stat-done'),
      failed: document.getElementById('stat-failed'),
      last: document.getElementById('stat-last'),
    };

    function createCell(tag, className, text) {
      const el = document.createElement(tag);
      if (className) el.className = className;
      if (text !== undefined) el.textContent = text;
      return el;
    }

    async function loadCases() {
      try {
        const res = await fetch('/cases');
        if (!res.ok) throw new Error('Failed to load');
        const cases = await res.json();
        renderCases(cases);
        updateStats(cases);
      } catch (e) {
        console.error('Failed to load cases:', e);
      }
    }

    function createCell(tag, className, text) {
      const el = document.createElement(tag);
      if (className) el.className = className;
      if (text !== undefined) el.textContent = text;
      return el;
    }

    function createCaseRow(c) {
      const row = document.createElement('div');
      row.className = 'case-row';
      row.dataset.id = c.case_id;

      const now = Date.now();
      const age = Math.floor((now - (c.updated_at || now)) / 1000);
      const timeStr = age < 60 ? age + 's ago' : age < 3600 ? Math.floor(age/60) + 'm ago' : Math.floor(age/3600) + 'h ago';
      const statusClass = 'status-' + (c.status || 'queued');

      const caseIdCell = createCell('div', 'case-id', c.case_id);

      const statusCell = createCell('div');
      const statusBadge = createCell('span', 'status ' + statusClass, c.status || 'queued');
      statusCell.appendChild(statusBadge);

      const phaseCell = createCell('div', 'phase', c.phase || 'pending');

      const timeCell = createCell('div', 'timestamp',
        age < 60 ? age + 's ago' : age < 3600 ? Math.floor(age/60) + 'm ago' : Math.floor(age/3600) + 'h ago');

      const actionsCell = createCell('div', 'actions');
      if (c.status !== 'done' && c.status !== 'failed') {
        const btn = createCell('button', '', 'Running...');
        btn.disabled = true;
        actionsCell.appendChild(btn);
      } else {
        const btn = createCell('button', '', 'View');
        btn.onclick = function() { window.open('/cases/' + c.case_id, '_blank'); };
        actionsCell.appendChild(btn);
      }

      row.append(caseIdCell, statusCell, phaseCell, timeCell, actionsCell);
      return row;
    }

    function renderCases(cases) {
      rowsEl.innerHTML = '';
      if (!cases || cases.length === 0) {
        const empty = document.createElement('div');
        empty.className = 'empty';
        empty.textContent = 'No cases yet. Trigger a GitLab pipeline or merge request.';
        rowsEl.appendChild(empty);
        return;
      }

      cases.forEach(function(c) {
        rowsEl.appendChild(createCaseRow(c));
      });
    }

    function updateStats(cases) {
      var counts = { queued: 0, running: 0, done: 0, failed: 0 };
      var latest = 0;
      cases.forEach(function(c) {
        var s = (c.status || 'queued').toLowerCase();
        if (counts[s] !== undefined) counts[s]++;
        if (c.updated_at && c.updated_at > latest) latest = c.updated_at;
      });
      statEls.queued.textContent = counts.queued;
      statEls.running.textContent = counts.running;
      statEls.done.textContent = counts.done;
      statEls.failed.textContent = counts.failed;
      statEls.last.textContent = latest ? new Date(latest).toLocaleTimeString() : '—';
    }

    // Initial load + polling
    loadCases();
    setInterval(loadCases, 2000);
  </script>
</body>
</html>
        """)

    routes = [
        Route("/", dashboard, methods=["GET"]),
        Route("/cases", list_cases, methods=["GET"]),
        Route("/webhook/gitlab", gitlab_webhook, methods=["POST"]),
        Route("/trigger/manual", manual_trigger, methods=["POST"]),
        Route("/cases/{case_id}", case_status, methods=["GET"]),
        Route("/healthz", healthz, methods=["GET"]),
    ]

    middleware = [
        Middleware(BodyLimitMiddleware),
    ]

    app = Starlette(routes=routes, middleware=middleware, lifespan=lifespan)
    app.state.settings = settings
    app.state.queue = queue
    return app


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("lade.webhook.app:create_app", host="0.0.0.0", port=8080, factory=True)
