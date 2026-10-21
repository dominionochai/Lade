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
from starlette.responses import JSONResponse, PlainTextResponse
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
            # In sync mode (tests), call runner immediately
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
        context = {}
        if trigger_file.exists():
            with suppress(Exception):
                context = json.loads(trigger_file.read_text())

        return JSONResponse({
            "case_id": case_id,
            "phase": "running",
            "finding_count": 0,
            "status": "running",
            "audit_chain_head": "pending",
            "report_path": None,
            "context": context,
        })

    async def healthz(request: Request) -> PlainTextResponse:
        return PlainTextResponse("ok")

    routes = [
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
