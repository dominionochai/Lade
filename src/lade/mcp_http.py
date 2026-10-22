"""HTTP/SSE transport for the Lade MCP server to enable Duo Agent Platform integration."""

from __future__ import annotations

import asyncio
import json
import os
import uuid
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Any, AsyncIterator

import anyio
from anyio.streams.memory import MemoryObjectReceiveStream, MemoryObjectSendStream
from mcp.server.mcpserver import MCPServer
from mcp.types import (
    CallToolRequest,
    CallToolResult,
    InitializeRequest,
    InitializeResult,
    ListToolsRequest,
    ListToolsResult,
    JSONRPCRequest,
    JSONRPCResponse,
    JSONRPCError,
)

from lade.server.app import mcp as lade_mcp, init_server, get_cfg, get_ctx, has_ctx
from lade.server.tools import core, devsecops  # noqa: F401 - register tools

try:
    from starlette.applications import Starlette
    from starlette.middleware.cors import CORSMiddleware
    from starlette.requests import Request
    from starlette.responses import JSONResponse, StreamingResponse
    from starlette.routing import Route, Mount
    from starlette.middleware import Middleware
    from starlette.middleware.base import BaseHTTPMiddleware
    STARLETTE_AVAILABLE = True
except ImportError:
    STARLETTE_AVAILABLE = False


@dataclass
class MCPHTTPSession:
    """Represents an active MCP session over HTTP/SSE."""
    session_id: str
    request_stream: MemoryObjectSendStream
    response_stream: MemoryObjectReceiveStream
    initialized: bool = False


class MCPHTTPTransport:
    """HTTP/SSE transport for MCP server."""

    def __init__(self, mcp_server: MCPServer):
        self.mcp_server = mcp_server
        self.sessions: dict[str, MCPHTTPSession] = {}
        self._message_queues: dict[str, asyncio.Queue] = {}

    async def handle_initialize(self, request: InitializeRequest) -> InitializeResult:
        """Handle MCP initialize request."""
        return InitializeResult(
            protocolVersion="2024-11-05",
            capabilities={
                "tools": {},
                "resources": {},
                "prompts": {},
            },
            serverInfo={
                "name": "Lade",
                "version": "1.0.0",
            },
        )

    async def handle_list_tools(self) -> ListToolsResult:
        """List available tools from the Lade MCP server."""
        # Get tools from the Lade MCP server
        tools_result = await self.mcp_server.list_tools()
        tools = []
        for tool in tools_result:
            tools.append({
                "name": tool.name,
                "description": tool.description or f"Lade tool: {tool.name}",
                "inputSchema": tool.input_schema,
            })

        return ListToolsResult(tools=tools)

    async def handle_call_tool(self, request: CallToolRequest) -> CallToolResult:
        """Execute a tool call on the Lade MCP server."""
        tool_name = request.params.name
        arguments = request.params.arguments or {}

        try:
            # Execute the tool via the MCP server
            result = await self.mcp_server.call_tool(tool_name, arguments)
            # Convert result to CallToolResult format
            content = []
            if isinstance(result, list):
                for item in result:
                    if hasattr(item, 'text'):
                        content.append({"type": "text", "text": item.text})
                    else:
                        content.append({"type": "text", "text": str(item)})
            elif hasattr(result, 'text'):
                content.append({"type": "text", "text": result.text})
            else:
                content.append({"type": "text", "text": str(result)})
            
            return CallToolResult(
                content=content,
                isError=False,
            )
        except Exception as e:
            return CallToolResult(
                content=[{"type": "text", "text": f"Tool error: {str(e)}"}],
                isError=True,
            )

    async def handle_request(self, request: JSONRPCRequest) -> JSONRPCResponse | None:
        """Route incoming JSON-RPC request to appropriate handler."""
        try:
            if request.method == "initialize":
                result = await self.handle_initialize(request.params)
                return JSONRPCResponse(jsonrpc="2.0", id=request.id, result=result.model_dump())
            elif request.method == "tools/list":
                result = await self.handle_list_tools()
                return JSONRPCResponse(jsonrpc="2.0", id=request.id, result=result.model_dump())
            elif request.method == "tools/call":
                result = await self.handle_call_tool(request.params)
                return JSONResponse(result.model_dump())
            else:
                return JSONRPCResponse(
                    jsonrpc="2.0",
                    id=request.id,
                    result={"error": {"code": -32601, "message": f"Method not found: {request.method}"}},
                )
        except Exception as e:
            return JSONRPCResponse(
                jsonrpc="2.0",
                id=request.id,
                result={"error": {"code": -32603, "message": f"Internal error: {str(e)}"}},
            )


# Global transport instance
_transport: MCPHTTPTransport | None = None


def get_transport() -> MCPHTTPTransport:
    global _transport
    if _transport is None:
        _transport = MCPHTTPTransport(lade_mcp)
    return _transport


def create_mcp_http_app() -> "Starlette":
    """Create a Starlette app with MCP HTTP/SSE endpoints."""
    if not STARLETTE_AVAILABLE:
        raise RuntimeError("Starlette not available. Install starlette and uvicorn.")

    transport = get_transport()

    async def sse_endpoint(request: Request):
        """SSE endpoint for MCP communication."""
        session_id = request.query_params.get("session_id", str(uuid.uuid4()))

        async def event_generator() -> AsyncIterator[str]:
            # Send initial connection event
            yield f"data: {json.dumps({'type': 'connected', 'session_id': session_id})}\n\n"

            # Keep connection alive
            try:
                while True:
                    await asyncio.sleep(30)
                    yield f": keepalive\n\n"
            except asyncio.CancelledError:
                pass

        return StreamingResponse(
            event_generator(),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
                "X-Session-ID": session_id,
            }
        )

    async def messages_endpoint(request: Request):
        """Handle MCP JSON-RPC messages via HTTP POST."""
        try:
            body = await request.json()
            request_obj = JSONRPCRequest(**body)
            transport = get_transport()
            response = await transport.handle_request(request_obj)
            if response is None:
                return JSONResponse({"error": "No response"}, status_code=204)
            return JSONResponse(response.model_dump(exclude_none=True))
        except Exception as e:
            return JSONResponse({"error": str(e)}, status_code=500)

    async def health(request: Request):
        return JSONResponse({"status": "ok", "service": "lade-mcp-http"})

    async def tools_list(request: Request):
        transport = get_transport()
        result = await transport.handle_list_tools()
        return JSONResponse(result.model_dump())

    # Initialize server config
    @asynccontextmanager
    async def lifespan(app: Starlette):
        # Initialize server config
        db_dir = os.getenv("LADE_DB_DIR", "/tmp/lade")
        init_server(Path(db_dir))
        yield

    app = Starlette(
        routes=[
            Route("/health", health, methods=["GET"]),
            Route("/mcp/sse", sse_endpoint, methods=["GET"]),
            Route("/mcp/messages", messages_endpoint, methods=["POST"]),
            Route("/mcp/tools", tools_list, methods=["GET"]),
        ],
        lifespan=lifespan,
        middleware=[
            Middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"]),
        ],
    )

    return app


def run_mcp_http_server(host: str = "0.0.0.0", port: int = 8081):
    """Run the MCP HTTP server."""
    if not STARLETTE_AVAILABLE:
        raise RuntimeError("Starlette and uvicorn required. Install with: pip install starlette uvicorn")

    import uvicorn

    app = create_mcp_http_app()
    uvicorn.run(app, host=host, port=port, log_level="info")


if __name__ == "__main__":
    run_mcp_http_server()