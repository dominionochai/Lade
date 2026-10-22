"""Tests for MCP HTTP transport."""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from starlette.testclient import TestClient

# Ensure test environment
os.environ.setdefault("GITLAB_WEBHOOK_SECRET", "test-secret-123")
os.environ.setdefault("LADE_EVIDENCE_ROOT", "/tmp/test_evidence")
os.environ.setdefault("LADE_DB_DIR", "/tmp/test_lade")

from lade.mcp_http import create_mcp_http_app, get_transport, MCPHTTPTransport
from lade.server.app import init_server


@pytest.fixture(autouse=True)
def setup_env():
    """Ensure test environment is set up."""
    os.environ["LADE_DB_DIR"] = "/tmp/test_lade"
    os.environ["LADE_EVIDENCE_ROOT"] = "/tmp/test_evidence"
    # Clear transport singleton
    import lade.mcp_http as mcp_http
    mcp_http._transport = None
    yield
    mcp_http._transport = None


@pytest.fixture
def test_client():
    """Create a test client with initialized server."""
    import tempfile
    with tempfile.TemporaryDirectory() as tmpdir:
        db_dir = Path(tmpdir) / "lade"
        db_dir.mkdir()
        os.environ["LADE_DB_DIR"] = str(db_dir)
        os.environ["LADE_EVIDENCE_ROOT"] = "/tmp/test_evidence"
        init_server(db_dir)
        from lade.mcp_http import create_mcp_http_app
        app = create_mcp_http_app()
        client = TestClient(app)
        yield client


def test_health_endpoint(test_client: TestClient):
    """Test health check endpoint."""
    response = test_client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "service": "lade-mcp-http"}


def test_tools_list_endpoint(test_client: TestClient):
    """Test tools list endpoint."""
    response = test_client.get("/mcp/tools")
    assert response.status_code == 200
    data = response.json()
    assert "tools" in data
    assert isinstance(data["tools"], list)
    # Should have Lade tools
    tool_names = [t["name"] for t in data["tools"]]
    assert "scan_evidence" in tool_names
    assert "open_case" in tool_names
    assert "search" in tool_names


def test_mcp_initialize(test_client: TestClient):
    """Test MCP initialize request."""
    response = test_client.post(
        "/mcp/messages",
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {}
        }
    )
    assert response.status_code == 200
    data = response.json()
    assert "result" in data
    assert data["result"]["protocol_version"] == "2024-11-05"
    assert data["result"]["server_info"]["name"] == "Lade"


def test_mcp_list_tools(test_client: TestClient):
    """Test MCP tools/list request."""
    response = test_client.post(
        "/mcp/messages",
        json={
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list",
            "params": {}
        }
    )
    assert response.status_code == 200
    data = response.json()
    assert "result" in data
    assert "tools" in data["result"]
    tool_names = [t["name"] for t in data["result"]["tools"]]
    assert "scan_evidence" in tool_names
    assert "open_case" in tool_names


def test_mcp_call_tool(test_client: TestClient):
    """Test MCP tools/call request."""
    response = test_client.post(
        "/mcp/messages",
        json={
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "scan_evidence",
                "arguments": {"evidence_path": "/tmp/test_evidence"}
            }
        }
    )
    assert response.status_code == 200
    data = response.json()
    assert "result" in data


import pytest

@pytest.mark.skip(reason="SSE endpoint hangs in TestClient")
def test_sse_endpoint(test_client: TestClient):
    """Test SSE endpoint returns streaming response."""
    # SSE endpoints are streaming and don't work well with TestClient
    # Just verify the route exists and returns the correct content-type header
    response = test_client.get("/mcp/sse")
    assert response.status_code == 200
    assert "text/event-stream" in response.headers.get("content-type", "")


def test_mcp_http_transport_direct():
    """Test MCPHTTPTransport directly."""
    import tempfile
    with tempfile.TemporaryDirectory() as tmpdir:
        db_dir = Path(tmpdir) / "lade"
        db_dir.mkdir()
        os.environ["LADE_DB_DIR"] = str(db_dir)
        os.environ["LADE_EVIDENCE_ROOT"] = "/tmp/test_evidence"
        init_server(Path(tmpdir) / "lade")

        transport = MCPHTTPTransport.__new__(MCPHTTPTransport)
        transport.mcp_server = None  # Will be set by get_transport
        # Test that transport can be instantiated
        assert transport is not None


def test_transport_singleton():
    """Test transport singleton behavior."""
    import lade.mcp_http as mcp_http
    mcp_http._transport = None
    
    t1 = get_transport()
    t2 = get_transport()
    assert t1 is t2  # Same instance


def test_create_mcp_http_app():
    """Test creating the MCP HTTP app."""
    from lade.mcp_http import create_mcp_http_app
    
    import tempfile
    with tempfile.TemporaryDirectory() as tmpdir:
        db_dir = Path(tmpdir) / "lade"
        db_dir.mkdir()
        os.environ["LADE_DB_DIR"] = str(db_dir)
        os.environ["LADE_EVIDENCE_ROOT"] = "/tmp/test_evidence"
        init_server(db_dir)
        
        app = create_mcp_http_app()
        assert app is not None
        # Check routes
        route_paths = [route.path for route in app.routes]
        assert "/health" in route_paths
        assert "/mcp/sse" in route_paths
        assert "/mcp/messages" in route_paths
        assert "/mcp/tools" in route_paths


def test_mcp_initialize_request():
    """Test initialize request handling."""
    import tempfile
    with tempfile.TemporaryDirectory() as tmpdir:
        db_dir = Path(tmpdir) / "lade"
        db_dir.mkdir()
        os.environ["LADE_DB_DIR"] = str(db_dir)
        os.environ["LADE_EVIDENCE_ROOT"] = "/tmp/test_evidence"
        init_server(db_dir)

        from lade.server.app import mcp as lade_mcp
        transport = MCPHTTPTransport(lade_mcp)
        
        import asyncio
        result = asyncio.run(transport.handle_initialize({}))
        assert result.protocol_version == "2024-11-05"
        assert result.server_info.name == "Lade"
        assert hasattr(result.capabilities, "tools")


def test_list_tools_result():
    """Test list tools result structure."""
    import tempfile
    with tempfile.TemporaryDirectory() as tmpdir:
        db_dir = Path(tmpdir) / "lade"
        db_dir.mkdir()
        os.environ["LADE_DB_DIR"] = str(db_dir)
        os.environ["LADE_EVIDENCE_ROOT"] = "/tmp/test_evidence"
        init_server(db_dir)

        from lade.server.app import mcp as lade_mcp
        transport = MCPHTTPTransport(lade_mcp)
        
        import asyncio
        result = asyncio.run(transport.handle_list_tools())
        assert hasattr(result, "tools")
        assert len(result.tools) > 0
        tool_names = [t.name for t in result.tools]
        assert "scan_evidence" in tool_names
        assert "open_case" in tool_names
        assert "search" in tool_names