"""CLI command to run the MCP HTTP server for Duo integration."""

from __future__ import annotations

import os
from pathlib import Path

import click

from lade import __version__
from lade.patterns import DB_DIR_ENV_VAR, DEFAULT_DB_DIR


@click.command()
@click.option(
    "--host",
    default="0.0.0.0",
    show_default=True,
    help="Host to bind to.",
)
@click.option(
    "--port",
    default=8081,
    show_default=True,
    type=click.IntRange(min=1, max=65535),
    help="Port to bind to.",
)
@click.option(
    "--db-dir",
    default=DEFAULT_DB_DIR,
    envvar=DB_DIR_ENV_VAR,
    show_default=True,
    help="Directory containing per-case databases.",
)
def serve_mcp_http(
    host: str,
    port: int,
    db_dir: str,
) -> None:
    """Run the Lade MCP HTTP server for Duo Agent Platform integration.

    This exposes the Lade MCP tools over HTTP/SSE for the GitLab Duo Agent Platform
    to connect and invoke tools.

    Required environment variables for Duo integration:
      GITLAB_TOKEN         - GitLab API token (for Duo agent to call GitLab API)
      GITLAB_PROJECT_ID    - GitLab project ID or path
      MCP_AUTH_TOKEN       - Optional auth token for MCP server

    The MCP server will be available at:
      SSE endpoint:     http://host:port/mcp/sse
      Messages endpoint: http://host:port/mcp/messages
      Tools list:       http://host:port/mcp/tools
      Health check:     http://host:port/health
    """
    os.environ["LADE_DB_DIR"] = db_dir

    import uvicorn
    from lade.mcp_http import create_mcp_http_app

    app = create_mcp_http_app()

    click.echo(f"Starting Lade MCP HTTP server on {host}:{port}")
    click.echo(f"Database directory: {db_dir}")
    click.echo("Endpoints:")
    click.echo(f"  SSE:        http://{host}:8081/mcp/sse")
    click.echo(f"  Messages:   http://{host}:8081/mcp/messages")
    click.echo(f"  Tools list: http://{host}:8081/mcp/tools")
    click.echo(f"  Health:     http://{host}:8081/health")

    import uvicorn
    uvicorn.run(create_mcp_http_app, host="0.0.0.0", port=8081, log_level="info", factory=True)


if __name__ == "__main__":
    serve_mcp_http()