"""FastMCP server factories for the three supported transports."""

from __future__ import annotations

import os

from fastmcp import FastMCP
from fastmcp.server.middleware.logging import StructuredLoggingMiddleware
from mcp.types import Icon

from plane_mcp.auth import (
    AuthentikOIDCProvider,
    PlaneHeaderAuthProvider,
    PlaneOAuthProvider,
    resolve_config_url,
)
from plane_mcp.instructions import SERVER_INSTRUCTIONS
from plane_mcp.storage import build_token_store
from plane_mcp.tools import register_tools


def _public_base_url() -> str:
    """Public HTTPS base URL of this server (no trailing slash), per CONTRACT §A.

    Prefers ``MCP_PUBLIC_BASE_URL``, falling back to ``PLANE_OAUTH_PROVIDER_BASE_URL``.
    """
    return (os.getenv("MCP_PUBLIC_BASE_URL") or os.getenv("PLANE_OAUTH_PROVIDER_BASE_URL") or "").rstrip("/")


def get_oauth_mcp(base_path: str = "/") -> FastMCP:
    """Build the FastMCP instance for the OAuth HTTP / SSE transports."""
    oauth_mcp = FastMCP(
        "Plane MCP Server",
        instructions=SERVER_INSTRUCTIONS,
        icons=[Icon(src="https://plane.so/favicon.ico", alt="Plane MCP Server")],
        website_url="https://plane.so",
        auth=PlaneOAuthProvider(
            client_id=os.getenv("PLANE_OAUTH_PROVIDER_CLIENT_ID", ""),
            client_secret=os.getenv("PLANE_OAUTH_PROVIDER_CLIENT_SECRET", ""),
            base_url=f"{os.getenv('PLANE_OAUTH_PROVIDER_BASE_URL')}{base_path}",
            plane_base_url=os.getenv("PLANE_BASE_URL", ""),
            plane_internal_base_url=os.getenv("PLANE_INTERNAL_BASE_URL", ""),
            enable_cimd=os.getenv("PLANE_OAUTH_PROVIDER_ENABLE_CIMD", "false").lower() == "true",
            client_storage=build_token_store(),
            required_scopes=["read", "write"],
            allowed_client_redirect_uris=[
                # Localhost only for http (dynamic ports from MCP clients)
                "http://localhost:*",
                "http://localhost:*/*",
                "http://127.0.0.1:*",
                "http://127.0.0.1:*/*",
                # Known MCP client custom protocol schemes
                "cursor://*",
                "vscode://*",
                "vscode-insiders://*",
                "windsurf://*",
                "claude://*",
                # Claude.ai web client
                "https://claude.ai/*",
            ],
        ),
    )
    oauth_mcp.add_middleware(StructuredLoggingMiddleware(include_payloads=True))
    register_tools(oauth_mcp)
    return oauth_mcp


def get_authentik_oauth_mcp(base_path: str = "/") -> FastMCP:
    """Build the FastMCP instance protected by the Authentik OIDC provider.

    Mirrors ``get_oauth_mcp`` but uses :class:`AuthentikOIDCProvider`. This is the
    Claude.ai *web* connector endpoint. ``base_path`` is the mount path (carrying the
    optional ``MCP_PATH_PREFIX``), e.g. ``/http``. ``issuer_url`` is pinned to the
    root public URL so OIDC discovery does not 404 under the mount path.
    """
    public_base = _public_base_url()
    jwt_signing_key = os.getenv("MCP_JWT_SIGNING_KEY") or None

    authentik_mcp = FastMCP(
        "Plane MCP Server",
        instructions=SERVER_INSTRUCTIONS,
        icons=[Icon(src="https://plane.so/favicon.ico", alt="Plane MCP Server")],
        website_url="https://plane.so",
        auth=AuthentikOIDCProvider(
            config_url=resolve_config_url(),
            client_id=os.getenv("AUTHENTIK_CLIENT_ID", ""),
            client_secret=os.getenv("AUTHENTIK_CLIENT_SECRET", ""),
            audience=os.getenv("AUTHENTIK_AUDIENCE") or None,
            base_url=f"{public_base}{base_path}",
            issuer_url=public_base,
            required_scopes=["openid", "email", "profile"],
            client_storage=build_token_store(),
            jwt_signing_key=jwt_signing_key,
            require_authorization_consent=True,
            enable_cimd=False,
        ),
    )
    authentik_mcp.add_middleware(StructuredLoggingMiddleware(include_payloads=True))
    register_tools(authentik_mcp)
    return authentik_mcp


def get_header_mcp():
    header_mcp = FastMCP(
        "Plane MCP Server (header-http)",
        instructions=SERVER_INSTRUCTIONS,
        auth=PlaneHeaderAuthProvider(
            required_scopes=["read", "write"],
        ),
    )
    header_mcp.add_middleware(StructuredLoggingMiddleware(include_payloads=True))
    register_tools(header_mcp)
    return header_mcp


def get_stdio_mcp():
    stdio_mcp = FastMCP(
        "Plane MCP Server (stdio)",
        instructions=SERVER_INSTRUCTIONS,
    )
    stdio_mcp.add_middleware(StructuredLoggingMiddleware(include_payloads=True))
    register_tools(stdio_mcp)
    return stdio_mcp
