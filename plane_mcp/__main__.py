"""Main entry point for the Plane MCP Server."""

import json
import logging
import os
import sys
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from enum import Enum

import uvicorn
from fastmcp.server.dependencies import get_access_token
from starlette.applications import Starlette
from starlette.middleware.cors import CORSMiddleware
from starlette.routing import Mount

from plane_mcp.server import (
    get_authentik_oauth_mcp,
    get_header_mcp,
    get_oauth_mcp,
    get_stdio_mcp,
)


def _authentik_configured() -> bool:
    """True when Authentik OIDC is configured (CONTRACT §F priority 1)."""
    has_config_url = bool(os.getenv("AUTHENTIK_CONFIG_URL")) or bool(
        os.getenv("AUTHENTIK_BASE_URL") and os.getenv("AUTHENTIK_APP_SLUG")
    )
    return bool(os.getenv("AUTHENTIK_CLIENT_ID")) and has_config_url


def _plane_cloud_oauth_configured() -> bool:
    """True when legacy Plane-Cloud OAuth is configured (CONTRACT §F priority 2)."""
    return bool(os.getenv("PLANE_OAUTH_PROVIDER_CLIENT_ID")) and bool(os.getenv("PLANE_OAUTH_PROVIDER_CLIENT_SECRET"))


class UserContextFilter(logging.Filter):
    """Attach the authenticated user's id to every log record.

    Pulls the current request's access token via FastMCP's dependency, which
    returns None (never raises) outside a request context — so startup logs and
    stdio mode simply carry no user info. Only the opaque user id is recorded;
    PII such as the display name / email is intentionally never logged.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        user_id = None
        try:
            token = get_access_token()
            if token:
                user_id = token.claims.get("sub")
        except Exception as exc:
            # Never let logging enrichment break a request, but leave a signal.
            record.user_context_enrichment_error = type(exc).__name__
        record.user_id = user_id
        return True


class JSONFormatter(logging.Formatter):
    """JSON log formatter for structured logging (Datadog, ELK, etc.)."""

    def format(self, record: logging.LogRecord) -> str:
        log_entry = {
            "timestamp": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        user_id = getattr(record, "user_id", None)
        if user_id:
            log_entry["user_id"] = user_id
        err = getattr(record, "user_context_enrichment_error", None)
        if err:
            log_entry["user_context_enrichment_error"] = err
        if record.exc_info and record.exc_info[1]:
            log_entry["error"] = {
                "type": type(record.exc_info[1]).__name__,
                "message": str(record.exc_info[1]),
            }
        return json.dumps(log_entry)


def configure_json_logging():
    """Replace FastMCP's Rich handlers with a JSON formatter on the fastmcp logger."""
    fastmcp_logger = logging.getLogger("fastmcp")

    # Remove all existing handlers (Rich)
    for handler in fastmcp_logger.handlers[:]:
        fastmcp_logger.removeHandler(handler)

    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(JSONFormatter())
    handler.addFilter(UserContextFilter())
    fastmcp_logger.addHandler(handler)
    fastmcp_logger.setLevel(logging.INFO)
    fastmcp_logger.propagate = False


configure_json_logging()

logger = logging.getLogger("fastmcp.plane_mcp")


class ServerMode(Enum):
    STDIO = "stdio"
    SSE = "sse"
    HTTP = "http"


@asynccontextmanager
async def combined_lifespan(*apps):
    """Combine the lifespans of an arbitrary set of mounted MCP apps."""
    from contextlib import AsyncExitStack

    async with AsyncExitStack() as stack:
        for app in apps:
            await stack.enter_async_context(app.lifespan(app))
        yield


def main() -> None:
    """Run the MCP server."""
    server_mode = ServerMode.STDIO
    if len(sys.argv) > 1:
        server_mode = ServerMode(sys.argv[1])

    if server_mode == ServerMode.STDIO:
        # Validate API_KEY and PLANE_WORKSPACE_SLUG are set
        if not os.getenv("PLANE_API_KEY"):
            raise ValueError("PLANE_API_KEY is not set")
        if not os.getenv("PLANE_WORKSPACE_SLUG"):
            raise ValueError("PLANE_WORKSPACE_SLUG is not set")

        get_stdio_mcp().run()
        return

    if server_mode == ServerMode.HTTP:
        prefix = os.getenv("MCP_PATH_PREFIX") or ""

        # Header/PAT MCP is always available (unchanged across all provider modes).
        header_app = get_header_mcp().http_app(stateless_http=True)

        routes = []
        lifespan_apps = []
        provider_mounted = False

        # Provider selection (CONTRACT §F). Boot must never crash without a
        # reachable upstream IdP or Plane-Cloud creds — fall through on failure.
        if _authentik_configured():
            # 1. Authentik OIDC — the Claude.ai *web* connector endpoint.
            #
            # OIDCProxy fetches the Authentik discovery document synchronously at
            # construction, so a transient Authentik/DNS outage would otherwise
            # take down the ENTIRE HTTP server (including the unrelated
            # /http/api-key endpoint). Guard it: on failure, log loudly and fall
            # through to the next provider so the server still boots.
            try:
                authentik_mcp = get_authentik_oauth_mcp(prefix + "/http")
                authentik_app = authentik_mcp.http_app(stateless_http=True)
                authentik_well_known = authentik_mcp.auth.get_well_known_routes(mcp_path="/mcp")

                # -----------------------------------------------------------
                # PROVISION ROUTES (self-service PAT linking — provision agent).
                #
                # plane_mcp.provisioning exposes the self-service link/unlink
                # page (GET/POST {prefix}/http/provision[...], per CONTRACT §F)
                # via a `provision_routes(prefix) -> list[Route]` factory (the
                # routes depend on the runtime MCP_PATH_PREFIX). The PAT +
                # workspace mappings are shared with client.py's credential
                # resolver via the `plane_mcp.pat_store.get_pat_store()`
                # process-wide singleton.
                #
                # Guarded so a provisioning-layer misconfig can't take down the
                # whole HTTP server: the MCP + api-key endpoints still mount,
                # and the warning makes the missing self-service page diagnosable.
                from plane_mcp.provisioning import provision_routes as build_provision_routes

                try:
                    provision_route_list = build_provision_routes(prefix)
                except Exception as exc:  # noqa: BLE001 - never let provisioning crash boot
                    provision_route_list = []
                    logger.warning("Provision routes not mounted (provisioning init failed): %s", exc)
                # -----------------------------------------------------------

                routes += [
                    *authentik_well_known,
                    *provision_route_list,
                    Mount(prefix + "/http/api-key", app=header_app),
                    Mount(prefix + "/http", app=authentik_app),
                ]
                lifespan_apps += [authentik_app, header_app]
                provider_mounted = True

                # First-run provisioning links sent to Claude.ai must be absolute
                # to be clickable (CONTRACT §A requires MCP_PUBLIC_BASE_URL).
                if not (os.getenv("MCP_PUBLIC_BASE_URL") or os.getenv("PLANE_OAUTH_PROVIDER_BASE_URL")):
                    logger.warning(
                        "MCP_PUBLIC_BASE_URL is not set — the first-run provisioning link sent to "
                        "Claude.ai will be relative and non-clickable. Set it to the public HTTPS base URL."
                    )
                logger.info("HTTP provider: Authentik OIDC (web connector at %s/http/mcp)", prefix)
            except Exception as exc:  # noqa: BLE001 - IdP discovery unreachable, misconfig, etc.
                logger.critical(
                    "Authentik OIDC provider failed to initialize (%s): %s. Falling back so the server "
                    "still boots; the Claude.ai web connector will be unavailable until the server is "
                    "restarted with a reachable Authentik.",
                    type(exc).__name__,
                    exc,
                )

        if not provider_mounted and _plane_cloud_oauth_configured():
            # 2. Legacy Plane-Cloud OAuth — current behavior (OAuth + SSE).
            oauth_mcp = get_oauth_mcp(prefix + "/http")
            oauth_app = oauth_mcp.http_app(stateless_http=True)

            sse_mcp = get_oauth_mcp(prefix)
            sse_app = sse_mcp.http_app(transport="sse")

            # mcp_path is appended to the auth provider's base_url to form the
            # advertised resource URL. base_url already carries the prefix, so these
            # stay at /mcp and /sse to avoid double-prefixing.
            oauth_well_known = oauth_mcp.auth.get_well_known_routes(mcp_path="/mcp")
            sse_well_known = sse_mcp.auth.get_well_known_routes(mcp_path="/sse")
            lifespan_apps += [oauth_app, header_app, sse_app]

            routes += [
                *oauth_well_known,
                *sse_well_known,
                Mount(prefix + "/http/api-key", app=header_app),
                Mount(prefix + "/http", app=oauth_app),
                Mount(prefix or "/", app=sse_app),
            ]
            provider_mounted = True
            logger.info("HTTP provider: legacy Plane-Cloud OAuth")

        if not provider_mounted:
            # 3. Header auth only — no usable OAuth provider (none configured, or
            # the Authentik provider failed to initialize). No crash.
            lifespan_apps += [header_app]
            routes += [
                Mount(prefix + "/http/api-key", app=header_app),
            ]
            logger.warning(
                "HTTP provider: header/PAT auth only — no usable OAuth provider "
                "(neither Authentik OIDC nor Plane-Cloud OAuth is configured/reachable). "
                "Only %s/http/api-key/mcp is available.",
                prefix,
            )

        app = Starlette(
            routes=routes,
            lifespan=lambda app: combined_lifespan(*lifespan_apps),
        )

        app.add_middleware(
            CORSMiddleware,
            allow_origins=["*"],
            allow_credentials=False,
            allow_methods=["*"],
            allow_headers=["*"],
        )

        # Configure uvicorn loggers to use JSON formatting too
        for uv_logger_name in ("uvicorn", "uvicorn.error"):
            uv_logger = logging.getLogger(uv_logger_name)
            for h in uv_logger.handlers[:]:
                uv_logger.removeHandler(h)
            uv_handler = logging.StreamHandler(sys.stderr)
            uv_handler.setFormatter(JSONFormatter())
            uv_handler.addFilter(UserContextFilter())
            uv_logger.addHandler(uv_handler)

        logger.info("Starting HTTP server at URLs: /mcp and /header/mcp")
        uvicorn.run(
            app,
            host="0.0.0.0",
            port=8211,
            log_level="info",
            access_log=False,
        )
        return


if __name__ == "__main__":
    main()
