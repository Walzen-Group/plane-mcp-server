"""Self-service provisioning page for the Authentik-OIDC connector (CONTRACT §F/§G).

A Claude.ai *web* user authenticates the MCP connector via Authentik, but the IdP
token is **not** a Plane credential. This module hosts the small standalone web page
where that user links their Plane Personal Access Token (PAT) — establishing the
``sub`` -> PAT mapping that ``client.py`` resolves per request.

Flow:
1. ``GET  {prefix}/http/provision``           — no session -> 302 to Authentik; session -> link/unlink page.
2. ``GET  {prefix}/http/provision/callback``  — Authentik auth-code callback; verify id_token; set session cookie.
3. ``POST {prefix}/http/provision``           — save the pasted PAT (+ chosen workspace). CSRF-protected.
4. ``POST {prefix}/http/provision/disconnect``— delete the user's mapping. CSRF-protected.

Security (CONTRACT §H):
- The page is unreachable without a valid signed session; every POST is CSRF-checked.
- id_token is fully JWKS-verified (signature + ``iss`` + ``aud == client_id`` + ``exp``)
  plus a per-login ``nonce`` bound through a short-lived signed cookie.
- Session + flow cookies are Fernet-encrypted (reusing the PAT-store key derivation),
  ``HttpOnly``, ``Secure``, ``SameSite=Lax``, short TTL.
- **Auto-mint is NOT feasible — PASTE-ONLY** (CONTRACT §G). The submitted PAT is
  validated against ``{PLANE_INTERNAL_BASE_URL}/api/v1/users/me/`` before storing.
- PAT values and the session payload are never logged.
"""

from __future__ import annotations

import json
import os
import secrets
import time
from functools import lru_cache
from html import escape
from urllib.parse import urlencode

import httpx
from cryptography.fernet import Fernet, InvalidToken
from fastmcp.server.auth.oidc_proxy import OIDCConfiguration
from fastmcp.server.auth.providers.jwt import JWTVerifier
from fastmcp.utilities.logging import get_logger
from starlette.requests import Request
from starlette.responses import HTMLResponse, PlainTextResponse, RedirectResponse, Response
from starlette.routing import Route

from plane_mcp.auth import resolve_config_url
from plane_mcp.pat_store import derive_fernet_key, get_pat_store

logger = get_logger(__name__)

# Cookie names.
_SESSION_COOKIE = "mcp_provision_session"
_FLOW_COOKIE = "mcp_provision_flow"  # short-lived state/nonce/csrf carrier

# TTLs (seconds).
_SESSION_TTL = 30 * 60  # <= 30 min per CONTRACT §G
_FLOW_TTL = 10 * 60  # auth-code round-trip window

_OIDC_DISCOVERY_TIMEOUT = 10
_HTTP_TIMEOUT = 10


# --------------------------------------------------------------------------- #
# Configuration helpers
# --------------------------------------------------------------------------- #
def _public_base_url() -> str:
    """Public HTTPS base URL of this server (no trailing slash); mirrors server.py."""
    return (os.getenv("MCP_PUBLIC_BASE_URL") or os.getenv("PLANE_OAUTH_PROVIDER_BASE_URL") or "").rstrip("/")


def _plane_web_url() -> str:
    """Plane web-app base for deep-linking the PAT-create page (CONTRACT §A).

    Prefers ``PLANE_WEB_URL``; otherwise derives it from ``PLANE_BASE_URL`` by
    stripping a trailing ``/api``.
    """
    web = os.getenv("PLANE_WEB_URL")
    if web:
        return web.rstrip("/")
    base = (os.getenv("PLANE_BASE_URL") or "https://api.plane.so").rstrip("/")
    if base.endswith("/api"):
        base = base[: -len("/api")]
    return base


def _plane_internal_base_url() -> str:
    """Base URL used for server-to-server PAT validation; mirrors client.py."""
    return (os.getenv("PLANE_INTERNAL_BASE_URL") or os.getenv("PLANE_BASE_URL", "https://api.plane.so")).rstrip("/")


@lru_cache(maxsize=1)
def _fernet() -> Fernet:
    """Fernet for the provision cookies.

    Reuses the PAT-store key-derivation so deployments configure a single secret
    (``MCP_PAT_ENCRYPTION_KEY``, fallback ``AUTHENTIK_CLIENT_SECRET``).
    """
    secret = os.getenv("MCP_PAT_ENCRYPTION_KEY") or os.getenv("AUTHENTIK_CLIENT_SECRET")
    if not secret:
        raise RuntimeError(
            "Provisioning requires a cookie-signing secret: set MCP_PAT_ENCRYPTION_KEY "
            "(or AUTHENTIK_CLIENT_SECRET as a fallback)."
        )
    return Fernet(derive_fernet_key(secret))


@lru_cache(maxsize=1)
def _oidc_config() -> OIDCConfiguration:
    """Fetch (once) and cache the Authentik OIDC discovery document.

    ``get_oidc_configuration`` is a synchronous ``@classmethod`` requiring explicit
    ``strict`` and ``timeout_seconds`` (the loose 1-arg form fails) — CONTRACT §G.
    """
    return OIDCConfiguration.get_oidc_configuration(
        resolve_config_url(),
        strict=None,
        timeout_seconds=_OIDC_DISCOVERY_TIMEOUT,
    )


@lru_cache(maxsize=1)
def _id_token_verifier() -> JWTVerifier:
    """JWTVerifier for the session-login id_token (sig + iss + aud == client_id + exp).

    No ``required_scopes`` — id_tokens do not carry an OAuth ``scope`` claim, and the
    base verifier rejects tokens missing required scopes.
    """
    cfg = _oidc_config()
    client_id = os.getenv("AUTHENTIK_CLIENT_ID", "")
    return JWTVerifier(
        jwks_uri=str(cfg.jwks_uri),
        issuer=str(cfg.issuer),
        audience=client_id,
    )


# --------------------------------------------------------------------------- #
# Cookie codec (Fernet-encrypted JSON with an embedded issue time)
# --------------------------------------------------------------------------- #
def _encode_cookie(payload: dict) -> str:
    data = {**payload, "iat": int(time.time())}
    return _fernet().encrypt(json.dumps(data).encode("utf-8")).decode("utf-8")


def _decode_cookie(value: str | None, *, ttl: int) -> dict | None:
    if not value:
        return None
    try:
        raw = _fernet().decrypt(value.encode("utf-8"))
    except (InvalidToken, ValueError):
        return None
    try:
        data = json.loads(raw.decode("utf-8"))
    except (ValueError, TypeError):
        return None
    iat = data.get("iat")
    if not isinstance(iat, int) or (time.time() - iat) > ttl:
        return None
    return data


def _set_cookie(resp: Response, name: str, value: str, *, max_age: int) -> None:
    resp.set_cookie(
        name,
        value,
        max_age=max_age,
        httponly=True,
        secure=True,
        samesite="lax",
        path="/",
    )


def _clear_cookie(resp: Response, name: str) -> None:
    resp.delete_cookie(name, path="/")


def _current_session(request: Request) -> dict | None:
    """Return the validated session payload ``{sub, email, csrf, iat}`` or None."""
    return _decode_cookie(request.cookies.get(_SESSION_COOKIE), ttl=_SESSION_TTL)


# --------------------------------------------------------------------------- #
# URL helpers
# --------------------------------------------------------------------------- #
def _provision_path(prefix: str) -> str:
    return f"{prefix}/http/provision"


def _callback_url(prefix: str) -> str:
    return f"{_public_base_url()}{prefix}/http/provision/callback"


# --------------------------------------------------------------------------- #
# HTML rendering (minimal, self-contained, CSP-friendly: no external assets)
# --------------------------------------------------------------------------- #
_STYLE = (
    "body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;"
    "max-width:34rem;margin:3rem auto;padding:0 1.25rem;color:#1a1a1a;line-height:1.55}"
    "h1{font-size:1.4rem}h2{font-size:1.1rem;margin-top:1.75rem}"
    "input[type=text]{width:100%;box-sizing:border-box;padding:.6rem;font-size:1rem;"
    "border:1px solid #ccc;border-radius:6px;margin:.3rem 0 1rem}"
    "button{background:#3f76ff;color:#fff;border:0;border-radius:6px;padding:.6rem 1.1rem;"
    "font-size:1rem;cursor:pointer}button.secondary{background:#eee;color:#1a1a1a}"
    "a{color:#3f76ff}.muted{color:#666;font-size:.9rem}"
    "code{background:#f3f3f3;padding:.1rem .35rem;border-radius:4px;font-size:.9em}"
    ".ok{color:#0a7d33}.card{border:1px solid #e3e3e3;border-radius:10px;padding:1.25rem 1.5rem}"
)


def _page(title: str, body: str, *, status: int = 200) -> HTMLResponse:
    html = (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<meta name='robots' content='noindex'>"
        f"<title>{escape(title)}</title><style>{_STYLE}</style></head><body>{body}</body></html>"
    )
    return HTMLResponse(html, status_code=status)


def _render_linked(email: str, workspace: str, action: str, csrf: str) -> HTMLResponse:
    body = (
        "<h1>Plane connector</h1>"
        "<div class='card'>"
        f"<p class='ok'><strong>&#10003; Connected</strong> as <code>{escape(email)}</code></p>"
        f"<p>Workspace: <code>{escape(workspace) if workspace else '(none — set a default below)'}</code></p>"
        "<p class='muted'>You're all set. You can now use the Plane connector in Claude.ai.</p>"
        f"<form method='post' action='{escape(action)}/disconnect' "
        "onsubmit=\"return confirm('Disconnect your Plane account from this connector?')\">"
        f"<input type='hidden' name='csrf' value='{escape(csrf)}'>"
        "<button class='secondary' type='submit'>Disconnect</button>"
        "</form>"
        "</div>"
        "<h2>Update link</h2>" + _link_form(action, csrf, workspace)
    )
    return _page("Plane connector — connected", body)


def _link_form(action: str, csrf: str, workspace_default: str, *, error: str | None = None) -> str:
    pat_url = f"{_plane_web_url()}/settings/profile/api-tokens/"
    err_html = f"<p style='color:#c0392b'>{escape(error)}</p>" if error else ""
    return (
        "<div class='card'>"
        f"{err_html}"
        "<p>Link your Plane account so the connector can act as <em>you</em>.</p>"
        "<ol>"
        f"<li>Create a Personal Access Token at "
        f"<a href='{escape(pat_url)}' target='_blank' rel='noopener noreferrer'>{escape(pat_url)}</a>.</li>"
        "<li>Paste it below and choose your workspace.</li>"
        "</ol>"
        f"<form method='post' action='{escape(action)}' autocomplete='off'>"
        f"<input type='hidden' name='csrf' value='{escape(csrf)}'>"
        "<label for='pat'>Personal Access Token</label>"
        "<input id='pat' name='pat' type='text' autocomplete='off' spellcheck='false' "
        "placeholder='plane_api_...' required>"
        "<label for='workspace'>Workspace slug</label>"
        f"<input id='workspace' name='workspace' type='text' spellcheck='false' "
        f"value='{escape(workspace_default)}' placeholder='my-workspace'>"
        "<button type='submit'>Link account</button>"
        "</form>"
        "</div>"
    )


def _render_unlinked(action: str, csrf: str, workspace_default: str, *, error: str | None = None) -> HTMLResponse:
    body = "<h1>Link your Plane account</h1>" + _link_form(action, csrf, workspace_default, error=error)
    status = 400 if error else 200
    return _page("Plane connector — link your account", body, status=status)


# --------------------------------------------------------------------------- #
# Route handlers
# --------------------------------------------------------------------------- #
def _make_handlers(prefix: str):
    provision_path = _provision_path(prefix)

    async def provision_get(request: Request) -> Response:
        session = _current_session(request)
        if not session:
            return _start_login(prefix)

        sub = session.get("sub", "")
        email = session.get("email", "")
        csrf = session.get("csrf", "")
        store = get_pat_store()
        default_ws = os.getenv("PLANE_WORKSPACE_SLUG", "")

        if store.get_pat(sub):
            workspace = store.get_workspace(sub) or default_ws
            return _render_linked(email, workspace, provision_path, csrf)

        return _render_unlinked(provision_path, csrf, default_ws)

    async def provision_post(request: Request) -> Response:
        session = _current_session(request)
        if not session:
            return _start_login(prefix)

        form = await request.form()
        if not _csrf_ok(session, form.get("csrf")):
            return PlainTextResponse("CSRF validation failed.", status_code=403)

        sub = session.get("sub", "")
        email = session.get("email", "")
        csrf = session.get("csrf", "")
        default_ws = os.getenv("PLANE_WORKSPACE_SLUG", "")

        pat = (form.get("pat") or "").strip()
        workspace = (form.get("workspace") or "").strip() or default_ws

        if not pat:
            return _render_unlinked(provision_path, csrf, workspace, error="Paste a Personal Access Token.")

        if not await _validate_pat(pat, workspace):
            # Never echo the PAT back into the page.
            return _render_unlinked(
                provision_path,
                csrf,
                workspace,
                error="That token was rejected by Plane. Check the token (and that it isn't expired).",
            )

        store = get_pat_store()
        store.set_pat(sub, pat)
        store.set_workspace(sub, workspace)
        logger.info("Linked Plane PAT for user %s (workspace=%s)", sub, workspace or "(default)")
        return _render_linked(email, workspace, provision_path, csrf)

    async def provision_disconnect(request: Request) -> Response:
        session = _current_session(request)
        if not session:
            return _start_login(prefix)

        form = await request.form()
        if not _csrf_ok(session, form.get("csrf")):
            return PlainTextResponse("CSRF validation failed.", status_code=403)

        sub = session.get("sub", "")
        get_pat_store().delete(sub)
        logger.info("Unlinked Plane PAT for user %s", sub)
        return RedirectResponse(provision_path, status_code=303)

    async def provision_callback(request: Request) -> Response:
        return await _handle_callback(request, prefix)

    return provision_get, provision_post, provision_disconnect, provision_callback


def _csrf_ok(session: dict, submitted: object) -> bool:
    """Double-submit CSRF check: form token must equal the session-bound token."""
    expected = session.get("csrf")
    if not expected or not isinstance(submitted, str) or not submitted:
        return False
    return secrets.compare_digest(expected, submitted)


def _start_login(prefix: str) -> Response:
    """Begin the standalone Authentik auth-code flow (CONTRACT §G)."""
    cfg = _oidc_config()
    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)

    params = {
        "client_id": os.getenv("AUTHENTIK_CLIENT_ID", ""),
        "response_type": "code",
        "redirect_uri": _callback_url(prefix),
        "scope": "openid email profile",
        "state": state,
        "nonce": nonce,
    }
    authorize_url = f"{str(cfg.authorization_endpoint)}?{urlencode(params)}"

    resp = RedirectResponse(authorize_url, status_code=302)
    _set_cookie(resp, _FLOW_COOKIE, _encode_cookie({"state": state, "nonce": nonce}), max_age=_FLOW_TTL)
    return resp


async def _handle_callback(request: Request, prefix: str) -> Response:
    provision_path = _provision_path(prefix)

    # Authentik may return an error (e.g. denied consent).
    if request.query_params.get("error"):
        return PlainTextResponse(
            f"Authentication failed: {request.query_params.get('error')}",
            status_code=400,
        )

    flow = _decode_cookie(request.cookies.get(_FLOW_COOKIE), ttl=_FLOW_TTL)
    if not flow:
        return PlainTextResponse("Login session expired or invalid. Restart from the provision page.", status_code=400)

    state = request.query_params.get("state")
    code = request.query_params.get("code")
    if not state or not code or not secrets.compare_digest(flow.get("state", ""), state):
        return PlainTextResponse("Invalid login state.", status_code=400)

    cfg = _oidc_config()
    client_id = os.getenv("AUTHENTIK_CLIENT_ID", "")
    client_secret = os.getenv("AUTHENTIK_CLIENT_SECRET", "")

    # Exchange the auth code for tokens (client_secret_basic).
    try:
        async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT) as http:
            token_resp = await http.post(
                str(cfg.token_endpoint),
                data={
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": _callback_url(prefix),
                },
                auth=(client_id, client_secret),
                headers={"Accept": "application/json"},
            )
    except httpx.RequestError as exc:
        logger.warning("Token exchange request failed: %s", exc)
        return PlainTextResponse("Token exchange failed.", status_code=502)

    if token_resp.status_code != 200:
        logger.warning("Token exchange rejected by IdP: %s", token_resp.status_code)
        return PlainTextResponse("Token exchange rejected by the identity provider.", status_code=400)

    id_token = token_resp.json().get("id_token")
    if not id_token:
        return PlainTextResponse("Identity provider did not return an id_token.", status_code=400)

    # Verify the id_token: signature + iss + aud == client_id + exp (JWKS).
    verified = await _id_token_verifier().load_access_token(id_token)
    if verified is None:
        logger.warning("id_token verification failed during provision callback")
        return PlainTextResponse("Identity token verification failed.", status_code=400)

    claims = verified.claims
    # Bind the login to our per-request nonce (replay / token-injection defense).
    if claims.get("nonce") != flow.get("nonce"):
        logger.warning("id_token nonce mismatch during provision callback")
        return PlainTextResponse("Login nonce mismatch.", status_code=400)

    sub = claims.get("sub")
    if not sub:
        return PlainTextResponse("Identity token missing subject.", status_code=400)
    email = claims.get("email") or claims.get("preferred_username") or ""

    # Establish the session. A fresh CSRF token is bound to this session.
    resp = RedirectResponse(provision_path, status_code=303)
    session_payload = {"sub": sub, "email": email, "csrf": secrets.token_urlsafe(32)}
    _set_cookie(resp, _SESSION_COOKIE, _encode_cookie(session_payload), max_age=_SESSION_TTL)
    _clear_cookie(resp, _FLOW_COOKIE)
    logger.info("Provision session established for user %s", sub)
    return resp


async def _validate_pat(pat: str, workspace: str) -> bool:
    """Validate a candidate PAT against Plane before storing (CONTRACT §G).

    Calls ``GET {PLANE_INTERNAL_BASE_URL}/api/v1/users/me/`` with the ``X-Api-Key``
    header (same check the header-auth provider performs). Never logs the PAT.
    """
    user_url = f"{_plane_internal_base_url()}/api/v1/users/me/"
    try:
        async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT) as http:
            resp = await http.get(
                user_url,
                headers={"x-api-key": pat, "Content-Type": "application/json"},
            )
    except httpx.RequestError as exc:
        logger.warning("PAT validation request failed: %s", exc)
        return False

    if resp.status_code != 200:
        logger.warning("PAT validation against Plane API failed: %s", resp.status_code)
        return False
    return True


# --------------------------------------------------------------------------- #
# Public factory consumed by __main__.py
# --------------------------------------------------------------------------- #
def provision_routes(prefix: str = "") -> list[Route]:
    """Build the provision Starlette routes for the given ``MCP_PATH_PREFIX``.

    Mounted at the top level alongside the Authentik well-known routes (CONTRACT §F):
      - ``GET  {prefix}/http/provision``
      - ``GET  {prefix}/http/provision/callback``
      - ``POST {prefix}/http/provision``
      - ``POST {prefix}/http/provision/disconnect``
    """
    provision_get, provision_post, provision_disconnect, provision_callback = _make_handlers(prefix)
    base = _provision_path(prefix)
    return [
        Route(base, provision_get, methods=["GET"]),
        Route(f"{base}/callback", provision_callback, methods=["GET"]),
        Route(base, provision_post, methods=["POST"]),
        Route(f"{base}/disconnect", provision_disconnect, methods=["POST"]),
    ]


# Alias matching auth-core's primary insertion-point name (CONTRACT §F / auth-core brief).
def build_provision_routes(prefix: str = "") -> list[Route]:
    """Alias for :func:`provision_routes` (the name auth-core's insertion point expects)."""
    return provision_routes(prefix)
