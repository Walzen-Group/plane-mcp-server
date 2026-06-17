"""Authentik OIDC provider for FastMCP.

This wraps FastMCP's ``OIDCProxy`` (which does Dynamic Client Registration, PKCE,
consent, ``.well-known`` discovery and JWKS-based JWT verification) to protect the
MCP server with the org's Authentik IdP. It is the endpoint a Claude.ai *web*
connector talks to.

The provider is modeled on ``fastmcp.server.auth.providers.auth0.Auth0Provider``.
The one Authentik-specific concern is encoded by ``AuthentikTokenVerifier``: it
stamps every verified identity with ``auth_method = "authentik_oidc"`` so that
``client.py::get_plane_client_context()`` knows to resolve the per-user Plane PAT
from the store instead of forwarding the (non-Plane) IdP token. The IdP token must
NEVER reach the Plane API.

We verify the **id_token** (``verify_id_token=True``) rather than the access_token:
the id_token is always a standard JWT whose ``aud == client_id``, which is robust
even when Authentik issues opaque access tokens.
"""

from __future__ import annotations

import os
from typing import Literal

from fastmcp.server.auth import TokenVerifier
from fastmcp.server.auth.auth import AccessToken
from fastmcp.server.auth.oidc_proxy import OIDCProxy
from fastmcp.server.auth.providers.jwt import JWTVerifier
from fastmcp.utilities.logging import get_logger
from key_value.aio.protocols import AsyncKeyValue
from pydantic import AnyHttpUrl

logger = get_logger(__name__)

AUTH_METHOD = "authentik_oidc"

# The default set of redirect URI patterns we accept from MCP clients performing
# loopback / custom-scheme redirects, plus the Claude.ai web connector. Mirrors the
# list configured for the legacy Plane-Cloud OAuth provider in server.py.
DEFAULT_ALLOWED_CLIENT_REDIRECT_URIS: list[str] = [
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
]


def resolve_config_url() -> str:
    """Resolve the Authentik OIDC discovery URL from the environment.

    Prefers ``AUTHENTIK_CONFIG_URL``; otherwise derives it from
    ``AUTHENTIK_BASE_URL`` + ``AUTHENTIK_APP_SLUG`` per CONTRACT §A.

    Raises:
        ValueError: if neither form is configured.
    """
    config_url = os.getenv("AUTHENTIK_CONFIG_URL")
    if config_url:
        return config_url.strip()

    base_url = os.getenv("AUTHENTIK_BASE_URL")
    app_slug = os.getenv("AUTHENTIK_APP_SLUG")
    if base_url and app_slug:
        base = base_url.rstrip("/")
        return f"{base}/application/o/{app_slug}/.well-known/openid-configuration"

    raise ValueError(
        "Authentik OIDC is not configured: set AUTHENTIK_CONFIG_URL, or both AUTHENTIK_BASE_URL and AUTHENTIK_APP_SLUG."
    )


class AuthentikTokenVerifier(JWTVerifier):
    """JWT verifier that stamps the resolved identity with ``auth_method``.

    All real verification (JWKS signature, ``iss``, ``aud == client_id``, ``exp``)
    is performed by the base :class:`JWTVerifier`. We only decorate a *successful*
    result with ``auth_method = "authentik_oidc"`` so downstream credential
    resolution knows to look up a per-user Plane PAT.

    It intentionally does **not** add the PAT to claims — the PAT never travels in
    a token.
    """

    async def load_access_token(self, token: str) -> AccessToken | None:
        result = await super().load_access_token(token)
        if result is None:
            return None
        # AccessToken is a Pydantic model — copy, do not mutate, to preserve
        # the verified sub/email/aud/exp/iss claims untouched.
        return result.model_copy(update={"claims": {**result.claims, "auth_method": AUTH_METHOD}})


class AuthentikOIDCProvider(OIDCProxy):
    """Authentik OIDC provider for FastMCP.

    A thin ``OIDCProxy`` subclass that injects an :class:`AuthentikTokenVerifier`
    so verified identities carry ``auth_method = "authentik_oidc"``.

    Example:
        ```python
        auth = AuthentikOIDCProvider(
            config_url="https://auth.example.com/application/o/<slug>/.well-known/openid-configuration",
            client_id="...",
            client_secret="...",
            base_url="https://mcp.example.com/http",
            issuer_url="https://mcp.example.com",
        )
        mcp = FastMCP("Plane MCP Server", auth=auth)
        ```
    """

    def __init__(
        self,
        *,
        config_url: AnyHttpUrl | str,
        client_id: str,
        client_secret: str,
        base_url: AnyHttpUrl | str,
        issuer_url: AnyHttpUrl | str | None = None,
        audience: str | None = None,
        required_scopes: list[str] | None = None,
        allowed_client_redirect_uris: list[str] | None = None,
        client_storage: AsyncKeyValue | None = None,
        jwt_signing_key: str | bytes | None = None,
        require_authorization_consent: bool | Literal["external"] = True,
        enable_cimd: bool = False,
        timeout_seconds: int | None = None,
    ) -> None:
        """Initialize the Authentik OIDC provider.

        Args:
            config_url: Authentik OIDC discovery URL.
            client_id: Authentik OAuth2/OpenID provider client id.
            client_secret: Authentik client secret.
            base_url: Public URL where OAuth endpoints are accessible (includes the
                ``/http`` mount path).
            issuer_url: Root-level public issuer URL. MUST be passed explicitly when
                mounted under a path, otherwise discovery 404s. ``OIDCProxy`` defaults
                this to ``base_url`` (which carries ``/http``).
            audience: Token audience. Ignored when ``verify_id_token`` is on (the
                verifier audience defaults to ``client_id``); accepted for parity.
            required_scopes: OIDC scopes (default
                ``["openid", "email", "profile", "offline_access"]``). ``offline_access``
                is required for Authentik (2024.2+) to issue a refresh token; without it
                the connection dies when the access token expires and cannot be renewed.
            allowed_client_redirect_uris: Allowed MCP-client redirect patterns
                (default: localhost / editor schemes / ``https://claude.ai/*``).
            client_storage: Storage backend for OAuth state (shared token store).
            jwt_signing_key: Secret for signing FastMCP-minted tokens. If None,
                ``OIDCProxy`` derives one from the client secret.
            require_authorization_consent: Show the consent screen (default True).
            enable_cimd: CIMD client support. Disabled by default to narrow the
                client-acceptance surface to the fixed Claude.ai connector.
            timeout_seconds: HTTP timeout for discovery / JWKS fetches.
        """
        if not client_secret:
            raise ValueError("client_secret is required - set via parameter or AUTHENTIK_CLIENT_SECRET")

        self._authentik_scopes = required_scopes or ["openid", "email", "profile", "offline_access"]
        self._authentik_audience = audience

        super().__init__(
            config_url=config_url,
            client_id=client_id,
            client_secret=client_secret,
            audience=audience,
            timeout_seconds=timeout_seconds,
            verify_id_token=True,
            required_scopes=self._authentik_scopes,
            base_url=base_url,
            issuer_url=issuer_url,
            allowed_client_redirect_uris=(
                allowed_client_redirect_uris
                if allowed_client_redirect_uris is not None
                else DEFAULT_ALLOWED_CLIENT_REDIRECT_URIS
            ),
            client_storage=client_storage,
            jwt_signing_key=jwt_signing_key,
            require_authorization_consent=require_authorization_consent,
            enable_cimd=enable_cimd,
        )

        logger.info(
            "Initialized Authentik OIDC provider for client %s with scopes: %s",
            client_id,
            self._authentik_scopes,
        )

    def get_token_verifier(
        self,
        *,
        algorithm: str | None = None,
        audience: str | None = None,
        required_scopes: list[str] | None = None,
        timeout_seconds: int | None = None,
    ) -> TokenVerifier:
        """Return an :class:`AuthentikTokenVerifier` bound to the discovered JWKS.

        Called inside ``OIDCProxy.__init__`` with the discovered ``jwks_uri`` /
        ``issuer`` and (because ``verify_id_token=True``) ``audience=client_id``.
        """
        return AuthentikTokenVerifier(
            jwks_uri=str(self.oidc_config.jwks_uri),
            issuer=str(self.oidc_config.issuer),
            algorithm=algorithm,
            audience=audience,
            required_scopes=required_scopes,
        )
