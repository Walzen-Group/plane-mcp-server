"""Unit tests for credential resolution in client.py (CONTRACT §E/§H).

The security-critical seam: with ``auth_method="authentik_oidc"`` the IdP token must
NEVER become the Plane credential — the per-user PAT (looked up by ``sub``) is used
instead, with the per-user workspace. An unlinked user gets the first-run ``ToolError``
carrying the provision URL. The api-key and legacy-OAuth branches are unchanged.

No network: ``get_access_token`` and the PAT store are patched; ``PlaneClient`` is real
but never makes a call (we only inspect how it was constructed).
"""

from unittest.mock import patch

import pytest
from cryptography.fernet import Fernet
from fastmcp.exceptions import ToolError
from fastmcp.server.auth.auth import AccessToken

import plane_mcp.client as client_mod
from plane_mcp.client import get_plane_client_context
from plane_mcp.pat_store import PatStore, derive_fernet_key


def _access_token(claims: dict, token: str = "idp-token-xyz") -> AccessToken:
    return AccessToken(token=token, client_id="client-abc", scopes=[], claims=claims)


def _fresh_store() -> PatStore:
    return PatStore(fernet=Fernet(derive_fernet_key("client-ctx-test")))


class TestAuthentikOIDCBranch:
    def test_mapped_pat_builds_client_with_api_key_not_access_token(self, monkeypatch):
        """The PAT is used as api_key; the IdP token must not reach Plane."""
        monkeypatch.setenv("PLANE_INTERNAL_BASE_URL", "http://plane.internal:8000")
        store = _fresh_store()
        store.set_pat("user-1", "plane_api_USERPAT")
        store.set_workspace("user-1", "acme")

        token = _access_token({"auth_method": "authentik_oidc", "sub": "user-1", "email": "a@x.com"})
        with (
            patch.object(client_mod, "get_access_token", return_value=token),
            patch.object(client_mod, "get_pat_store", return_value=store),
        ):
            ctx = get_plane_client_context()

        assert ctx.workspace_slug == "acme"
        # The Plane credential is the PAT, never the IdP token.
        assert ctx.client.config.api_key == "plane_api_USERPAT"
        assert ctx.client.config.access_token is None
        assert ctx.client.config.api_key != "idp-token-xyz"

    def test_workspace_falls_back_to_env_when_unset(self, monkeypatch):
        monkeypatch.setenv("PLANE_WORKSPACE_SLUG", "default-ws")
        store = _fresh_store()
        store.set_pat("user-2", "pat-2")  # no per-user workspace stored

        token = _access_token({"auth_method": "authentik_oidc", "sub": "user-2"})
        with (
            patch.object(client_mod, "get_access_token", return_value=token),
            patch.object(client_mod, "get_pat_store", return_value=store),
        ):
            ctx = get_plane_client_context()

        assert ctx.workspace_slug == "default-ws"
        assert ctx.client.config.api_key == "pat-2"

    def test_unlinked_user_raises_first_run_tool_error_with_provision_url(self, monkeypatch):
        monkeypatch.setenv("MCP_PUBLIC_BASE_URL", "https://mcp.example.com")
        monkeypatch.setenv("MCP_PATH_PREFIX", "")
        store = _fresh_store()  # user-3 not linked

        token = _access_token({"auth_method": "authentik_oidc", "sub": "user-3"})
        with (
            patch.object(client_mod, "get_access_token", return_value=token),
            patch.object(client_mod, "get_pat_store", return_value=store),
        ):
            with pytest.raises(ToolError) as exc_info:
                get_plane_client_context()

        msg = str(exc_info.value)
        assert "https://mcp.example.com/http/provision" in msg
        # The IdP token must not be leaked in the actionable error.
        assert "idp-token-xyz" not in msg

    def test_missing_sub_raises_tool_error(self, monkeypatch):
        """A token with no sub cannot be mapped -> treated as unlinked."""
        store = _fresh_store()
        token = _access_token({"auth_method": "authentik_oidc"})  # no sub
        with (
            patch.object(client_mod, "get_access_token", return_value=token),
            patch.object(client_mod, "get_pat_store", return_value=store),
        ):
            with pytest.raises(ToolError):
                get_plane_client_context()

    def test_per_user_isolation_distinct_pats(self, monkeypatch):
        """Two different subs resolve to their own PAT + workspace, never cross."""
        store = _fresh_store()
        store.set_pat("user-a", "pat-A")
        store.set_workspace("user-a", "ws-a")
        store.set_pat("user-b", "pat-B")
        store.set_workspace("user-b", "ws-b")

        for sub, pat, ws in (("user-a", "pat-A", "ws-a"), ("user-b", "pat-B", "ws-b")):
            token = _access_token({"auth_method": "authentik_oidc", "sub": sub})
            with (
                patch.object(client_mod, "get_access_token", return_value=token),
                patch.object(client_mod, "get_pat_store", return_value=store),
            ):
                ctx = get_plane_client_context()
            assert ctx.client.config.api_key == pat
            assert ctx.workspace_slug == ws


class TestApiKeyBranches:
    def test_api_key_header_uses_token_as_api_key(self, monkeypatch):
        monkeypatch.setenv("PLANE_WORKSPACE_SLUG", "")
        token = _access_token(
            {"auth_method": "api_key_header", "workspace_slug": "hdr-ws"},
            token="header-api-key",
        )
        with patch.object(client_mod, "get_access_token", return_value=token):
            ctx = get_plane_client_context()
        assert ctx.client.config.api_key == "header-api-key"
        assert ctx.client.config.access_token is None
        assert ctx.workspace_slug == "hdr-ws"

    def test_api_key_env_uses_token_as_api_key(self):
        token = _access_token({"auth_method": "api_key_env"}, token="env-api-key")
        with patch.object(client_mod, "get_access_token", return_value=token):
            ctx = get_plane_client_context()
        assert ctx.client.config.api_key == "env-api-key"
        assert ctx.client.config.access_token is None


class TestLegacyOAuthBranch:
    def test_oauth_passes_token_as_access_token(self, monkeypatch):
        monkeypatch.setenv("PLANE_WORKSPACE_SLUG", "")
        token = _access_token({"auth_method": "oauth", "workspace_slug": "oauth-ws"}, token="oauth-bearer")
        with patch.object(client_mod, "get_access_token", return_value=token):
            ctx = get_plane_client_context()
        # Legacy Plane-Cloud pass-through: token goes through as the bearer.
        assert ctx.client.config.access_token == "oauth-bearer"
        assert ctx.client.config.api_key is None
        assert ctx.workspace_slug == "oauth-ws"

    def test_default_auth_method_is_oauth(self, monkeypatch):
        """No auth_method claim -> defaults to legacy oauth pass-through."""
        monkeypatch.setenv("PLANE_WORKSPACE_SLUG", "")
        token = _access_token({}, token="bearer-default")
        with patch.object(client_mod, "get_access_token", return_value=token):
            ctx = get_plane_client_context()
        assert ctx.client.config.access_token == "bearer-default"


class TestStdioFallback:
    def test_no_access_token_uses_env_api_key(self, monkeypatch):
        """stdio mode: no request token -> env PLANE_API_KEY is the credential."""
        monkeypatch.setenv("PLANE_API_KEY", "env-stdio-key")
        monkeypatch.setenv("PLANE_WORKSPACE_SLUG", "stdio-ws")
        with patch.object(client_mod, "get_access_token", return_value=None):
            ctx = get_plane_client_context()
        assert ctx.client.config.api_key == "env-stdio-key"
        assert ctx.client.config.access_token is None
        assert ctx.workspace_slug == "stdio-ws"


class TestProvisionUrl:
    def test_provision_url_composition(self, monkeypatch):
        monkeypatch.setenv("MCP_PUBLIC_BASE_URL", "https://mcp.example.com/")
        monkeypatch.setenv("MCP_PATH_PREFIX", "/api")
        assert client_mod.provision_url() == "https://mcp.example.com/api/http/provision"

    def test_provision_url_falls_back_to_oauth_base(self, monkeypatch):
        monkeypatch.delenv("MCP_PUBLIC_BASE_URL", raising=False)
        monkeypatch.delenv("MCP_PATH_PREFIX", raising=False)
        monkeypatch.setenv("PLANE_OAUTH_PROVIDER_BASE_URL", "https://fallback.example.com")
        assert client_mod.provision_url() == "https://fallback.example.com/http/provision"
