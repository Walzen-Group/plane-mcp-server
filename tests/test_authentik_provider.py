"""Unit tests for the Authentik OIDC provider + token verifier (CONTRACT §B/§C).

- ``AuthentikTokenVerifier.load_access_token`` stamps ``auth_method`` on a valid
  id_token while preserving ``sub``/``email``, and returns ``None`` on invalid/expired
  tokens. Tokens are minted with ``RSAKeyPair`` and verified against its public key, so
  no JWKS fetch / network is required.
- Provider construction wiring: ``config_url`` derivation from base+slug, and the
  default ``allowed_client_redirect_uris`` includes ``https://claude.ai/*``. Discovery
  is mocked so construction never touches the network.
"""

import contextlib
from unittest.mock import patch

import anyio
import pytest
from fastmcp.server.auth.oidc_proxy import OIDCConfiguration
from fastmcp.server.auth.providers.jwt import RSAKeyPair

from plane_mcp.auth.authentik_oidc_provider import (
    AUTH_METHOD,
    DEFAULT_ALLOWED_CLIENT_REDIRECT_URIS,
    AuthentikOIDCProvider,
    AuthentikTokenVerifier,
    resolve_config_url,
)

ISSUER = "https://auth.example.com/application/o/plane/"
CLIENT_ID = "client-abc"


def _run(coro):
    """Drive a coroutine to completion (no pytest-asyncio plugin in this venv)."""
    return anyio.run(lambda: coro)


def _fake_oidc_config() -> OIDCConfiguration:
    """A fully-populated (non-strict) discovery doc so construction needs no network."""
    return OIDCConfiguration(
        strict=False,
        issuer=ISSUER,
        authorization_endpoint=f"{ISSUER}authorize/",
        token_endpoint=f"{ISSUER}token/",
        jwks_uri=f"{ISSUER}jwks/",
        response_types_supported=["code"],
        subject_types_supported=["public"],
        id_token_signing_alg_values_supported=["RS256"],
    )


@contextlib.contextmanager
def _patched_discovery():
    with patch.object(
        OIDCConfiguration,
        "get_oidc_configuration",
        classmethod(lambda cls, *a, **k: _fake_oidc_config()),
    ):
        yield


# --------------------------------------------------------------------------- #
# AuthentikTokenVerifier
# --------------------------------------------------------------------------- #
class TestAuthentikTokenVerifier:
    def _verifier(self, kp: RSAKeyPair) -> AuthentikTokenVerifier:
        # public_key path -> verifier checks locally, no JWKS fetch.
        return AuthentikTokenVerifier(public_key=kp.public_key, issuer=ISSUER, audience=CLIENT_ID)

    def test_valid_token_gets_auth_method_and_preserves_claims(self):
        kp = RSAKeyPair.generate()
        token = kp.create_token(
            subject="user-123",
            issuer=ISSUER,
            audience=CLIENT_ID,
            additional_claims={"email": "alice@example.com", "name": "Alice"},
        )
        result = _run(self._verifier(kp).load_access_token(token))

        assert result is not None
        assert result.claims["auth_method"] == AUTH_METHOD
        # Verified identity claims are preserved untouched.
        assert result.claims["sub"] == "user-123"
        assert result.claims["email"] == "alice@example.com"
        assert result.claims["name"] == "Alice"
        assert result.claims["aud"] == CLIENT_ID

    def test_does_not_add_pat_to_claims(self):
        """The verifier must not add the PAT to claims (CONTRACT §B)."""
        kp = RSAKeyPair.generate()
        token = kp.create_token(subject="user-1", issuer=ISSUER, audience=CLIENT_ID)
        result = _run(self._verifier(kp).load_access_token(token))
        assert result is not None
        # No PAT ever lands in claims.
        assert all("pat" not in str(k).lower() for k in result.claims)

    def test_expired_token_returns_none(self):
        kp = RSAKeyPair.generate()
        token = kp.create_token(subject="user-1", issuer=ISSUER, audience=CLIENT_ID, expires_in_seconds=-30)
        assert _run(self._verifier(kp).load_access_token(token)) is None

    def test_wrong_audience_returns_none(self):
        kp = RSAKeyPair.generate()
        token = kp.create_token(subject="user-1", issuer=ISSUER, audience="some-other-client")
        assert _run(self._verifier(kp).load_access_token(token)) is None

    def test_wrong_issuer_returns_none(self):
        kp = RSAKeyPair.generate()
        token = kp.create_token(subject="user-1", issuer="https://evil.example/", audience=CLIENT_ID)
        assert _run(self._verifier(kp).load_access_token(token)) is None

    def test_wrong_signing_key_returns_none(self):
        """A token signed by a different key must not verify against our public key."""
        kp_real = RSAKeyPair.generate()
        kp_attacker = RSAKeyPair.generate()
        token = kp_attacker.create_token(subject="user-1", issuer=ISSUER, audience=CLIENT_ID)
        assert _run(self._verifier(kp_real).load_access_token(token)) is None

    def test_garbage_token_returns_none(self):
        kp = RSAKeyPair.generate()
        assert _run(self._verifier(kp).load_access_token("not-a-jwt")) is None


# --------------------------------------------------------------------------- #
# resolve_config_url
# --------------------------------------------------------------------------- #
class TestResolveConfigUrl:
    def test_explicit_config_url_wins(self, monkeypatch):
        monkeypatch.setenv("AUTHENTIK_CONFIG_URL", "https://auth.example.com/x/.well-known/openid-configuration")
        monkeypatch.setenv("AUTHENTIK_BASE_URL", "https://ignored.example.com")
        monkeypatch.setenv("AUTHENTIK_APP_SLUG", "ignored")
        assert resolve_config_url() == "https://auth.example.com/x/.well-known/openid-configuration"

    def test_derived_from_base_and_slug(self, monkeypatch):
        monkeypatch.delenv("AUTHENTIK_CONFIG_URL", raising=False)
        monkeypatch.setenv("AUTHENTIK_BASE_URL", "https://auth.example.com/")  # trailing slash trimmed
        monkeypatch.setenv("AUTHENTIK_APP_SLUG", "plane")
        assert resolve_config_url() == ("https://auth.example.com/application/o/plane/.well-known/openid-configuration")

    def test_unconfigured_raises(self, monkeypatch):
        monkeypatch.delenv("AUTHENTIK_CONFIG_URL", raising=False)
        monkeypatch.delenv("AUTHENTIK_BASE_URL", raising=False)
        monkeypatch.delenv("AUTHENTIK_APP_SLUG", raising=False)
        with pytest.raises(ValueError):
            resolve_config_url()


# --------------------------------------------------------------------------- #
# Provider construction wiring
# --------------------------------------------------------------------------- #
class TestProviderConstruction:
    def _build(self, **overrides):
        kwargs = dict(
            config_url=f"{ISSUER}.well-known/openid-configuration",
            client_id=CLIENT_ID,
            client_secret="secret-xyz",
            base_url="https://mcp.example.com/http",
            issuer_url="https://mcp.example.com",
        )
        kwargs.update(overrides)
        return AuthentikOIDCProvider(**kwargs)

    def test_constructs_without_network(self):
        with _patched_discovery():
            provider = self._build()
        assert isinstance(provider, AuthentikOIDCProvider)

    def test_get_token_verifier_is_authentik_verifier(self):
        with _patched_discovery():
            provider = self._build()
            verifier = provider.get_token_verifier()
        assert isinstance(verifier, AuthentikTokenVerifier)

    def test_default_redirect_uris_include_claude_ai(self):
        # Independent of construction: the default list is the contract surface.
        assert "https://claude.ai/*" in DEFAULT_ALLOWED_CLIENT_REDIRECT_URIS

    def test_constructed_provider_allows_claude_ai_redirect(self):
        with _patched_discovery():
            provider = self._build()
        # OAuthProxy stores the allowed patterns; assert claude.ai is present.
        allowed = getattr(provider, "_allowed_client_redirect_uris", None)
        assert allowed is not None
        assert "https://claude.ai/*" in [str(p) for p in allowed]

    def test_default_scopes(self):
        with _patched_discovery():
            provider = self._build()
        assert provider._authentik_scopes == ["openid", "email", "profile"]

    def test_missing_client_secret_raises(self):
        with _patched_discovery():
            with pytest.raises(ValueError):
                self._build(client_secret="")

    def test_custom_redirect_uris_respected(self):
        custom = ["https://only.example/*"]
        with _patched_discovery():
            provider = self._build(allowed_client_redirect_uris=custom)
        allowed = [str(p) for p in getattr(provider, "_allowed_client_redirect_uris", [])]
        assert allowed == custom
