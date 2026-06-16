"""Unit tests for the self-service provisioning routes (CONTRACT §F/§G/§H).

Security surface under test:
- ``GET /http/provision`` with no/invalid/tampered session -> 302 to Authentik login.
- POST without a valid session -> login redirect; with a session but bad/missing CSRF -> 403.
- A submitted PAT that fails Plane ``/users/me/`` validation is NOT stored and is never
  echoed back; a valid PAT is stored (encrypted) with the chosen workspace.
- ``disconnect`` removes the mapping (CSRF-checked).
- The auth-code callback verifies the id_token + nonce and establishes the session.

All HTTP is mocked: Authentik discovery is patched to a static config, the id_token
verifier is a local-key ``JWTVerifier`` (no JWKS fetch), and the Plane PAT-validation /
token-exchange calls go through an injected ``httpx.MockTransport``. No live network.
"""

import contextlib
import json
import time
from unittest.mock import patch

import httpx
import pytest
from cryptography.fernet import Fernet
from fastmcp.server.auth.oidc_proxy import OIDCConfiguration
from fastmcp.server.auth.providers.jwt import JWTVerifier, RSAKeyPair
from starlette.applications import Starlette
from starlette.testclient import TestClient

import plane_mcp.provisioning as prov
from plane_mcp.pat_store import PatStore, derive_fernet_key

# These tests deliberately pass per-request cookies to the Starlette TestClient to
# keep each request's auth state isolated and explicit. Starlette deprecates that in
# favour of client-instance cookies, but per-request is the behaviour we want here, so
# silence only that specific third-party DeprecationWarning.
pytestmark = pytest.mark.filterwarnings("ignore:Setting per-request cookies.*:DeprecationWarning")

ISSUER = "https://auth.example.com/application/o/plane/"
CLIENT_ID = "client-abc"
SECRET = "provision-test-secret"


def _fake_oidc_config() -> OIDCConfiguration:
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


@pytest.fixture
def store():
    """Fresh in-memory PatStore shared with the provisioning module via patching."""
    return PatStore(fernet=Fernet(derive_fernet_key(SECRET)))


@pytest.fixture(autouse=True)
def _reset_caches_and_env(monkeypatch):
    """Clear the module's lru_caches and set the env the routes read."""
    monkeypatch.setenv("AUTHENTIK_CLIENT_ID", CLIENT_ID)
    monkeypatch.setenv("AUTHENTIK_CLIENT_SECRET", "authentik-secret")
    monkeypatch.setenv("AUTHENTIK_CONFIG_URL", f"{ISSUER}.well-known/openid-configuration")
    monkeypatch.setenv("MCP_PAT_ENCRYPTION_KEY", SECRET)
    monkeypatch.setenv("MCP_PUBLIC_BASE_URL", "https://testserver")
    monkeypatch.setenv("PLANE_INTERNAL_BASE_URL", "http://plane.internal:8000")
    monkeypatch.setenv("PLANE_WEB_URL", "https://plane.example.com")
    monkeypatch.setenv("PLANE_WORKSPACE_SLUG", "default-ws")
    prov._fernet.cache_clear()
    prov._oidc_config.cache_clear()
    prov._id_token_verifier.cache_clear()
    yield
    # Stop any patchers started by _client() so the store patch never leaks.
    patch.stopall()
    prov._fernet.cache_clear()
    prov._oidc_config.cache_clear()
    prov._id_token_verifier.cache_clear()


@contextlib.contextmanager
def _patched_discovery():
    with patch.object(
        OIDCConfiguration,
        "get_oidc_configuration",
        classmethod(lambda cls, *a, **k: _fake_oidc_config()),
    ):
        yield


def _client(store) -> TestClient:
    """Build a TestClient over the provision routes with the shared store patched in.

    https base URL so the Secure session/flow cookies round-trip.
    """
    app = Starlette(routes=prov.provision_routes(""))
    # Point the provisioning module's store accessor at our isolated store. The
    # autouse fixture's patch.stopall() in teardown undoes this so it never leaks.
    patch.object(prov, "get_pat_store", return_value=store).start()
    return TestClient(app, base_url="https://testserver", raise_server_exceptions=False)


def _session_cookie(sub: str, email: str, csrf: str) -> str:
    """Forge a *valid* session cookie using the module's own codec."""
    return prov._encode_cookie({"sub": sub, "email": email, "csrf": csrf})


# --------------------------------------------------------------------------- #
# GET /http/provision — auth gating
# --------------------------------------------------------------------------- #
class TestProvisionGetAuthGating:
    def test_no_session_redirects_to_authentik(self, store):
        with _patched_discovery():
            tc = _client(store)
            resp = tc.get("/http/provision", follow_redirects=False)
        assert resp.status_code == 302
        loc = resp.headers["location"]
        assert loc.startswith(f"{ISSUER}authorize/")
        assert f"client_id={CLIENT_ID}" in loc
        assert "scope=openid+email+profile" in loc or "scope=openid%20email%20profile" in loc
        assert "redirect_uri=" in loc
        # A short-lived flow cookie (state+nonce) is set.
        assert prov._FLOW_COOKIE in resp.headers.get("set-cookie", "")

    def test_tampered_session_cookie_redirects_to_login(self, store):
        with _patched_discovery():
            tc = _client(store)
            resp = tc.get(
                "/http/provision",
                cookies={prov._SESSION_COOKIE: "not-a-valid-fernet-token"},
                follow_redirects=False,
            )
        assert resp.status_code == 302
        assert resp.headers["location"].startswith(f"{ISSUER}authorize/")

    def test_expired_session_cookie_redirects_to_login(self, store):
        # Hand-craft a session whose iat is older than the TTL.
        prov._fernet.cache_clear()
        f = prov._fernet()
        stale_iat = int(time.time()) - prov._SESSION_TTL - 60
        stale = f.encrypt(json.dumps({"sub": "u", "email": "e", "csrf": "c", "iat": stale_iat}).encode()).decode()
        with _patched_discovery():
            tc = _client(store)
            resp = tc.get("/http/provision", cookies={prov._SESSION_COOKIE: stale}, follow_redirects=False)
        assert resp.status_code == 302
        assert resp.headers["location"].startswith(f"{ISSUER}authorize/")


# --------------------------------------------------------------------------- #
# GET /http/provision — authed views
# --------------------------------------------------------------------------- #
class TestProvisionGetAuthed:
    def test_unlinked_user_sees_link_form(self, store):
        cookie = _session_cookie("user-1", "u1@example.com", "csrf-token")
        with _patched_discovery():
            tc = _client(store)
            resp = tc.get("/http/provision", cookies={prov._SESSION_COOKIE: cookie})
        assert resp.status_code == 200
        body = resp.text
        assert "Personal Access Token" in body
        # Deep-links to the Plane PAT-create page.
        assert "https://plane.example.com/settings/profile/api-tokens/" in body
        # Workspace default is prefilled.
        assert "default-ws" in body

    def test_linked_user_sees_connected_view(self, store):
        store.set_pat("user-1", "plane_api_LINKED")
        store.set_workspace("user-1", "acme")
        cookie = _session_cookie("user-1", "u1@example.com", "csrf-token")
        with _patched_discovery():
            tc = _client(store)
            resp = tc.get("/http/provision", cookies={prov._SESSION_COOKIE: cookie})
        assert resp.status_code == 200
        body = resp.text
        assert "Connected" in body
        assert "u1@example.com" in body
        assert "acme" in body
        # The PAT itself must never be rendered.
        assert "plane_api_LINKED" not in body


# --------------------------------------------------------------------------- #
# POST /http/provision — CSRF + PAT validation + storage
# --------------------------------------------------------------------------- #
def _mock_plane_transport(*, ok: bool) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path.endswith("/api/v1/users/me/")
        assert request.headers.get("x-api-key")  # PAT sent as X-Api-Key
        return httpx.Response(200 if ok else 401, json={"id": "u1"} if ok else {"error": "bad"})

    return httpx.MockTransport(handler)


@contextlib.contextmanager
def _patched_plane(*, ok: bool):
    transport = _mock_plane_transport(ok=ok)
    real_async_client = httpx.AsyncClient

    def factory(*args, **kwargs):
        kwargs.pop("timeout", None)
        return real_async_client(transport=transport, timeout=5)

    with patch.object(prov.httpx, "AsyncClient", side_effect=factory):
        yield


class TestProvisionPost:
    def test_post_without_session_redirects_to_login(self, store):
        with _patched_discovery():
            tc = _client(store)
            resp = tc.post("/http/provision", data={"pat": "x", "csrf": "y"}, follow_redirects=False)
        assert resp.status_code == 302
        assert resp.headers["location"].startswith(f"{ISSUER}authorize/")

    def test_post_missing_csrf_rejected(self, store):
        cookie = _session_cookie("user-1", "u1@example.com", "the-csrf")
        with _patched_discovery():
            tc = _client(store)
            resp = tc.post(
                "/http/provision",
                data={"pat": "plane_api_X", "workspace": "acme"},  # no csrf field
                cookies={prov._SESSION_COOKIE: cookie},
            )
        assert resp.status_code == 403
        assert store.get_pat("user-1") is None

    def test_post_wrong_csrf_rejected(self, store):
        cookie = _session_cookie("user-1", "u1@example.com", "the-csrf")
        with _patched_discovery():
            tc = _client(store)
            resp = tc.post(
                "/http/provision",
                data={"pat": "plane_api_X", "workspace": "acme", "csrf": "WRONG"},
                cookies={prov._SESSION_COOKIE: cookie},
            )
        assert resp.status_code == 403
        assert store.get_pat("user-1") is None

    def test_post_bad_pat_not_stored_and_not_echoed(self, store):
        cookie = _session_cookie("user-1", "u1@example.com", "the-csrf")
        with _patched_discovery(), _patched_plane(ok=False):
            tc = _client(store)
            resp = tc.post(
                "/http/provision",
                data={"pat": "plane_api_BADTOKEN", "workspace": "acme", "csrf": "the-csrf"},
                cookies={prov._SESSION_COOKIE: cookie},
            )
        assert resp.status_code == 400
        assert store.get_pat("user-1") is None  # rejected -> not stored
        assert "plane_api_BADTOKEN" not in resp.text  # never echoed back

    def test_post_valid_pat_stored_encrypted_and_workspace_persisted(self, store):
        cookie = _session_cookie("user-1", "u1@example.com", "the-csrf")
        with _patched_discovery(), _patched_plane(ok=True):
            tc = _client(store)
            resp = tc.post(
                "/http/provision",
                data={"pat": "plane_api_GOODTOKEN", "workspace": "acme", "csrf": "the-csrf"},
                cookies={prov._SESSION_COOKIE: cookie},
            )
        assert resp.status_code == 200
        assert "Connected" in resp.text
        assert store.get_pat("user-1") == "plane_api_GOODTOKEN"
        assert store.get_workspace("user-1") == "acme"
        # Stored at rest as ciphertext, not plaintext.
        raw = store._mem_pat["mcp:pat:user-1"]
        assert "plane_api_GOODTOKEN" not in raw
        # The PAT is not rendered into the success page.
        assert "plane_api_GOODTOKEN" not in resp.text

    def test_post_empty_pat_rejected(self, store):
        cookie = _session_cookie("user-1", "u1@example.com", "the-csrf")
        with _patched_discovery():
            tc = _client(store)
            resp = tc.post(
                "/http/provision",
                data={"pat": "   ", "workspace": "acme", "csrf": "the-csrf"},
                cookies={prov._SESSION_COOKIE: cookie},
            )
        assert resp.status_code == 400
        assert store.get_pat("user-1") is None

    def test_post_blank_workspace_falls_back_to_default(self, store):
        cookie = _session_cookie("user-1", "u1@example.com", "the-csrf")
        with _patched_discovery(), _patched_plane(ok=True):
            tc = _client(store)
            tc.post(
                "/http/provision",
                data={"pat": "plane_api_OK", "workspace": "", "csrf": "the-csrf"},
                cookies={prov._SESSION_COOKIE: cookie},
            )
        assert store.get_workspace("user-1") == "default-ws"


# --------------------------------------------------------------------------- #
# POST /http/provision/disconnect
# --------------------------------------------------------------------------- #
class TestDisconnect:
    def test_disconnect_bad_csrf_keeps_link(self, store):
        store.set_pat("user-1", "plane_api_LINKED")
        cookie = _session_cookie("user-1", "u1@example.com", "the-csrf")
        with _patched_discovery():
            tc = _client(store)
            resp = tc.post(
                "/http/provision/disconnect",
                data={"csrf": "WRONG"},
                cookies={prov._SESSION_COOKIE: cookie},
            )
        assert resp.status_code == 403
        assert store.get_pat("user-1") == "plane_api_LINKED"  # still linked

    def test_disconnect_valid_csrf_removes_mapping(self, store):
        store.set_pat("user-1", "plane_api_LINKED")
        store.set_workspace("user-1", "acme")
        cookie = _session_cookie("user-1", "u1@example.com", "the-csrf")
        with _patched_discovery():
            tc = _client(store)
            resp = tc.post(
                "/http/provision/disconnect",
                data={"csrf": "the-csrf"},
                cookies={prov._SESSION_COOKIE: cookie},
                follow_redirects=False,
            )
        assert resp.status_code == 303
        assert store.get_pat("user-1") is None
        assert store.get_workspace("user-1") is None


# --------------------------------------------------------------------------- #
# GET /http/provision/callback — auth-code exchange + id_token verification
# --------------------------------------------------------------------------- #
class TestCallback:
    def _flow_cookie(self, state: str, nonce: str) -> str:
        return prov._encode_cookie({"state": state, "nonce": nonce})

    @contextlib.contextmanager
    def _patched_token_exchange(self, id_token: str, *, status: int = 200):
        def handler(request: httpx.Request) -> httpx.Response:
            assert request.url.path.endswith("/token/")
            return httpx.Response(status, json={"id_token": id_token} if status == 200 else {"error": "x"})

        transport = httpx.MockTransport(handler)
        real_async_client = httpx.AsyncClient

        def factory(*args, **kwargs):
            kwargs.pop("timeout", None)
            return real_async_client(transport=transport, timeout=5)

        with patch.object(prov.httpx, "AsyncClient", side_effect=factory):
            yield

    @contextlib.contextmanager
    def _patched_verifier(self, kp: RSAKeyPair):
        verifier = JWTVerifier(public_key=kp.public_key, issuer=ISSUER, audience=CLIENT_ID)
        # Bypass the lru_cache + discovery-dependent verifier builder.
        with patch.object(prov, "_id_token_verifier", lambda: verifier):
            yield

    def test_callback_success_sets_session_and_redirects(self, store):
        kp = RSAKeyPair.generate()
        nonce = "the-nonce"
        state = "the-state"
        id_token = kp.create_token(
            subject="user-1",
            issuer=ISSUER,
            audience=CLIENT_ID,
            additional_claims={"email": "u1@example.com", "nonce": nonce},
        )
        with _patched_discovery(), self._patched_token_exchange(id_token), self._patched_verifier(kp):
            tc = _client(store)
            resp = tc.get(
                "/http/provision/callback",
                params={"state": state, "code": "auth-code-123"},
                cookies={prov._FLOW_COOKIE: self._flow_cookie(state, nonce)},
                follow_redirects=False,
            )
        assert resp.status_code == 303
        assert resp.headers["location"] == "/http/provision"
        # A session cookie was established.
        set_cookie = resp.headers.get("set-cookie", "")
        assert prov._SESSION_COOKIE in set_cookie

    def test_callback_wrong_state_rejected(self, store):
        with _patched_discovery():
            tc = _client(store)
            resp = tc.get(
                "/http/provision/callback",
                params={"state": "attacker-state", "code": "c"},
                cookies={prov._FLOW_COOKIE: self._flow_cookie("real-state", "n")},
                follow_redirects=False,
            )
        assert resp.status_code == 400

    def test_callback_no_flow_cookie_rejected(self, store):
        with _patched_discovery():
            tc = _client(store)
            resp = tc.get(
                "/http/provision/callback",
                params={"state": "s", "code": "c"},
                follow_redirects=False,
            )
        assert resp.status_code == 400

    def test_callback_nonce_mismatch_rejected(self, store):
        kp = RSAKeyPair.generate()
        state = "the-state"
        id_token = kp.create_token(
            subject="user-1",
            issuer=ISSUER,
            audience=CLIENT_ID,
            additional_claims={"email": "u1@example.com", "nonce": "ATTACKER-NONCE"},
        )
        with _patched_discovery(), self._patched_token_exchange(id_token), self._patched_verifier(kp):
            tc = _client(store)
            resp = tc.get(
                "/http/provision/callback",
                params={"state": state, "code": "c"},
                cookies={prov._FLOW_COOKIE: self._flow_cookie(state, "REAL-NONCE")},
                follow_redirects=False,
            )
        assert resp.status_code == 400
        # No session was established on a nonce mismatch.
        assert prov._SESSION_COOKIE not in resp.headers.get("set-cookie", "")

    def test_callback_idp_error_rejected(self, store):
        with _patched_discovery():
            tc = _client(store)
            resp = tc.get(
                "/http/provision/callback",
                params={"error": "access_denied"},
                follow_redirects=False,
            )
        assert resp.status_code == 400

    def test_callback_token_exchange_failure_rejected(self, store):
        state = "the-state"
        with _patched_discovery(), self._patched_token_exchange("", status=400):
            tc = _client(store)
            resp = tc.get(
                "/http/provision/callback",
                params={"state": state, "code": "c"},
                cookies={prov._FLOW_COOKIE: self._flow_cookie(state, "n")},
                follow_redirects=False,
            )
        assert resp.status_code == 400


# --------------------------------------------------------------------------- #
# Route construction (no live IdP needed)
# --------------------------------------------------------------------------- #
class TestRouteConstruction:
    def test_routes_built_for_prefix(self):
        routes = prov.provision_routes("/api")
        paths = {r.path for r in routes}
        assert "/api/http/provision" in paths
        assert "/api/http/provision/callback" in paths
        assert "/api/http/provision/disconnect" in paths

    def test_build_alias_matches(self):
        assert len(prov.build_provision_routes("")) == len(prov.provision_routes(""))
