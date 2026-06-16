"""Unit tests for the per-user PAT store (CONTRACT §D).

Covers: set/get/delete round-trip, per-user isolation, encryption at rest
(stored bytes are not the plaintext PAT), workspace get/set + fallback semantics,
and the in-memory vs Redis backends. Fully offline — no live Redis/network for the
in-memory tests; the Redis-backend tests use ``fakeredis`` (already a dependency).
"""

from cryptography.fernet import Fernet

from plane_mcp.pat_store import (
    PAT_KEY_PREFIX,
    WS_KEY_PREFIX,
    PatStore,
    derive_fernet_key,
)


def _store() -> PatStore:
    """Build an in-memory PatStore with a deterministic test key."""
    return PatStore(fernet=Fernet(derive_fernet_key("unit-test-secret")))


class TestDeriveFernetKey:
    def test_deterministic_and_valid_fernet_key(self):
        """Same secret -> same key; the key is a usable Fernet key."""
        k1 = derive_fernet_key("secret-a")
        k2 = derive_fernet_key("secret-a")
        assert k1 == k2
        # 32 raw bytes -> urlsafe base64 == 44 chars
        assert len(k1) == 44
        # Round-trips through Fernet without raising.
        f = Fernet(k1)
        assert f.decrypt(f.encrypt(b"hello")) == b"hello"

    def test_different_secret_yields_different_key(self):
        assert derive_fernet_key("secret-a") != derive_fernet_key("secret-b")


class TestPatRoundTrip:
    def test_set_get_delete(self):
        store = _store()
        assert store.get_pat("user-1") is None
        store.set_pat("user-1", "plane_api_AAA")
        assert store.get_pat("user-1") == "plane_api_AAA"
        store.delete("user-1")
        assert store.get_pat("user-1") is None

    def test_overwrite_replaces_value(self):
        store = _store()
        store.set_pat("user-1", "plane_api_OLD")
        store.set_pat("user-1", "plane_api_NEW")
        assert store.get_pat("user-1") == "plane_api_NEW"

    def test_empty_sub_is_rejected_or_noop(self):
        store = _store()
        assert store.get_pat("") is None
        store.delete("")  # no-op, must not raise
        try:
            store.set_pat("", "x")
            raise AssertionError("expected ValueError for empty sub")
        except ValueError:
            pass

    def test_empty_pat_rejected(self):
        store = _store()
        try:
            store.set_pat("user-1", "")
            raise AssertionError("expected ValueError for empty pat")
        except ValueError:
            pass


class TestEncryptionAtRest:
    def test_stored_bytes_are_not_plaintext(self):
        """The raw stored value must be ciphertext, not the PAT (CONTRACT §D/§H)."""
        store = _store()
        pat = "plane_api_SUPERSECRET"
        store.set_pat("user-1", pat)
        raw = store._mem_pat[PAT_KEY_PREFIX + "user-1"]  # in-memory holds ciphertext
        assert pat not in raw
        assert raw != pat
        # And it decrypts back to the original via the store's Fernet.
        assert store.get_pat("user-1") == pat

    def test_value_undecryptable_with_other_key_is_treated_as_unlinked(self):
        """A PAT encrypted under one key must not be readable by another (rotation)."""
        store_a = PatStore(fernet=Fernet(derive_fernet_key("secret-a")))
        store_a.set_pat("user-1", "plane_api_AAA")
        ciphertext = store_a._mem_pat[PAT_KEY_PREFIX + "user-1"]

        store_b = PatStore(fernet=Fernet(derive_fernet_key("secret-b")))
        store_b._mem_pat[PAT_KEY_PREFIX + "user-1"] = ciphertext
        # Wrong key -> InvalidToken handled internally -> None, not an exception/leak.
        assert store_b.get_pat("user-1") is None


class TestPerUserIsolation:
    def test_users_never_see_each_others_pat(self):
        store = _store()
        store.set_pat("user-a", "pat-A")
        store.set_pat("user-b", "pat-B")
        assert store.get_pat("user-a") == "pat-A"
        assert store.get_pat("user-b") == "pat-B"

    def test_delete_is_scoped_to_one_user(self):
        store = _store()
        store.set_pat("user-a", "pat-A")
        store.set_pat("user-b", "pat-B")
        store.set_workspace("user-a", "ws-a")
        store.set_workspace("user-b", "ws-b")

        store.delete("user-a")

        assert store.get_pat("user-a") is None
        assert store.get_workspace("user-a") is None
        # user-b untouched
        assert store.get_pat("user-b") == "pat-B"
        assert store.get_workspace("user-b") == "ws-b"

    def test_workspace_isolation(self):
        store = _store()
        store.set_workspace("user-a", "acme")
        store.set_workspace("user-b", "globex")
        assert store.get_workspace("user-a") == "acme"
        assert store.get_workspace("user-b") == "globex"


class TestWorkspace:
    def test_set_get_workspace(self):
        store = _store()
        assert store.get_workspace("user-1") is None
        store.set_workspace("user-1", "my-workspace")
        assert store.get_workspace("user-1") == "my-workspace"

    def test_workspace_stored_plaintext(self):
        """Workspace slug is allowed plaintext at rest (CONTRACT §D)."""
        store = _store()
        store.set_workspace("user-1", "my-workspace")
        assert store._mem_ws[WS_KEY_PREFIX + "user-1"] == "my-workspace"

    def test_empty_sub_workspace_is_noop(self):
        store = _store()
        assert store.get_workspace("") is None


class TestRedisBackend:
    """Exercise the Redis code path with fakeredis (no live server)."""

    def _redis_store(self):
        import fakeredis

        return PatStore(fernet=Fernet(derive_fernet_key("unit-test-secret")), redis_client=fakeredis.FakeStrictRedis())

    def test_redis_round_trip_and_encryption(self):
        store = self._redis_store()
        store.set_pat("user-1", "plane_api_RED")
        assert store.get_pat("user-1") == "plane_api_RED"

        # Stored bytes in Redis are ciphertext, not plaintext.
        raw = store._redis.get(PAT_KEY_PREFIX + "user-1")
        assert raw is not None
        assert b"plane_api_RED" not in raw

        store.set_workspace("user-1", "acme")
        assert store.get_workspace("user-1") == "acme"

        store.delete("user-1")
        assert store.get_pat("user-1") is None
        assert store.get_workspace("user-1") is None

    def test_redis_per_user_isolation(self):
        store = self._redis_store()
        store.set_pat("user-a", "pat-A")
        store.set_pat("user-b", "pat-B")
        assert store.get_pat("user-a") == "pat-A"
        assert store.get_pat("user-b") == "pat-B"
        store.delete("user-a")
        assert store.get_pat("user-a") is None
        assert store.get_pat("user-b") == "pat-B"
