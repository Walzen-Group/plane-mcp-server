"""Per-user Plane PAT store for the Authentik-OIDC connector.

Maps a verified Authentik identity (``sub``) to that user's Plane Personal Access
Token (PAT) and chosen workspace slug. In OIDC mode the IdP token is **not** a Plane
credential, so ``client.py`` resolves the PAT from here, per request, by ``sub``.

Design (CONTRACT §D):
- **Sync** interface — called from the sync ``get_plane_client_context()`` (which
  FastMCP runs in an anyio worker thread, so a sync Redis read does not block the
  event loop) and from the async provision routes. Short socket timeouts bound the
  worst case.
- Backends: Redis (reuse the ``REDIS_*`` env, same selection idea as
  ``storage.build_token_store``) or an in-memory dict fallback (dev only).
- Keys: ``mcp:pat:{sub}`` and ``mcp:ws:{sub}``.
- PAT values are **Fernet-encrypted** at rest with a key derived from
  ``MCP_PAT_ENCRYPTION_KEY`` (fallback: derived from ``AUTHENTIK_CLIENT_SECRET`` with
  a warning). Workspace slugs are stored plaintext. PATs are never logged.
"""

from __future__ import annotations

import base64
import os

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from fastmcp.utilities.logging import get_logger

logger = get_logger(__name__)

PAT_KEY_PREFIX = "mcp:pat:"
WS_KEY_PREFIX = "mcp:ws:"

# Fixed, non-secret salt + iteration count. The encryption strength comes from the
# secret, not the salt; a fixed salt keeps the derived key stable across restarts so
# previously stored PATs remain decryptable.
_KDF_SALT = b"plane-mcp-pat-store-v1"
_KDF_ITERATIONS = 200_000

# Short timeouts so a sync Redis read inside a tool call can't hang the worker thread.
_REDIS_TIMEOUT_SECONDS = 2.0


def derive_fernet_key(secret: str) -> bytes:
    """Derive a urlsafe-base64 32-byte Fernet key from an arbitrary secret.

    Uses PBKDF2-HMAC-SHA256 with a fixed salt so the key is deterministic for a given
    secret (required for decrypting previously stored values).
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=_KDF_SALT,
        iterations=_KDF_ITERATIONS,
    )
    raw = kdf.derive(secret.encode("utf-8"))
    return base64.urlsafe_b64encode(raw)


def _resolve_encryption_secret() -> str:
    """Resolve the secret used to derive the Fernet key (CONTRACT §A/§D)."""
    secret = os.getenv("MCP_PAT_ENCRYPTION_KEY")
    if secret:
        return secret

    fallback = os.getenv("AUTHENTIK_CLIENT_SECRET")
    if fallback:
        logger.warning(
            "MCP_PAT_ENCRYPTION_KEY is not set — deriving the PAT encryption key from "
            "AUTHENTIK_CLIENT_SECRET. Set MCP_PAT_ENCRYPTION_KEY in production so "
            "stored PATs survive a client-secret rotation."
        )
        return fallback

    raise RuntimeError(
        "Cannot derive a PAT encryption key: set MCP_PAT_ENCRYPTION_KEY (or AUTHENTIK_CLIENT_SECRET as a fallback)."
    )


class PatStore:
    """Sync per-user PAT + workspace store with Fernet-encrypted PATs at rest."""

    def __init__(self, *, fernet: Fernet, redis_client=None) -> None:
        self._fernet = fernet
        self._redis = redis_client
        # In-memory fallback holds already-encrypted PAT bytes (str) so both
        # backends share the same encrypt/decrypt path.
        self._mem_pat: dict[str, str] = {}
        self._mem_ws: dict[str, str] = {}

    # --- PAT --------------------------------------------------------------
    def get_pat(self, sub: str) -> str | None:
        """Return the decrypted PAT for ``sub``, or None if unset/undecryptable."""
        if not sub:
            return None
        encrypted = self._read(PAT_KEY_PREFIX + sub, self._mem_pat)
        if encrypted is None:
            return None
        try:
            return self._fernet.decrypt(encrypted.encode("utf-8")).decode("utf-8")
        except (InvalidToken, ValueError):
            # Key rotated or corrupt value — treat as unlinked rather than leaking.
            logger.warning("Stored PAT for user could not be decrypted; treating as unlinked.")
            return None

    def set_pat(self, sub: str, pat: str) -> None:
        """Encrypt and store the PAT for ``sub``. Never logs the PAT value."""
        if not sub:
            raise ValueError("sub is required")
        if not pat:
            raise ValueError("pat is required")
        encrypted = self._fernet.encrypt(pat.encode("utf-8")).decode("utf-8")
        self._write(PAT_KEY_PREFIX + sub, encrypted, self._mem_pat)

    def delete(self, sub: str) -> None:
        """Remove both the PAT and workspace mapping for ``sub``."""
        if not sub:
            return
        self._delete(PAT_KEY_PREFIX + sub, self._mem_pat)
        self._delete(WS_KEY_PREFIX + sub, self._mem_ws)

    # --- Workspace --------------------------------------------------------
    def get_workspace(self, sub: str) -> str | None:
        """Return the stored workspace slug for ``sub``, or None."""
        if not sub:
            return None
        return self._read(WS_KEY_PREFIX + sub, self._mem_ws)

    def set_workspace(self, sub: str, slug: str) -> None:
        """Store the workspace slug (plaintext) for ``sub``."""
        if not sub:
            raise ValueError("sub is required")
        self._write(WS_KEY_PREFIX + sub, slug, self._mem_ws)

    # --- Backend helpers --------------------------------------------------
    def _read(self, key: str, mem: dict[str, str]) -> str | None:
        if self._redis is not None:
            value = self._redis.get(key)
            if value is None:
                return None
            return value.decode("utf-8") if isinstance(value, bytes) else value
        return mem.get(key)

    def _write(self, key: str, value: str, mem: dict[str, str]) -> None:
        if self._redis is not None:
            self._redis.set(key, value)
        else:
            mem[key] = value

    def _delete(self, key: str, mem: dict[str, str]) -> None:
        if self._redis is not None:
            self._redis.delete(key)
        else:
            mem.pop(key, None)


def build_pat_store() -> PatStore:
    """Build a :class:`PatStore` from the environment (Redis or in-memory).

    Backend selection mirrors ``storage.build_token_store`` precedence: use Redis
    when ``REDIS_HOST``/``REDIS_PORT`` are configured (with an optional password),
    otherwise fall back to an in-memory dict (dev only). The Fernet key is derived
    from ``MCP_PAT_ENCRYPTION_KEY`` (fallback: ``AUTHENTIK_CLIENT_SECRET``).
    """
    fernet = Fernet(derive_fernet_key(_resolve_encryption_secret()))

    redis_host = os.getenv("REDIS_HOST")
    redis_port = os.getenv("REDIS_PORT")
    if redis_host and redis_port:
        import redis  # local import: only when Redis is configured

        password = os.getenv("REDIS_PASSWORD") or None
        use_ssl = (os.getenv("REDIS_SSL") or "").strip().lower() in {"1", "true", "yes", "on"}
        client = redis.Redis(
            host=redis_host,
            port=int(redis_port),
            password=password,
            ssl=use_ssl,
            socket_connect_timeout=_REDIS_TIMEOUT_SECONDS,
            socket_timeout=_REDIS_TIMEOUT_SECONDS,
        )
        logger.info(
            "PAT store: Redis (host=%s, port=%s, ssl=%s, auth=%s)",
            redis_host,
            redis_port,
            use_ssl,
            "password" if password else "none",
        )
        return PatStore(fernet=fernet, redis_client=client)

    logger.warning("PAT store: in-memory (mappings lost on restart). Set REDIS_HOST and REDIS_PORT for production.")
    return PatStore(fernet=fernet)


# Module singleton so client.py and provisioning share one instance.
_pat_store: PatStore | None = None


def get_pat_store() -> PatStore:
    """Return the process-wide :class:`PatStore`, building it on first use.

    This is the public accessor the ``provision`` agent and ``client.py`` consume.
    """
    global _pat_store
    if _pat_store is None:
        _pat_store = build_pat_store()
    return _pat_store
