"""
Fernet-encrypted tenant secret store.

Secrets are stored in the `tenant_secrets` table as Fernet ciphertext.
The encryption key is loaded from the SECRET_ENCRYPTION_KEY environment variable
(base64-urlsafe Fernet key, 32 bytes → 44 chars after encoding).

Generate a key:
    python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"

If the env var is absent in development, a warning is emitted and a per-process
ephemeral key is used (secrets will not survive restarts).  In production mode
(ENVIRONMENT=production) the key is required — startup raises RuntimeError.
"""
import asyncio
import logging
import os

from cryptography.fernet import Fernet, InvalidToken
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from models import TenantSecret

log = logging.getLogger(__name__)

_RAW_KEY = os.getenv("SECRET_ENCRYPTION_KEY", "")

if not _RAW_KEY:
    if os.getenv("ENVIRONMENT", "development") == "production":
        raise RuntimeError(
            "SECRET_ENCRYPTION_KEY must be set in production. "
            "Run: python -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\""
        )
    _ephemeral_key = Fernet.generate_key()
    log.warning(
        "SECRET_ENCRYPTION_KEY not set — using ephemeral key. "
        "Secrets will not survive process restarts."
    )
    _fernet = Fernet(_ephemeral_key)
else:
    _fernet = Fernet(_RAW_KEY.encode())


def _encrypt(plaintext: str) -> str:
    return _fernet.encrypt(plaintext.encode()).decode()


def _decrypt(ciphertext: str) -> str:
    return _fernet.decrypt(ciphertext.encode()).decode()


async def get_secret(session: AsyncSession, tenant_id: str, key: str) -> str | None:
    """Return the decrypted secret value, or None if not found."""
    stmt = (
        select(TenantSecret)
        .where(TenantSecret.tenant_id == tenant_id, TenantSecret.key == key)
    )
    result = await session.execute(stmt)
    row = result.scalar_one_or_none()
    if row is None:
        return None
    try:
        return _decrypt(row.value_enc)
    except InvalidToken:
        log.error("Failed to decrypt secret key=%s tenant=%s — key mismatch?", key, tenant_id)
        return None


async def set_secret(session: AsyncSession, tenant_id: str, key: str, value: str) -> None:
    """Upsert an encrypted secret for a tenant."""
    from datetime import datetime, timezone

    stmt = (
        select(TenantSecret)
        .where(TenantSecret.tenant_id == tenant_id, TenantSecret.key == key)
    )
    result = await session.execute(stmt)
    row = result.scalar_one_or_none()

    ciphertext = _encrypt(value)
    now = datetime.now(timezone.utc)

    if row is None:
        row = TenantSecret(
            tenant_id=tenant_id,
            key=key,
            value_enc=ciphertext,
            updated_at=now,
        )
        session.add(row)
    else:
        row.value_enc = ciphertext
        row.updated_at = now

    await session.flush()


def get_connector_secret(key: str, default: str = "") -> str:
    """Sync helper for connector/agent code to read a per-tenant secret.

    Resolution order:
    1. If a tenant_id is active in the current context, try the vault first.
    2. Fall back to ``os.getenv(key, default)`` on any error or when no
       tenant is set (preserves full backward-compatibility with env-only setups).

    Uses the same ``_run_async`` pattern as other sync→async bridges in the
    codebase (see mdm_agent, policy_lifecycle, etc.).
    """
    from tenant_context import get_current_tenant_id

    tenant_id = get_current_tenant_id()
    if not tenant_id:
        return os.getenv(key, default)

    async def _fetch() -> str | None:
        from database import AsyncSessionLocal

        async with AsyncSessionLocal() as session:
            return await get_secret(session, tenant_id, key)

    def _run_async(coro):
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                import concurrent.futures
                future = asyncio.run_coroutine_threadsafe(coro, loop)
                return future.result(timeout=10)
            else:
                return loop.run_until_complete(coro)
        except RuntimeError:
            return asyncio.run(coro)

    try:
        value = _run_async(_fetch())
        if value is not None:
            return value
    except Exception:
        log.debug(
            "get_connector_secret: vault lookup failed for key=%s tenant=%s — using env fallback",
            key,
            tenant_id,
        )

    return os.getenv(key, default)


async def set_oauth_token(
    session: AsyncSession,
    tenant_id: str,
    provider: str,
    access_token: str,
    expires_in: int,
    refresh_token: str = "",
) -> None:
    """Store OAuth tokens in vault with computed expiry timestamp.

    Writes up to three keys per provider:
      {PROVIDER}_ACCESS_TOKEN  — the bearer token
      {PROVIDER}_TOKEN_EXPIRY  — ISO 8601 UTC datetime when the access token expires
      {PROVIDER}_REFRESH_TOKEN — for refreshing (written only when non-empty)
    """
    from datetime import datetime, timezone, timedelta

    expiry = datetime.now(timezone.utc) + timedelta(seconds=expires_in)
    prefix = provider.upper()
    await set_secret(session, tenant_id, f"{prefix}_ACCESS_TOKEN", access_token)
    await set_secret(session, tenant_id, f"{prefix}_TOKEN_EXPIRY", expiry.isoformat())
    if refresh_token:
        await set_secret(session, tenant_id, f"{prefix}_REFRESH_TOKEN", refresh_token)


async def get_oauth_token(
    session: AsyncSession,
    tenant_id: str,
    provider: str,
    refresh_url: str = "",
    client_id: str = "",
    client_secret_key: str = "",
    buffer_seconds: int = 300,
) -> str | None:
    """Return a valid access token for the provider, refreshing if expired.

    If the stored token is missing or within ``buffer_seconds`` of expiry and
    ``refresh_url`` is provided, attempts an RFC 6749 refresh_token grant.
    Returns None if no valid token is available after the refresh attempt.
    """
    from datetime import datetime, timezone, timedelta
    import httpx

    prefix = provider.upper()
    access_token = await get_secret(session, tenant_id, f"{prefix}_ACCESS_TOKEN")
    expiry_str = await get_secret(session, tenant_id, f"{prefix}_TOKEN_EXPIRY")

    if access_token and expiry_str:
        try:
            expiry = datetime.fromisoformat(expiry_str)
            if expiry.tzinfo is None:
                expiry = expiry.replace(tzinfo=timezone.utc)
            if datetime.now(timezone.utc) < expiry - timedelta(seconds=buffer_seconds):
                return access_token  # still valid
        except ValueError:
            pass  # malformed expiry — fall through to refresh

    # Attempt refresh
    if not refresh_url:
        return access_token  # no refresh configured — return what we have (may be None)

    refresh_token = await get_secret(session, tenant_id, f"{prefix}_REFRESH_TOKEN")
    if not refresh_token:
        log.warning(
            "OAuth refresh: no refresh_token for provider=%s tenant=%s", provider, tenant_id
        )
        return None

    client_sec = ""
    if client_secret_key:
        client_sec = await get_secret(session, tenant_id, client_secret_key) or ""

    try:
        async with httpx.AsyncClient(timeout=15) as http:
            resp = await http.post(
                refresh_url,
                data={
                    "grant_type": "refresh_token",
                    "refresh_token": refresh_token,
                    "client_id": client_id,
                    "client_secret": client_sec,
                },
            )
            resp.raise_for_status()
            data = resp.json()
            new_access = data["access_token"]
            new_expires_in = int(data.get("expires_in", 3600))
            new_refresh = data.get("refresh_token", refresh_token)  # some providers rotate it
            await set_oauth_token(
                session, tenant_id, provider, new_access, new_expires_in, new_refresh
            )
            log.info(
                "OAuth refresh: refreshed token for provider=%s tenant=%s", provider, tenant_id
            )
            return new_access
    except Exception as exc:
        log.error(
            "OAuth refresh failed for provider=%s tenant=%s: %s", provider, tenant_id, exc
        )
        return None


async def delete_secret(session: AsyncSession, tenant_id: str, key: str) -> bool:
    """Delete a secret. Returns True if it existed."""
    stmt = (
        select(TenantSecret)
        .where(TenantSecret.tenant_id == tenant_id, TenantSecret.key == key)
    )
    result = await session.execute(stmt)
    row = result.scalar_one_or_none()
    if row is None:
        return False
    await session.delete(row)
    await session.flush()
    return True
