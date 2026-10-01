"""Redis client and connection management for SentinelX."""

from typing import Any, Optional
try:
    import redis.asyncio as aioredis
    HAS_REDIS = True
except ImportError:
    HAS_REDIS = False
    aioredis = None

try:
    from backend.app.core.config import settings
except ImportError:
    class DummySettings:
        REDIS_URL = "redis://localhost:6379/0"
    settings = DummySettings()
from backend.app.core.logging import logger

redis_client: Optional[Any] = None


async def get_redis():
    """Retrieve the global Redis async client instance with graceful fallback."""
    global redis_client
    if not HAS_REDIS or aioredis is None:
        return None
    if redis_client is None:
        try:
            redis_client = aioredis.from_url(
                settings.REDIS_URL,
                encoding="utf-8",
                decode_responses=True,
                socket_connect_timeout=3.0,
            )
        except Exception as exc:
            logger.warning(f"Could not connect to Redis at {settings.REDIS_URL}: {exc}")
            return None
    return redis_client


async def close_redis() -> None:
    """Close Redis client connection on shutdown."""
    global redis_client
    if redis_client is not None:
        try:
            await redis_client.close()
        except Exception:
            pass
        redis_client = None
        logger.info("Redis client disconnected.")
