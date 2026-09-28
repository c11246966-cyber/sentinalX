"""Redis client and connection management for SentinelX."""

from typing import Optional
import redis.asyncio as aioredis
from backend.app.core.config import settings
from backend.app.core.logging import logger

redis_client: Optional[aioredis.Redis] = None


async def get_redis() -> aioredis.Redis:
    """Retrieve the global Redis async client instance."""
    global redis_client
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
            raise
    return redis_client


async def close_redis() -> None:
    """Close Redis client connection on shutdown."""
    global redis_client
    if redis_client is not None:
        await redis_client.close()
        redis_client = None
        logger.info("Redis client disconnected.")
