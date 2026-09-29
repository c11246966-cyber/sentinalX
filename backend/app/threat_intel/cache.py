"""Threat Intelligence Redis caching layer with seamless in-memory fallback."""

import json
import time
from typing import Any, Dict, Optional
from backend.app.core.logging import logger
try:
    from backend.app.core.redis import get_redis
except ImportError:
    get_redis = None

try:
    from backend.app.core.config import settings
except ImportError:
    settings = None


class ThreatIntelCache:
    """Manages Redis caching for threat intelligence lookups with local memory backup."""

    _memory_cache: Dict[str, Dict[str, Any]] = {}
    _memory_expiry: Dict[str, float] = {}
    MAX_MEMORY_CACHE_ITEMS = 1000

    @classmethod
    def _make_key(cls, indicator: str, indicator_type: str) -> str:
        clean = indicator.strip().lower()
        return f"sentinelx:intel:{indicator_type}:{clean}"

    @classmethod
    def get_ttl(cls) -> int:
        return int(getattr(settings, "THREAT_INTEL_CACHE_TTL_SECONDS", 3600) if settings else 3600)

    @classmethod
    async def get(cls, indicator: str, indicator_type: str) -> Optional[Dict[str, Any]]:
        """Retrieve cached enrichment payload from Redis or in-memory fallback."""
        key = cls._make_key(indicator, indicator_type)

        # 1. Try Redis
        try:
            client = await get_redis()
            val = await client.get(key)
            if val:
                return json.loads(val)
        except Exception as exc:
            logger.debug(f"Redis cache miss/bypass ({type(exc).__name__}). Checking memory cache.")

        # 2. In-memory fallback
        now = time.time()
        if key in cls._memory_cache:
            if now < cls._memory_expiry.get(key, 0):
                return cls._memory_cache[key]
            else:
                # Expired
                cls._memory_cache.pop(key, None)
                cls._memory_expiry.pop(key, None)

        return None

    @classmethod
    async def set(
        cls,
        indicator: str,
        indicator_type: str,
        data: Dict[str, Any],
        ttl_seconds: Optional[int] = None,
    ) -> None:
        """Cache enrichment result in Redis and in-memory backup."""
        key = cls._make_key(indicator, indicator_type)
        ttl = ttl_seconds if ttl_seconds is not None else cls.get_ttl()
        serialized = json.dumps(data, default=str)

        # 1. Try Redis
        try:
            client = await get_redis()
            await client.setex(key, ttl, serialized)
        except Exception as exc:
            logger.debug(f"Could not persist to Redis cache ({type(exc).__name__}). Using in-memory fallback.")

        # 2. Always maintain in-memory copy
        if len(cls._memory_cache) >= cls.MAX_MEMORY_CACHE_ITEMS:
            # Evict oldest entry
            oldest_key = min(cls._memory_expiry, key=cls._memory_expiry.get, default=None)
            if oldest_key:
                cls._memory_cache.pop(oldest_key, None)
                cls._memory_expiry.pop(oldest_key, None)

        cls._memory_cache[key] = data
        cls._memory_expiry[key] = time.time() + ttl

    @classmethod
    def clear_memory_cache(cls) -> None:
        """Utility for test isolation."""
        cls._memory_cache.clear()
        cls._memory_expiry.clear()
