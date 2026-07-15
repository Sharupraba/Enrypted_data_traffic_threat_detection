import asyncio
import time
import logging
from cachetools import TTLCache

logger = logging.getLogger("zenith.enrichment.cache")

# Shared TTLCache instances
# ip_cache: TTL 1 hour (3600 seconds)
# domain_cache: TTL 6 hours (21600 seconds)
# ja3_cache: TTL 24 hours (86400 seconds)
ip_cache = TTLCache(maxsize=10000, ttl=3600)
domain_cache = TTLCache(maxsize=5000, ttl=21600)
ja3_cache = TTLCache(maxsize=50000, ttl=86400)

class AsyncRateLimiter:
    """
    Limits API calls to a strict interval to protect external rate quotas.
    """
    def __init__(self, rate_limit_seconds: float = 15.0):
        self.rate_limit_seconds = rate_limit_seconds
        self.last_called = 0.0
        self._lock = asyncio.Lock()

    async def wait(self):
        async with self._lock:
            now = time.time()
            elapsed = now - self.last_called
            delay = self.rate_limit_seconds - elapsed
            if delay > 0:
                logger.debug(f"Throttling request: sleeping for {delay:.2f}s to respect API rate limits.")
                await asyncio.sleep(delay)
            self.last_called = time.time()

# Single global rate limiter for VirusTotal API key (4 calls/minute)
vt_rate_limiter = AsyncRateLimiter(rate_limit_seconds=15.0)
