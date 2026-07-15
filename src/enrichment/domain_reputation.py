import os
import json
import logging
import asyncio
import urllib.request
import urllib.error
from typing import Tuple
from .intel_cache import domain_cache, vt_rate_limiter

logger = logging.getLogger("zenith.enrichment.domain")

def _query_virustotal_domain(domain: str, api_key: str) -> int:
    """
    Synchronous helper to check domain reputation via VirusTotal.
    """
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    req = urllib.request.Request(url)
    req.add_header("x-apikey", api_key)
    
    try:
        with urllib.request.urlopen(req, timeout=5) as response:
            res = json.loads(response.read().decode())
            stats = res["data"]["attributes"]["last_analysis_stats"]
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            total = sum(stats.values())
            if total > 0 and (malicious + suspicious) > 0:
                # Returns percentage of malicious votes
                return int(((malicious + suspicious) / total) * 100)
            return 0
    except Exception as e:
        logger.warning(f"VirusTotal Domain query failed for {domain}: {e}")
        return 0

async def check_domain_reputation(domain: str) -> Tuple[int, bool]:
    """
    Enriches threat alerts with domain reputation scores.
    Returns: (score [0-100], enrichment_available)
    """
    if not domain:
        return 0, True

    # 1. Check local TTL cache (6 hours)
    if domain in domain_cache:
        return domain_cache[domain], True

    # 2. Retrieve key
    vt_key = os.getenv("VIRUSTOTAL_API_KEY")
    if not vt_key:
        return 0, False

    # 3. Enforce rate limiting
    await vt_rate_limiter.wait()

    try:
        score = await asyncio.to_thread(_query_virustotal_domain, domain, vt_key)
        
        # Save to local TTL cache
        domain_cache[domain] = score
        return score, True
    except Exception as e:
        logger.error(f"Domain reputation enrichment failed for {domain}: {e}")
        return 0, False
