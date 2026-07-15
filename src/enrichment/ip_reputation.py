import os
import json
import logging
import asyncio
import urllib.request
import urllib.error
import ipaddress
from typing import Tuple
from .intel_cache import ip_cache, vt_rate_limiter

logger = logging.getLogger("zenith.enrichment.ip")

def _query_abuseipdb(ip: str, api_key: str) -> int:
    """
    Synchronous helper to check IP reputation via AbuseIPDB.
    """
    url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90"
    req = urllib.request.Request(url)
    req.add_header("Key", api_key)
    req.add_header("Accept", "application/json")
    
    try:
        with urllib.request.urlopen(req, timeout=5) as response:
            res = json.loads(response.read().decode())
            return int(res["data"]["abuseConfidenceScore"])
    except Exception as e:
        logger.warning(f"AbuseIPDB query failed for {ip}: {e}")
        return 0

def _query_virustotal(ip: str, api_key: str) -> int:
    """
    Synchronous helper to check IP reputation via VirusTotal.
    """
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
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
        logger.warning(f"VirusTotal IP query failed for {ip}: {e}")
        return 0

async def check_ip_reputation(ip: str) -> Tuple[int, bool]:
    """
    Enriches threat alerts with external IP reputation scores.
    Returns: (score [0-100], enrichment_available)
    """
    # 1. Skip checks for private/local IP addresses
    try:
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.is_private or ip_obj.is_loopback:
            return 0, True
    except ValueError:
        return 0, False

    # 2. Check local TTL cache
    if ip in ip_cache:
        return ip_cache[ip], True

    # 3. Retrieve keys
    abuse_key = os.getenv("ABUSEIPDB_API_KEY")
    vt_key = os.getenv("VIRUSTOTAL_API_KEY")
    
    if not abuse_key and not vt_key:
        logger.debug("No threat intelligence API keys configured. Skipping IP enrichment.")
        return 0, False

    abuse_score = 0
    vt_score = 0
    tasks = []

    # 4. Schedule lookups
    if abuse_key:
        tasks.append(asyncio.to_thread(_query_abuseipdb, ip, abuse_key))
        
    if vt_key:
        # Enforce strict 4 calls/minute limit for VT key
        await vt_rate_limiter.wait()
        tasks.append(asyncio.to_thread(_query_virustotal, ip, vt_key))

    if not tasks:
        return 0, False

    try:
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        idx = 0
        if abuse_key:
            res = results[idx]
            abuse_score = res if isinstance(res, int) else 0
            idx += 1
        if vt_key:
            res = results[idx]
            vt_score = res if isinstance(res, int) else 0
            
        # Combine using maximum score (pessimistic rating)
        final_score = max(abuse_score, vt_score)
        
        # Save to local TTL cache
        ip_cache[ip] = final_score
        return final_score, True
        
    except Exception as e:
        logger.error(f"IP enrichment task orchestration failed for {ip}: {e}")
        return 0, False
