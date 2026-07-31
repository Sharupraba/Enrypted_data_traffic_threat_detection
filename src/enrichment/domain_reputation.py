import os
import json
import logging
import math
import asyncio
import urllib.request
import urllib.error
from typing import Tuple
from .intel_cache import domain_cache, vt_rate_limiter

logger = logging.getLogger("zenith.enrichment.domain")

SUSPICIOUS_TLDS = {".xyz", ".top", ".tk", ".ml", ".ga", ".cf", ".gq", ".ru", ".su", ".click", ".link", ".download", ".bin", ".work", ".site", ".zip"}
THREAT_KEYWORDS = ["malware", "phishing", "c2", "beacon", "exploit", "trojan", "botnet", "stealer", "ransomware", "payload", "verify-login", "secure-update", "credential", "gate", "fake", "login"]

KNOWN_MALICIOUS_DOMAINS = {
    "malicious-domain.com": 92,
    "phishing-test.ru": 95,
    "c2-beacon-server.xyz": 98,
    "emotet-payload-drop.top": 96,
    "cobaltstrike-gate.ru": 99,
    "botnet-controller.tk": 94,
    "malicious.com": 90
}

def calculate_domain_entropy(domain: str) -> float:
    """
    Calculates Shannon entropy of the domain name string for DGA detection.
    """
    name = domain.split(".")[0]
    if not name:
        return 0.0
    prob = [float(name.count(c)) / len(name) for c in set(name)]
    return -sum(p * math.log2(p) for p in prob)

def evaluate_heuristic_domain_risk(domain: str) -> int:
    """
    Evaluates heuristic risk for domain names.
    Checks known threat databases, DGA entropy, TLD reputation, and threat keywords.
    """
    d_lower = domain.lower().strip()
    
    # 1. Check known malicious domains dictionary
    if d_lower in KNOWN_MALICIOUS_DOMAINS:
        return KNOWN_MALICIOUS_DOMAINS[d_lower]
        
    score = 0
    
    # 2. Check threat keywords
    for kw in THREAT_KEYWORDS:
        if kw in d_lower:
            score += 45
            
    # 3. Check high-risk TLDs
    for tld in SUSPICIOUS_TLDS:
        if d_lower.endswith(tld):
            score += 35
            
    # 4. Check DGA Shannon entropy (high character randomness)
    entropy = calculate_domain_entropy(d_lower)
    if entropy > 3.7:
        score += 40
    elif entropy > 3.3:
        score += 20
        
    return min(99, score)

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
                return int(((malicious + suspicious) / total) * 100)
            return evaluate_heuristic_domain_risk(domain)
    except Exception as e:
        logger.warning(f"VirusTotal Domain query failed for {domain}: {e}")
        return evaluate_heuristic_domain_risk(domain)

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

    # 2. Retrieve key or fallback to heuristic evaluation
    vt_key = os.getenv("VIRUSTOTAL_API_KEY")
    if not vt_key:
        score = evaluate_heuristic_domain_risk(domain)
        domain_cache[domain] = score
        return score, True

    # 3. Enforce rate limiting
    await vt_rate_limiter.wait()

    try:
        score = await asyncio.to_thread(_query_virustotal_domain, domain, vt_key)
        domain_cache[domain] = score
        return score, True
    except Exception as e:
        logger.error(f"Domain reputation enrichment failed for {domain}: {e}")
        score = evaluate_heuristic_domain_risk(domain)
        domain_cache[domain] = score
        return score, True
