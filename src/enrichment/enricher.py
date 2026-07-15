import asyncio
import logging
from typing import Dict
from .ip_reputation import check_ip_reputation
from .domain_reputation import check_domain_reputation
from .ja3_lookup import lookup_ja3
from .cert_checker import assess_certificate

logger = logging.getLogger("zenith.enrichment.orchestrator")

async def enrich_threat(prediction_dict: dict) -> dict:
    """
    Enriches ML threat alerts with reputational intelligence.
    Only runs if the prediction is classified as 'Threat'.
    """
    res = dict(prediction_dict)
    
    # If not a threat, skip enrichment and return standard fields
    if prediction_dict.get("classification") != "Threat":
        res.update({
            "ip_reputation_score": 0,
            "domain_reputation_score": 0,
            "ja3_match": False,
            "ja3_match_score": 0,
            "ja3_threat_label": None,
            "cert_risk_score": 0,
            "enrichment_available": True
        })
        return res

    src_ip = prediction_dict.get("src_ip")
    dst_ip = prediction_dict.get("dst_ip")
    sni = prediction_dict.get("sni")
    ja3_hash = prediction_dict.get("ja3_hash")

    # Run reputation queries in parallel
    tasks = []
    
    # IP queries (checks both source and destination reputation)
    ip_to_check = []
    if dst_ip:
        ip_to_check.append(dst_ip)
    if src_ip:
        ip_to_check.append(src_ip)
        
    for ip in ip_to_check:
        tasks.append(check_ip_reputation(ip))
        
    # Domain query
    if sni:
        tasks.append(check_domain_reputation(sni))
    else:
        # Dummy task yielding clean domain reputation
        tasks.append(asyncio.sleep(0, result=(0, True)))

    logger.info(f"Enriching threat flow {prediction_dict.get('flow_id')} (IPs={ip_to_check}, SNI={sni})...")

    try:
        query_results = await asyncio.gather(*tasks)
        
        # Aggregate IP reputation
        ip_score = 0
        enrichment_available = True
        
        # First elements are IP check results
        num_ips = len(ip_to_check)
        for i in range(num_ips):
            score, ok = query_results[i]
            ip_score = max(ip_score, score)
            if not ok:
                enrichment_available = False
                
        # Last element is Domain check result
        domain_score, domain_ok = query_results[-1]
        if not domain_ok:
            enrichment_available = False
            
    except Exception as e:
        logger.error(f"Enrichment orchestration failed: {e}")
        ip_score = 0
        domain_score = 0
        enrichment_available = False

    # JA3 lookup (local, synchronous)
    ja3_res = lookup_ja3(ja3_hash)

    # Certificate check (local, synchronous)
    cert_res = assess_certificate(prediction_dict)

    res.update({
        "ip_reputation_score": ip_score,
        "domain_reputation_score": domain_score,
        "ja3_match": ja3_res["ja3_match"],
        "ja3_match_score": ja3_res["ja3_match_score"],
        "ja3_threat_label": ja3_res["ja3_threat_label"],
        "cert_risk_score": cert_res["cert_risk_score"],
        "enrichment_available": enrichment_available
    })

    logger.info(f"Enrichment complete. IP Score: {ip_score}, Domain Score: {domain_score}, JA3 Match: {ja3_res['ja3_match']}")
    return res
