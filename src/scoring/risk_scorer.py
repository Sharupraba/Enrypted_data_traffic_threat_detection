import logging

logger = logging.getLogger("zenith.scoring")

def compute_tls_risk_score(tls_features: dict) -> int:
    """
    Computes an additive TLS risk score based on version and certificate anomalies.
    Capped at 100.
    """
    score = 0
    
    # 1. TLS Version check
    version = tls_features.get("tls_version") or ""
    if version:
        try:
            version_val = int(version, 16)
            if version_val < 0x0303:  # TLS < 1.2
                score += 40
            elif version_val == 0x0303:  # TLS 1.2
                score += 15
        except ValueError:
            pass
            
    # 2. Certificate flags
    if tls_features.get("cert_self_signed"):
        score += 30
    if tls_features.get("cert_expired"):
        score += 25
    if tls_features.get("cert_domain_mismatch"):
        score += 25
    if tls_features.get("cert_is_short_lived"):
        score += 20
        
    return min(score, 100)

def compute_risk_score(enriched_flow: dict) -> dict:
    """
    Main scoring entry point. Combines ML confidence, threat intelligence,
    and TLS risk scores using a weighted formula. Supports fallback weights
    if external enrichment APIs are unavailable.
    """
    classification = enriched_flow.get("classification", "Benign")
    
    # Normal/Benign flows get a safe rating immediately
    if classification != "Threat":
        return {
            "risk_score": 0,
            "severity": "Safe",
            "ml_contribution": 0.0,
            "ti_contribution": 0.0,
            "tls_contribution": 0.0,
            "ml_confidence_score": 0,
            "threat_intel_score": 0,
            "tls_risk_score": 0
        }
        
    # ML Confidence Score (0-100)
    ml_confidence_score = float(enriched_flow.get("confidence", 0.0))
    
    # Threat Intelligence Score (0-100)
    ip_score = enriched_flow.get("ip_reputation_score", 0)
    domain_score = enriched_flow.get("domain_reputation_score", 0)
    ja3_match_score = enriched_flow.get("ja3_match_score", 0)
    threat_intel_score = max(ip_score, domain_score, ja3_match_score)
    
    # TLS Risk Score (0-100)
    tls_risk_score = compute_tls_risk_score(enriched_flow)
    
    # Check if enrichment was available
    enrichment_available = enriched_flow.get("enrichment_available", True)
    
    if enrichment_available:
        # Standard weights: 50% ML, 30% Threat Intel, 20% TLS Risk
        ml_weight = 0.50
        ti_weight = 0.30
        tls_weight = 0.20
    else:
        # Fallback weights: 70% ML, 0% Threat Intel, 30% TLS Risk
        ml_weight = 0.70
        ti_weight = 0.00
        tls_weight = 0.30
        
    ml_contribution = ml_confidence_score * ml_weight
    ti_contribution = threat_intel_score * ti_weight
    tls_contribution = tls_risk_score * tls_weight
    
    final_score = int(round(ml_contribution + ti_contribution + tls_contribution))
    final_score = min(max(final_score, 0), 100)
    
    # Severity mapping
    if final_score <= 20:
        severity = "Safe"
    elif final_score <= 40:
        severity = "Low"
    elif final_score <= 60:
        severity = "Medium"
    elif final_score <= 80:
        severity = "High"
    else:
        severity = "Critical"
        
    return {
        "risk_score": final_score,
        "severity": severity,
        "ml_contribution": round(ml_contribution, 1),
        "ti_contribution": round(ti_contribution, 1),
        "tls_contribution": round(tls_contribution, 1),
        "ml_confidence_score": int(ml_confidence_score),
        "threat_intel_score": int(threat_intel_score),
        "tls_risk_score": int(tls_risk_score)
    }
