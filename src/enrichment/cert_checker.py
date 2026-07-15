def assess_certificate(tls_features: dict) -> dict:
    """
    Evaluates certificate risk based on parsed metadata fields from Phase 3.
    Returns: {"cert_risk_score": int} in the range [0, 100].
    """
    score = 0
    
    if tls_features.get("cert_self_signed"):
        score += 30
    if tls_features.get("cert_expired"):
        score += 25
    if tls_features.get("cert_domain_mismatch"):
        score += 25
    if tls_features.get("cert_is_short_lived"):
        score += 20
        
    return {
        "cert_risk_score": min(score, 100)
    }
