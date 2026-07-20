import logging

logger = logging.getLogger("zenith.detection.multiclass")

ATTACK_CATEGORIES = [
    "Benign",
    "DDoS",
    "PortScan",
    "Botnet",
    "Web Attack",
    "Exfiltration",
    "Infiltration"
]

def classify_attack_category(features: dict, ml_classification: str, ml_confidence: float) -> dict:
    """
    Evaluates multi-class attack categorization based on flow volume, timing patterns,
    TCP flag distributions, and port behaviors.
    
    Returns:
        {
            "attack_category": str,
            "category_confidence": float
        }
    """
    if ml_classification != "Threat":
        return {
            "attack_category": "Benign",
            "category_confidence": round(100.0 - ml_confidence, 1)
        }

    # Extract metrics for multi-class classification
    packets_per_sec = float(features.get("packets_per_sec", 0.0))
    bytes_per_sec = float(features.get("bytes_per_sec", 0.0))
    syn_count = int(features.get("syn_count", 0))
    total_packets = int(features.get("total_packets", 0))
    bytes_sent = int(features.get("bytes_sent", 0))
    bytes_received = int(features.get("bytes_received", 0))
    dst_port = int(features.get("dst_port", 0))
    down_up_ratio = float(features.get("down_up_ratio", 1.0))
    domain_entropy = float(features.get("domain_entropy", 0.0))
    burst_count = int(features.get("burst_count", 0))
    psh_count = int(features.get("psh_count", 0))

    # 1. DDoS Attack Signature (high throughput, flooding rates)
    if packets_per_sec > 500 or syn_count > 30 or bytes_per_sec > 2_000_000:
        return {
            "attack_category": "DDoS",
            "category_confidence": round(min(99.9, ml_confidence + 5.0), 1)
        }

    # 2. PortScan Reconnaissance Signature (high SYN ratio, small packet counts)
    if syn_count >= 1 and total_packets <= 12 and (bytes_sent < 2000 and bytes_received < 2000):
        return {
            "attack_category": "PortScan",
            "category_confidence": round(min(99.9, ml_confidence + 3.0), 1)
        }

    # 3. Exfiltration Signature (high upload asymmetry)
    if bytes_sent > 1_000_000 and down_up_ratio < 0.15:
        return {
            "attack_category": "Exfiltration",
            "category_confidence": round(min(99.9, ml_confidence + 4.0), 1)
        }

    # 4. Infiltration Signature (heavy download payload transfer)
    if bytes_received > 5_000_000 and down_up_ratio > 5.0:
        return {
            "attack_category": "Infiltration",
            "category_confidence": round(min(99.9, ml_confidence + 2.0), 1)
        }

    # 5. Web Attack Signature (HTTP/S targets with high PSH or domain entropy)
    if dst_port in [80, 443, 8080, 8443] and (psh_count > 8 or domain_entropy > 3.8):
        return {
            "attack_category": "Web Attack",
            "category_confidence": round(ml_confidence, 1)
        }

    # 6. Botnet / Command & Control Signature (periodic bursts, C2 beaconing)
    if burst_count > 5 or features.get("ja3_hash"):
        return {
            "attack_category": "Botnet",
            "category_confidence": round(ml_confidence, 1)
        }

    # Default Threat Category fallback
    return {
        "attack_category": "Botnet",
        "category_confidence": round(ml_confidence, 1)
    }
