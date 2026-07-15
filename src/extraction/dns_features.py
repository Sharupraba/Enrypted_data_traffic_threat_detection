import math
import numpy as np

def calculate_shannon_entropy(s: str) -> float:
    """
    Calculates the Shannon entropy of a string (domain label).
    """
    if not s:
        return 0.0
    char_counts = {}
    for c in s:
        char_counts[c] = char_counts.get(c, 0) + 1
    total_chars = len(s)
    entropy = -sum((count / total_chars) * math.log2(count / total_chars) for count in char_counts.values())
    return float(entropy)

def extract_dns_features(flow: dict) -> dict:
    """
    Extracts DNS metrics such as query frequency, domain entropy, and NXDOMAIN rates.
    """
    fwd_pkts = flow.get("fwd_packets", [])
    bwd_pkts = flow.get("bwd_packets", [])
    all_pkts = fwd_pkts + bwd_pkts
    
    dns_domain = None
    dns_query_frequency = 0.0
    domain_entropy = 0.0
    nxdomain_rate = 0.0
    dns_response_count = 0
    subdomain_level = 0
    
    qnames = []
    rcodes = []
    queries_count = 0
    responses_count = 0
    
    for p in all_pkts:
        dns_info = p.get("dns_info")
        if dns_info:
            q = dns_info.get("qr")
            if q == 0:  # query
                queries_count += 1
                if dns_info.get("qname"):
                    qnames.append(dns_info["qname"])
            elif q == 1:  # response
                responses_count += 1
                rcode = dns_info.get("rcode")
                if rcode is not None:
                    rcodes.append(rcode)
                    
    if qnames:
        dns_domain = qnames[0]
        subdomain_level = max(0, len(dns_domain.split(".")) - 2)
        domain_entropy = calculate_shannon_entropy(dns_domain)
        
    duration = flow.get("duration", 0.0)
    if duration > 0:
        dns_query_frequency = queries_count / duration
        
    if rcodes:
        nxdomain_count = sum(1 for r in rcodes if r == 3)  # 3 = NXDOMAIN (non-existent domain)
        nxdomain_rate = nxdomain_count / len(rcodes)
        
    return {
        "dns_domain": dns_domain,
        "dns_query_frequency": dns_query_frequency,
        "domain_entropy": domain_entropy,
        "nxdomain_rate": nxdomain_rate,
        "dns_response_count": responses_count,
        "subdomain_level": subdomain_level
    }
