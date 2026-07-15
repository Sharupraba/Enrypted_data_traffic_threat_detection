def extract_tcp_features(flow: dict) -> dict:
    """
    Computes TCP flag occurrences, flag rates, and direction-specific flag statistics.
    """
    fwd_pkts = flow.get("fwd_packets", [])
    bwd_pkts = flow.get("bwd_packets", [])
    total_packets = len(fwd_pkts) + len(bwd_pkts)
    
    syn_count = 0
    ack_count = 0
    fin_count = 0
    rst_count = 0
    psh_count = 0
    urg_count = 0
    
    fwd_syn_count = 0
    bwd_syn_count = 0
    
    for p in fwd_pkts:
        flags = p.get("tcp_flags") or ""
        if "S" in flags:
            syn_count += 1
            fwd_syn_count += 1
        if "A" in flags:
            ack_count += 1
        if "F" in flags:
            fin_count += 1
        if "R" in flags:
            rst_count += 1
        if "P" in flags:
            psh_count += 1
        if "U" in flags:
            urg_count += 1
            
    for p in bwd_pkts:
        flags = p.get("tcp_flags") or ""
        if "S" in flags:
            syn_count += 1
            bwd_syn_count += 1
        if "A" in flags:
            ack_count += 1
        if "F" in flags:
            fin_count += 1
        if "R" in flags:
            rst_count += 1
        if "P" in flags:
            psh_count += 1
        if "U" in flags:
            urg_count += 1
            
    syn_rate = syn_count / total_packets if total_packets > 0 else 0.0
    rst_rate = rst_count / total_packets if total_packets > 0 else 0.0
    psh_rate = psh_count / total_packets if total_packets > 0 else 0.0
    fin_rst_ratio = (fin_count + rst_count) / total_packets if total_packets > 0 else 0.0
    
    return {
        "syn_count": syn_count,
        "ack_count": ack_count,
        "fin_count": fin_count,
        "rst_count": rst_count,
        "psh_count": psh_count,
        "urg_count": urg_count,
        "syn_rate": syn_rate,
        "rst_rate": rst_rate,
        "psh_rate": psh_rate,
        "fwd_syn_count": fwd_syn_count,
        "bwd_syn_count": bwd_syn_count,
        "fin_rst_ratio": fin_rst_ratio
    }
