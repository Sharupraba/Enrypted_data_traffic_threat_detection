import numpy as np

def extract_flow_features(flow: dict) -> dict:
    """
    Computes statistical flow features from forward and backward packet lists.
    """
    fwd_pkts = flow.get("fwd_packets", [])
    bwd_pkts = flow.get("bwd_packets", [])
    
    total_fwd_packets = len(fwd_pkts)
    total_bwd_packets = len(bwd_pkts)
    total_packets = total_fwd_packets + total_bwd_packets
    
    fwd_sizes = [p["pkt_len"] for p in fwd_pkts]
    bwd_sizes = [p["pkt_len"] for p in bwd_pkts]
    all_sizes = fwd_sizes + bwd_sizes
    
    bytes_sent = sum(fwd_sizes)
    bytes_received = sum(bwd_sizes)
    total_bytes = bytes_sent + bytes_received
    
    flow_duration = flow.get("duration", 0.0)
    
    avg_fwd_packet_size = float(np.mean(fwd_sizes)) if fwd_sizes else 0.0
    avg_bwd_packet_size = float(np.mean(bwd_sizes)) if bwd_sizes else 0.0
    avg_packet_size = float(np.mean(all_sizes)) if all_sizes else 0.0
    
    fwd_pkt_size_std = float(np.std(fwd_sizes)) if len(fwd_sizes) > 1 else 0.0
    bwd_pkt_size_std = float(np.std(bwd_sizes)) if len(bwd_sizes) > 1 else 0.0
    
    fwd_pkt_size_max = float(np.max(fwd_sizes)) if fwd_sizes else 0.0
    fwd_pkt_size_min = float(np.min(fwd_sizes)) if fwd_sizes else 0.0
    bwd_pkt_size_max = float(np.max(bwd_sizes)) if bwd_sizes else 0.0
    bwd_pkt_size_min = float(np.min(bwd_sizes)) if bwd_sizes else 0.0
    
    if flow_duration > 0:
        packets_per_sec = total_packets / flow_duration
        bytes_per_sec = total_bytes / flow_duration
        fwd_bytes_per_sec = bytes_sent / flow_duration
        bwd_bytes_per_sec = bytes_received / flow_duration
    else:
        packets_per_sec = 0.0
        bytes_per_sec = 0.0
        fwd_bytes_per_sec = 0.0
        bwd_bytes_per_sec = 0.0
        
    return {
        "flow_duration": flow_duration,
        "total_fwd_packets": total_fwd_packets,
        "total_bwd_packets": total_bwd_packets,
        "total_packets": total_packets,
        "bytes_sent": bytes_sent,
        "bytes_received": bytes_received,
        "total_bytes": total_bytes,
        "avg_fwd_packet_size": avg_fwd_packet_size,
        "avg_bwd_packet_size": avg_bwd_packet_size,
        "avg_packet_size": avg_packet_size,
        "fwd_pkt_size_std": fwd_pkt_size_std,
        "bwd_pkt_size_std": bwd_pkt_size_std,
        "fwd_pkt_size_max": fwd_pkt_size_max,
        "fwd_pkt_size_min": fwd_pkt_size_min,
        "bwd_pkt_size_max": bwd_pkt_size_max,
        "bwd_pkt_size_min": bwd_pkt_size_min,
        "packets_per_sec": packets_per_sec,
        "bytes_per_sec": bytes_per_sec,
        "fwd_bytes_per_sec": fwd_bytes_per_sec,
        "bwd_bytes_per_sec": bwd_bytes_per_sec
    }
