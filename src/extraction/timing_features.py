import numpy as np

def extract_timing_features(flow: dict) -> dict:
    """
    Computes IAT statistics, active/idle period statistics, and counts burst events.
    """
    fwd_pkts = flow.get("fwd_packets", [])
    bwd_pkts = flow.get("bwd_packets", [])
    
    all_pkts = sorted(fwd_pkts + bwd_pkts, key=lambda x: x["timestamp"])
    
    if len(all_pkts) < 2:
        return {
            "iat_mean": 0.0,
            "iat_std": 0.0,
            "iat_min": 0.0,
            "iat_max": 0.0,
            "fwd_iat_mean": 0.0,
            "fwd_iat_std": 0.0,
            "fwd_iat_min": 0.0,
            "fwd_iat_max": 0.0,
            "bwd_iat_mean": 0.0,
            "bwd_iat_std": 0.0,
            "bwd_iat_min": 0.0,
            "bwd_iat_max": 0.0,
            "burst_count": 0,
            "burst_avg_size": 0.0,
            "active_time_mean": 0.0,
            "idle_time_mean": 0.0
        }
        
    # Overall IATs (ms)
    iats = [(all_pkts[i]["timestamp"] - all_pkts[i-1]["timestamp"]) * 1000.0 for i in range(1, len(all_pkts))]
    iat_mean = float(np.mean(iats))
    iat_std = float(np.std(iats)) if len(iats) > 1 else 0.0
    iat_min = float(np.min(iats))
    iat_max = float(np.max(iats))
    
    # Forward IATs
    fwd_pkts_sorted = sorted(fwd_pkts, key=lambda x: x["timestamp"])
    if len(fwd_pkts_sorted) > 1:
        fwd_iats = [(fwd_pkts_sorted[i]["timestamp"] - fwd_pkts_sorted[i-1]["timestamp"]) * 1000.0 for i in range(1, len(fwd_pkts_sorted))]
        fwd_iat_mean = float(np.mean(fwd_iats))
        fwd_iat_std = float(np.std(fwd_iats)) if len(fwd_iats) > 1 else 0.0
        fwd_iat_min = float(np.min(fwd_iats))
        fwd_iat_max = float(np.max(fwd_iats))
    else:
        fwd_iat_mean = 0.0
        fwd_iat_std = 0.0
        fwd_iat_min = 0.0
        fwd_iat_max = 0.0
        
    # Backward IATs
    bwd_pkts_sorted = sorted(bwd_pkts, key=lambda x: x["timestamp"])
    if len(bwd_pkts_sorted) > 1:
        bwd_iats = [(bwd_pkts_sorted[i]["timestamp"] - bwd_pkts_sorted[i-1]["timestamp"]) * 1000.0 for i in range(1, len(bwd_pkts_sorted))]
        bwd_iat_mean = float(np.mean(bwd_iats))
        bwd_iat_std = float(np.std(bwd_iats)) if len(bwd_iats) > 1 else 0.0
        bwd_iat_min = float(np.min(bwd_iats))
        bwd_iat_max = float(np.max(bwd_iats))
    else:
        bwd_iat_mean = 0.0
        bwd_iat_std = 0.0
        bwd_iat_min = 0.0
        bwd_iat_max = 0.0
        
    # Active/Idle intervals
    active_periods = []
    idle_periods = []
    
    current_period_start = all_pkts[0]["timestamp"]
    current_period_last = all_pkts[0]["timestamp"]
    
    for i in range(1, len(all_pkts)):
        iat = (all_pkts[i]["timestamp"] - all_pkts[i-1]["timestamp"]) * 1000.0
        if iat > 100.0:  # idle interval: > 100ms
            active_periods.append(current_period_last - current_period_start)
            idle_periods.append(iat / 1000.0)  # in seconds
            current_period_start = all_pkts[i]["timestamp"]
            
        current_period_last = all_pkts[i]["timestamp"]
        
    active_periods.append(current_period_last - current_period_start)
    
    # Compute bursts
    burst_count = 0
    burst_sizes = []
    current_burst_size = 0
    
    for iat in iats:
        if iat < 10.0:
            if current_burst_size == 0:
                current_burst_size = 2
            else:
                current_burst_size += 1
        else:
            if current_burst_size > 0:
                burst_count += 1
                burst_sizes.append(current_burst_size)
                current_burst_size = 0
                
    if current_burst_size > 0:
        burst_count += 1
        burst_sizes.append(current_burst_size)
        
    burst_avg_size = float(np.mean(burst_sizes)) if burst_sizes else 0.0
    active_time_mean = float(np.mean(active_periods)) if active_periods else 0.0
    idle_time_mean = float(np.mean(idle_periods)) if idle_periods else 0.0
    
    return {
        "iat_mean": iat_mean,
        "iat_std": iat_std,
        "iat_min": iat_min,
        "iat_max": iat_max,
        "fwd_iat_mean": fwd_iat_mean,
        "fwd_iat_std": fwd_iat_std,
        "fwd_iat_min": fwd_iat_min,
        "fwd_iat_max": fwd_iat_max,
        "bwd_iat_mean": bwd_iat_mean,
        "bwd_iat_std": bwd_iat_std,
        "bwd_iat_min": bwd_iat_min,
        "bwd_iat_max": bwd_iat_max,
        "burst_count": burst_count,
        "burst_avg_size": burst_avg_size,
        "active_time_mean": active_time_mean,
        "idle_time_mean": idle_time_mean
    }
