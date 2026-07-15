from .flow_features import extract_flow_features
from .tcp_features import extract_tcp_features
from .timing_features import extract_timing_features
from .tls_features import extract_tls_features
from .dns_features import extract_dns_features

def extract_features(flow: dict) -> dict:
    """
    Orchestrates all metadata extraction modules and builds a single flat dictionary.
    """
    if hasattr(flow, "to_dict"):
        flow_dict = flow.to_dict()
    else:
        flow_dict = flow

    features = {}
    features.update(extract_flow_features(flow_dict))
    features.update(extract_tcp_features(flow_dict))
    features.update(extract_timing_features(flow_dict))
    features.update(extract_tls_features(flow_dict))
    features.update(extract_dns_features(flow_dict))
    
    # Attach tracking identifiers
    features["flow_id"] = flow_dict.get("flow_id")
    features["src_ip"] = flow_dict.get("src_ip")
    features["dst_ip"] = flow_dict.get("dst_ip")
    features["src_port"] = flow_dict.get("src_port")
    features["dst_port"] = flow_dict.get("dst_port")
    features["protocol"] = flow_dict.get("protocol")
    features["timestamp"] = flow_dict.get("start_time")
    
    return features
