import pandas as pd
import numpy as np
from sklearn.impute import SimpleImputer
from sklearn.preprocessing import StandardScaler, MinMaxScaler

# List of raw features generated in Phase 3
RAW_FEATURE_COLS = [
    "flow_duration", "total_fwd_packets", "total_bwd_packets", "total_packets",
    "bytes_sent", "bytes_received", "total_bytes", "avg_fwd_packet_size",
    "avg_bwd_packet_size", "avg_packet_size", "fwd_pkt_size_std", "bwd_pkt_size_std",
    "fwd_pkt_size_max", "fwd_pkt_size_min", "bwd_pkt_size_max", "bwd_pkt_size_min",
    "packets_per_sec", "bytes_per_sec", "fwd_bytes_per_sec", "bwd_bytes_per_sec",
    
    "syn_count", "ack_count", "fin_count", "rst_count", "psh_count", "urg_count",
    "syn_rate", "rst_rate", "psh_rate", "fwd_syn_count", "bwd_syn_count", "fin_rst_ratio",
    
    "iat_mean", "iat_std", "iat_min", "iat_max", 
    "fwd_iat_mean", "fwd_iat_std", "fwd_iat_max", "fwd_iat_min",
    "bwd_iat_mean", "bwd_iat_std", "bwd_iat_max", "bwd_iat_min",
    "burst_count", "burst_avg_size", "active_time_mean",
    "idle_time_mean",
    
    "tls_version_risk", "tls_extension_count", "cert_days_to_expiry",
    "cipher_is_weak", "cert_self_signed", "cert_expired", "cert_domain_mismatch",
    "cert_is_short_lived", "sni_is_ip", "has_sni", "alpn_is_suspicious",
    
    "dns_query_frequency", "domain_entropy", "nxdomain_rate", "dns_response_count",
    "subdomain_level"
]

def clean_raw_metadata(df: pd.DataFrame) -> pd.DataFrame:
    """
    Cleans raw metadata DataFrame before derived features or pipelines are run.
    Replaces inf and -inf values with NaN, and handles missing columns.
    """
    df_clean = df.copy()
    
    # Fill in any missing raw columns in case they weren't produced
    for col in RAW_FEATURE_COLS:
        if col not in df_clean.columns:
            if (col.startswith("cert_") or 
                col.endswith("_weak") or 
                col.endswith("_mismatch") or 
                col.startswith("has_") or 
                col.endswith("_suspicious") or 
                col.endswith("_is_ip")):
                df_clean[col] = False
            elif col == "tls_version_risk":
                df_clean[col] = -1  # indicates not a TLS flow
            elif col == "cert_days_to_expiry":
                df_clean[col] = -1
            else:
                df_clean[col] = 0.0
                
    # Filter and keep columns in exact order
    df_clean = df_clean[RAW_FEATURE_COLS]
    
    # Replace infs with NaN
    df_clean = df_clean.replace([np.inf, -np.inf], np.nan)
    
    # Fill NaNs with median/zero defaults
    df_clean = df_clean.fillna(0.0)
    
    return df_clean
