import pandas as pd
from .derived_features import DerivedFeatureTransformer
from .preprocessor import clean_raw_metadata

def transform_to_model_input(raw_features_df: pd.DataFrame) -> pd.DataFrame:
    """
    Takes a raw features DataFrame (Phase 3 format) and applies:
    1. Cleaning (handling NaNs, infinities, and missing columns)
    2. Derived feature calculation (ratios, symmetry, cv)
    3. Mapping and ordering of the exact 30 features the model expects
    """
    # 1. Clean raw metadata
    cleaned_df = clean_raw_metadata(raw_features_df)
    
    # 2. Compute derived features
    transformer = DerivedFeatureTransformer()
    engineered_df = transformer.transform(cleaned_df)
    
    # 3. Map Phase 3 internal feature names to model training feature names
    mapping = {
        "flow_duration": "Flow Duration",
        "total_fwd_packets": "Total Fwd Packets",
        "total_bwd_packets": "Total Backward Packets",
        "bytes_sent": "Total Length of Fwd Packets",
        "bytes_received": "Total Length of Bwd Packets",
        
        "avg_fwd_packet_size": "Fwd Packet Length Mean",
        "fwd_pkt_size_std": "Fwd Packet Length Std",
        "fwd_pkt_size_max": "Fwd Packet Length Max",
        "fwd_pkt_size_min": "Fwd Packet Length Min",
        
        "avg_bwd_packet_size": "Bwd Packet Length Mean",
        "bwd_pkt_size_std": "Bwd Packet Length Std",
        "bwd_pkt_size_max": "Bwd Packet Length Max",
        "bwd_pkt_size_min": "Bwd Packet Length Min",
        
        "bytes_per_sec": "Flow Bytes/s",
        "packets_per_sec": "Flow Packets/s",
        
        "iat_mean": "Flow IAT Mean",
        "iat_std": "Flow IAT Std",
        "iat_max": "Flow IAT Max",
        "iat_min": "Flow IAT Min",
        
        "fwd_iat_mean": "Fwd IAT Mean",
        "fwd_iat_std": "Fwd IAT Std",
        "fwd_iat_max": "Fwd IAT Max",
        "fwd_iat_min": "Fwd IAT Min",
        
        "bwd_iat_mean": "Bwd IAT Mean",
        "bwd_iat_std": "Bwd IAT Std",
        "bwd_iat_max": "Bwd IAT Max",
        "bwd_iat_min": "Bwd IAT Min",
        
        "psh_count": "Fwd PSH Flags",
        "syn_count": "SYN Flag Count",
        "down_up_ratio": "Down/Up Ratio"
    }
    
    model_input_df = pd.DataFrame()
    for raw_name, model_name in mapping.items():
        model_input_df[model_name] = engineered_df[raw_name]
        
    return model_input_df
