import numpy as np
import pandas as pd
from sklearn.base import BaseEstimator, TransformerMixin

class DerivedFeatureTransformer(BaseEstimator, TransformerMixin):
    """
    Scikit-learn custom transformer that computes high-signal ratios, 
    rate derivatives, and coefficients of variation from raw flow metadata.
    """
    def __init__(self):
        pass
        
    def fit(self, X, y=None):
        return self
        
    def transform(self, X, y=None):
        # Ensure X is a DataFrame
        if not isinstance(X, pd.DataFrame):
            df = pd.DataFrame(X)
        else:
            df = X.copy()
            
        # 1. upload_ratio = bytes_sent / (bytes_sent + bytes_received)
        total_bytes = df["bytes_sent"] + df["bytes_received"]
        df["upload_ratio"] = np.where(total_bytes == 0, 0.0, df["bytes_sent"] / total_bytes)
        
        # 2. download_ratio = bytes_received / (bytes_sent + bytes_received)
        df["download_ratio"] = np.where(total_bytes == 0, 0.0, df["bytes_received"] / total_bytes)
        
        # 3. packet_rate = total_packets / flow_duration
        df["packet_rate"] = np.where(df["flow_duration"] == 0, 0.0, df["total_packets"] / df["flow_duration"])
        
        # 4. fwd_packet_rate = total_fwd_packets / flow_duration
        df["fwd_packet_rate"] = np.where(df["flow_duration"] == 0, 0.0, df["total_fwd_packets"] / df["flow_duration"])
        
        # 5. bwd_packet_rate = total_bwd_packets / flow_duration
        df["bwd_packet_rate"] = np.where(df["flow_duration"] == 0, 0.0, df["total_bwd_packets"] / df["flow_duration"])
        
        # 6. flow_symmetry = 1 - abs(total_fwd_packets - total_bwd_packets) / total_packets
        df["flow_symmetry"] = np.where(
            df["total_packets"] == 0, 
            1.0, 
            1.0 - (np.abs(df["total_fwd_packets"] - df["total_bwd_packets"]) / df["total_packets"])
        )
        
        # 7. byte_ratio = bytes_sent / bytes_received
        df["byte_ratio"] = df["bytes_sent"] / (df["bytes_received"] + 1e-9)
        
        # 8. down_up_ratio = bytes_received / bytes_sent (to match prototype Down/Up Ratio)
        df["down_up_ratio"] = df["bytes_received"] / (df["bytes_sent"] + 1e-9)
        
        # 9. header_ratio (average estimation for framing overhead)
        df["header_ratio"] = 0.05
        
        # 10. iat_cv = iat_std / iat_mean
        df["iat_cv"] = df["iat_std"] / (df["iat_mean"] + 1e-9)
        
        return df
