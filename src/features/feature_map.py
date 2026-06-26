"""
feature_map.py
Canonical list of 30 training feature names used by the model.
Also handles any post-extraction cleanup (inf, NaN replacement).
"""
import numpy as np
import pandas as pd

# The 30 features the XGBoost model was trained on
TRAINING_FEATURES = [
    'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets',
    'Total Length of Fwd Packets', 'Total Length of Bwd Packets',
    'Fwd Packet Length Mean', 'Fwd Packet Length Std',
    'Fwd Packet Length Max', 'Fwd Packet Length Min',
    'Bwd Packet Length Mean', 'Bwd Packet Length Std',
    'Bwd Packet Length Max', 'Bwd Packet Length Min',
    'Flow Bytes/s', 'Flow Packets/s',
    'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min',
    'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max', 'Fwd IAT Min',
    'Bwd IAT Mean', 'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min',
    'Fwd PSH Flags', 'SYN Flag Count', 'Down/Up Ratio',
]

IDENTITY_COLS = ['src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol', 'sni', 'ja3_hash']

def clean_features(df: pd.DataFrame) -> pd.DataFrame:
    """Replace inf and NaN with 0 in feature columns."""
    feature_df = df[TRAINING_FEATURES].copy()
    feature_df = feature_df.replace([np.inf, -np.inf], np.nan)
    feature_df = feature_df.fillna(0)
    return feature_df
