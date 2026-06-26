import pandas as pd
import joblib
from sklearn.metrics import classification_report, roc_auc_score
from pathlib import Path

def verify_performance():
    print("--- Zenith Model Verification Engine (Lightweight) ---")
    model_path = Path("models/xgboost_model.pkl")
    scaler_path = Path("models/scaler.pkl")
    data_path = Path("data/cicids2017_cleaned.parquet")
    
    # Load 1000 samples only
    df = pd.read_parquet(data_path).sample(n=1000, random_state=42)
    model = joblib.load(model_path)
    scaler = joblib.load(scaler_path)
    
    FEATURE_COLS = [
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
        'Fwd PSH Flags', 'SYN Flag Count', 'Down/Up Ratio'
    ]
    
    X = scaler.transform(df[FEATURE_COLS])
    y_pred = model.predict(X)
    y_prob = model.predict_proba(X)[:, 1]
    
    print("\n[VERIFICATION RESULTS]")
    print(f"ROC-AUC: {roc_auc_score(df['label'], y_prob):.4f}")
    print("\nClassification Report:")
    print(classification_report(df['label'], y_pred, target_names=['Benign', 'Threat']))

if __name__ == "__main__":
    verify_performance()
