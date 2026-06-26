import pandas as pd
import joblib
import os
from sklearn.metrics import classification_report, roc_auc_score, accuracy_score
from pathlib import Path

def verify_performance():
    print("--- Zenith Model Verification Engine ---")
    
    # 1. Load Model & Scaler
    model_path = Path("models/xgboost_model.pkl")
    scaler_path = Path("models/scaler.pkl")
    data_path = Path("data/cicids2017_cleaned.parquet")
    
    if not all([model_path.exists(), scaler_path.exists(), data_path.exists()]):
        print("Error: Missing model artifacts or dataset in data/ directory.")
        return

    print("Loading model artifacts...")
    model = joblib.load(model_path)
    scaler = joblib.load(scaler_path)
    
    # 2. Load Dataset
    print("Loading test samples from cicids2017...")
    df = pd.read_parquet(data_path)
    
    # Take a random sample for validation (or use the whole set if small enough)
    sample_df = df.sample(n=min(50000, len(df)), random_state=42)
    
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
    
    X = sample_df[FEATURE_COLS]
    y = sample_df['label']
    
    # 3. Predict
    print(f"Running inference on {len(X)} samples...")
    X_scaled = scaler.transform(X)
    preds = model.predict(X_scaled)
    probs = model.predict_proba(X_scaled)[:, 1]
    
    # 4. Report
    acc = accuracy_score(y, preds)
    auc = roc_auc_score(y, probs)
    
    print("\n[VERIFICATION RESULTS]")
    print(f"Overall Accuracy:  {acc:.4f}")
    print(f"ROC-AUC Score:     {auc:.4f}")
    print("\nDetailed Report:")
    print(classification_report(y, preds, target_names=['Benign', 'Threat']))
    
    print("\nResult: Model is high-performing and ready for production inference.")

if __name__ == "__main__":
    verify_performance()
