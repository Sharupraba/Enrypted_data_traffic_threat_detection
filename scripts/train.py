import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, roc_auc_score
import xgboost as xgb
import joblib
import os

print("Starting model training...")

# Load cleaned data
data_path = 'data/cicids2017_cleaned.parquet'
if not os.path.exists(data_path):
    print(f"File not found: {data_path}. Run prep.py first.")
    exit(1)

df = pd.read_parquet(data_path)

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

X = df[FEATURE_COLS]
y = df['label']

X_train, X_temp, y_train, y_temp = train_test_split(X, y, test_size=0.30, random_state=42, stratify=y)
X_val, X_test, y_val, y_test = train_test_split(X_temp, y_temp, test_size=0.50, random_state=42, stratify=y_temp)

print("Scaling data...")
scaler = StandardScaler()
X_train_s = scaler.fit_transform(X_train)
X_val_s   = scaler.transform(X_val)
X_test_s  = scaler.transform(X_test)

print("Training XGBoost model...")
model = xgb.XGBClassifier(
    n_estimators=100, # Lower for faster prototype training
    max_depth=6,
    learning_rate=0.1,
    scale_pos_weight=len(y_train[y_train==0]) / len(y_train[y_train==1]),
    use_label_encoder=False,
    eval_metric='logloss',
    random_state=42,
)

model.fit(X_train_s, y_train, eval_set=[(X_val_s, y_val)], early_stopping_rounds=10, verbose=True)

# Evaluate
y_pred = model.predict(X_test_s)
y_prob = model.predict_proba(X_test_s)[:, 1]
print("\nClassification Report:")
print(classification_report(y_test, y_pred, target_names=['Benign', 'Threat']))
print(f"ROC-AUC: {roc_auc_score(y_test, y_prob):.4f}")

# Save
if not os.path.exists('models'):
    os.makedirs('models')

joblib.dump(model, 'models/xgboost_model.pkl')
joblib.dump(scaler, 'models/scaler.pkl')
joblib.dump(FEATURE_COLS, 'models/feature_cols.pkl')
print("\nSuccess: Models saved to models/ directory.")
