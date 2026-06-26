import pandas as pd
import glob
import numpy as np
from sklearn.utils import resample
import os

print("Starting memory-efficient data preparation...")

# 1. Load, Clean, and Downsample individually
csv_files = glob.glob('data/cicids2017/*.csv')
if not csv_files:
    print("No CSV files found in data/cicids2017/")
    exit(1)

print(f"Found {len(csv_files)} files. Processing one by one...")

cleaned_dfs = []

for f in csv_files:
    print(f"Loading {os.path.basename(f)}...")
    try:
        # Load one file
        df = pd.read_csv(f, encoding='cp1252')
        df.columns = df.columns.str.strip()
        
        # Binary Label
        df['label'] = df['Label'].apply(lambda x: 0 if x == 'BENIGN' else 1)
        df = df.drop(columns=['Label'])
        
        # Clean
        df = df.replace([np.inf, -np.inf], np.nan)
        df = df.dropna(thresh=int(0.5 * len(df.columns)))
        df = df.dropna()
        df = df.drop_duplicates()
        
        # Downsample Benign immediately if too large to save memory
        benign = df[df['label'] == 0]
        threat = df[df['label'] == 1]
        
        if len(threat) > 0 and len(benign) > len(threat) * 5:
            benign = resample(benign, n_samples=len(threat) * 5, random_state=42)
            df = pd.concat([benign, threat])
        elif len(threat) == 0:
            # If no threats, just take a small sample of benign to keep the dataset size manageable
            df = resample(benign, n_samples=min(10000, len(benign)), random_state=42)
            
        cleaned_dfs.append(df)
        print(f"  Processed {len(df)} rows.")
        
    except Exception as e:
        print(f"  Error processing {f}: {e}")

# Concat cleaned chunks
print("Concatenating processed chunks...")
final_df = pd.concat(cleaned_dfs, ignore_index=True)

# Final re-balancing
print("Final balancing...")
benign = final_df[final_df['label'] == 0]
threat = final_df[final_df['label'] == 1]

if len(benign) > len(threat) * 3:
    benign = resample(benign, n_samples=len(threat) * 3, random_state=42)
    final_df = pd.concat([benign, threat]).sample(frac=1, random_state=42)

print(f"Balanced dataset: {len(final_df)} rows")
print(final_df['label'].value_counts())

# Save cleaned data
output_path = 'data/cicids2017_cleaned.parquet'
final_df.to_parquet(output_path, index=False)
print(f"Cleaned data saved to {output_path}")
