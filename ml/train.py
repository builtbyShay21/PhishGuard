import os
import hashlib
import pandas as pd
import numpy as np
import urllib.parse
from datetime import datetime
import joblib

from sklearn.model_selection import GroupShuffleSplit
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline

from src.url_validator import normalize_and_validate_url
from src.feature_extractor import URLFeatureExtractor
from ml.evaluate import evaluate_models

def load_and_prepare_data(csv_path):
    df = pd.read_csv(csv_path)
    
    if 'status' not in df.columns:
        raise ValueError("Missing 'status' column in dataset.")
        
    records = []
    other_statuses = set()
    
    for idx, row in df.iterrows():
        status = row['status']
        if status not in ['legitimate', 'phishing']:
            other_statuses.add(status)
            continue
            
        raw_url = str(row.get('url', '')).strip()
        if not raw_url:
            continue
            
        try:
            norm_url = normalize_and_validate_url(raw_url)
            parsed = urllib.parse.urlparse(norm_url)
            hostname = parsed.hostname or ''
            
            features = URLFeatureExtractor(norm_url).extract_features()
            label = 1 if status == 'phishing' else 0
            
            record = {
                'original_index': idx,
                'raw_url': raw_url,
                'norm_url': norm_url,
                'hostname': hostname,
                'label': label,
            }
            record.update(features)
            records.append(record)
        except Exception:
            continue
            
    if other_statuses:
        print(f"Ignored other statuses: {other_statuses}")
        
    df_prepared = pd.DataFrame(records)
    df_prepared = df_prepared.drop_duplicates(subset=['norm_url']).reset_index(drop=True)
    return df_prepared

def create_split_manifest(df_prepared, train_idx, test_idx, output_path):
    manifest = []
    
    for idx in train_idx:
        row = df_prepared.iloc[idx]
        manifest.append({
            'index': row['original_index'],
            'label': row['label'],
            'split': 'train',
            'hostname_hash': hashlib.sha256(row['hostname'].encode()).hexdigest()[:16]
        })
        
    for idx in test_idx:
        row = df_prepared.iloc[idx]
        manifest.append({
            'index': row['original_index'],
            'label': row['label'],
            'split': 'test',
            'hostname_hash': hashlib.sha256(row['hostname'].encode()).hexdigest()[:16]
        })
        
    manifest_df = pd.DataFrame(manifest)
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    manifest_df.to_csv(output_path, index=False)
    print(f"Split manifest saved safely to {output_path}")

def train_pipeline(csv_path="data/raw/phishing_urls.csv", models_dir="models", results_path="data/processed/ml_results.json"):
    print("Preparing dataset...")
    df = load_and_prepare_data(csv_path)
    
    feature_cols = [
        'url_length', 'hostname_length', 'path_length', 'num_dots', 'num_hyphens', 
        'num_digits', 'num_subdomains', 'is_ipv4', 'has_at_symbol', 'has_punycode', 
        'num_percent_encoded', 'num_query_params', 'has_non_standard_port', 
        'uses_https', 'num_suspicious_keywords'
    ]
    
    X = df[feature_cols]
    y = df['label']
    groups = df['hostname']
    
    print("Performing Group-Aware Split...")
    gss = GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=42)
    train_idx, test_idx = next(gss.split(X, y, groups))
    
    X_train, y_train, groups_train = X.iloc[train_idx], y.iloc[train_idx], groups.iloc[train_idx]
    X_test, y_test, groups_test = X.iloc[test_idx], y.iloc[test_idx], groups.iloc[test_idx]
    
    train_hosts = set(groups_train)
    test_hosts = set(groups_test)
    
    if not train_hosts.isdisjoint(test_hosts):
        raise ValueError("CRITICAL LEAKAGE: Hostname overlap detected between train and test sets!")
        
    print(f"Train samples: {len(X_train)}")
    print(f"Test samples: {len(X_test)}")
    print(f"Train legitimate: {sum(y_train == 0)}, Train phishing: {sum(y_train == 1)}")
    print(f"Test legitimate: {sum(y_test == 0)}, Test phishing: {sum(y_test == 1)}")
    print(f"Unique train hostnames: {len(train_hosts)}")
    print(f"Unique test hostnames: {len(test_hosts)}")
    print(f"Hostname overlap: {len(train_hosts.intersection(test_hosts))}")
    
    # Save manifest
    create_split_manifest(df, train_idx, test_idx, "data/processed/split_manifest.csv")
    
    print("\nTraining Logistic Regression...")
    lr_pipeline = Pipeline([
        ('scaler', StandardScaler()),
        ('classifier', LogisticRegression(max_iter=2000, random_state=42, class_weight="balanced"))
    ])
    lr_pipeline.fit(X_train, y_train)
    
    print("Training Random Forest...")
    rf_model = RandomForestClassifier(n_estimators=300, random_state=42, n_jobs=-1, class_weight="balanced")
    rf_model.fit(X_train, y_train)
    
    # Save models
    os.makedirs(models_dir, exist_ok=True)
    joblib.dump(lr_pipeline, os.path.join(models_dir, "logistic_regression.joblib"))
    joblib.dump(rf_model, os.path.join(models_dir, "random_forest.joblib"))
    
    # Evaluate
    evaluate_models(lr_pipeline, rf_model, X_test, y_test, feature_cols, results_path, 
                    len(df), len(X_train), len(X_test), 
                    sum(y_train == 0), sum(y_train == 1), 
                    sum(y_test == 0), sum(y_test == 1),
                    len(train_hosts), len(test_hosts),
                    len(df[df['label']==0]), len(df[df['label']==1]))

if __name__ == "__main__":
    train_pipeline()
