import os
import pytest
import pandas as pd
import numpy as np
import joblib

from sklearn.model_selection import GroupShuffleSplit
from ml.train import load_and_prepare_data, train_pipeline

@pytest.fixture
def dummy_dataset(tmp_path):
    csv = tmp_path / "dummy_dataset.csv"
    pd.DataFrame({
        "url": [
            "http://example.com/legit", 
            "https://example.com/safe", 
            "http://phish.com/bad", 
            "http://phish.com/worse",
            "http://other.com/1",
            "http://other.com/2",
            "http://test.com/3",
            "http://test.com/4",
            "http://more.com/5",
            "http://more.com/6"
        ],
        "status": [
            "legitimate", "legitimate", "phishing", "phishing",
            "legitimate", "phishing", "legitimate", "phishing",
            "legitimate", "phishing"
        ]
    }).to_csv(csv, index=False)
    return csv

def test_data_preparation_and_features(dummy_dataset):
    df = load_and_prepare_data(str(dummy_dataset))
    
    # Check what got extracted
    assert 'status' not in df.columns
    assert 'url' not in df.columns
    
    feature_cols = [
        'url_length', 'hostname_length', 'path_length', 'num_dots', 'num_hyphens', 
        'num_digits', 'num_subdomains', 'is_ipv4', 'has_at_symbol', 'has_punycode', 
        'num_percent_encoded', 'num_query_params', 'has_non_standard_port', 
        'uses_https', 'num_suspicious_keywords'
    ]
    
    # Ensure they exist
    for f in feature_cols:
        assert f in df.columns
        
def test_group_aware_split(dummy_dataset):
    df = load_and_prepare_data(str(dummy_dataset))
    
    feature_cols = ['url_length', 'uses_https']
    X = df[feature_cols]
    y = df['label']
    groups = df['hostname']
    
    # Assert hostname is excluded from X
    assert 'hostname' not in X.columns
    assert 'raw_url' not in X.columns
    
    gss = GroupShuffleSplit(n_splits=1, test_size=0.3, random_state=42)
    train_idx, test_idx = next(gss.split(X, y, groups))
    
    train_hosts = set(groups.iloc[train_idx])
    test_hosts = set(groups.iloc[test_idx])
    
    assert len(train_hosts.intersection(test_hosts)) == 0
    
    # both classes exist in training and test data (due to dummy design and random_state)
    assert len(set(y.iloc[train_idx])) == 2
    assert len(set(y.iloc[test_idx])) == 2

def test_full_pipeline(dummy_dataset, tmp_path):
    models_dir = tmp_path / "models"
    results_path = tmp_path / "results.json"
    
    # This also tests that LR trains and RF trains
    train_pipeline(str(dummy_dataset), str(models_dir), str(results_path))
    
    # Assert models are saved and loadable
    lr = joblib.load(models_dir / "logistic_regression.joblib")
    rf = joblib.load(models_dir / "random_forest.joblib")
    
    assert hasattr(lr, "predict")
    assert hasattr(rf, "predict")
    
    # Load evaluation JSON and check metrics
    assert os.path.exists(results_path)
    import json
    with open(results_path) as f:
        res = json.load(f)
        
        for model in ['logistic_regression', 'random_forest']:
            metrics = res['models'][model]['metrics']
            for m in ['accuracy', 'precision', 'recall', 'f1_score', 'roc_auc', 'average_precision']:
                assert 0.0 <= metrics[m] <= 1.0
                
            cm = metrics['confusion_matrix']
            total_test = res['split']['test_samples']
            assert cm['TN'] + cm['FP'] + cm['FN'] + cm['TP'] == total_test
