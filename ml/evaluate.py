import os
import json
import numpy as np
import pandas as pd
from datetime import datetime

from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score, average_precision_score, confusion_matrix

def evaluate_models(lr_pipeline, rf_model, X_test, y_test, feature_cols, results_path, 
                    total_samples, train_samples, test_samples, 
                    train_legit, train_phish, 
                    test_legit, test_phish,
                    unique_train_hosts, unique_test_hosts,
                    total_legit, total_phish):
                    
    print("\nEvaluating Models on Independent Test Set...")
    
    def get_metrics(model, name):
        y_pred = model.predict(X_test)
        y_prob = model.predict_proba(X_test)[:, 1] if hasattr(model, "predict_proba") else y_pred
        
        acc = accuracy_score(y_test, y_pred)
        prec = precision_score(y_test, y_pred, zero_division=0)
        rec = recall_score(y_test, y_pred, zero_division=0)
        f1 = f1_score(y_test, y_pred, zero_division=0)
        roc = roc_auc_score(y_test, y_prob)
        ap = average_precision_score(y_test, y_prob)
        cm = confusion_matrix(y_test, y_pred)
        tn, fp, fn, tp = cm.ravel() if cm.size == 4 else (0,0,0,0)
        
        return {
            'accuracy': float(acc),
            'precision': float(prec),
            'recall': float(rec),
            'f1_score': float(f1),
            'roc_auc': float(roc),
            'average_precision': float(ap),
            'confusion_matrix': {
                'TN': int(tn),
                'FP': int(fp),
                'FN': int(fn),
                'TP': int(tp)
            }
        }
        
    lr_metrics = get_metrics(lr_pipeline, "Logistic Regression")
    rf_metrics = get_metrics(rf_model, "Random Forest")
    
    # Feature Importances
    # Logistic Regression
    lr_classifier = lr_pipeline.named_steps['classifier']
    lr_coefs = lr_classifier.coef_[0]
    lr_importances = {feat: float(coef) for feat, coef in zip(feature_cols, lr_coefs)}
    lr_importances_sorted = dict(sorted(lr_importances.items(), key=lambda item: abs(item[1]), reverse=True))
    
    # Random Forest
    rf_importances_raw = rf_model.feature_importances_
    rf_importances = {feat: float(imp) for feat, imp in zip(feature_cols, rf_importances_raw)}
    rf_importances_sorted = dict(sorted(rf_importances.items(), key=lambda item: item[1], reverse=True))
    
    results = {
        'timestamp': datetime.utcnow().isoformat() + "Z",
        'dataset': {
            'total_samples': total_samples,
            'legitimate': total_legit,
            'phishing': total_phish
        },
        'split': {
            'train_samples': train_samples,
            'test_samples': test_samples,
            'train_legitimate': train_legit,
            'train_phishing': train_phish,
            'test_legitimate': test_legit,
            'test_phishing': test_phish,
            'unique_train_hostnames': unique_train_hosts,
            'unique_test_hostnames': unique_test_hosts,
            'hostname_overlap': 0 # We asserted this in train
        },
        'features': feature_cols,
        'models': {
            'logistic_regression': {
                'metrics': lr_metrics,
                'feature_coefficients': lr_importances_sorted
            },
            'random_forest': {
                'metrics': rf_metrics,
                'feature_importances': rf_importances_sorted
            }
        }
    }
    
    os.makedirs(os.path.dirname(results_path), exist_ok=True)
    with open(results_path, 'w') as f:
        json.dump(results, f, indent=4)
        
    print(f"\nEvaluation complete. Results saved to {results_path}")
    
    # Print the report
    print("\n" + "="*50)
    print("FINAL REPORT")
    print("="*50)
    
    print("\nDATASET")
    print(f"- Total samples: {total_samples}")
    print(f"- Legitimate: {total_legit}")
    print(f"- Phishing: {total_phish}")
    
    print("\nSPLIT")
    print(f"- Train samples: {train_samples}")
    print(f"- Test samples: {test_samples}")
    print(f"- Train class distribution: {train_legit} Legit / {train_phish} Phish")
    print(f"- Test class distribution: {test_legit} Legit / {test_phish} Phish")
    print(f"- Unique train hostnames: {unique_train_hosts}")
    print(f"- Unique test hostnames: {unique_test_hosts}")
    print(f"- Hostname overlap: 0")
    
    print("\nLOGISTIC REGRESSION")
    print(f"- Accuracy: {lr_metrics['accuracy']:.4f}")
    print(f"- Precision: {lr_metrics['precision']:.4f}")
    print(f"- Recall: {lr_metrics['recall']:.4f}")
    print(f"- F1: {lr_metrics['f1_score']:.4f}")
    print(f"- ROC-AUC: {lr_metrics['roc_auc']:.4f}")
    print(f"- Average Precision: {lr_metrics['average_precision']:.4f}")
    print(f"- TN / FP / FN / TP: {lr_metrics['confusion_matrix']['TN']} / {lr_metrics['confusion_matrix']['FP']} / {lr_metrics['confusion_matrix']['FN']} / {lr_metrics['confusion_matrix']['TP']}")
    
    print("\nRANDOM FOREST")
    print(f"- Accuracy: {rf_metrics['accuracy']:.4f}")
    print(f"- Precision: {rf_metrics['precision']:.4f}")
    print(f"- Recall: {rf_metrics['recall']:.4f}")
    print(f"- F1: {rf_metrics['f1_score']:.4f}")
    print(f"- ROC-AUC: {rf_metrics['roc_auc']:.4f}")
    print(f"- Average Precision: {rf_metrics['average_precision']:.4f}")
    print(f"- TN / FP / FN / TP: {rf_metrics['confusion_matrix']['TN']} / {rf_metrics['confusion_matrix']['FP']} / {rf_metrics['confusion_matrix']['FN']} / {rf_metrics['confusion_matrix']['TP']}")
    
    print("\nFEATURE ANALYSIS")
    print("Top Logistic Regression coefficients:")
    for k, v in list(lr_importances_sorted.items())[:5]:
        print(f"  {k}: {v:.4f}")
        
    print("\nTop Random Forest feature importances:")
    for k, v in list(rf_importances_sorted.items())[:5]:
        print(f"  {k}: {v:.4f}")

    print("\n" + "="*50)
