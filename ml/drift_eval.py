"""
Phishield Concept Drift Evaluation Module
Evaluates the trained Random Forest model on an unseen fresh-URL dataset (Gama et al., 2014)
to assess model robustness and drift against evolving phishing tactics.
"""

import json
import os
import sys

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import joblib
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    roc_auc_score
)
from app.features import FEATURE_NAMES


def evaluate_drift(data_dir: str = "ml/data", models_dir: str = "ml/models") -> dict:
    model_path = os.path.join(models_dir, "phishield_rf_model.joblib")
    drift_path = os.path.join(data_dir, "drift_dataset.csv")
    
    if not os.path.exists(model_path):
        raise FileNotFoundError(f"Model file not found at {model_path}. Run train_models.py first.")
    if not os.path.exists(drift_path):
        raise FileNotFoundError(f"Drift dataset not found at {drift_path}. Run dataset_generator.py first.")
        
    model = joblib.load(model_path)
    drift_df = pd.read_csv(drift_path)
    
    X_drift = drift_df[FEATURE_NAMES]
    y_drift = drift_df['label']
    
    preds = model.predict(X_drift)
    probs = model.predict_proba(X_drift)[:, 1]
    
    acc = accuracy_score(y_drift, preds)
    prec = precision_score(y_drift, preds)
    rec = recall_score(y_drift, preds)
    f1 = f1_score(y_drift, preds)
    auc = roc_auc_score(y_drift, probs)
    cm = confusion_matrix(y_drift, preds).tolist()
    
    drift_results = {
        'evaluation_type': 'Fresh URL Concept Drift Evaluation',
        'sample_count': len(drift_df),
        'accuracy': round(acc, 4),
        'precision': round(prec, 4),
        'recall': round(rec, 4),
        'f1_score': round(f1, 4),
        'roc_auc': round(auc, 4),
        'confusion_matrix': {
            'true_negative': cm[0][0],
            'false_positive': cm[0][1],
            'false_negative': cm[1][0],
            'true_positive': cm[1][1]
        },
        'robustness_status': 'Robust' if acc >= 0.88 and rec >= 0.88 else 'Needs Adaptation'
    }
    
    output_path = os.path.join(models_dir, "drift_metrics.json")
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(drift_results, f, indent=2)
        
    print(f"Drift Evaluation Complete: Accuracy={acc:.4f}, Precision={prec:.4f}, Recall={rec:.4f}, F1={f1:.4f}")
    print(f"Results saved to: {output_path}")
    return drift_results


if __name__ == "__main__":
    evaluate_drift()
