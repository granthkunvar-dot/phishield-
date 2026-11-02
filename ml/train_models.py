"""
Phishield Model Training & Comparison Pipeline
Trains Baseline Logistic Regression and Random Forest models on URL-only features.
Evaluates on a 20% held-out test set against SMART Objective O2:
Target: >= 90% accuracy, >= 0.90 precision & recall, sub-second latency.
"""

import json
import os
import sys
import time

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import joblib
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    roc_auc_score,
    classification_report
)
from app.features import FEATURE_NAMES


def train_and_evaluate(data_dir: str = "ml/data", models_dir: str = "ml/models"):
    os.makedirs(models_dir, exist_ok=True)
    
    train_path = os.path.join(data_dir, "train_dataset.csv")
    test_path = os.path.join(data_dir, "test_dataset.csv")
    
    if not os.path.exists(train_path) or not os.path.exists(test_path):
        raise FileNotFoundError(f"Dataset files not found in {data_dir}. Run dataset_generator.py first.")
        
    train_df = pd.read_csv(train_path)
    test_df = pd.read_csv(test_path)
    
    X_train = train_df[FEATURE_NAMES]
    y_train = train_df['label']
    
    X_test = test_df[FEATURE_NAMES]
    y_test = test_df['label']
    
    print(f"Loaded training data: {len(X_train)} samples, testing data: {len(X_test)} samples")
    
    # --- 1. Baseline Model: Logistic Regression ---
    print("\n--- Training Baseline Model (Logistic Regression) ---")
    baseline = LogisticRegression(max_iter=1000, random_state=42)
    start_t = time.time()
    baseline.fit(X_train, y_train)
    baseline_train_time = time.time() - start_t
    
    base_preds = baseline.predict(X_test)
    base_probs = baseline.predict_proba(X_test)[:, 1]
    
    base_acc = accuracy_score(y_test, base_preds)
    base_prec = precision_score(y_test, base_preds)
    base_rec = recall_score(y_test, base_preds)
    base_f1 = f1_score(y_test, base_preds)
    base_auc = roc_auc_score(y_test, base_probs)
    
    print(f"Baseline Accuracy:  {base_acc:.4f}")
    print(f"Baseline Precision: {base_prec:.4f}")
    print(f"Baseline Recall:    {base_rec:.4f}")
    print(f"Baseline F1-Score:  {base_f1:.4f}")
    
    # --- 2. Advanced Model: Random Forest Classifier ---
    print("\n--- Training Advanced Model (Random Forest Classifier) ---")
    rf = RandomForestClassifier(
        n_estimators=100,
        max_depth=15,
        min_samples_split=4,
        min_samples_leaf=2,
        random_state=42,
        n_jobs=-1
    )
    start_t = time.time()
    rf.fit(X_train, y_train)
    rf_train_time = time.time() - start_t
    
    # Inference timing
    start_infer = time.time()
    rf_preds = rf.predict(X_test)
    rf_probs = rf.predict_proba(X_test)[:, 1]
    total_infer_time = time.time() - start_infer
    avg_latency_ms = (total_infer_time / len(X_test)) * 1000
    
    rf_acc = accuracy_score(y_test, rf_preds)
    rf_prec = precision_score(y_test, rf_preds)
    rf_rec = recall_score(y_test, rf_preds)
    rf_f1 = f1_score(y_test, rf_preds)
    rf_auc = roc_auc_score(y_test, rf_probs)
    rf_cm = confusion_matrix(y_test, rf_preds).tolist()
    
    print(f"Random Forest Accuracy:  {rf_acc:.4f} (Target >= 0.90)")
    print(f"Random Forest Precision: {rf_prec:.4f} (Target >= 0.90)")
    print(f"Random Forest Recall:    {rf_rec:.4f} (Target >= 0.90)")
    print(f"Random Forest F1-Score:  {rf_f1:.4f}")
    print(f"Random Forest ROC-AUC:   {rf_auc:.4f}")
    print(f"Avg Inference Latency:   {avg_latency_ms:.3f} ms per URL")
    print(f"Confusion Matrix:        TN={rf_cm[0][0]}, FP={rf_cm[0][1]}, FN={rf_cm[1][0]}, TP={rf_cm[1][1]}")
    
    # Feature importances
    importances = sorted(
        zip(FEATURE_NAMES, rf.feature_importances_),
        key=lambda x: x[1],
        reverse=True
    )
    print("\nTop 5 Most Informative Features:")
    for f_name, imp in importances[:5]:
        print(f"  - {f_name}: {imp:.4f}")
        
    # Save Random Forest Model
    model_save_path = os.path.join(models_dir, "phishield_rf_model.joblib")
    joblib.dump(rf, model_save_path)
    print(f"\nSaved Random Forest model to: {model_save_path}")
    
    # Save detailed evaluation metrics
    metrics = {
        'training_date': time.strftime('%Y-%m-%d %H:%M:%S'),
        'dataset': {
            'train_samples': len(X_train),
            'test_samples': len(X_test),
            'feature_count': len(FEATURE_NAMES),
            'features': FEATURE_NAMES
        },
        'baseline_logistic_regression': {
            'accuracy': round(base_acc, 4),
            'precision': round(base_prec, 4),
            'recall': round(base_rec, 4),
            'f1_score': round(base_f1, 4),
            'roc_auc': round(base_auc, 4),
            'training_time_sec': round(baseline_train_time, 3)
        },
        'random_forest': {
            'accuracy': round(rf_acc, 4),
            'precision': round(rf_prec, 4),
            'recall': round(rf_rec, 4),
            'f1_score': round(rf_f1, 4),
            'roc_auc': round(rf_auc, 4),
            'avg_latency_ms': round(avg_latency_ms, 3),
            'training_time_sec': round(rf_train_time, 3),
            'confusion_matrix': {
                'true_negative': rf_cm[0][0],
                'false_positive': rf_cm[0][1],
                'false_negative': rf_cm[1][0],
                'true_positive': rf_cm[1][1]
            },
            'top_features': [{'feature': k, 'importance': round(float(v), 4)} for k, v in importances[:10]]
        },
        'meets_objective_o2': bool(rf_acc >= 0.90 and rf_prec >= 0.90 and rf_rec >= 0.90)
    }
    
    metrics_path = os.path.join(models_dir, "model_metrics.json")
    with open(metrics_path, 'w', encoding='utf-8') as f:
        json.dump(metrics, f, indent=2)
    print(f"Metrics saved to: {metrics_path}")
    print(f"Meets SMART Objective O2: {metrics['meets_objective_o2']}")
    return metrics


if __name__ == "__main__":
    train_and_evaluate()
