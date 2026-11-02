"""
Phishield Model & Hybrid Decision Engine
Combines 13 transparent heuristic rules (40% weight) with Random Forest ML predictions (60% weight).
Produces a Three-Level Rating (Safe / Suspicious / Phishing) with plain-English explanations.
Ensures graceful fallback to heuristic rules if the ML model is unavailable.
"""

import os
import joblib
import pandas as pd
from app.features import extract_features_vector, FEATURE_NAMES
from app.rules import PhishieldRuleEngine
from app.utils import defang_url, mask_sensitive_query_params

DEFAULT_MODEL_PATH = os.path.join(
    os.path.dirname(__file__), '..', 'ml', 'models', 'phishield_rf_model.joblib'
)


class PhishieldDetector:
    def __init__(self, model_path: str = None):
        self.model_path = model_path or os.environ.get('PHISHIELD_MODEL_PATH', DEFAULT_MODEL_PATH)
        self.model = None
        self._load_model()

    def _load_model(self):
        """Loads trained Random Forest model from disk if present."""
        if os.path.exists(self.model_path):
            try:
                self.model = joblib.load(self.model_path)
            except Exception as e:
                print(f"Warning: Could not load ML model from {self.model_path}: {e}")
                self.model = None
        else:
            self.model = None

    def predict(self, url: str) -> dict:
        """
        Performs full hybrid scan on a given URL.
        Returns:
            - rating: 'safe', 'suspicious', or 'phishing'
            - rating_label: Human-friendly badge text
            - composite_score: float (0.0 to 1.0)
            - rules_score: float (0.0 to 1.0)
            - ml_score: float (0.0 to 1.0)
            - rules_breakdown: list of 13 evaluated rules with explanations
            - defanged_url: non-clickable defanged display string
            - masked_url: sensitive parameter masked string
            - advisory_text: plain-English guidance for users
        """
        # 1. Evaluate 13 URL heuristic rules (40% weight)
        engine = PhishieldRuleEngine(url)
        rule_eval = engine.evaluate_all()
        rules_score = rule_eval['rules_score']

        # 2. Extract tabular feature vector and run ML model (60% weight)
        if self.model is not None:
            features = extract_features_vector(url)
            # Create DataFrame with exact feature names to prevent scikit-learn warnings
            X = pd.DataFrame([features], columns=FEATURE_NAMES)
            try:
                probs = self.model.predict_proba(X)
                ml_score = float(probs[0][1])
            except Exception:
                ml_score = rules_score
        else:
            ml_score = rules_score

        # 3. Compute weighted composite score (40% Rules, 60% ML)
        composite_score = round((rules_score * 0.40) + (ml_score * 0.60), 4)

        # 4. Map to Three-Level Rating with cautious, non-overtrusting language
        if composite_score < 0.35:
            rating = 'safe'
            rating_label = 'No Warning Signs Found'
            advisory_text = (
                "No phishing indicators were identified in the address structure. "
                "Note: This is advisory and not an absolute guarantee of safety; always remain vigilant."
            )
        elif composite_score < 0.65:
            rating = 'suspicious'
            rating_label = 'Suspicious Indicators Detected'
            advisory_text = (
                "Moderate warning signs were detected in the address formatting or domain structure. "
                "Exercise high caution before proceeding or submitting any information."
            )
        else:
            rating = 'phishing'
            rating_label = 'High-Risk Phishing Warning'
            advisory_text = (
                "High-confidence phishing indicators were identified. "
                "Do NOT enter passwords, financial details, or personal data on this site."
            )

        return {
            'url_original': url,
            'url_defanged': defang_url(url),
            'url_masked': mask_sensitive_query_params(url),
            'rating': rating,
            'rating_label': rating_label,
            'composite_score': composite_score,
            'rules_score': round(rules_score, 4),
            'ml_score': round(ml_score, 4),
            'triggered_count': rule_eval['triggered_count'],
            'total_rules': rule_eval['total_rules'],
            'rules_breakdown': rule_eval['rules'],
            'advisory_text': advisory_text,
            'model_available': self.model is not None
        }


_default_detector = None


def get_detector() -> PhishieldDetector:
    global _default_detector
    if _default_detector is None:
        _default_detector = PhishieldDetector()
    return _default_detector
