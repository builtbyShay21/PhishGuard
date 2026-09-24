import os
import joblib
import warnings
import numpy as np

# Suppress sklearn warnings about feature names if passed as numpy arrays
warnings.filterwarnings("ignore", category=UserWarning, module="sklearn")

class MLPredictor:
    # Exactly match the features used during training
    FEATURE_ORDER = [
        'url_length', 'hostname_length', 'path_length', 'num_dots', 'num_hyphens', 
        'num_digits', 'num_subdomains', 'is_ipv4', 'has_at_symbol', 'has_punycode', 
        'num_percent_encoded', 'num_query_params', 'has_non_standard_port', 
        'uses_https', 'num_suspicious_keywords'
    ]

    def __init__(self, model_path="models/random_forest.joblib"):
        self.model = None
        self.model_path = model_path
        self.threshold = 0.50
        
        if os.path.exists(self.model_path):
            try:
                self.model = joblib.load(self.model_path)
            except Exception as e:
                print(f"Error loading ML model from {self.model_path}: {e}")
                self.model = None

    def predict(self, features: dict) -> dict:
        if self.model is None:
            return {
                "available": False,
                "error": "Model file unavailable or failed to load."
            }

        # Check for missing features
        missing = [f for f in self.FEATURE_ORDER if f not in features]
        if missing:
            raise ValueError(f"Missing required ML features: {missing}")
            
        # Extract features in exact order and ensure numeric format
        x_input = []
        for f in self.FEATURE_ORDER:
            val = features[f]
            # Convert booleans to 1/0
            if isinstance(val, bool):
                x_input.append(1 if val else 0)
            else:
                x_input.append(float(val))
                
        # Reshape for single prediction
        X = np.array([x_input])
        
        # Predict
        try:
            probabilities = self.model.predict_proba(X)[0]
            benign_prob = float(probabilities[0])
            phish_prob = float(probabilities[1])
            
            # Predict using threshold
            pred_class = 1 if phish_prob >= self.threshold else 0
            pred_label = "SUSPICIOUS" if pred_class == 1 else "BENIGN-LIKE"
            
            return {
                "available": True,
                "phishing_probability": phish_prob,
                "benign_probability": benign_prob,
                "predicted_class": pred_class,
                "prediction_label": pred_label,
                "threshold": self.threshold,
                "model": "Random Forest"
            }
        except Exception as e:
            return {
                "available": False,
                "error": f"Prediction failed: {e}"
            }
