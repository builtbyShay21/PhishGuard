import os
import pytest
from src.ml_predictor import MLPredictor
from unittest.mock import patch, MagicMock

def test_ml_predictor_missing_model():
    predictor = MLPredictor(model_path="invalid_path.joblib")
    result = predictor.predict({})
    assert result["available"] is False
    assert "error" in result

def test_ml_predictor_missing_features():
    # Mock joblib to pretend model loaded
    with patch("joblib.load") as mock_load:
        mock_model = MagicMock()
        mock_load.return_value = mock_model
        
        # Manually create mock file for exists check, or just patch exists
        with patch("os.path.exists", return_value=True):
            predictor = MLPredictor(model_path="dummy.joblib")
            
            with pytest.raises(ValueError, match="Missing required ML features"):
                predictor.predict({"url_length": 50}) # missing other 14

def test_ml_predictor_success():
    with patch("joblib.load") as mock_load:
        mock_model = MagicMock()
        mock_model.predict_proba.return_value = [[0.2, 0.8]]
        mock_load.return_value = mock_model
        
        with patch("os.path.exists", return_value=True):
            predictor = MLPredictor(model_path="dummy.joblib")
            
            features = {
                'url_length': 100, 'hostname_length': 20, 'path_length': 30, 
                'num_dots': 2, 'num_hyphens': 1, 'num_digits': 5, 
                'num_subdomains': 1, 'is_ipv4': False, 'has_at_symbol': False, 
                'has_punycode': False, 'num_percent_encoded': 0, 
                'num_query_params': 1, 'has_non_standard_port': False, 
                'uses_https': True, 'num_suspicious_keywords': 0
            }
            
            result = predictor.predict(features)
            
            assert result["available"] is True
            assert result["phishing_probability"] == 0.8
            assert result["benign_probability"] == 0.2
            assert result["predicted_class"] == 1
            assert result["prediction_label"] == "SUSPICIOUS"
            
            # test benign
            mock_model.predict_proba.return_value = [[0.9, 0.1]]
            result2 = predictor.predict(features)
            assert result2["prediction_label"] == "BENIGN-LIKE"
            
            # Check arguments passed to predict_proba
            args, _ = mock_model.predict_proba.call_args
            x_input = args[0][0]
            
            assert len(x_input) == 15
            # is_ipv4 is index 7, False -> 0
            assert x_input[7] == 0
            # uses_https is index 13, True -> 1
            assert x_input[13] == 1
