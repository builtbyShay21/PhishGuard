import pytest
from unittest.mock import patch, MagicMock
from src.analysis_service import AnalysisService

@pytest.fixture
def mock_ml_predictor():
    mock = MagicMock()
    mock.predict.return_value = {
        "available": True,
        "phishing_probability": 0.1,
        "benign_probability": 0.9,
        "predicted_class": 0,
        "prediction_label": "BENIGN-LIKE",
        "threshold": 0.50,
        "model": "Random Forest"
    }
    return mock

def test_analysis_service_benign(mock_ml_predictor):
    service = AnalysisService(ml_predictor=mock_ml_predictor)
    result = service.analyze("https://google.com")
    
    assert result["normalized_url"] == "https://google.com"
    assert "overall_assessment" in result
    assert result["overall_assessment"] == "LOW CONCERN"
    
    assert "heuristic" in result
    assert result["heuristic"]["risk_score"] == 0
    
    assert "ml" in result
    assert result["ml"]["prediction_label"] == "BENIGN-LIKE"

def test_analysis_service_high_heuristic_high_ml(mock_ml_predictor):
    # ML says Phishing
    mock_ml_predictor.predict.return_value = {
        "available": True,
        "phishing_probability": 0.95,
        "benign_probability": 0.05,
        "predicted_class": 1,
        "prediction_label": "SUSPICIOUS",
        "threshold": 0.50,
        "model": "Random Forest"
    }
    service = AnalysisService(ml_predictor=mock_ml_predictor)
    
    # Very suspicious URL (high heuristic score)
    result = service.analyze("http://192.168.1.1/login@bank.com-verify.php?x=1&y=2&z=3&a=4&b=5")
    
    assert result["overall_assessment"] == "HIGH CONCERN"
    assert result["heuristic"]["risk_level"] in ["HIGH", "CRITICAL"]

def test_analysis_service_disagreement_1(mock_ml_predictor):
    # ML says Phishing, but URL is simple (heuristic LOW)
    mock_ml_predictor.predict.return_value = {
        "available": True,
        "phishing_probability": 0.95,
        "benign_probability": 0.05,
        "predicted_class": 1,
        "prediction_label": "SUSPICIOUS",
        "threshold": 0.50,
        "model": "Random Forest"
    }
    service = AnalysisService(ml_predictor=mock_ml_predictor)
    
    result = service.analyze("https://example.com")
    
    assert result["overall_assessment"] == "REVIEW RECOMMENDED"
    assert result["heuristic"]["risk_level"] == "LOW"

def test_analysis_service_ml_unavailable(mock_ml_predictor):
    mock_ml_predictor.predict.return_value = {
        "available": False,
        "error": "Model missing"
    }
    service = AnalysisService(ml_predictor=mock_ml_predictor)
    
    # Benign URL
    result_low = service.analyze("https://example.com")
    assert result_low["overall_assessment"] == "LOW CONCERN"
    
    # Suspicious URL (IP + @ + HTTP + Port = 60 -> HIGH / ELEVATED depending on boundaries)
    result_high = service.analyze("http://192.168.1.1:8080/login@bank")
    assert result_high["overall_assessment"] in ["ELEVATED CONCERN", "HIGH CONCERN"]
