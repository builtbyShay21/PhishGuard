from src.url_validator import normalize_and_validate_url
from src.feature_extractor import URLFeatureExtractor
from src.risk_engine import RiskEngine
from src.ml_predictor import MLPredictor

class AnalysisService:
    def __init__(self, ml_predictor=None):
        # Allow passing predictor for testing or reusing instance
        self.ml_predictor = ml_predictor if ml_predictor else MLPredictor()

    def analyze(self, raw_url: str) -> dict:
        normalized_url = normalize_and_validate_url(raw_url)
        
        extractor = URLFeatureExtractor(normalized_url)
        features = extractor.extract_features()
        
        risk_engine = RiskEngine()
        heuristic_analysis = risk_engine.analyze(features)
        heuristic_score = heuristic_analysis["risk_score"]
        heuristic_level = heuristic_analysis["risk_level"]
        indicators = heuristic_analysis["indicators"]
        
        ml_result = self.ml_predictor.predict(features)
        
        # Hybrid Interpretation
        overall_assessment, agreement_status = self._interpret_hybrid(heuristic_level, ml_result)
        
        return {
            "normalized_url": normalized_url,
            "overall_assessment": overall_assessment,
            "agreement_status": agreement_status,
            "features": features,
            "heuristic": {
                "risk_score": heuristic_score,
                "risk_level": heuristic_level,
                "indicators": indicators
            },
            "ml": ml_result
        }

    def _interpret_hybrid(self, heuristic_level: str, ml_result: dict) -> tuple:
        if not ml_result.get("available", False):
            # If ML fails, fallback entirely to heuristic
            if heuristic_level in ["HIGH", "CRITICAL"]:
                return "HIGH CONCERN", "Heuristic analysis indicates significant risk. (ML analysis unavailable)"
            elif heuristic_level == "MODERATE":
                return "ELEVATED CONCERN", "Heuristic analysis indicates moderate risk. (ML analysis unavailable)"
            else:
                return "LOW CONCERN", "No significant heuristic risk indicators detected. (ML analysis unavailable)"

        ml_label = ml_result.get("prediction_label")
        
        if ml_label == "BENIGN-LIKE" and heuristic_level in ["LOW", "GUARDED"]:
            assessment = "LOW CONCERN"
            agreement = "The current analysis detected limited suspicious characteristics. Both ML and heuristic models agree."
        elif ml_label == "SUSPICIOUS" and heuristic_level in ["HIGH", "CRITICAL"]:
            assessment = "HIGH CONCERN"
            agreement = "Multiple independent analysis methods detected severe suspicious characteristics."
        elif ml_label == "SUSPICIOUS" and heuristic_level == "MODERATE":
            assessment = "ELEVATED CONCERN"
            agreement = "ML and heuristic analysis both detected elevated risk signals."
        elif ml_label == "SUSPICIOUS" and heuristic_level in ["LOW", "GUARDED"]:
            assessment = "REVIEW RECOMMENDED"
            agreement = "Mixed signals: ML detected suspicious patterns, but heuristic risk is low."
        elif ml_label == "BENIGN-LIKE" and heuristic_level in ["MODERATE", "HIGH", "CRITICAL"]:
            assessment = "REVIEW RECOMMENDED"
            agreement = "Mixed signals: Heuristic analysis detected risks, but ML classified it as benign-like."
        else:
            assessment = "UNKNOWN"
            agreement = "Unable to determine consensus."

        return assessment, agreement
