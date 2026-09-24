from typing import Dict, Any, List

class RiskEngine:
    """
    Evaluates URL features to produce a transparent heuristic risk score.
    """

    DISCLAIMER = "The heuristic score represents potential security indicators and does not prove that a URL is malicious."

    def __init__(self):
        pass

    def _determine_risk_level(self, score: int) -> str:
        """
        Maps a risk score to a risk level.
        """
        if score <= 19:
            return "LOW"
        elif score <= 39:
            return "GUARDED"
        elif score <= 59:
            return "MODERATE"
        elif score <= 79:
            return "HIGH"
        else:
            return "CRITICAL"

    def analyze(self, features: Dict[str, Any]) -> Dict[str, Any]:
        """
        Calculates the risk score based on the extracted features.

        Args:
            features: Dictionary of URL features.

        Returns:
            Dictionary containing the final score, level, and indicators.
        """
        score = 0
        indicators: List[Dict[str, Any]] = []

        def add_indicator(name: str, points: int, severity: str, explanation: str):
            nonlocal score
            score += points
            indicators.append({
                "indicator": name,
                "points": points,
                "severity": severity,
                "explanation": explanation
            })

        # HIGH-VALUE INDICATORS
        if features.get("is_ipv4"):
            add_indicator("IP Address Hostname", 20, "high", "The URL uses an IPv4 address directly instead of a domain name.")

        if features.get("has_at_symbol"):
            add_indicator("@ Symbol", 20, "high", "The URL contains an @ symbol, often used to obfuscate the real destination.")

        if features.get("has_punycode"):
            add_indicator("Punycode Hostname", 15, "high", "The hostname uses punycode, which can be used for homograph attacks.")

        if features.get("has_non_standard_port"):
            add_indicator("Non-standard Port", 10, "medium", "The URL explicitly specifies a non-standard port.")

        if not features.get("uses_https"):
            add_indicator("HTTP Connection", 10, "medium", "The URL does not use HTTPS.")

        # STRUCTURAL INDICATORS
        if features.get("num_subdomains", 0) >= 3:
            add_indicator("Multiple Subdomains", 10, "medium", "The URL has 3 or more subdomains.")

        url_length = features.get("url_length", 0)
        if url_length >= 120:
            add_indicator("Very Long URL", 10, "medium", "The URL is 120 characters or longer.")
        elif url_length >= 75:
            add_indicator("Long URL", 5, "low", "The URL is 75 characters or longer.")

        if features.get("num_hyphens", 0) >= 4:
            add_indicator("Multiple Hyphens", 5, "low", "The URL contains 4 or more hyphens.")

        if features.get("num_percent_encoded", 0) >= 5:
            add_indicator("Percent Encoding", 10, "medium", "The URL contains 5 or more percent-encoded characters.")

        # SUSPICIOUS TERMINOLOGY
        suspicious_count = features.get("num_suspicious_keywords", 0)
        if suspicious_count >= 3:
            add_indicator("Suspicious Terminology", 15, "high", "3 or more security-sensitive terms were found in the URL.")
        elif suspicious_count == 2:
            add_indicator("Suspicious Terminology", 10, "medium", "2 security-sensitive terms were found in the URL.")
        elif suspicious_count == 1:
            add_indicator("Suspicious Terminology", 5, "low", "1 security-sensitive term was found in the URL.")

        # DIGIT HEURISTIC
        if features.get("num_digits", 0) >= 10:
            add_indicator("Excessive Digits", 5, "low", "The URL contains 10 or more digits.")

        # QUERY COMPLEXITY
        if features.get("num_query_params", 0) >= 5:
            add_indicator("High Query Complexity", 5, "low", "The URL contains 5 or more query parameters.")

        # Cap the score at 100
        final_score = min(score, 100)

        return {
            "risk_score": final_score,
            "risk_level": self._determine_risk_level(final_score),
            "indicators": indicators,
            "indicator_count": len(indicators),
            "disclaimer": self.DISCLAIMER
        }
