import pytest
from src.url_validator import normalize_and_validate_url
from src.feature_extractor import URLFeatureExtractor
from src.risk_engine import RiskEngine

def get_risk_result(url: str):
    norm_url = normalize_and_validate_url(url)
    extractor = URLFeatureExtractor(norm_url)
    features = extractor.extract_features()
    engine = RiskEngine()
    return engine.analyze(features)

def test_normal_low_risk_https_url():
    result = get_risk_result("https://www.example.com")
    assert result["risk_score"] == 0
    assert result["risk_level"] == "LOW"
    assert result["indicator_count"] == 0

def test_ipv4_url():
    result = get_risk_result("http://192.168.1.1/path")
    # IP (+20) + HTTP (+10) = 30
    # Plus digits might be >= 10 (+5). 19216811 is 8 digits. So score is 30.
    # num_dots is 3, num_subdomains is 0 (IP check does not count subdomains typically, but feature extractor gives max(0, 3-1)=2. So not >=3.
    assert "IP Address Hostname" in [i["indicator"] for i in result["indicators"]]
    assert result["risk_score"] == 30
    assert result["risk_level"] == "GUARDED"

def test_http_url():
    result = get_risk_result("http://example.com")
    assert result["risk_score"] == 10
    assert result["risk_level"] == "LOW"
    assert "HTTP Connection" in [i["indicator"] for i in result["indicators"]]

def test_at_symbol():
    result = get_risk_result("https://user:pass@example.com")
    assert result["risk_score"] == 20
    assert result["risk_level"] == "GUARDED"
    assert "@ Symbol" in [i["indicator"] for i in result["indicators"]]

def test_punycode():
    result = get_risk_result("https://xn--bcher-kva.example.com")
    assert result["risk_score"] == 15
    assert result["risk_level"] == "LOW"
    assert "Punycode Hostname" in [i["indicator"] for i in result["indicators"]]

def test_non_standard_port():
    result = get_risk_result("https://example.com:8443")
    assert result["risk_score"] == 10
    assert result["risk_level"] == "LOW"
    assert "Non-standard Port" in [i["indicator"] for i in result["indicators"]]

def test_multiple_suspicious_keywords():
    # 3 keywords: login, secure, update
    result = get_risk_result("https://example.com/login/secure/update")
    assert result["risk_score"] == 15
    assert result["risk_level"] == "LOW"
    assert "Suspicious Terminology" in [i["indicator"] for i in result["indicators"]]
    assert any(i["points"] == 15 for i in result["indicators"] if i["indicator"] == "Suspicious Terminology")

def test_very_long_url():
    # 120 chars
    long_str = "a" * 100
    result = get_risk_result(f"https://example.com/{long_str}")
    # URL length >= 120 (+10)
    assert result["risk_score"] == 10
    assert result["risk_level"] == "LOW"
    assert "Very Long URL" in [i["indicator"] for i in result["indicators"]]

def test_score_cannot_exceed_100():
    # Combining many indicators to exceed 100
    # IP (+20), HTTP (+10), @ (+20), Port (+10), Punycode (+15) (Cannot do IP and Punycode easily, let's use Punycode domain)
    # Domain: xn--something.com (+15)
    # subdomains: a.b.c.xn--something.com (+10)
    # length > 120 (+10)
    # hyphens > 4 (+5)
    # % encoded > 5 (+10)
    # keywords > 3 (+15)
    # digits > 10 (+5)
    # query params > 5 (+5)
    url = "http://user:pass@a.b.c.xn--bcher-kva.com:8080/login/secure/update/account-1-2-3-4?q=1%20%20%20%20%201234567890&a=1&b=2&c=3&d=4"
    # HTTP: 10
    # @: 20
    # Punycode: 15
    # Port: 10
    # Subdomains: >=3 (a.b.c.xn...) -> dots=4, sub=3 -> 10
    # Hyphens: >= 4 -> 5
    # Encoded: >= 5 -> 10
    # Keywords: login, secure, update, account -> 15
    # Length: >120 -> 10
    # Digits: >10 -> 5
    # Query Params: >5 -> 5
    # Total sum = 115
    result = get_risk_result(url)
    assert result["risk_score"] == 100
    assert result["risk_level"] == "CRITICAL"

def test_correct_risk_level_boundaries():
    engine = RiskEngine()
    assert engine._determine_risk_level(0) == "LOW"
    assert engine._determine_risk_level(19) == "LOW"
    assert engine._determine_risk_level(20) == "GUARDED"
    assert engine._determine_risk_level(39) == "GUARDED"
    assert engine._determine_risk_level(40) == "MODERATE"
    assert engine._determine_risk_level(59) == "MODERATE"
    assert engine._determine_risk_level(60) == "HIGH"
    assert engine._determine_risk_level(79) == "HIGH"
    assert engine._determine_risk_level(80) == "CRITICAL"
    assert engine._determine_risk_level(100) == "CRITICAL"
