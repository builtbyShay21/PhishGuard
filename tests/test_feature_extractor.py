import pytest
from src.url_validator import normalize_and_validate_url
from src.feature_extractor import URLFeatureExtractor

def test_normal_https_url():
    url = "https://www.example.com/path?query=1"
    norm_url = normalize_and_validate_url(url)
    assert norm_url == url
    extractor = URLFeatureExtractor(norm_url)
    features = extractor.extract_features()
    assert features["uses_https"] is True
    assert features["num_query_params"] == 1

def test_url_without_scheme():
    url = "example.com"
    norm_url = normalize_and_validate_url(url)
    assert norm_url == "https://example.com"
    
def test_ipv4_url():
    url = "http://192.168.1.1/login"
    norm_url = normalize_and_validate_url(url)
    extractor = URLFeatureExtractor(norm_url)
    features = extractor.extract_features()
    assert features["is_ipv4"] is True
    assert features["num_suspicious_keywords"] >= 1
    
def test_url_with_at_symbol():
    url = "https://user:pass@example.com"
    norm_url = normalize_and_validate_url(url)
    extractor = URLFeatureExtractor(norm_url)
    features = extractor.extract_features()
    assert features["has_at_symbol"] is True
    
def test_punycode_hostname():
    url = "https://xn--bcher-kva.example.com"
    norm_url = normalize_and_validate_url(url)
    extractor = URLFeatureExtractor(norm_url)
    features = extractor.extract_features()
    assert features["has_punycode"] is True

def test_url_with_query_params():
    url = "https://example.com/search?q=phishing&page=2"
    norm_url = normalize_and_validate_url(url)
    extractor = URLFeatureExtractor(norm_url)
    features = extractor.extract_features()
    assert features["num_query_params"] == 2
    
def test_percent_encoding():
    url = "https://example.com/path%20with%20spaces"
    norm_url = normalize_and_validate_url(url)
    extractor = URLFeatureExtractor(norm_url)
    features = extractor.extract_features()
    assert features["num_percent_encoded"] == 2
    
def test_empty_input():
    with pytest.raises(ValueError, match="URL cannot be empty"):
        normalize_and_validate_url("   ")

def test_unsupported_scheme():
    with pytest.raises(ValueError, match="Unsupported scheme"):
        normalize_and_validate_url("ftp://example.com")
