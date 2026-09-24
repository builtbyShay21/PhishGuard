import urllib.parse
import ipaddress
from typing import Dict, Any

class URLFeatureExtractor:
    """
    Extracts lexical features from a URL for phishing detection analysis.
    """
    
    SUSPICIOUS_KEYWORDS = [
        "login", "verify", "account", "secure", "update", "banking", 
        "signin", "confirm", "password", "credential", "wallet", "payment"
    ]
    
    def __init__(self, url: str):
        """
        Initializes the extractor with a URL.
        
        Args:
            url: The normalized URL string to analyze.
        """
        self.url = url
        self.parsed_url = urllib.parse.urlparse(url)
        
    def extract_features(self) -> Dict[str, Any]:
        """
        Extracts various lexical features from the URL.
        
        Returns:
            A dictionary containing the extracted features.
        """
        hostname = self.parsed_url.hostname or ""
        path = self.parsed_url.path
        query = self.parsed_url.query
        
        features = {}
        
        # Length features
        features["url_length"] = len(self.url)
        features["hostname_length"] = len(hostname)
        features["path_length"] = len(path)
        
        # Character counts in the entire URL
        features["num_dots"] = self.url.count(".")
        features["num_hyphens"] = self.url.count("-")
        features["num_digits"] = sum(c.isdigit() for c in self.url)
        
        # Subdomains count (heuristically based on dots in hostname)
        features["num_subdomains"] = max(0, hostname.count(".") - 1)
        
        # IPv4 check
        is_ipv4 = False
        try:
            ipaddress.IPv4Address(hostname)
            is_ipv4 = True
        except ipaddress.AddressValueError:
            pass
        features["is_ipv4"] = is_ipv4
        
        # @ symbol
        features["has_at_symbol"] = "@" in self.url
        
        # Punycode
        features["has_punycode"] = "xn--" in hostname.lower()
        
        # Percent encoding count
        features["num_percent_encoded"] = self.url.count("%")
        
        # Query parameters count
        if query:
            parsed_query = urllib.parse.parse_qs(query)
            features["num_query_params"] = len(parsed_query)
        else:
            features["num_query_params"] = 0
            
        # Non-standard port
        port = self.parsed_url.port
        is_standard_port = port is None or port in (80, 443)
        features["has_non_standard_port"] = not is_standard_port
        
        # HTTPS usage
        features["uses_https"] = self.parsed_url.scheme == "https"
        
        # Suspicious keywords
        url_lower = self.url.lower()
        suspicious_count = sum(1 for keyword in self.SUSPICIOUS_KEYWORDS if keyword in url_lower)
        features["num_suspicious_keywords"] = suspicious_count
        
        return features
