import urllib.parse

def normalize_and_validate_url(url: str) -> str:
    """
    Normalizes and validates a URL string.
    
    Args:
        url: The URL string to validate.
        
    Returns:
        The normalized URL string.
        
    Raises:
        ValueError: If the URL is empty, invalid, or uses an unsupported scheme.
    """
    url = url.strip()
    if not url:
        raise ValueError("URL cannot be empty.")
        
    # Check if a scheme is present; if not, prepend https://
    parsed = urllib.parse.urlparse(url)
    if not parsed.scheme and not parsed.netloc:
        url = "https://" + url
        parsed = urllib.parse.urlparse(url)
        
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"Unsupported scheme: '{parsed.scheme}'. Only http and https are allowed.")
        
    if not parsed.netloc:
        raise ValueError("Invalid URL: missing hostname.")
        
    return urllib.parse.urlunparse(parsed)
