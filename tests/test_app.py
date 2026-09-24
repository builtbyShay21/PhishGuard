import pytest
from app import app

@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client

def test_index_get(client):
    response = client.get("/")
    assert response.status_code == 200
    assert b"PhishGuard" in response.data
    assert b"Analyze Before" in response.data

def test_valid_url_submission(client):
    response = client.post("/", data={"url": "https://example.com/login"})
    assert response.status_code == 200
    assert b"THREAT ANALYSIS REPORT" in response.data
    assert b"RISK" in response.data
    assert b"https://example.com/login" in response.data

def test_url_without_scheme(client):
    response = client.post("/", data={"url": "example.com"})
    assert response.status_code == 200
    assert b"https://example.com" in response.data

def test_empty_url(client):
    response = client.post("/", data={"url": "   "})
    assert response.status_code == 200
    assert b"Please enter a URL." in response.data

def test_unsupported_scheme(client):
    response = client.post("/", data={"url": "ftp://example.com"})
    assert response.status_code == 200
    assert b"Unsupported scheme" in response.data

def test_xss_prevention(client):
    malicious_url = "http://example.com/<script>alert(1)</script>"
    response = client.post("/", data={"url": malicious_url})
    assert response.status_code == 200
    # Should be HTML escaped by Jinja automatically, so the raw <script> tag shouldn't be rendered as-is
    assert b"<script>alert(1)</script>" not in response.data
    assert b"&lt;script&gt;alert(1)&lt;/script&gt;" in response.data
