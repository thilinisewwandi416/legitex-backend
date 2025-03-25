import joblib
import pandas as pd
import socket
import validators
import re
from urllib.parse import urlparse
from fuzzywuzzy import fuzz

rf_model, FEATURE_COLUMNS = joblib.load("phishing_detector_rf.pkl")
svm_model, _ = joblib.load("phishing_detector_svm.pkl")

def is_valid_url(url):
    return validators.url(url)

def check_domain_exists(domain):
    try:
        socket.gethostbyname(domain)
        return True
    except socket.gaierror:
        return False

def is_typosquatting(domain):
    common_domains = ["google.com", "paypal.com", "amazon.com", "facebook.com"]
    return any(fuzz.ratio(domain, common) > 80 for common in common_domains)

def extract_url_features(url):
    parsed_url = urlparse(url)
    domain = parsed_url.netloc
    features = {
        'NumDots': url.count("."),
        'SubdomainLevel': len(domain.split(".")) - 2,
        'UrlLength': len(url),
        'NumDash': url.count("-"),
        'AtSymbol': 1 if "@" in url else 0,
        'IpAddress': 1 if re.match(r'\\d+\\.\\d+\\.\\d+\\.\\d+', domain) else 0,
        'HostnameLength': len(domain)
    }
    return {feature: features.get(feature, 0) for feature in FEATURE_COLUMNS}

def analyze_url(url):
    if not is_valid_url(url):
        return {"error": "Invalid URL format."}

    parsed_url = urlparse(url)
    domain = parsed_url.netloc
    if not check_domain_exists(domain):
        return {"error": f"Domain {domain} does not exist."}

    typosquatting = is_typosquatting(domain)
    features = extract_url_features(url)
    feature_df = pd.DataFrame([features])

    rf_proba = rf_model.predict_proba(feature_df)[0][1]
    svm_proba = svm_model.predict_proba(feature_df)[0][1]

    phishing_confidence = max(rf_proba, svm_proba)
    return {
        "typosquatting_detected": typosquatting,
        "phishing_confidence": phishing_confidence,
        "is_phishing": phishing_confidence > 0.5
    }