import joblib
import pandas as pd
import socket
import validators
import re
from urllib.parse import urlparse

# Load Random Forest model and features
rf_model, features = joblib.load("phishing_detector_rf_advanced.pkl")

# Validate URL format
def is_valid_url(url):
    return validators.url(url)

# DNS check
def check_domain_exists(domain):
    try:
        socket.gethostbyname(domain)
        return True
    except socket.gaierror:
        return False

# Updated feature extractor
def extract_features(url):
    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    path = parsed.path.lower()
    query = parsed.query.lower()

    return {
        'URLLength': len(url),
        'DomainLength': len(domain),
        'IsDomainIP': 1 if re.match(r'\d+\.\d+\.\d+\.\d+', domain) else 0,
        'NoOfSubDomain': len(domain.split('.')) - 2,
        'IsHTTPS': 1 if parsed.scheme == 'https' else 0,
        'ContainsLoginKeyword': int(any(k in url for k in ['login', 'signin', 'secure', 'auth', 'account'])),
        'ContainsOfficeKeyword': int(any(k in url for k in ['office', '365', 'microsoft', 'outlook'])),
        'HasRandomSubdomain': 1 if re.match(r'^[a-z0-9]{6,}-', domain) else 0,
        'ContainsTokenOrParam': 1 if '?' in url or 'token=' in url else 0,
        'PathDepth': path.count('/'),
        'SpecialCharCount': sum(url.count(c) for c in ['@', '%', '-', '_', '=', '&']),
        'HasHexEncoding': 1 if re.search(r'%[0-9a-fA-F]{2}', url) else 0,
        'HasNumericSubdomain': 1 if any(part.isdigit() for part in domain.split('.')) else 0,
    }

# Labeling logic
def classify_confidence(confidence):
    if confidence <= 10:
        return "SECURE", "#4caf50"
    elif confidence <= 30:
        return "MODERATELY SECURE", "#ff9800"
    elif confidence <= 50:
        return "HIGH RISK", "#ff5722"
    else:
        return "DANGEROUS", "#f44336"

# Main analysis function
def analyze_url(url):
    if not is_valid_url(url):
        return {"error": "Invalid URL format."}

    parsed_url = urlparse(url)
    domain = parsed_url.netloc
    if not check_domain_exists(domain):
        return {"error": f"Domain {domain} does not exist."}

    features_dict = extract_features(url)
    feature_df = pd.DataFrame([features_dict])[features]

    confidence = rf_model.predict_proba(feature_df)[0][1] * 100
    label, color = classify_confidence(confidence)

    return {
        "url": url,
        "phishing_confidence": round(confidence, 2),
        "label": label,
        "color": color,
        "is_phishing": bool(confidence > 50)
    }

# Optional direct test
if __name__ == "__main__":
    test_url = input("🔍 Enter a URL to analyze: ").strip()
    result = analyze_url(test_url)
    print("\n🎯 Analysis Result:")
    for k, v in result.items():
        print(f"{k}: {v}")