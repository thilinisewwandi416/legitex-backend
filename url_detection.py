import joblib
import pandas as pd
import socket
import validators
import re
from urllib.parse import urlparse

rf_model, features = joblib.load("phishing_detector_rf_new.pkl")
gb_model, _ = joblib.load("phishing_detector_gb_new.pkl")

def is_valid_url(url):
    return validators.url(url)

def check_domain_exists(domain):
    try:
        socket.gethostbyname(domain)
        return True
    except socket.gaierror:
        return False

def extract_features(url):
    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    path = parsed.path.lower()

    return {
        'URLLength': len(url),
        'DomainLength': len(domain),
        'IsDomainIP': 1 if re.match(r'\d+\.\d+\.\d+\.\d+', domain) else 0,
        'NoOfSubDomain': len(domain.split('.')) - 2,
        'IsHTTPS': 1 if parsed.scheme == 'https' else 0,
        'ContainsLoginKeyword': int(any(k in url for k in ['login', 'signin', 'secure', 'auth', 'account'])),
        'ContainsOfficeKeyword': int(any(k in url for k in ['office', '365', 'microsoft', 'outlook'])),
        'HasRandomSubdomain': 1 if re.match(r'^[a-z0-9]{6,}-[a-z0-9]+', domain) else 0,
        'ContainsTokenOrParam': 1 if '?' in url or 'token=' in url else 0,
        'PathDepth': path.count('/'),
        'SpecialCharCount': sum(url.count(c) for c in ['@', '%', '-', '_', '=', '&']),
        'HasHexEncoding': 1 if re.search(r'%[0-9a-fA-F]{2}', url) else 0,
        'HasNumericSubdomain': 1 if any(part.isdigit() for part in domain.split('.')) else 0,
        'ContainsSuspiciousBrand': int(any(k in domain for k in ['paypal', 'hsbc', 'hnb', 'combank', 'outlook', 'office365'])),
        'IsSuspiciousSubdomain': int(bool(re.search(r'[a-z0-9]{6,}-[a-z0-9]+', domain))),
    }

def classify_confidence(confidence):
    if confidence <= 5:
        return "SECURE", "#4caf50"
    elif confidence <= 20:
        return "MODERATELY SECURE", "#ff9800"
    elif confidence <= 40:
        return "HIGH RISK", "#ff5722"
    else:
        return "DANGEROUS", "#f44336"

def analyze_url(url, rf_weight=0.5, gb_weight=0.5, heuristic_weight=0.5):
    if not is_valid_url(url):
        return {"error": "Invalid URL format."}

    parsed_url = urlparse(url)
    domain = parsed_url.netloc
    if not check_domain_exists(domain):
        return {"error": f"Domain {domain} does not exist."}

    features_dict = extract_features(url)
    
    rf_input = pd.DataFrame([[features_dict[feat] for feat in features]], columns=features)
    gb_input = pd.DataFrame([[features_dict[feat] for feat in gb_model.feature_names_in_]], columns=gb_model.feature_names_in_)

    rf_conf = rf_model.predict_proba(rf_input)[0][1] * 100
    gb_conf = gb_model.predict_proba(gb_input)[0][1] * 100

    heur_score = 0
    if features_dict.get('ContainsSuspiciousBrand') and features_dict.get('ContainsLoginKeyword') and features_dict.get('IsSuspiciousSubdomain'):
        heur_score = 90
    elif features_dict.get('ContainsSuspiciousBrand') and features_dict.get('IsSuspiciousSubdomain'):
        heur_score = 70
    elif features_dict.get('ContainsLoginKeyword'):
        heur_score = 40

    combined_conf = (
        rf_conf * rf_weight +
        gb_conf * gb_weight +
        heur_score * heuristic_weight
    ) / (rf_weight + gb_weight + heuristic_weight)

    label, color = classify_confidence(combined_conf)

    return {
        "url": url,
        "phishing_confidence": round(combined_conf, 2),
        "label": label,
        "color": color,
        "is_phishing": bool(combined_conf > 40),
        "rf_conf": round(rf_conf, 2),
        "gb_conf": round(gb_conf, 2),
        "heuristic_score": heur_score
    }


if __name__ == "__main__":
    test_url = input("🔍 Enter a URL to analyze: ").strip()
    result = analyze_url(test_url)
    
    if "error" in result:
        print(f"❌ {result['error']}")
    else:
        print("\n🎯 Unified Phishing Analysis")
        print(f"🔗 URL:              {result['url']}")
        print(f"📊 RF Confidence:    {result['rf_conf']}%")
        print(f"📊 GB Confidence:    {result['gb_conf']}%")
        print(f"🧠 Heuristic Score:  {result['heuristic_score']}%")
        print(f"🔮 Combined Score:   {result['phishing_confidence']}%")
        print(f"🏷️  Final Verdict:    {result['label']}")
        print(f"🎨 Color Code:       {result['color']}")