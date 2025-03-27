import random
from urllib.parse import urlparse

def check_visual_similarity(url):
    parsed = urlparse(url)
    domain = parsed.netloc

    if "alerting-services.com" in domain:
        # Random high visual similarity (80% - 98%) for suspicious domains
        similarity_score = round(random.uniform(80.0, 98.0), 2)
        return {
            "visual_similarity_detected": True,
            "similarity_score": similarity_score,
            "reason": "Suspicious subdomain under alerting-services.com"
        }

    # Low similarity score (0% - 5%) for non-suspicious domains
    similarity_score = round(random.uniform(0.0, 5.0), 2)
    return {
        "visual_similarity_detected": False,
        "similarity_score": similarity_score
    }
