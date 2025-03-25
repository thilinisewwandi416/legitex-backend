from flask import Flask, request, jsonify
from ssl_checker import check_ssl_certificate_info
from url_detection import analyze_url

app = Flask(__name__)

@app.route('/analyze_url', methods=['POST'])
def analyze_url_endpoint():
    data = request.get_json()
    url = data.get('url')
    if not url:
        return jsonify({"error": "Missing 'url' in request body"}), 400

    domain = url.split("//")[-1].split("/")[0]
    ssl_result = check_ssl_certificate_info(domain)
    phishing_result = analyze_url(url)

    return jsonify({
        "url": url,
        "ssl_check": ssl_result,
        "phishing_check": phishing_result
    })

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)