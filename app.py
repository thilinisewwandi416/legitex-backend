from flask import Flask, request, jsonify
from models import db, URLCheck
from ssl_checker import check_ssl_certificate_info
from url_detection import analyze_url
from auth import auth_bp, token_required
from visual_similarity import check_visual_similarity
from datetime import datetime
import os

app = Flask(__name__)

db_user = os.environ.get('DB_USERNAME', 'legitex')
db_password = os.environ.get('DB_PASSWORD', '4dxr25Dk6GTeqO1M')
db_host = os.environ.get('DB_HOST', '35.240.249.232')
db_name = os.environ.get('DB_NAME', 'legitex')

app.config['SQLALCHEMY_DATABASE_URI'] = f'mysql+pymysql://{db_user}:{db_password}@{db_host}/{db_name}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = os.environ.get('SECRET_KEY', 'a022f97d61d66eacaa5217c8e8da7923b1e4626e12d0d1bac27ac0b8c1bfe28c')

db.init_app(app)

with app.app_context():
    db.create_all()

app.register_blueprint(auth_bp)

@app.route('/analyze_url', methods=['POST'])
@token_required
def analyze_url_endpoint(current_user):
    data = request.get_json()
    url = data.get('url')
    if not url:
        return jsonify({"error": "Missing 'url' in request body"}), 400

    domain = url.split("//")[-1].split("/")[0]
    ssl_result = check_ssl_certificate_info(domain)
    phishing_result = analyze_url(url)
    visual_result = check_visual_similarity(url)

    url_check = URLCheck(
        user_id=current_user.id,
        url=url,
        phishing_confidence=phishing_result.get("phishing_confidence", 0),
        visual_similarity_detected=visual_result.get("visual_similarity_detected", False),
        is_safe=not phishing_result.get("is_phishing", False)
    )
    db.session.add(url_check)
    db.session.commit()

    return jsonify({
        "url": url,
        "ssl_check": ssl_result,
        "phishing_check": phishing_result,
        "visual_similarity": visual_result
    })

@app.route('/report', methods=['GET'])
@token_required
def report(current_user):
    checks = URLCheck.query.filter_by(user_id=current_user.id).order_by(URLCheck.checked_at.desc()).all()
    report_data = []

    for check in checks:
        title = "Phishing detected" if check.phishing_confidence > 0.5 else "Likely Safe"
        issue = []
        if check.phishing_confidence > 0.5:
            issue.append("URL Reputation")
        if check.visual_similarity_detected:
            issue.append("Visual Clone")
        if not issue:
            issue.append("None")

        report_data.append({
            "url": check.url,
            "score": "Critical" if not check.is_safe else "Safe",
            "title": title,
            "issue": ", ".join(issue),
            "checked_at": check.checked_at.strftime("%Y-%m-%d %H:%M:%S")
        })

    return jsonify(report_data)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
