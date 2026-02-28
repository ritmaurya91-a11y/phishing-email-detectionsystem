from flask import Flask, render_template, request
import re
import time

app = Flask(__name__)

PHISHING_KEYWORDS = [
    "urgent", "verify", "account suspended",
    "click here", "bank", "password",
    "login", "confirm", "limited time",
    "update your account", "security alert"
]

def detect_urls(text):
    url_pattern = r'(https?://[^\s]+)'
    return re.findall(url_pattern, text)

def analyze_email(content):
    score = 0
    found_keywords = []
    found_urls = detect_urls(content)

    content_lower = content.lower()

    for keyword in PHISHING_KEYWORDS:
        if keyword in content_lower:
            score += 10
            found_keywords.append(keyword)

    if len(found_urls) > 0:
        score += 15

    for url in found_urls:
        if re.search(r'https?://\d+\.\d+\.\d+\.\d+', url):
            score += 20

    if content.count("!") > 3:
        score += 10

    if score >= 40:
        risk = "High Risk (Likely Phishing)"
    elif score >= 20:
        risk = "Moderate Risk"
    else:
        risk = "Safe Email"

    return score, risk, found_keywords, found_urls


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/analyze', methods=['POST'])
def analyze():
    email_content = request.form['email_content']
    start_time = time.time()

    score, risk, keywords, urls = analyze_email(email_content)

    end_time = time.time()
    analysis_time = round(end_time - start_time, 4)

    return render_template('result.html',
                           score=score,
                           risk=risk,
                           keywords=keywords,
                           urls=urls,
                           analysis_time=analysis_time)


if __name__ == '__main__':
    app.run(debug=True)
