
import streamlit as st
import re
import time

st.set_page_config(page_title="Phishing Email Detector", page_icon="🔐")

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

    confidence = min(score, 100)

    return score, confidence, risk, found_keywords, found_urls


st.title("🔐 AI Powered Phishing Email Detection System")
st.write("Enter an email message below to analyze its phishing risk level.")

email_input = st.text_area("📧 Paste Email Content Here", height=250)

if st.button("🔍 Analyze Email"):
    if email_input.strip() == "":
        st.warning("Please enter email content.")
    else:
        start_time = time.time()
        score, confidence, risk, keywords, urls = analyze_email(email_input)
        end_time = time.time()

        st.subheader("📊 Analysis Result")

        if "High" in risk:
            st.error("🚨 HIGH RISK EMAIL DETECTED")
            st.markdown("### ⚠️ This email shows strong indicators of phishing. Do NOT click any suspicious links.")
        elif "Moderate" in risk:
            st.warning("⚠️ MODERATE RISK EMAIL")
            st.markdown("### ⚠️ This email may contain suspicious elements. Verify before taking action.")
        else:
            st.success("✅ SAFE EMAIL")
            st.markdown("### ✅ This email appears safe based on analysis.")

        st.write(f"**Risk Score:** {score}")
        st.write(f"**Confidence Level:** {confidence}%")
        st.write(f"**Detected Keywords:** {keywords if keywords else 'None'}")
        st.write(f"**Detected URLs:** {urls if urls else 'None'}")
        st.write(f"**Analysis Time:** {round(end_time - start_time, 4)} seconds")

        st.subheader("🧠 AI Analysis Report")

        report = f"""
The system analyzed the email using keyword detection and URL pattern recognition techniques.
It identified {len(keywords)} phishing-related keyword(s) and {len(urls)} suspicious URL(s).
Phishing emails commonly use urgent language to create panic and force quick decisions.
They may request sensitive information such as passwords, banking details, or account verification.
Suspicious URLs, especially IP-based links, are strong phishing indicators.
Legitimate organizations rarely use raw IP addresses in official communications.
Excessive punctuation such as multiple exclamation marks also increases risk probability.
The calculated risk score for this email is {score}.
Based on this score, the email is classified as "{risk}".
The confidence level of this classification is {confidence}%.
Users should avoid clicking unknown links or downloading attachments from suspicious emails.
Always verify the sender's identity before sharing sensitive information.
Automated detection improves security but manual verification is recommended for critical actions.
Stay alert and practice safe email handling habits to prevent cyber threats.
        """

        st.write(report)
