import streamlit as st
from src.detector import analyze_url

st.set_page_config(page_title="CyberShield - Phishing URL Detector", page_icon="🛡️", layout="centered")

st.title("🛡️ CyberShield")
st.subheader("Phishing URL Detection System")
st.write("Enter a URL to analyze its structure and identify suspicious characteristics.")

url = st.text_input("URL", placeholder="https://example.com/login")

if st.button("Analyze URL", type="primary"):
    if not url.strip():
        st.warning("Please enter a URL.")
    else:
        result = analyze_url(url.strip())
        st.divider()
        if result["label"] == "Phishing":
            st.error(f"⚠️ {result['label']} — Risk score: {result['score']}/100")
        elif result["label"] == "Suspicious":
            st.warning(f"⚠️ {result['label']} — Risk score: {result['score']}/100")
        else:
            st.success(f"✅ {result['label']} — Risk score: {result['score']}/100")

        st.write(f"**Normalized URL:** `{result['normalized_url']}`")
        st.write("### Why was it flagged?")
        if result["reasons"]:
            for reason in result["reasons"]:
                st.write(f"- {reason}")
        else:
            st.write("- No major suspicious indicators were detected.")

        st.write("### Extracted features")
        st.json(result["features"])

st.caption("Academic defensive-security project. Analyze URLs only; do not visit suspicious links.")
