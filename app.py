import streamlit as st
from detector import analyze_phishing

st.set_page_config(page_title="Intelligent Phishing Detection & Response", layout="centered")

st.title("🛡️ Intelligent Phishing Detection & Response System")
st.markdown("Analyze suspicious emails, sender details, and URLs to assess risk and get guidance[cite: 3].")

with st.form("phishing_form"):
    sender = st.text_input("Sender Email Address", placeholder="e.g., support@update-paypal-security.com")
    url = st.text_input("Suspicious URL (if any)", placeholder="e.g., http://192.168.1.1/login")
    content = st.text_area("Message / Email Content", placeholder="Paste the message content here...")
    
    submitted = st.form_submit_button("Analyze Threat")

if submitted:
    if not sender and not content:
        st.warning("Please provide at least the sender details or message content.")
    else:
        result = analyze_phishing(sender, url, content)
        
        st.divider()
        st.subheader("📊 Analysis & Risk Assessment")
        
        if "HIGH" in result["risk_level"]:
            st.error(f"**Classification:** {result['risk_level']}")
        elif "MEDIUM" in result["risk_level"]:
            st.warning(f"**Classification:** {result['risk_level']}")
        else:
            st.success(f"**Classification:** {result['risk_level']}")
            
        st.metric(label="Calculated Risk Score", value=f"{result['risk_score']}/100")
        
        st.subheader("🔍 Detected Indicators (Evidence)")
        if result["indicators"]:
            for ind in result["indicators"]:
                st.write(f"- {ind}")
        else:
            st.write("- No suspicious indicators found.")
            
        st.subheader("💡 Recommended Security Action")
        st.info(result["recommendation"])
        
        report_text = f"""PHISHING SECURITY REPORT
----------------------------------------
Sender: {sender}
URL: {url}
Risk Level: {result['risk_level']}
Risk Score: {result['risk_score']}/100

Evidence Found:
""" + "\n".join([f"- {i}" for i in result['indicators']]) + f"""

Recommended Action:
{result['recommendation']}
"""
        st.download_button(
            label="Download Security Report (.txt)",
            data=report_text,
            file_name="phishing_security_report.txt",
            mime="text/plain"
        )