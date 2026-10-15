import re
from urllib.parse import urlparse

def analyze_phishing(sender: str, url: str, content: str) -> dict:
    indicators = []
    risk_score = 0
    
    free_providers = ["gmail.com", "yahoo.com", "hotmail.com", "outlook.com"]
    sender_lower = sender.lower()
    if "@" in sender_lower:
        domain = sender_lower.split("@")[1]
        if any(fp in domain for fp in free_providers) and ("support" in content.lower() or "security" in content.lower()):
            indicators.append("Suspicious use of free email provider claiming official service/support.")
            risk_score += 30
    else:
        indicators.append("Invalid or missing sender email format.")
        risk_score += 20

    if url:
        parsed_url = urlparse(url)
        netloc = parsed_url.netloc or url
        
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", netloc.split(":")[0]):
            indicators.append("URL uses a raw IP address instead of a domain name.")
            risk_score += 40
            
        if "@" in url:
            indicators.append("URL contains '@' symbol, often used to obscure true destination.")
            risk_score += 35
            
        brands = ["paypal", "netflix", "amazon", "apple", "google", "bank"]
        for brand in brands:
            if brand in url.lower() and not url.lower().endswith(f".{brand}.com") and brand not in netloc.lower():
                indicators.append(f"Potential typosquatting or brand impersonation detected for: {brand}")
                risk_score += 25
    else:
        indicators.append("No URL provided for analysis.")

    urgent_keywords = ["urgent", "verify", "suspended", "immediate action", "click here", "login now", "expired"]
    found_keywords = [kw for kw in urgent_keywords if kw in content.lower()]
    if found_keywords:
        indicators.append(f"High-pressure or urgent language detected: {', '.join(found_keywords)}")
        risk_score += len(found_keywords) * 10

    if risk_score >= 50:
        risk_level = "HIGH RISK (Likely Phishing)"
        recommendation = "Do not click links, do not reply, and report this communication immediately."
    elif risk_score >= 20:
        risk_level = "MEDIUM RISK (Suspicious)"
        recommendation = "Proceed with extreme caution. Verify the sender through official independent channels."
    else:
        risk_level = "LOW RISK (Appears Safe)"
        recommendation = "No major threat indicators found, but always remain vigilant."

    return {
        "risk_score": min(risk_score, 100),
        "risk_level": risk_level,
        "indicators": indicators,
        "recommendation": recommendation
    }