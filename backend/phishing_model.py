import re
import tldextract
import whois
from datetime import datetime
import requests

def check_for_phishing_rules(url):
    """
    Analyzes a URL using a set of rules, assigning a score and a verdict.
    """
    suspicious_score = 0
    safe_score = 0
    suspicious_reasons = []
    safe_reasons = []

    # Extract domain info using tldextract
    try:
        extracted = tldextract.extract(url)
        domain = extracted.domain + '.' + extracted.suffix
        suffix = extracted.suffix
    except Exception:
        return "Malicious", 100, ["Invalid URL format."], []

    # --- Suspicious Rules ---
    # Rule 1: Check for an IP address instead of a domain name
    ip_pattern = r"(?:\d{1,3}\.){3}\d{1,3}"
    if re.search(ip_pattern, url):
        suspicious_score += 40
        suspicious_reasons.append("URL uses an IP address instead of a domain.")

    # Rule 2: No HTTPS
    if not url.startswith("https://"):
        suspicious_score += 20
        suspicious_reasons.append("URL does not use HTTPS.")

    # Rule 3: @ symbol trick
    if "@" in url:
        suspicious_score += 40
        suspicious_reasons.append("URL contains '@' symbol (phishing trick).")

    # Rule 4: Too many hyphens in domain
    if domain.count("-") > 2:
        suspicious_score += 15
        suspicious_reasons.append("Too many hyphens in the domain.")

    # Rule 5: Unusually long domain name
    if len(domain) > 20:
        suspicious_score += 15
        suspicious_reasons.append("Unusually long domain name.")
        
    # Rule 6: Too many subdomains
    if extracted.subdomain.count(".") > 1:
        suspicious_score += 15
        suspicious_reasons.append("Too many subdomains in the URL.")

    # Rule 7: Suspicious TLDs
    bad_tlds = ["xyz", "tk", "top", "buzz", "click", "gq", "ml"]
    if suffix in bad_tlds:
        suspicious_score += 30
        suspicious_reasons.append(f"Suspicious top-level domain: .{suffix}.")
    
    # Rule 8: Common phishing keywords
    phishing_keywords = ["login", "verify", "secure", "account", "update", "banking"]
    found_keywords = [kw for kw in phishing_keywords if kw in url.lower()]
    if found_keywords:
        suspicious_score += 25
        suspicious_reasons.append(f"Suspicious keyword(s) found in URL: {', '.join(found_keywords)}.")

    # Rule 9: Check for URL Redirection
    try:
        response = requests.get(url, allow_redirects=False, timeout=5)
        if 300 <= response.status_code < 400:
            suspicious_score += 20
            suspicious_reasons.append("URL uses a redirect, which is a common phishing tactic.")
    except (requests.exceptions.RequestException, requests.exceptions.Timeout):
        suspicious_score += 10
        suspicious_reasons.append("Could not connect to the URL.")

    # Rule 10: Check for a very old domain
    try:
        domain_info = whois.whois(domain)
        if isinstance(domain_info.creation_date, list):
            creation_date = domain_info.creation_date[0]
        else:
            creation_date = domain_info.creation_date
            
        if creation_date:
            days_old = (datetime.now() - creation_date).days
            if days_old < 60:
                suspicious_score += 30
                suspicious_reasons.append(f"Domain is very new (registered {days_old} days ago).")
            elif days_old > 365:
                safe_score += 20
                safe_reasons.append(f"Domain is old and trusted (registered {days_old} days ago).")
    except Exception:
        pass

    # --- New Safe Rules ---
    # Rule 11: Check for HTTPS
    if url.startswith("https://"):
        safe_score += 10
        safe_reasons.append("URL uses a secure HTTPS connection.")
        
    # Rule 12: Check for a common TLD
    common_tlds = [".com", ".org", ".net", ".gov", ".edu"]
    if extracted.suffix in common_tlds:
        safe_score += 10
        safe_reasons.append(f"URL uses a common TLD: .{extracted.suffix}.")

    # Decide verdict based on the two scores
    verdict = ""
    score_to_display = 0
    reasons_to_display = []
    
    if suspicious_score > safe_score:
        if suspicious_score >= 60:
            verdict = "Malicious"
            score_to_display = suspicious_score
        else:
            verdict = "Suspicious"
            score_to_display = suspicious_score
        reasons_to_display = suspicious_reasons
    elif suspicious_score == safe_score and suspicious_score > 0:
        verdict = "Suspicious"
        score_to_display = suspicious_score
        reasons_to_display = suspicious_reasons
    else:
        verdict = "Safe"
        score_to_display = safe_score
        reasons_to_display = safe_reasons

    # Ensure the score is not negative
    if score_to_display < 0:
        score_to_display = 0
        
    if not reasons_to_display and verdict == "Safe":
        reasons_to_display.append("No obvious suspicious signs found.")
        
    return verdict, score_to_display, reasons_to_display
