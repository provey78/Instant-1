import re
from urllib.parse import urlparse
import ipaddress
import requests
import logging
import os
import time

logger = logging.getLogger(__name__)

# Suspicious keywords for URL checks
SUSPICIOUS_KEYWORDS = ['login', 'secure', 'account', 'update', 'bank', 'verify', 'signin', 'password']

# Hardcoded API Keys (as requested)
# WARNING: For production, use environment variables or a secure config file instead.
ABUSEIPDB_API_KEY = '474d1ac4942db951d3e17b411652db34c566de66c709b2118c38735ca797fdc3c2086cc253052c28'
IPINFO_API_KEY = '8497f12d11a03e'
VIRUSTOTAL_API_KEY = '3561a4da8adb933ccc428ce84f314e191fde11147034b9e5a237856463da72b1'

def is_valid_url(url):
    """Validate if the input is a proper URL."""
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc]) and re.match(r'^https?://', url)
    except ValueError:
        return False

def is_valid_ip(ip):
    """Validate if the input is a valid IP address (IPv4 or IPv6)."""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def analyze_url(url):
    """Analyze a URL for suspicious patterns with a structured scoring system (0-100)."""
    parsed = urlparse(url)
    netloc = parsed.netloc
    path = parsed.path.lower()

    score = 0
    reasons = []

    # High-risk checks (50 points each)
    if is_valid_ip(netloc):  # Domain is an IP address (highly suspicious)
        score += 50
        reasons.append("High Risk: Domain uses an IP address, often indicative of phishing")

    # Medium-risk checks (25 points each)
    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in path:
            score += 25
            reasons.append(f"Medium Risk: Contains suspicious keyword '{keyword}'")
            break

    # Low-risk checks (5-15 points each)
    if len(url) > 75:  # Long URL
        score += 10
        reasons.append("Low Risk: URL length exceeds 75 characters, potentially obfuscating intent")

    if parsed.scheme != 'https':  # No HTTPS
        score += 15
        reasons.append("Low Risk: Does not use HTTPS, increasing vulnerability")

    # Check VirusTotal for URL reputation
    vt_score, vt_reason = check_virustotal_url(url)
    if vt_score > 0:
        score += vt_score
        reasons.append(vt_reason)

    # Normalize score to 100 (cap at 100 to avoid exceeding)
    score = min(score, 100)

    is_suspicious = score >= 30  # Threshold for "Suspicious"
    return is_suspicious, score, reasons

def check_virustotal_url(url):
    """
    Check URL against VirusTotal for malicious indicators.
    Returns a score (0-50) based on the number of engines flagging the URL.
    """
    vt_url = 'https://www.virustotal.com/api/v3/urls'
    headers = {'x-apikey': VIRUSTOTAL_API_KEY}
    data = {'url': url}

    try:
        response = requests.post(vt_url, headers=headers, data=data, timeout=10)
        response.raise_for_status()
        analysis_id = response.json()['data']['id']

        # Wait for analysis to complete (VirusTotal requires polling)
        analysis_url = f'https://www.virustotal.com/api/v3/analyses/{analysis_id}'
        for _ in range(5):  # Retry up to 5 times
            response = requests.get(analysis_url, headers=headers, timeout=10)
            response.raise_for_status()
            status = response.json()['data']['attributes']['status']
            if status == 'completed':
                stats = response.json()['data']['attributes']['stats']
                malicious = stats.get('malicious', 0)
                if malicious > 0:
                    score = min(malicious * 10, 50)  # Cap at 50 points
                    reason = f"High Risk: URL flagged as malicious by {malicious} VirusTotal engines"
                    return score, reason
                return 0, "No malicious activity detected by VirusTotal"
            time.sleep(2)
        return 0, "VirusTotal analysis timed out"
    except requests.RequestException as e:
        logger.error(f"Failed to check URL with VirusTotal: {e}")
        return 0, "Warning: Unable to verify URL with VirusTotal due to service failure"

def get_ip_reputation(ip):
    """
    Assign a risk score (0-100) to an IP based on AbuseIPDB, IPinfo.io, and heuristics.
    """
    risk_score = 0
    reasons = []

    # 1. Blacklist Check (AbuseIPDB)
    try:
        url = 'https://api.abuseipdb.com/api/v2/check'
        params = {'ipAddress': ip, 'maxAgeInDays': '90'}
        headers = {'Key': ABUSEIPDB_API_KEY, 'Accept': 'application/json'}
        response = requests.get(url, headers=headers, params=params, timeout=10)
        response.raise_for_status()
        data = response.json()
        abuse_score = data['data']['abuseConfidenceScore']

        if abuse_score > 0:
            risk_score = abuse_score  # Use AbuseIPDB's confidence score directly (0-100)
            if abuse_score > 50:
                reasons.append(f"High Risk: IP flagged in blacklist with confidence score of {abuse_score}%")
            else:
                reasons.append(f"Low Risk: IP has a minor blacklist flag with confidence score of {abuse_score}%")
    except requests.RequestException as e:
        logger.error(f"Failed to check IP with AbuseIPDB: {e}")
        reasons.append("Warning: Unable to verify IP blacklist status due to service failure")
        risk_score += 10  # Add minimal risk for unverified IPs

    # 2. Geolocation & VPN Check (IPinfo.io)
    try:
        url = f'https://ipinfo.io/{ip}/json?token={IPINFO_API_KEY}'
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        data = response.json()
        if 'bogon' in data or 'vpn' in data.get('privacy', {}):
            risk_score += 20
            reasons.append("Medium Risk: IP belongs to a VPN, proxy, or bogon range, often used for malicious purposes")
    except requests.RequestException as e:
        logger.error(f"Failed to check IP geolocation with IPinfo.io: {e}")
        reasons.append("Warning: Unable to verify IP geolocation due to service failure")

    # 3. Additional Heuristics (e.g., numeric sum of segments)
    try:
        segments = [int(part) for part in ip.split('.')]
        suspicion_factor = sum(segments)
        if suspicion_factor > 500:
            risk_score += 15
            reasons.append("Low Risk: IP segments suggest potential suspicious pattern")
    except ValueError:
        risk_score += 100  # Invalid IP is extremely suspicious
        reasons.append("Critical Risk: IP format is invalid or malformed")

    # Clip the score to a max of 100
    risk_score = min(risk_score, 100)
    return risk_score, reasons

def classify_ip_risk(score):
    """
    Converts numerical score into a risk category.
    """
    if score < 30:
        return "Safe"
    elif score < 70:
        return "Suspicious"
    else:
        return "Highly Suspicious"

def analyze_ip(ip):
    """
    Analyze an IP address using the structured scoring system.
    """
    if not is_valid_ip(ip):
        return False, 0, ["Invalid: Input is not a valid IP address"]

    score, reasons = get_ip_reputation(ip)
    risk_category = classify_ip_risk(score)
    is_suspicious = risk_category != "Safe"

    return is_suspicious, score, reasons
