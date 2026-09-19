import ipaddress
import re
from urllib.parse import urlparse

SUSPICIOUS_KEYWORDS = {
    "login", "verify", "verification", "account", "secure", "update",
    "password", "signin", "confirm", "banking", "wallet", "invoice",
    "payment", "unlock", "credential", "free", "bonus"
}

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "goo.gl", "ow.ly",
    "buff.ly", "cutt.ly", "shorturl.at"
}

def normalize_url(url: str) -> str:
    url = url.strip()
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        url = "http://" + url
    return url

def is_ip_host(host: str) -> bool:
    if not host:
        return False
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False

def extract_features(url: str) -> dict:
    normalized = normalize_url(url)
    parsed = urlparse(normalized)
    host = parsed.hostname or ""
    path = parsed.path or ""
    full = normalized.lower()

    subdomains = max(0, host.count(".") - 1)
    suspicious_keyword_count = sum(1 for k in SUSPICIOUS_KEYWORDS if k in full)
    special_chars = sum(full.count(c) for c in ["@", "-", "_", "=", "&", "%"])
    hyphen_count = host.count("-")
    digit_count = sum(ch.isdigit() for ch in host)
    query_length = len(parsed.query)
    entropy_like = len(set(host)) / max(len(host), 1)

    return {
        "url_length": len(normalized),
        "hostname_length": len(host),
        "path_length": len(path),
        "dot_count": normalized.count("."),
        "subdomain_count": subdomains,
        "has_ip_address": is_ip_host(host),
        "uses_https": parsed.scheme.lower() == "https",
        "has_at_symbol": "@" in normalized,
        "hyphen_count": hyphen_count,
        "digit_count_in_host": digit_count,
        "special_character_count": special_chars,
        "suspicious_keyword_count": suspicious_keyword_count,
        "query_length": query_length,
        "is_url_shortener": host.lower() in SHORTENERS,
        "has_punycode": "xn--" in host.lower(),
        "host": host,
        "scheme": parsed.scheme.lower(),
    }

def analyze_url(url: str) -> dict:
    normalized = normalize_url(url)
    f = extract_features(url)
    score = 0
    reasons = []

    if not f["uses_https"]:
        score += 15
        reasons.append("The URL does not use HTTPS.")
    if f["has_ip_address"]:
        score += 25
        reasons.append("The hostname is an IP address instead of a normal domain.")
    if f["has_at_symbol"]:
        score += 25
        reasons.append("The URL contains '@', which can hide the actual destination.")
    if f["url_length"] > 100:
        score += 15
        reasons.append("The URL is unusually long.")
    elif f["url_length"] > 75:
        score += 8
        reasons.append("The URL is longer than typical.")
    if f["subdomain_count"] >= 3:
        score += 15
        reasons.append("The URL contains many subdomain levels.")
    elif f["subdomain_count"] == 2:
        score += 7
        reasons.append("The URL contains multiple subdomain levels.")
    if f["suspicious_keyword_count"] >= 3:
        score += 20
        reasons.append("Several security/account-related keywords appear in the URL.")
    elif f["suspicious_keyword_count"] == 2:
        score += 12
        reasons.append("Security/account-related keywords appear in the URL.")
    elif f["suspicious_keyword_count"] == 1:
        score += 5
        reasons.append("A potentially sensitive keyword appears in the URL.")
    if f["hyphen_count"] >= 3:
        score += 10
        reasons.append("The hostname contains several hyphens.")
    if f["special_character_count"] >= 8:
        score += 10
        reasons.append("The URL contains many special characters.")
    if f["is_url_shortener"]:
        score += 15
        reasons.append("The URL uses a known URL-shortening domain.")
    if f["has_punycode"]:
        score += 20
        reasons.append("The hostname contains punycode, which can be used in look-alike domains.")

    score = min(score, 100)

    if score >= 60:
        label = "Phishing"
    elif score >= 30:
        label = "Suspicious"
    else:
        label = "Legitimate"

    return {
        "label": label,
        "score": score,
        "normalized_url": normalized,
        "reasons": reasons,
        "features": f,
    }
