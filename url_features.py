import re
from urllib.parse import urlparse


def extract_features(url):

    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    parsed = urlparse(url)
    domain = parsed.netloc
    path = parsed.path

    suspicious_words = [
        "login",
        "verify",
        "account",
        "secure",
        "update",
        "bank",
        "password",
        "signin",
        "confirm",
        "free",
        "bonus"
    ]

    features = [
        len(url),
        url.count("."),
        url.count("-"),
        url.count("@"),
        url.count("?"),
        url.count("="),
        url.count("&"),
        url.count("/"),
        sum(c.isdigit() for c in url),
        1 if parsed.scheme == "https" else 0,
        1 if re.search(r"\d+\.\d+\.\d+\.\d+", domain) else 0,
        sum(word in url.lower() for word in suspicious_words),
        len(domain),
        len(path)
    ]

    return features


def analyze_url(url):

    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    parsed = urlparse(url)
    domain = parsed.netloc

    risks = []

    if parsed.scheme != "https":
        risks.append("Website does not use HTTPS")

    if re.search(r"\d+\.\d+\.\d+\.\d+", domain):
        risks.append("URL uses an IP address instead of a domain")

    if len(url) > 75:
        risks.append("URL is unusually long")

    if "@" in url:
        risks.append("URL contains @ symbol")

    suspicious_words = [
        "login",
        "verify",
        "account",
        "secure",
        "update",
        "bank",
        "password",
        "signin",
        "confirm"
    ]

    found_words = [
        word for word in suspicious_words
        if word in url.lower()
    ]

    if found_words:
        risks.append(
            "Suspicious keywords: " + ", ".join(found_words)
        )

    if url.count("-") >= 3:
        risks.append("URL contains many hyphens")

    return risks