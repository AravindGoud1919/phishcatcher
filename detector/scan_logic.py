import re
def scan_logic(url):
    # Placeholder logic – you can replace this with real ML prediction
    return "Legitimate Website!" if "https" in url else "Phishing Website!"


def scan_logic(url):
    # Example feature-based logic
    if "@" in url or "//" in url.split('/')[2]:
        return "Phishing Website!"
    elif len(url) > 75 or url.count('-') > 3:
        return "Suspicious Website!"
    else:
        return "Legitimate Website!"
