import os
import joblib
import re
import json
from urllib.parse import urlparse
from django.shortcuts import render
from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
from .models import ScanHistory

# 1. Feature explanation map
feature_labels = {
    0: "IP address in URL",
    1: "Unusually long URL",
    2: "Shortened URL service (bit.ly, tinyurl)",
    3: "'@' symbol in URL",
    4: "Redirect using '//' after domain",
    5: "Hyphen in domain name",
    6: "Misleading HTTPS token",
    7: "Suspicious file types (.jpg, .js)",
    8: "URL starts with 'http://' (not secure)",
    9: "Missing .com/.org (low trust)"
}

# 2. Load trained ML model
model_path = os.path.join(os.path.dirname(__file__), 'phish_model.pkl')
model = joblib.load(model_path)

# 3. Extract features from URL
def extract_features(url):
    return [
        1 if re.match(r"^(http|https):\/\/\d+\.\d+\.\d+\.\d+", url) else -1,
        1 if len(url) >= 75 else -1,
        1 if any(s in url for s in ['bit.ly', 'tinyurl', 't.co']) else -1,
        1 if "@" in url else -1,
        1 if url.count("//") > 1 else -1,
        1 if "-" in urlparse(url).netloc else -1,
        1 if "https" in url and not url.startswith("https://") else -1,
        1 if any(ext in url for ext in ['.jpg', '.png', '.js']) else -1,
        1 if url.startswith("http://") else -1,
        1 if ".com" in url or ".org" in url else 0
    ]

# 4. HTML-based form scanner
def scan_url(request):
    result = None
    explanation = []
    url = ""

    if request.method == 'POST':
        url = request.POST.get('url')
        features = extract_features(url)
        for i, value in enumerate(features):
            if value == 1:
                explanation.append(feature_labels[i])
        prediction = model.predict([features])[0]
        result = "Phishing Website Detected!" if prediction == 1 else "Legitimate Website!"
        ScanHistory.objects.create(url=url, result=result)

    return render(request, 'detector/scan_url.html', {
        'result': result,
        'explanation': explanation,
        'url': url
    })

# 5. View past scan history
def view_history(request):
     scans = ScanHistory.objects.all().order_by('-scanned_at')

    # Split the features into list form
     for scan in scans:
         scan.reasons = scan.features_triggered.split(",") if scan.features_triggered else []

     return render(request, 'detector/history.html', {'scans': scans})

# 6. API endpoint for Chrome Extension
@csrf_exempt
def api_scan(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body.decode('utf-8'))   # ✅ decode the body before json.loads
            url = data.get('url', '')
            features = extract_features(url)
            prediction = model.predict([features])[0]
            result = "Phishing Website Detected!" if prediction == 1 else "Legitimate Website!"
            ScanHistory.objects.create(url=url, result=result)
            return JsonResponse({"result": result})
        except Exception as e:
            return JsonResponse({"error": str(e)})
    return JsonResponse({"error": "Only POST allowed"})