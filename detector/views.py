import os
import joblib
import json
from django.shortcuts import render
from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
from .models import ScanHistory

# 1. Load vectorizer and model
BASE_DIR = os.path.dirname(__file__)
model = joblib.load(os.path.join(BASE_DIR, 'phish_model.pkl'))
vectorizer = joblib.load(os.path.join(BASE_DIR, 'vectorizer.pkl'))

# 2. HTML scanner view
def scan_url(request):
    result = None
    explanation = []
    url = ""

    if request.method == 'POST':
        url = request.POST.get('url')
        features = vectorizer.transform([url])
        prediction = model.predict(features)[0]
        result = "Phishing Website Detected!" if prediction == 1 else "Legitimate Website!"
        ScanHistory.objects.create(url=url, result=result)
    
    return render(request, 'detector/scan_url.html', {
        'result': result,
        'explanation': explanation,
        'url': url
    })

# 3. History view
def view_history(request):
    scans = ScanHistory.objects.all().order_by('-scanned_at')[:100]
    return render(request, 'detector/history.html', {'scans': scans})

# 4. API for Chrome Extension
@csrf_exempt
def api_scan(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body.decode('utf-8'))
            url = data.get('url', '')
            features = vectorizer.transform([url])
            prediction = model.predict(features)[0]
            result = "Phishing Website Detected!" if prediction == 1 else "Legitimate Website!"
            ScanHistory.objects.create(url=url, result=result)
            return JsonResponse({"result": result})
        except Exception as e:
            return JsonResponse({"error": str(e)})
    return JsonResponse({"error": "Only POST allowed"})
