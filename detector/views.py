import os
import json
import datetime
from detector.smart_features import URLFeatures
from detector.utils import extract_url_text
import joblib

from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.shortcuts import render
from urllib.parse import unquote

# Load trained model (which includes both TF-IDF + custom features)
model_path = os.path.join(os.path.dirname(__file__), 'phish_model.pkl')
model = joblib.load(model_path)

def scan_logic(url):
    # ✅ Predict using full pipeline model
    prediction = model.predict([url])[0]
    prediction_label = 'Phishing Website!' if prediction == 1 else 'Legitimate Website!'

    # ✅ Create scan log entry
    log_entry = {
        'url': url,
        'result': prediction_label,
        'timestamp': datetime.datetime.now().isoformat()
    }

    # ✅ Save to scan_log.json
    log_path = os.path.join(os.path.dirname(__file__), 'scan_log.json')
    if os.path.exists(log_path):
        with open(log_path, 'r+') as f:
            try:
                logs = json.load(f)
            except json.JSONDecodeError:
                logs = []
            logs.append(log_entry)
            f.seek(0)
            json.dump(logs, f, indent=2)
    else:
        with open(log_path, 'w') as f:
            json.dump([log_entry], f, indent=2)

    return prediction_label

@csrf_exempt
def scan_url(request):
    result = None
    url = ""
    explanation = []

    if request.method == 'POST':
        try:
            data = json.loads(request.body) if request.content_type == 'application/json' else request.POST
            url = data.get('url', '').strip()

            if url:
                result = scan_logic(url)
        except json.JSONDecodeError:
            return JsonResponse({'error': 'Invalid JSON data'}, status=400)

    elif request.method == 'GET':
        url = request.GET.get('url', '').strip()
        if url:
            result = scan_logic(url)

    return render(request, 'detector/scan_url.html', {
        'url': url,
        'result': result,
        'explanation': explanation  # Keep placeholder if you add reasons later
    })

@csrf_exempt
def api_scan(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            url = data.get('url', '').strip()

            if not url:
                return JsonResponse({'error': 'No URL provided'}, status=400)

            result = scan_logic(url)

            return JsonResponse({
                'result': result
            })

        except json.JSONDecodeError:
            return JsonResponse({'error': 'Invalid JSON'}, status=400)

    return JsonResponse({'error': 'Only POST requests allowed'}, status=405)

def view_history(request):
    log_file_path = os.path.join(os.path.dirname(__file__), 'scan_log.json')

    if os.path.exists(log_file_path):
        with open(log_file_path, 'r') as f:
            try:
                data = json.load(f)
                # ✅ Format timestamps for display
                for entry in data:
                    if 'timestamp' in entry:
                        try:
                            dt = datetime.datetime.fromisoformat(entry['timestamp'])
                            entry['timestamp'] = dt.strftime("%d %b %Y, %I:%M %p")
                        except:
                            pass
            except json.JSONDecodeError:
                data = {"error": "Log file is corrupted"}
    else:
        data = {"message": "No scan history found."}

    return render(request, 'detector/history.html', {'scans': data})

def view_result(request):
    url = request.GET.get('url', '')
    result = None
    explanation = None

    if url:
        result = scan_logic(url)

    return render(request, 'detector/scan_url.html', {
        'url': url,
        'result': result,
        'explanation': explanation
    })
