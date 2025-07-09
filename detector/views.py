# views.py
import os
import json
import datetime
from urllib.parse import urlparse

from django.shortcuts import render, redirect
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from django.contrib.auth.decorators import login_required
from django.contrib import messages

from detector.smart_features import URLFeatures
from detector.utils import extract_url_text
import joblib

# === Load model ===
model_path = os.path.join(os.path.dirname(__file__), 'phish_model.pkl')
model = joblib.load(model_path)

# === Safe domain whitelist ===
SAFE_DOMAINS = [
    'openai.com', 'chatgpt.com', 'google.com',
    'github.com', 'youtube.com', 'microsoft.com'
]

def is_whitelisted(url):
    domain = urlparse(url).netloc.replace("www.", "")
    return any(domain == safe or domain.endswith("." + safe) for safe in SAFE_DOMAINS)

# === Core scanner ===
def scan_logic(url):
    if is_whitelisted(url):
        prediction_label = 'Legitimate Website!'
        top_words = ['This domain is in the known safe list.']
    else:
        prediction = model.predict([url])[0]
        prediction_label = 'Phishing Website!' if prediction == 1 else 'Legitimate Website!'

        # Fallback for non-TFIDF models like smart features
        top_words = ["Detected by URL features (e.g., length, symbols, HTTPS)"]

        # If model uses TF-IDF vectorizer
        try:
            if hasattr(model, 'named_steps') and 'vectorizer' in model.named_steps:
                vec = model.named_steps['vectorizer']
                feature_names = vec.get_feature_names_out()
                tfidf_scores = vec.transform([url])
                scores = tfidf_scores.toarray()[0]
                top_indices = scores.argsort()[::-1][:5]
                top_words = [feature_names[i] for i in top_indices if scores[i] > 0] or top_words
        except:
            pass

    # Save to log
    log_entry = {
        'url': url,
        'prediction': prediction_label,
        'timestamp': datetime.datetime.now().isoformat(),
        'top_words': top_words
    }

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

    return prediction_label, top_words

# === Home View ===
@login_required
def home(request):
    prediction = None
    explanation = []
    history = []

    if request.method == 'POST':
        url = request.POST.get('url', '').strip()
        if url:
            prediction, explanation = scan_logic(url)

    log_path = os.path.join(os.path.dirname(__file__), 'scan_log.json')
    if os.path.exists(log_path):
        with open(log_path, 'r') as f:
            try:
                logs = json.load(f)
                logs.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
                for entry in logs[:10]:
                    try:
                        dt = datetime.datetime.fromisoformat(entry['timestamp'])
                        entry['timestamp'] = dt.strftime("%d %b %Y, %I:%M %p")
                    except:
                        pass
                history = logs[:10]
            except:
                history = []

    return render(request, 'detector/home.html', {
        'prediction': prediction,
        'explanation': explanation,
        'scan_history': history
    })

# === API for Chrome Extension ===
@csrf_exempt
def api_scan(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            url = data.get('url', '').strip()

            if not url:
                return JsonResponse({'error': 'No URL provided'}, status=400)

            result, top_words = scan_logic(url)
            return JsonResponse({'result': result, 'top_words': top_words})

        except json.JSONDecodeError:
            return JsonResponse({'error': 'Invalid JSON'}, status=400)

    return JsonResponse({'error': 'Only POST requests allowed'}, status=405)

# === Full History Page ===
@login_required
def view_history(request):
    log_path = os.path.join(os.path.dirname(__file__), 'scan_log.json')

    scans = []
    if os.path.exists(log_path):
        with open(log_path, 'r') as f:
            try:
                logs = json.load(f)
                for entry in logs:
                    try:
                        dt = datetime.datetime.fromisoformat(entry['timestamp'])
                        entry['timestamp'] = dt.strftime("%d %b %Y, %I:%M %p")
                    except:
                        pass
                scans = logs[::-1]
            except:
                scans = []

    return render(request, 'detector/history.html', {'scans': scans})

# === Result Page (Optional) ===
@login_required
def view_result(request):
    url = request.GET.get('url', '')
    result = None
    explanation = []

    if url:
        result, explanation = scan_logic(url)

    return render(request, 'detector/scan_url.html', {
        'url': url,
        'result': result,
        'explanation': explanation
    })

# === Scan URL via POST/GET ===
@csrf_exempt
@login_required
def scan_url(request):
    result = None
    url = ""
    explanation = []

    if request.method == 'POST':
        try:
            data = json.loads(request.body) if request.content_type == 'application/json' else request.POST
            url = data.get('url', '').strip()
            if url:
                result, explanation = scan_logic(url)
        except json.JSONDecodeError:
            return JsonResponse({'error': 'Invalid JSON data'}, status=400)

    elif request.method == 'GET':
        url = request.GET.get('url', '').strip()
        if url:
            result, explanation = scan_logic(url)

    return render(request, 'detector/scan_url.html', {
        'url': url,
        'result': result,
        'explanation': explanation
    })

# === Register View ===
def register_view(request):
    if request.method == 'POST':
        username = request.POST.get('username').strip()
        email = request.POST.get('email').strip()
        password = request.POST.get('password')

        if User.objects.filter(username=username).exists():
            messages.error(request, 'Username already exists.')
            return redirect('register')

        user = User.objects.create_user(username=username, email=email, password=password)
        messages.success(request, 'Account created! Please log in.')
        return redirect('login')

    return render(request, 'auth/register.html')

# === Login View ===
def login_view(request):
    if request.method == 'POST':
        username = request.POST.get('username').strip()
        password = request.POST.get('password')

        user = authenticate(request, username=username, password=password)
        if user:
            login(request, user)
            return redirect('home')
        else:
            messages.error(request, 'Invalid username or password.')

    return render(request, 'auth/login.html')

# === Logout View ===
def logout_view(request):
    logout(request)
    return redirect('login')
