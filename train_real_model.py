import pandas as pd
import re
import joblib
from urllib.parse import urlparse
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report

# Load and clean dataset
df = pd.read_csv("dataset/phishing_data_real.csv").dropna()

# ✅ Rename properly BEFORE referencing columns
df = df.rename(columns={"url": "URL", "label": "Label"})

# Check
print(df.head())
print(df["Label"].value_counts())

# Feature extractor
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
        1 if not(".com" in url or ".org" in url) else -1
    ]

# Feature + label
X = df["URL"].apply(extract_features).tolist()
y = df["Label"].apply(lambda x: 1 if x == "phishing" else 0)  # lowercase match

# Train-test split
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Model training
model = RandomForestClassifier(n_estimators=100)
model.fit(X_train, y_train)

# Evaluation
y_pred = model.predict(X_test)
print(classification_report(y_test, y_pred))

# Save model
joblib.dump(model, "detector/phish_model.pkl")
print("✅ Model trained and saved as detector/phish_model.pkl")
