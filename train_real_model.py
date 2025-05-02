import pandas as pd
import joblib
import re
from urllib.parse import urlparse
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report

# 1. Load dataset and clean
df = pd.read_csv("dataset/phishing_data_real.csv")
df = df.rename(columns={"url": "URL", "label": "Label"})
df = df.dropna()

# 2. Confirm values
print("Label counts:", df["Label"].value_counts())  # Should show both phishing & legitimate

# 3. Feature extraction function
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

# 4. Extract features
X = df["URL"].apply(extract_features).tolist()
y = df["Label"].apply(lambda x: 1 if x.strip().lower() == "phishing" else 0)  # force lowercase match

# 5. Split and train
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
model = RandomForestClassifier(n_estimators=100)
model.fit(X_train, y_train)

# 6. Evaluate
y_pred = model.predict(X_test)
print("📊 Evaluation Results:")
print(classification_report(y_test, y_pred))

# 7. Save
joblib.dump(model, "detector/phish_model.pkl")
print("✅ Trained & saved to detector/phish_model.pkl")
