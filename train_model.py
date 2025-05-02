import pandas as pd
import re
import joblib
from urllib.parse import urlparse
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
from sklearn.utils import resample

# Load and clean dataset
df = pd.read_csv("dataset/phishing_data_real.csv").dropna()
df = df.rename(columns={"url": "URL", "label": "Label"})

# ✅ Check class balance
print("Before balancing:")
print(df["Label"].value_counts())

# ✅ Balance the dataset (upsample the minority class)
phishing_df = df[df["Label"] == "phishing"]
legitimate_df = df[df["Label"] == "legitimate"]

if len(phishing_df) < len(legitimate_df):
    phishing_df = resample(phishing_df, replace=True, n_samples=len(legitimate_df), random_state=42)
else:
    legitimate_df = resample(legitimate_df, replace=True, n_samples=len(phishing_df), random_state=42)

df_balanced = pd.concat([phishing_df, legitimate_df])

# ✅ Confirm new balance
print("After balancing:")
print(df_balanced["Label"].value_counts())

# ✅ Feature extraction
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

# ✅ Prepare training data
X = df_balanced["URL"].apply(extract_features).tolist()
y = df_balanced["Label"].apply(lambda x: 1 if x == "phishing" else 0)

# ✅ Split and train
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

model = RandomForestClassifier(n_estimators=100)
model.fit(X_train, y_train)

# ✅ Evaluate
y_pred = model.predict(X_test)
print("\nModel Evaluation:\n")
print(classification_report(y_test, y_pred))

# ✅ Save the model
joblib.dump(model, "detector/phish_model.pkl")
print("✅ Model trained and saved as detector/phish_model.pkl")
