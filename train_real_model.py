import pandas as pd
import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report

# 1. Load dataset
df = pd.read_csv("dataset/phishing_data_real.csv").dropna()
df = df.rename(columns={"url": "URL", "label": "Label"})

# 2. Encode label
df["Label"] = df["Label"].apply(lambda x: 1 if x.lower() == "phishing" else 0)

# 3. Vectorize URLs using TF-IDF
vectorizer = TfidfVectorizer()
X = vectorizer.fit_transform(df["URL"])
y = df["Label"]

# 4. Train-test split
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# 5. Train RandomForest model
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

# 6. Evaluate
y_pred = model.predict(X_test)
print(classification_report(y_test, y_pred))

# 7. Save model and vectorizer
joblib.dump(model, "detector/phish_model.pkl")
joblib.dump(vectorizer, "detector/vectorizer.pkl")
print("✅ Model and vectorizer saved successfully!")
