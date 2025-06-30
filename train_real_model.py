import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
import joblib
import os

# Load phishing and legitimate datasets
phish_df = pd.read_csv("dataset/phishing_data_real.csv")
legit_df = pd.read_csv("dataset/legitimate_urls.csv")

# Clean and label
phish_df['label'] = 'phishing'
legit_df['label'] = 'legitimate'

# Combine datasets
df = pd.concat([phish_df, legit_df], ignore_index=True)
df = df.dropna()

print("🔍 Dataset Summary:")
print(df['label'].value_counts())

# Convert label to numeric
df['label'] = df['label'].map({'legitimate': 0, 'phishing': 1})

# TF-IDF vectorization
vectorizer = TfidfVectorizer()
X = vectorizer.fit_transform(df['url'])
y = df['label']

# Train model
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X, y)

# Save model and vectorizer
joblib.dump(model, 'detector/phish_model.pkl')
joblib.dump(vectorizer, 'detector/vectorizer.pkl')

print("✅ Model and vectorizer saved successfully!")
