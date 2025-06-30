from detector.smart_features import URLFeatures
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
from sklearn.pipeline import FeatureUnion
from sklearn.base import BaseEstimator, TransformerMixin
from sklearn.preprocessing import FunctionTransformer
from sklearn.pipeline import Pipeline
from sklearn.utils import resample
import joblib
import re
from detector.utils import extract_url_text



# 2. Load datasets
phishing_df = pd.read_csv("dataset/phishing_data_real.csv")
legit_df = pd.read_csv("dataset/legitimate_urls.csv")

phishing_df['label'] = 'phishing'
legit_df['label'] = 'legitimate'

df = pd.concat([phishing_df[['url', 'label']], legit_df[['url', 'label']]])
df = df.dropna()

# 3. Balance the dataset
min_size = min(len(df[df.label == 'phishing']), len(df[df.label == 'legitimate']))
df = pd.concat([
    resample(df[df.label == 'phishing'], replace=False, n_samples=min_size, random_state=42),
    resample(df[df.label == 'legitimate'], replace=True, n_samples=min_size, random_state=42)
])

df['label_num'] = df['label'].map({'legitimate': 0, 'phishing': 1})


# 5. TF-IDF + Features
tfidf = TfidfVectorizer(token_pattern=r'[a-zA-Z0-9.-]+', max_features=300)

combined_features = FeatureUnion([
    ("url_features", URLFeatures()),
    ("tfidf", Pipeline([
        ("extract_url", FunctionTransformer(extract_url_text, validate=False)),
        ("tfidf", tfidf)
    ]))
])

# 6. Final pipeline
pipeline = Pipeline([
    ("features", combined_features),
    ("clf", RandomForestClassifier(n_estimators=100, random_state=42))
])

# 7. Train and save
pipeline.fit(df['url'], df['label_num'])
joblib.dump(pipeline, "detector/phish_model.pkl")
print("✅ Smart model trained and saved successfully.")
