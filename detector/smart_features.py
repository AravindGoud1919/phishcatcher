# detector/smart_features.py
from sklearn.base import BaseEstimator, TransformerMixin
from urllib.parse import urlparse
import re
import numpy as np

class URLFeatures(BaseEstimator, TransformerMixin):
    def fit(self, X, y=None): return self
    def transform(self, X):
        return np.array([
            [
                len(url),
                url.count('.'),
                url.count('-'),
                1 if url.startswith('https') else 0,
                1 if re.match(r'http[s]?://(\d{1,3}\.){3}\d{1,3}', url) else 0
            ] for url in X
        ])
