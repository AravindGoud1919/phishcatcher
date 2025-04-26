import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
import joblib
import os

# Load the dataset
data = pd.read_csv("dataset/phishing_dataset_sample.csv")

# Split features and label
X = data.drop("Label", axis=1)
y = data["Label"]

# Split into train/test sets
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Train the model
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

# Accuracy (just to see how it's doing)
accuracy = model.score(X_test, y_test)
print(f"✅ Model trained with accuracy: {accuracy * 100:.2f}%")

# Save the model inside detector folder
model_path = os.path.join("detector", "phish_model.pkl")
joblib.dump(model, model_path)

print(f"✅ Model saved to {model_path}")
