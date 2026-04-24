import os
import numpy as np
import librosa
import random
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
import joblib

DATASET_PATH = "dataset"

def extract_features(file_path):
    y, sr = librosa.load(file_path)

    duration = 5  # seconds

    if len(y) > sr * duration:
        start = random.randint(0, len(y) - sr * duration)
        y = y[start:start + sr * duration]

    mfcc = librosa.feature.mfcc(y=y, sr=sr, n_mfcc=40)
    return np.mean(mfcc.T, axis=0)

X = []
y = []

for label in ["real", "fake"]:
    folder = os.path.join(DATASET_PATH, label)

    for file in os.listdir(folder):
        path = os.path.join(folder, file)

        try:
            features = extract_features(path)
            X.append(features)
            y.append(0 if label == "real" else 1)
        except Exception as e:
            print("Skipping:", file, e)

X = np.array(X)
y = np.array(y)

print("Training model...")

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2)

model = RandomForestClassifier(
    n_estimators=100,
    class_weight="balanced"   # important for your imbalance
)

model.fit(X_train, y_train)

accuracy = model.score(X_test, y_test)
print("Accuracy:", accuracy)

joblib.dump(model, "deepfake_model.pkl")

print("✅ Model saved as deepfake_model.pkl")