import os
import glob
import librosa
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.svm import SVC
import joblib

def extract_mfcc_features(audio_path, n_mfcc=13, n_fft=2048, hop_length=512):
    try:
        audio_data, sr = librosa.load(audio_path, sr=None)
    except Exception as e:
        print(f"Error loading audio file {audio_path}: {e}")
        return None
    mfccs = librosa.feature.mfcc(y=audio_data, sr=sr, n_mfcc=n_mfcc, n_fft=n_fft, hop_length=hop_length)
    return np.mean(mfccs.T, axis=0)

def create_dataset(directory, label):
    X, y = [], []
    audio_files = glob.glob(os.path.join(directory, "*.wav"))
    for audio_path in audio_files:
        mfcc_features = extract_mfcc_features(audio_path)
        if mfcc_features is not None:
            X.append(mfcc_features)
            y.append(label)
    return X, y

if __name__ == "__main__":
    genuine_dir = "temp_deepfake_repo/real_audio"
    deepfake_dir = "temp_deepfake_repo/deepfake_audio"

    print("Extracting features from real audio...")
    X_genuine, y_genuine = create_dataset(genuine_dir, label=0)
    print("Extracting features from deepfake audio...")
    X_deepfake, y_deepfake = create_dataset(deepfake_dir, label=1)

    X = np.vstack((X_genuine, X_deepfake))
    y = np.hstack((y_genuine, y_deepfake))

    print(f"Total samples: {len(X)}")

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    # Since the dataset is extremely small (8 files), we train on the full dataset without splitting
    svm_classifier = SVC(kernel='linear', probability=True, random_state=42)
    svm_classifier.fit(X_scaled, y)
    print("Model trained successfully.")

    os.makedirs("models", exist_ok=True)
    joblib.dump(svm_classifier, "models/svm_model.pkl")
    joblib.dump(scaler, "models/scaler.pkl")
    print("Saved models/svm_model.pkl and models/scaler.pkl")
