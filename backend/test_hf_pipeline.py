import numpy as np
from transformers import pipeline

print("Loading pipe...")
pipe = pipeline("audio-classification", model="MelodyMachine/Deepfake-audio-detection-V2")
print("Pipe loaded")

# Simulate audio_bytes conversion
audio_bytes = b'\x00\x00' * 80000 # 160k bytes
waveform = np.frombuffer(audio_bytes, dtype=np.int16).astype(np.float32) / 32768.0

print("Running pipe...")
try:
    results = pipe({"sampling_rate": 16000, "raw": waveform})
    print("Results:", results)
except Exception as e:
    print("Error:", e)
