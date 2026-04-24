from transformers import pipeline

model_id = "MelodyMachine/Deepfake-audio-detection-V2"
print(f"Loading {model_id}...")
try:
    pipe = pipeline("audio-classification", model=model_id)
    print("Success loading model!")
    print(pipe.model.config.id2label)
except Exception as e:
    print(f"Failed to load: {e}")
