from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware
import re
import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification
import whois
import dns.resolver
from datetime import datetime
import asyncio
from functools import partial
import aiohttp

# ✅ NEW IMPORTS (for deepfake detection)
import joblib
import librosa
import numpy as np
import tempfile

app = FastAPI()

# ---------------- CORS ----------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------- LOAD PHISHING MODEL ----------------
print("Loading phishing detection model...")
phishing_model_name = "ealvaradob/bert-finetuned-phishing"
phishing_tokenizer = AutoTokenizer.from_pretrained(phishing_model_name)
phishing_model = AutoModelForSequenceClassification.from_pretrained(phishing_model_name)
phishing_model.eval()
print("Phishing model loaded.")

# ---------------- LOAD SENTIMENT MODEL ----------------
print("Loading sentiment/tone model...")
sentiment_model_name = "cardiffnlp/twitter-roberta-base-sentiment-latest"
sentiment_tokenizer = AutoTokenizer.from_pretrained(sentiment_model_name)
sentiment_model = AutoModelForSequenceClassification.from_pretrained(sentiment_model_name)
sentiment_model.eval()
print("Sentiment model loaded.")

# ---------------- LOAD DEEPFAKE AUDIO MODEL ----------------
print("Loading deepfake audio model...")
audio_model = joblib.load("deepfake_model.pkl")
print("Audio model loaded.")

# ---------------- URLHAUS API ----------------
URLHAUS_API = "https://urlhaus-api.abuse.ch/v1/url/"

# ---------------- REQUEST MODEL ----------------
class EmailRequest(BaseModel):
    text: str
    sender: str

# ---------------- HEALTH ----------------
@app.get("/health")
def health():
    return {"status": "ok"}

# ---------------- PHISHING ML SCORE ----------------
def get_phishing_score(text: str) -> float:
    inputs = phishing_tokenizer(
        text, return_tensors="pt", truncation=True,
        padding=True, max_length=512
    )
    with torch.no_grad():
        outputs = phishing_model(**inputs)
    probs = torch.softmax(outputs.logits, dim=1)
    return probs[0][1].item()

# ---------------- SENTIMENT + TONE ANALYSIS ----------------
def get_tone_analysis(text: str) -> dict:
    inputs = sentiment_tokenizer(
        text, return_tensors="pt", truncation=True,
        padding=True, max_length=512
    )
    with torch.no_grad():
        outputs = sentiment_model(**inputs)

    probs    = torch.softmax(outputs.logits, dim=1)
    negative = probs[0][0].item()
    neutral  = probs[0][1].item()
    positive = probs[0][2].item()

    text_lower = text.lower()

    urgency_markers = ["urgent","immediately","right away","act now","asap","within 24 hours","by end of day","eod","deadline","expires","limited time","time sensitive","as soon as possible"]
    authority_markers = ["on behalf of","as per","per our records","kindly","please be informed","this is to notify","dear valued","our records indicate","as requested","further to","please find attached","please ensure","compliance","failure to comply","legal action","account will be"]
    financial_markers = ["wire transfer","bank account","payment","invoice","credit card","password","credentials","login","verify","confirm","update your","validate"]

    urgency_count  = sum(1 for m in urgency_markers if m in text_lower)
    authority_count = sum(1 for m in authority_markers if m in text_lower)
    financial_count = sum(1 for m in financial_markers if m in text_lower)

    tone_risk  = 0.0
    tone_flags = []

    if negative > 0.6:
        tone_risk += 10
        tone_flags.append("High negative tone detected")
    elif negative > 0.4:
        tone_risk += 5
        tone_flags.append("Elevated negative tone")

    if neutral > 0.5 and authority_count >= 2:
        tone_risk += 10
        tone_flags.append("AI-like formal authority tone")
    elif neutral > 0.4 and authority_count >= 1:
        tone_risk += 5
        tone_flags.append("Formal authority tone")

    if urgency_count >= 1 and financial_count >= 1:
        tone_risk += 6
        tone_flags.append("Urgency + financial request")

    tone_risk = min(tone_risk, 25)

    return {
        "sentiment": {"negative": round(negative,3),"neutral": round(neutral,3),"positive": round(positive,3)},
        "tone_risk_score": round(tone_risk,1),
        "tone_flags": tone_flags
    }

# ---------------- AUDIO FEATURE EXTRACTION ----------------
def extract_features_from_bytes(audio_bytes):
    with tempfile.NamedTemporaryFile(delete=False, suffix=".wav") as temp_audio:
        temp_audio.write(audio_bytes)
        temp_audio.flush()

        y, sr = librosa.load(temp_audio.name, duration=5)
        mfcc = librosa.feature.mfcc(y=y, sr=sr, n_mfcc=40)
        return np.mean(mfcc.T, axis=0)

# ---------------- AUDIO WEBSOCKET (UPDATED) ----------------
@app.websocket("/api/analyze/audio")
async def analyze_audio(websocket: WebSocket):
    await websocket.accept()
    audio_buffer = b""

    try:
        await websocket.send_json({"type": "ready", "message": "Deepfake audio shield active"})

        while True:
            data = await websocket.receive_bytes()
            audio_buffer += data

            if len(audio_buffer) > 80000:  # ~5 sec chunk
                try:
                    features = extract_features_from_bytes(audio_buffer)

                    prediction = audio_model.predict([features])[0]
                    confidence = audio_model.predict_proba([features])[0][prediction]

                    result = "FAKE" if prediction == 1 else "REAL"

                    await websocket.send_json({
                        "type": "prediction",
                        "result": result,
                        "confidence": float(confidence)
                    })

                except Exception as e:
                    await websocket.send_json({
                        "type": "error",
                        "message": str(e)
                    })

                audio_buffer = b""

    except WebSocketDisconnect:
        print("Client disconnected")

    except Exception as e:
        print("Audio WebSocket error:", e)

    finally:
        try:
            await websocket.send_json({"type": "session_end"})
        except:
            pass