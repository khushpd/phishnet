from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware
import re
import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification

# Audio + ML
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

# ---------------- LOAD AUDIO MODEL ----------------
print("Loading deepfake audio model...")
audio_model = joblib.load("deepfake_model.pkl")
print("Audio model loaded.")

# ---------------- REQUEST MODEL ----------------
class EmailRequest(BaseModel):
    text: str
    sender: str

# ---------------- HEALTH ----------------
@app.get("/health")
def health():
    return {"status": "ok"}

# ---------------- PHISHING SCORE ----------------
def get_phishing_score(text: str) -> float:
    inputs = phishing_tokenizer(
        text, return_tensors="pt", truncation=True,
        padding=True, max_length=512
    )
    with torch.no_grad():
        outputs = phishing_model(**inputs)
    probs = torch.softmax(outputs.logits, dim=1)
    return probs[0][1].item()

# ---------------- TONE ANALYSIS ----------------
def get_tone_analysis(text: str) -> dict:
    inputs = sentiment_tokenizer(
        text, return_tensors="pt", truncation=True,
        padding=True, max_length=512
    )
    with torch.no_grad():
        outputs = sentiment_model(**inputs)

    probs = torch.softmax(outputs.logits, dim=1)

    negative = probs[0][0].item()
    neutral = probs[0][1].item()
    positive = probs[0][2].item()

    text_lower = text.lower()

    urgency_words = ["urgent", "immediately", "asap", "act now"]
    financial_words = ["password", "bank", "credit", "verify", "login"]

    urgency_count = sum(1 for w in urgency_words if w in text_lower)
    financial_count = sum(1 for w in financial_words if w in text_lower)

    tone_risk = 0

    if negative > 0.5:
        tone_risk += 10
    if urgency_count > 0:
        tone_risk += 5
    if financial_count > 0:
        tone_risk += 10

    tone_risk = min(tone_risk, 25)

    return {
        "sentiment": {
            "negative": round(negative, 3),
            "neutral": round(neutral, 3),
            "positive": round(positive, 3)
        },
        "tone_risk_score": tone_risk
    }

# ---------------- AUDIO FEATURE ----------------
def extract_features(audio_bytes):
    with tempfile.NamedTemporaryFile(delete=False, suffix=".wav") as f:
        f.write(audio_bytes)
        f.flush()
        y, sr = librosa.load(f.name, duration=5)
        mfcc = librosa.feature.mfcc(y=y, sr=sr, n_mfcc=40)
        return np.mean(mfcc.T, axis=0)

# ---------------- AUDIO SOCKET ----------------
@app.websocket("/api/analyze/audio")
async def analyze_audio(ws: WebSocket):
    await ws.accept()
    buffer = b""

    try:
        while True:
            data = await ws.receive_bytes()
            buffer += data

            if len(buffer) > 80000:
                try:
                    features = extract_features(buffer)
                    pred = audio_model.predict([features])[0]
                    conf = audio_model.predict_proba([features])[0][pred]

                    await ws.send_json({
                        "result": "FAKE" if pred else "REAL",
                        "confidence": float(conf)
                    })

                except Exception as e:
                    await ws.send_json({"error": str(e)})

                buffer = b""

    except WebSocketDisconnect:
        print("Audio disconnected")

# ---------------- EMAIL ANALYSIS ----------------
@app.post("/api/analyze/email")
async def analyze_email(req: EmailRequest):
    text = req.text
    sender = req.sender

    # URLs
    urls = re.findall(r'https?://\S+', text)

    # ML
    ml_prob = get_phishing_score(text)
    ml_score = int(ml_prob * 35)

    # Tone
    tone = get_tone_analysis(text)
    tone_score = int(tone["tone_risk_score"])

    # Indicators
    indicators = []
    t = text.lower()

    if "password" in t:
        indicators.append("Requests password")
    if "urgent" in t:
        indicators.append("Creates urgency")
    if "verify" in t:
        indicators.append("Verification request")

    # Final score
    total = min(ml_score + tone_score, 100)

    if total >= 70:
        risk = "HIGH"
    elif total >= 40:
        risk = "MEDIUM"
    else:
        risk = "LOW"

    return {
        "risk_score": total,
        "risk_level": risk,
        "ml_probability": ml_prob,
        "ml_score": ml_score,
        "tone_analysis": tone,
        "indicators": indicators,
        "sender_flags": [],
        "url_flags": [],
        "urls_found": urls,
        "urlhaus_results": [],
        "sender_intel": {}
    }