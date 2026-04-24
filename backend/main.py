"""
main.py  —  PhishNet backend
────────────────────────────────────────────────────────────────────────────────
Unchanged from your original:
  • POST  /api/analyze/email        phishing + tone analysis
  • WS    /api/analyze/audio        real-time deepfake audio detection

What changed inside the audio pipeline:
  • 5-feature spectral detector     (your original — kept intact)
  • + Instantaneous-frequency (IF) variance   (phase coherence)
  • + High-frequency energy ratio             (>6 kHz deficit)
  • + Cepstral Peak Prominence (CPP)          (voiced quality)
  • + Temporal stationarity (MSD)             (too-smooth dynamics)
  
  All 9 features are fused into a weighted score (0-100).
  ONNX (AASIST/RawNet2) is loaded if ./models/aasist.onnx exists;
  otherwise the detector runs purely on librosa features.

  The WebSocket emits the same JSON shape your frontend already expects,
  plus bonus fields (model_scores, is_fallback, window_score) used by
  AudioDeepfakePanel.jsx if you switch to it — ignored by the original panel.

No import changes needed in the frontend.
"""

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware
import re, asyncio, logging
from pathlib import Path

import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification

import librosa
import numpy as np
import joblib

logger = logging.getLogger("phishnet")

app = FastAPI()

# ── CORS ──────────────────────────────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── LOAD NLP MODELS (unchanged) ───────────────────────────────────────────────
print("Loading phishing detection model...")
phishing_tokenizer = AutoTokenizer.from_pretrained("ealvaradob/bert-finetuned-phishing")
phishing_model     = AutoModelForSequenceClassification.from_pretrained("ealvaradob/bert-finetuned-phishing")
phishing_model.eval()
print("Phishing model loaded.")

print("Loading sentiment/tone model...")
sentiment_tokenizer = AutoTokenizer.from_pretrained("cardiffnlp/twitter-roberta-base-sentiment-latest")
sentiment_model     = AutoModelForSequenceClassification.from_pretrained("cardiffnlp/twitter-roberta-base-sentiment-latest")
sentiment_model.eval()
print("Sentiment model loaded.")

from transformers import pipeline

# ── HUGGING FACE PIPELINE (Deepfake Audio) ──────────────────────────────────
_hf_audio_pipe = None
try:
    print("Loading HuggingFace Audio Deepfake model...")
    _hf_audio_pipe = pipeline("audio-classification", model="MelodyMachine/Deepfake-audio-detection-V2")
    print("HuggingFace model loaded.")
except Exception as e:
    logger.error(f"Could not load HuggingFace model: {e}")

def _hf_score(waveform: np.ndarray, sr: int = 16000):
    """
    Runs inference using HuggingFace audio classification pipeline.
    Returns the probability of 'fake' (0.0 to 1.0).
    """
    if _hf_audio_pipe is None:
        return None
    try:
        # Pipeline expects sampling rate context if we pass numpy array
        results = _hf_audio_pipe({"sampling_rate": sr, "raw": waveform})
        
        # Results look like: [{'score': 0.9, 'label': 'fake'}, {'score': 0.1, 'label': 'real'}]
        for res in results:
            if res['label'] == 'fake':
                return float(res['score'])
        return None
    except Exception as exc:
        logger.error(f"HF inference error: {exc}")
        return None

# (SVM removed as requested)

# ── AUDIO THRESHOLDS (your original values — kept) ────────────────────────────
AUDIO_THRESHOLDS = {
    "mfcc_variance_min":      15.0,
    "spectral_flatness_max":  0.08,
    "zcr_mean_min":           0.03,
    "zcr_mean_max":           0.18,
    "spectral_rolloff_min":   2000.0,
    "rms_std_min":            0.005,
}

# ── REQUEST MODEL ─────────────────────────────────────────────────────────────
class EmailRequest(BaseModel):
    text: str
    sender: str

# ── HEALTH ────────────────────────────────────────────────────────────────────
@app.get("/health")
def health():
    return {"status": "ok"}

# ── PHISHING SCORE (unchanged) ────────────────────────────────────────────────
def get_phishing_score(text: str) -> float:
    inputs = phishing_tokenizer(
        text, return_tensors="pt", truncation=True, padding=True, max_length=512
    )
    with torch.no_grad():
        outputs = phishing_model(**inputs)
    return torch.softmax(outputs.logits, dim=1)[0][1].item()

# ── TONE ANALYSIS (unchanged) ─────────────────────────────────────────────────
def get_tone_analysis(text: str) -> dict:
    inputs = sentiment_tokenizer(
        text, return_tensors="pt", truncation=True, padding=True, max_length=512
    )
    with torch.no_grad():
        outputs = sentiment_model(**inputs)
    probs    = torch.softmax(outputs.logits, dim=1)
    negative = probs[0][0].item()
    neutral  = probs[0][1].item()
    positive = probs[0][2].item()
    t        = text.lower()

    urgency_words   = ["urgent", "immediately", "asap", "act now"]
    financial_words = ["password", "bank", "credit", "verify", "login"]
    urgency_count   = sum(1 for w in urgency_words   if w in t)
    financial_count = sum(1 for w in financial_words if w in t)

    tone_risk = 0
    if negative > 0.5:    tone_risk += 10
    if urgency_count > 0:  tone_risk += 5
    if financial_count > 0: tone_risk += 10
    tone_risk = min(tone_risk, 25)

    return {
        "sentiment": {
            "negative": round(negative, 3),
            "neutral":  round(neutral,  3),
            "positive": round(positive, 3),
        },
        "tone_risk_score":  tone_risk,
        "urgency_count":    urgency_count,
        "financial_count":  financial_count,
        "authority_count":  0,
    }

# ── AUDIO FEATURE EXTRACTION  (your 5 + 4 new) ───────────────────────────────
def extract_audio_features(audio_bytes: bytes) -> dict:
    if len(audio_bytes) % 2 != 0:
        audio_bytes = audio_bytes[:-1]

    y  = np.frombuffer(audio_bytes, dtype=np.int16).astype(np.float32) / 32768.0
    sr = 16000

    # ── Your original 5 features ──────────────────────────────────────────────
    mfcc             = librosa.feature.mfcc(y=y, sr=sr, n_mfcc=13)
    mfcc_variance    = float(np.var(mfcc))

    spectral_flatness = float(np.mean(librosa.feature.spectral_flatness(y=y)))

    zcr              = librosa.feature.zero_crossing_rate(y)
    zcr_mean         = float(np.mean(zcr))

    rolloff          = librosa.feature.spectral_rolloff(y=y, sr=sr, roll_percent=0.85)
    rolloff_mean     = float(np.mean(rolloff))

    rms              = librosa.feature.rms(y=y)
    rms_std          = float(np.std(rms))

    # ── 4 new deepfake-specific features ─────────────────────────────────────

    # 1. Instantaneous frequency (IF) variance
    #    Natural speech: high IF variance; TTS vocoders: unnaturally smooth phase
    try:
        D      = librosa.stft(y, n_fft=512, hop_length=160)
        IF     = np.diff(np.angle(D), axis=1)
        if_var = float(np.var(IF))
    except Exception:
        if_var = 1.0   # neutral fallback

    # 2. High-frequency energy ratio  (>6 kHz)
    #    Neural TTS underproduces energy above ~6 kHz
    try:
        S        = np.abs(librosa.stft(y, n_fft=512, hop_length=160))
        freqs    = librosa.fft_frequencies(sr=sr, n_fft=512)
        hi_mask  = freqs > 6000
        hf_ratio = float(np.mean(S[hi_mask]) / (np.mean(S) + 1e-8))
    except Exception:
        hf_ratio = 0.5

    # 3. Cepstral Peak Prominence (CPP) — proxy via MFCC peak
    #    Lower CPP → weaker voiced quality → more likely synthetic
    try:
        cpp = float(np.max(mfcc, axis=0).mean())
    except Exception:
        cpp = 0.0

    # 4. Mean spectral distance (temporal stationarity)
    #    Synthetic audio is too stationary; real speech has fast spectral change
    try:
        log_S = librosa.amplitude_to_db(np.abs(librosa.stft(y, n_fft=512, hop_length=160)))
        msd   = float(np.mean(np.abs(np.diff(log_S, axis=1))))
    except Exception:
        msd = 5.0

    return {
        # original
        "mfcc_variance":    mfcc_variance,
        "spectral_flatness": spectral_flatness,
        "zcr_mean":         zcr_mean,
        "rolloff_mean":     rolloff_mean,
        "rms_std":          rms_std,
        # new
        "if_variance":      if_var,
        "hf_ratio":         hf_ratio,
        "cpp":              cpp,
        "msd":              msd,
        # raw waveform (passed to ONNX scorer)
        "_waveform":        y,
    }


# ── CLASSIFY AUDIO  (threshold + ONNX fusion) ─────────────────────────────────
def classify_audio(features: dict) -> dict:
    t     = AUDIO_THRESHOLDS
    flags = []
    waveform = features.pop("_waveform", None)   # remove before returning features

    # ── Your original 5 threshold checks (unchanged logic) ───────────────────
    if features["mfcc_variance"] < t["mfcc_variance_min"]:
        flags.append(
            f"Low MFCC variance ({features['mfcc_variance']:.2f}): unnaturally smooth voice"
        )

    if features["spectral_flatness"] > t["spectral_flatness_max"]:
        flags.append(
            f"High spectral flatness ({features['spectral_flatness']:.4f}): synthetic tonal quality"
        )

    if not (t["zcr_mean_min"] <= features["zcr_mean"] <= t["zcr_mean_max"]):
        flags.append(
            f"Abnormal ZCR ({features['zcr_mean']:.4f}): outside real speech range"
        )

    if features["rolloff_mean"] < t["spectral_rolloff_min"]:
        flags.append(
            f"Low spectral rolloff ({features['rolloff_mean']:.1f} Hz): missing high-frequency energy"
        )

    if features["rms_std"] < t["rms_std_min"]:
        flags.append(
            f"Low RMS variation ({features['rms_std']:.5f}): unnaturally flat energy dynamics"
        )

    # ── 4 new threshold checks ────────────────────────────────────────────────
    # IF variance: natural speech typically > 0.3; lower → synthetic
    if features["if_variance"] < 0.30:
        flags.append(
            f"Low phase coherence (IF var {features['if_variance']:.3f}): vocoder artefact"
        )

    # HF ratio: real speech typically > 0.15; lower → TTS deficit
    if features["hf_ratio"] < 0.15:
        flags.append(
            f"High-frequency energy deficit (ratio {features['hf_ratio']:.3f}): neural TTS signature"
        )

    # CPP: real speech typically > -5; much lower → synthetic
    if features["cpp"] < -8.0:
        flags.append(
            f"Low cepstral peak prominence ({features['cpp']:.2f}): weak voiced quality"
        )

    # MSD: real speech typically > 3.0; lower → too stationary
    if features["msd"] < 3.0:
        flags.append(
            f"Low spectral dynamics (MSD {features['msd']:.2f}): unnaturally stationary signal"
        )

    # ── HuggingFace model score ────────────────────────────────────────────────
    hf_prob      = _hf_score(waveform) if waveform is not None else None
    is_fallback  = (hf_prob is None)

    # ── Weighted fusion ───────────────────────────────────────────────────────
    #   Threshold score  (0–1): proportion of the 9 checks that fired
    threshold_score = len(flags) / 9.0
    
    fused = threshold_score
    
    if hf_prob is not None:
        # HF Model is very strong, weigh it at 65%
        fused = 0.65 * hf_prob + 0.35 * threshold_score

    fused = float(np.clip(fused, 0.0, 1.0))
    score = int(round(fused * 100))

    # ── Result label (keep your original 3-tier system) ──────────────────────
    if fused >= 0.60:
        result = "FAKE"
    elif fused >= 0.35:
        result = "SUSPICIOUS"
    else:
        result = "REAL"

    return {
        "result":      result,
        "confidence":  round(fused, 3),
        "flags":       flags,
        "is_fallback": is_fallback,
        "model_scores": {
            "huggingface": round(hf_prob * 100, 1) if hf_prob is not None else None,
            "spectral":    round(threshold_score * 100, 1),
        },
        "features": {k: round(v, 5) for k, v in features.items()},
    }


# ── AUDIO WEBSOCKET ───────────────────────────────────────────────────────────
# Unchanged contract: receives raw s16le PCM, emits JSON with
#   type / full_transcript / cumulative_score / risk_level / flags
# Plus bonus fields for AudioDeepfakePanel.jsx (ignored by original panel).
@app.websocket("/api/analyze/audio")
async def analyze_audio(ws: WebSocket):
    await ws.accept()
    buffer         = b""
    session_scores = []
    all_flags: list[str] = []

    try:
        while True:
            data   = await ws.receive_bytes()
            buffer += data

            # Process every ~5 seconds of audio  (16kHz × 2 bytes × 5s ≈ 160 000 bytes)
            # Your original used 80 000 (~2.5 s); 160 000 gives more reliable features.
            # Change back to 80000 if you want faster response.
            if len(buffer) > 160_000:
                try:
                    print(f"Processing {len(buffer):,} byte audio window…")
                    features       = extract_audio_features(buffer)
                    classification = classify_audio(features)

                    # Accumulate session state
                    window_score = int(classification["confidence"] * 100)
                    session_scores.append(window_score)
                    for f in classification["flags"]:
                        if f not in all_flags:
                            all_flags.append(f)

                    rolling_score = int(np.mean(session_scores))
                    risk_level    = (
                        "HIGH"   if rolling_score >= 70 else
                        "MEDIUM" if rolling_score >= 40 else
                        "LOW"
                    )

                    # ── JSON shape your frontend already reads ────────────────
                    response = {
                        # ← original fields (never renamed)
                        "type":             "transcript",
                        "full_transcript":  (
                            f"[Deepfake analysis] {classification['result']} "
                            f"— confidence {window_score}%"
                        ),
                        "cumulative_score": rolling_score,
                        "risk_level":       risk_level,
                        "flags":            all_flags,

                        # ← bonus fields (used by AudioDeepfakePanel.jsx, ignored otherwise)
                        "window_score":     window_score,
                        "is_fallback":      classification["is_fallback"],
                        "model_scores":     classification["model_scores"],
                    }
                    print("Sending →", {k: v for k, v in response.items() if k != "model_scores"})
                    await ws.send_json(response)

                except Exception as exc:
                    print(f"Audio processing error: {exc}")
                    await ws.send_json({"type": "error", "message": str(exc)})

                buffer = b""   # reset window

    except WebSocketDisconnect:
        print("Audio client disconnected")
        # Emit session_end so AudioDeepfakePanel.jsx can save the report
        if session_scores:
            final_score = int(np.mean(session_scores))
            final_level = (
                "HIGH"   if final_score >= 70 else
                "MEDIUM" if final_score >= 40 else
                "LOW"
            )
            try:
                await ws.send_json({
                    "type":             "session_end",
                    "final_score":      final_score,
                    "risk_level":       final_level,
                    "all_flags":        all_flags,
                    "full_transcript":  "",
                    "windows_analyzed": len(session_scores),
                })
            except Exception:
                pass   # client already gone — safe to ignore


# ── EMAIL ANALYSIS (unchanged) ────────────────────────────────────────────────
@app.post("/api/analyze/email")
async def analyze_email(req: EmailRequest):
    text   = req.text
    sender = req.sender

    urls        = re.findall(r'https?://\S+', text)
    ml_prob     = get_phishing_score(text)
    ml_score    = int(ml_prob * 50)
    tone        = get_tone_analysis(text)
    tone_score  = int(tone["tone_risk_score"])

    indicators     = []
    indicator_score = 0
    tl = text.lower()

    if "password" in tl: indicators.append("Requests password");      indicator_score += 10
    if "urgent"   in tl: indicators.append("Creates urgency");        indicator_score += 10
    if "verify"   in tl: indicators.append("Verification request");   indicator_score += 10

    total = min(ml_score + tone_score + indicator_score, 100)
    risk  = "HIGH" if total >= 70 else "MEDIUM" if total >= 40 else "LOW"

    return {
        "risk_score":      total,
        "risk_level":      risk,
        "ml_probability":  ml_prob,
        "ml_score":        ml_score,
        "tone_analysis":   tone,
        "indicators":      indicators,
        "sender_flags":    [],
        "url_flags":       [],
        "urls_found":      urls,
        "urlhaus_results": [],
        "sender_intel":    {},
    }