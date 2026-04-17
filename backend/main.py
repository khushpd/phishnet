from fastapi import FastAPI
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware
import re

app = FastAPI()

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class EmailRequest(BaseModel):
    text: str
    sender: str

@app.post("/api/analyze/email")
def analyze_email(data: EmailRequest):
    text = data.text.lower()
    sender = data.sender.lower()

    score = 0
    indicators = []
    sender_flags = []
    url_flags = []

    # ---------------- TEXT CHECKS ----------------
    if "urgent" in text:
        score += 30
        indicators.append("Urgency language detected")

    if "click here" in text:
        score += 30
        indicators.append("Suspicious link phrase")

    if "password" in text:
        score += 40
        indicators.append("Sensitive info request")

    # ---------------- SENDER CHECKS ----------------
    if "@" not in sender:
        sender_flags.append("Invalid email format")
        score += 20

    if sender.endswith("@gmail.com") or sender.endswith("@yahoo.com"):
        sender_flags.append("Free email provider (suspicious for corporate email)")
        score += 20

    if "paypa1" in sender or "micros0ft" in sender:
        sender_flags.append("Lookalike domain detected")
        score += 40

    # ---------------- URL EXTRACTION ----------------
    urls = re.findall(r'(https?://[^\s]+)', text)

    for url in urls:
        if "bit.ly" in url or "tinyurl" in url:
            url_flags.append(f"Shortened URL detected: {url}")
            score += 30

        if re.search(r'https?://\d+\.\d+\.\d+\.\d+', url):
            url_flags.append(f"IP-based URL detected: {url}")
            score += 40

        if "login" in url or "verify" in url:
            url_flags.append(f"Suspicious keyword in URL: {url}")
            score += 20

    # ---------------- FINAL RESPONSE ----------------
    return {
        "risk_score": score,
        "risk_level": "HIGH" if score > 60 else "MEDIUM" if score > 30 else "LOW",
        "indicators": indicators,
        "sender_flags": sender_flags,
        "url_flags": url_flags,
        "urls_found": urls
    }