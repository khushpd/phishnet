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
import json
from deepgram import DeepgramClient

app = FastAPI()

# ---------------- CORS ----------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------- LOAD ML MODEL ----------------
model_name = "ealvaradob/bert-finetuned-phishing"
tokenizer = AutoTokenizer.from_pretrained(model_name)
model = AutoModelForSequenceClassification.from_pretrained(model_name)

# ---------------- DEEPGRAM ----------------
DEEPGRAM_API_KEY = "42cfcc31320026fa12e1a1841994c4d9be281c03"

# ---------------- DISPOSABLE EMAIL DOMAINS ----------------
DISPOSABLE_DOMAINS = {
    "mailinator.com", "guerrillamail.com", "tempmail.com", "throwam.com",
    "sharklasers.com", "guerrillamailblock.com", "grr.la", "guerrillamail.info",
    "guerrillamail.biz", "guerrillamail.de", "guerrillamail.net", "guerrillamail.org",
    "spam4.me", "trashmail.com", "trashmail.me", "trashmail.net", "trashmail.at",
    "trashmail.io", "trashmail.xyz", "yopmail.com", "yopmail.fr", "cool.fr.nf",
    "jetable.fr.nf", "nospam.ze.tc", "nomail.xl.cx", "mega.zik.dj", "speed.1s.fr",
    "courriel.fr.nf", "moncourrier.fr.nf", "monemail.fr.nf", "monmail.fr.nf",
    "dispostable.com", "mailnull.com", "spamgourmet.com", "spamgourmet.net",
    "spamgourmet.org", "maildrop.cc", "discard.email", "spamspot.com",
    "fakeinbox.com", "mailexpire.com", "mailscrap.com",
    "spamfree24.org", "spamfree24.de", "spamfree24.eu", "spamfree24.info",
    "spamfree24.net", "spamfree.eu", "spamhole.com", "tempinbox.com",
    "tempr.email", "temp-mail.org", "getnada.com", "mohmal.com",
    "filzmail.com", "mailnesia.com",
}

# ---------------- KNOWN CORPORATE DOMAINS FOR LOOKALIKE ----------------
KNOWN_DOMAINS = [
    "paypal.com", "microsoft.com", "google.com", "apple.com", "amazon.com",
    "facebook.com", "instagram.com", "twitter.com", "linkedin.com", "netflix.com",
    "adobe.com", "dropbox.com", "salesforce.com", "slack.com", "zoom.us",
    "github.com", "gitlab.com", "atlassian.com", "stripe.com", "shopify.com",
    "bankofamerica.com", "chase.com", "wellsfargo.com", "citibank.com", "hsbc.com",
    "americanexpress.com", "mastercard.com", "visa.com", "fedex.com", "ups.com",
    "dhl.com", "usps.com", "irs.gov", "yahoo.com", "outlook.com", "hotmail.com",
    "office365.com", "onedrive.com", "icloud.com", "coinbase.com", "binance.com",
    "ebay.com", "walmart.com", "target.com", "bestbuy.com", "steam.com",
    "epicgames.com", "blizzard.com", "ea.com", "spotify.com", "twitch.tv",
]

# ---------------- SOCIAL ENGINEERING PHRASES ----------------
SOCIAL_ENGINEERING_PHRASES = [
    "wire transfer", "bank account", "routing number", "social security",
    "credit card", "confirm your identity", "verify your account",
    "urgent", "immediately", "act now", "limited time", "do not tell",
    "keep this confidential", "gift card", "send money", "western union",
    "ceo", "executive", "board of directors", "on behalf of",
    "password", "login credentials", "remote access", "click the link",
]

# ---------------- REQUEST MODEL ----------------
class EmailRequest(BaseModel):
    text: str
    sender: str

# ---------------- HEALTH ----------------
@app.get("/health")
def health():
    return {"status": "ok"}

# ---------------- ML FUNCTION ----------------
def get_ml_score(text):
    inputs = tokenizer(text, return_tensors="pt", truncation=True, padding=True)
    with torch.no_grad():
        outputs = model(**inputs)
    probs = torch.softmax(outputs.logits, dim=1)
    return probs[0][1].item()

# ---------------- LEVENSHTEIN ----------------
def levenshtein(s1, s2):
    if len(s1) < len(s2):
        return levenshtein(s2, s1)
    if len(s2) == 0:
        return len(s1)
    prev = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        curr = [i + 1]
        for j, c2 in enumerate(s2):
            curr.append(min(prev[j + 1] + 1, curr[j] + 1, prev[j] + (c1 != c2)))
        prev = curr
    return prev[len(s2)]

def check_lookalike(domain):
    domain_root = domain.split(".")[0] if "." in domain else domain
    best_match = None
    best_distance = 999
    for known in KNOWN_DOMAINS:
        known_root = known.split(".")[0]
        distance = levenshtein(domain_root.lower(), known_root.lower())
        if distance < best_distance:
            best_distance = distance
            best_match = known
    if 0 < best_distance <= 3:
        return best_match, best_distance
    return None, None

# ---------------- INDIVIDUAL ASYNC CHECK FUNCTIONS ----------------
async def check_whois(domain, loop):
    try:
        w = await asyncio.wait_for(
            loop.run_in_executor(None, partial(whois.whois, domain)),
            timeout=2.0
        )
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if creation_date:
            age_days = (datetime.now() - creation_date).days
            flag = None
            if age_days < 180:
                flag = "Very new domain — high risk"
            elif age_days < 730:
                flag = "Relatively new domain"
            return {"domain_age_days": age_days, "domain_age_flag": flag or "OK"}
    except:
        pass
    return {"domain_age_days": None, "domain_age_flag": "Unable to verify"}

async def check_mx(domain, loop):
    try:
        records = await asyncio.wait_for(
            loop.run_in_executor(None, partial(dns.resolver.resolve, domain, "MX")),
            timeout=2.0
        )
        if records:
            return True
    except:
        pass
    return False

async def check_spf(domain, loop):
    try:
        records = await asyncio.wait_for(
            loop.run_in_executor(None, partial(dns.resolver.resolve, domain, "TXT")),
            timeout=2.0
        )
        for record in records:
            if "v=spf1" in str(record):
                return True
    except:
        pass
    return False

async def check_dmarc(domain, loop):
    try:
        records = await asyncio.wait_for(
            loop.run_in_executor(None, partial(dns.resolver.resolve, f"_dmarc.{domain}", "TXT")),
            timeout=2.0
        )
        for record in records:
            if "v=DMARC1" in str(record):
                return True
    except:
        pass
    return False

def check_disposable(domain):
    return domain.lower() in DISPOSABLE_DOMAINS

# ---------------- CONCURRENT DOMAIN INTELLIGENCE ----------------
async def analyze_domain(domain):
    loop = asyncio.get_event_loop()
    whois_result, mx_result, spf_result, dmarc_result = await asyncio.gather(
        check_whois(domain, loop),
        check_mx(domain, loop),
        check_spf(domain, loop),
        check_dmarc(domain, loop),
    )
    is_disposable = check_disposable(domain)
    lookalike_match, lookalike_distance = check_lookalike(domain)
    return {
        "domain_age_days": whois_result["domain_age_days"],
        "domain_age_flag": whois_result["domain_age_flag"],
        "mx_valid": mx_result,
        "spf_present": spf_result,
        "dmarc_present": dmarc_result,
        "is_disposable": is_disposable,
        "lookalike_match": lookalike_match,
        "lookalike_distance": lookalike_distance,
    }

# ---------------- AUDIO NLP ANALYSIS ----------------
def analyze_transcript(transcript: str):
    text = transcript.lower()
    flags = []
    score = 0

    for phrase in SOCIAL_ENGINEERING_PHRASES:
        if phrase in text:
            flags.append(f"Social engineering: '{phrase}'")
            score += 20

    ml_prob = get_ml_score(text) if len(text.split()) > 3 else 0.0
    ml_contribution = int(ml_prob * 40)
    score += ml_contribution

    capped = min(score, 100)
    if capped >= 70:
        risk_level = "HIGH"
    elif capped >= 40:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    return {
        "score": capped,
        "risk_level": risk_level,
        "flags": flags,
        "ml_probability": ml_prob,
    }

# ---------------- EMAIL ENDPOINT ----------------
@app.post("/api/analyze/email")
async def analyze_email(data: EmailRequest):
    text = data.text.lower()
    sender = data.sender.lower()

    score = 0
    indicators = []
    sender_flags = []
    url_flags = []

    urgency_words = ["urgent", "immediately", "act now", "limited time", "expires", "asap", "right away"]
    for word in urgency_words:
        if word in text:
            score += 15
            indicators.append(f"Urgency language: '{word}'")
            break

    suspicious_phrases = ["click here", "verify your account", "confirm your identity", "suspended", "unusual activity"]
    for phrase in suspicious_phrases:
        if phrase in text:
            score += 15
            indicators.append(f"Suspicious phrase: '{phrase}'")
            break

    sensitive_words = ["password", "social security", "credit card", "bank account", "wire transfer", "ssn"]
    for word in sensitive_words:
        if word in text:
            score += 20
            indicators.append(f"Sensitive info request: '{word}'")
            break

    if "@" not in sender:
        sender_flags.append("Invalid email format")
        score += 20

    urls = re.findall(r'(https?://[^\s]+)', text)
    for url in urls:
        if any(short in url for short in ["bit.ly", "tinyurl", "t.co", "goo.gl", "ow.ly"]):
            url_flags.append(f"Shortened URL: {url}")
            score += 20
        if re.search(r'https?://\d+\.\d+\.\d+\.\d+', url):
            url_flags.append(f"IP-based URL: {url}")
            score += 30

    domain = sender.split("@")[-1] if "@" in sender else ""
    sender_intel = {}

    if domain:
        sender_intel = await analyze_domain(domain)

        age_days = sender_intel.get("domain_age_days")
        if age_days is not None:
            if age_days < 180:
                score += 25
                sender_flags.append("Very new domain — high risk")
            elif age_days < 730:
                score += 10
                sender_flags.append("Relatively new domain")

        if not sender_intel["mx_valid"]:
            score += 15
            sender_flags.append("No valid MX records")

        if not sender_intel["spf_present"]:
            score += 10
            sender_flags.append("Missing SPF record")

        if not sender_intel["dmarc_present"]:
            score += 10
            sender_flags.append("Missing DMARC record")

        if sender_intel["is_disposable"]:
            score += 30
            sender_flags.append("Disposable/temporary email provider")

        if sender_intel["lookalike_match"]:
            score += 35
            sender_flags.append(
                f"Lookalike domain — possible spoof of {sender_intel['lookalike_match']} "
                f"({sender_intel['lookalike_distance']} char difference)"
            )

    loop = asyncio.get_event_loop()
    ml_prob = await loop.run_in_executor(None, partial(get_ml_score, text))
    ml_score = int(ml_prob * 100)
    score += ml_score

    capped_score = min(score, 100)

    if capped_score >= 70:
        risk_level = "HIGH"
    elif capped_score >= 40:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    return {
        "risk_score": capped_score,
        "raw_score": score,
        "risk_level": risk_level,
        "indicators": indicators,
        "sender_flags": sender_flags,
        "url_flags": url_flags,
        "urls_found": urls,
        "ml_score": ml_score,
        "ml_probability": ml_prob,
        "sender_intel": sender_intel,
    }

# ---------------- AUDIO WEBSOCKET ENDPOINT ----------------
@app.websocket("/api/analyze/audio")
async def analyze_audio(websocket: WebSocket):
    await websocket.accept()

    deepgram = DeepgramClient(api_key=DEEPGRAM_API_KEY)

    full_transcript = ""
    cumulative_score = 0
    all_flags = []

    try:
        dg_connection = deepgram.listen.websocket.v("1")

        loop = asyncio.get_event_loop()

        async def send_to_frontend(transcript_chunk: str, is_final: bool):
            nonlocal full_transcript, cumulative_score, all_flags

            if not transcript_chunk.strip():
                return

            if is_final:
                full_transcript += " " + transcript_chunk

            analysis = analyze_transcript(full_transcript if is_final else transcript_chunk)

            if analysis["score"] > cumulative_score:
                cumulative_score = analysis["score"]

            for flag in analysis["flags"]:
                if flag not in all_flags:
                    all_flags.append(flag)

            if cumulative_score >= 70:
                risk_level = "HIGH"
            elif cumulative_score >= 40:
                risk_level = "MEDIUM"
            else:
                risk_level = "LOW"

            await websocket.send_json({
                "type": "transcript",
                "transcript_chunk": transcript_chunk,
                "full_transcript": full_transcript.strip(),
                "cumulative_score": cumulative_score,
                "risk_level": risk_level,
                "flags": all_flags,
                "is_final": is_final,
                "ml_probability": analysis["ml_probability"],
            })

        def on_message(self_ref, result, **kwargs):
            try:
                transcript = result.channel.alternatives[0].transcript
                is_final = result.is_final
                if transcript:
                    asyncio.run_coroutine_threadsafe(
                        send_to_frontend(transcript, is_final),
                        loop
                    )
            except Exception as e:
                print(f"Transcript handler error: {e}")

        def on_error(self_ref, error, **kwargs):
            print(f"Deepgram error: {error}")

        dg_connection.on("Results", on_message)
        dg_connection.on("Error", on_error)

        options = {
            "model": "nova-2",
            "language": "en",
            "encoding": "linear16",
            "sample_rate": 16000,
            "channels": 1,
            "interim_results": True,
            "endpointing": 300,
        }

        if not dg_connection.start(options):
            await websocket.send_json({"type": "error", "message": "Failed to connect to Deepgram"})
            return

        await websocket.send_json({"type": "ready", "message": "Audio shield active"})

        while True:
            try:
                data = await asyncio.wait_for(websocket.receive_bytes(), timeout=30.0)
                dg_connection.send(data)
            except asyncio.TimeoutError:
                break

    except WebSocketDisconnect:
        pass
    except Exception as e:
        print(f"Audio WebSocket error: {e}")
        try:
            await websocket.send_json({"type": "error", "message": str(e)})
        except:
            pass
    finally:
        try:
            dg_connection.finish()
        except:
            pass
        try:
            await websocket.send_json({
                "type": "session_end",
                "full_transcript": full_transcript.strip(),
                "final_score": cumulative_score,
                "all_flags": all_flags,
            })
        except:
            pass