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
from deepgram import DeepgramClient
import aiohttp

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

# ---------------- DEEPGRAM ----------------
DEEPGRAM_API_KEY = "42cfcc31320026fa12e1a1841994c4d9be281c03"

# ---------------- URLHAUS API ----------------
URLHAUS_API = "https://urlhaus-api.abuse.ch/v1/url/"

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

# ---------------- KNOWN CORPORATE DOMAINS ----------------
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

    urgency_markers = [
        "urgent", "immediately", "right away", "act now", "asap",
        "within 24 hours", "by end of day", "eod", "deadline",
        "expires", "limited time", "time sensitive", "as soon as possible"
    ]
    authority_markers = [
        "on behalf of", "as per", "per our records", "kindly",
        "please be informed", "this is to notify", "dear valued",
        "our records indicate", "as requested", "further to",
        "please find attached", "please ensure", "compliance",
        "failure to comply", "legal action", "account will be"
    ]
    financial_markers = [
        "wire transfer", "bank account", "payment", "invoice",
        "credit card", "password", "credentials", "login",
        "verify", "confirm", "update your", "validate"
    ]

    urgency_count  = sum(1 for m in urgency_markers  if m in text_lower)
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
        tone_flags.append("Clinical neutral tone with authority language — possible AI-drafted impersonation")
    elif neutral > 0.4 and authority_count >= 1:
        tone_risk += 5
        tone_flags.append("Formal authority tone detected")

    if urgency_count >= 2 and financial_count >= 1:
        tone_risk += 12
        tone_flags.append("Urgency combined with financial/credential request")
    elif urgency_count >= 1 and financial_count >= 1:
        tone_risk += 6
        tone_flags.append("Pressure + action request pattern")

    if positive > 0.5 and financial_count >= 1:
        tone_risk += 8
        tone_flags.append("Positive framing with financial request — possible reward scam")

    if positive > 0.75:
        tone_risk += 5
        tone_flags.append("Unusually positive tone")

    tone_risk = min(tone_risk, 25)

    return {
        "sentiment": {
            "negative": round(negative, 3),
            "neutral":  round(neutral,  3),
            "positive": round(positive, 3),
        },
        "tone_risk_score":  round(tone_risk, 1),
        "tone_flags":       tone_flags,
        "urgency_count":    urgency_count,
        "authority_count":  authority_count,
        "financial_count":  financial_count,
    }

# ---------------- URLHAUS LIVE THREAT INTELLIGENCE ----------------
async def check_url_urlhaus(url: str, session: aiohttp.ClientSession) -> dict:
    """
    Check a single URL against URLhaus real-time threat intelligence database.
    URLhaus tracks malicious URLs used in malware distribution and phishing.
    Returns threat status, malware family, and tags if the URL is known malicious.
    """
    result = {
        "url":          url,
        "is_malicious": False,
        "threat":       None,
        "malware":      None,
        "tags":         [],
        "date_added":   None,
    }
    try:
        payload = {"url": url}
        async with session.post(
            URLHAUS_API,
            data=payload,
            timeout=aiohttp.ClientTimeout(total=3.0)
        ) as resp:
            if resp.status == 200:
                data = await resp.json()
                if data.get("query_status") == "is_listed":
                    result["is_malicious"] = True
                    result["threat"]       = data.get("threat", "unknown")
                    result["date_added"]   = data.get("date_added", None)
                    tags = data.get("tags") or []
                    result["tags"]         = tags
                    # Extract malware family from payloads if available
                    payloads = data.get("payloads") or []
                    if payloads:
                        families = list({
                            p.get("signature") for p in payloads
                            if p.get("signature")
                        })
                        result["malware"] = families[0] if families else None
    except Exception as e:
        print(f"URLhaus check failed for {url}: {e}")
    return result

async def check_urls_urlhaus(urls: list) -> list:
    """Run URLhaus checks for all extracted URLs concurrently."""
    if not urls:
        return []
    async with aiohttp.ClientSession() as session:
        tasks = [check_url_urlhaus(url, session) for url in urls]
        results = await asyncio.gather(*tasks, return_exceptions=True)
    clean = []
    for r in results:
        if isinstance(r, dict):
            clean.append(r)
    return clean

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
    best_match  = None
    best_distance = 999
    for known in KNOWN_DOMAINS:
        known_root = known.split(".")[0]
        distance   = levenshtein(domain_root.lower(), known_root.lower())
        if distance < best_distance:
            best_distance = distance
            best_match    = known
    if 0 < best_distance <= 3:
        return best_match, best_distance
    return None, None

# ---------------- ASYNC DNS / WHOIS CHECKS ----------------
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
            if age_days < 180:
                flag = "Very new domain — high risk"
            elif age_days < 730:
                flag = "Relatively new domain"
            else:
                flag = "OK"
            return {"domain_age_days": age_days, "domain_age_flag": flag}
    except:
        pass
    return {"domain_age_days": None, "domain_age_flag": "Unable to verify"}

async def check_mx(domain, loop):
    try:
        records = await asyncio.wait_for(
            loop.run_in_executor(None, partial(dns.resolver.resolve, domain, "MX")),
            timeout=2.0
        )
        return bool(records)
    except:
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

async def analyze_domain(domain):
    loop = asyncio.get_event_loop()
    whois_result, mx_result, spf_result, dmarc_result = await asyncio.gather(
        check_whois(domain, loop),
        check_mx(domain, loop),
        check_spf(domain, loop),
        check_dmarc(domain, loop),
    )
    is_disposable   = check_disposable(domain)
    lookalike_match, lookalike_distance = check_lookalike(domain)
    return {
        "domain_age_days":    whois_result["domain_age_days"],
        "domain_age_flag":    whois_result["domain_age_flag"],
        "mx_valid":           mx_result,
        "spf_present":        spf_result,
        "dmarc_present":      dmarc_result,
        "is_disposable":      is_disposable,
        "lookalike_match":    lookalike_match,
        "lookalike_distance": lookalike_distance,
    }

# ---------------- AUDIO NLP ----------------
def analyze_transcript(transcript: str):
    text   = transcript.lower()
    flags  = []
    score  = 0

    for phrase in SOCIAL_ENGINEERING_PHRASES:
        if phrase in text:
            flags.append(f"Social engineering: '{phrase}'")
            score += 20

    ml_prob = get_phishing_score(text) if len(text.split()) > 3 else 0.0
    score  += int(ml_prob * 40)

    capped     = min(score, 100)
    risk_level = "HIGH" if capped >= 70 else "MEDIUM" if capped >= 40 else "LOW"

    return {
        "score":          capped,
        "risk_level":     risk_level,
        "flags":          flags,
        "ml_probability": ml_prob,
    }

# ---------------- EMAIL ENDPOINT ----------------
@app.post("/api/analyze/email")
async def analyze_email(data: EmailRequest):
    text       = data.text
    text_lower = text.lower()
    sender     = data.sender.lower()

    score        = 0
    indicators   = []
    sender_flags = []
    url_flags    = []

    # --- Text checks ---
    urgency_words = [
        "urgent", "immediately", "act now", "limited time",
        "expires", "asap", "right away"
    ]
    for word in urgency_words:
        if word in text_lower:
            score += 10
            indicators.append(f"Urgency language: '{word}'")
            break

    suspicious_phrases = [
        "click here", "verify your account", "confirm your identity",
        "suspended", "unusual activity"
    ]
    for phrase in suspicious_phrases:
        if phrase in text_lower:
            score += 10
            indicators.append(f"Suspicious phrase: '{phrase}'")
            break

    sensitive_words = [
        "password", "social security", "credit card",
        "bank account", "wire transfer", "ssn"
    ]
    for word in sensitive_words:
        if word in text_lower:
            score += 15
            indicators.append(f"Sensitive info request: '{word}'")
            break

    # --- Sender format check ---
    if "@" not in sender:
        sender_flags.append("Invalid email format")
        score += 15

    # --- URL extraction ---
    urls = re.findall(r'(https?://[^\s]+)', text_lower)
    for url in urls:
        if any(s in url for s in ["bit.ly", "tinyurl", "t.co", "goo.gl", "ow.ly"]):
            url_flags.append(f"Shortened URL: {url}")
            score += 15
        if re.search(r'https?://\d+\.\d+\.\d+\.\d+', url):
            url_flags.append(f"IP-based URL: {url}")
            score += 20

    # --- Domain intelligence + URLhaus + ML + Tone run concurrently ---
    domain = sender.split("@")[-1] if "@" in sender else ""

    loop = asyncio.get_event_loop()

    domain_task   = analyze_domain(domain) if domain else asyncio.sleep(0)
    urlhaus_task  = check_urls_urlhaus(urls)
    ml_task       = loop.run_in_executor(None, partial(get_phishing_score, text_lower))
    tone_task     = loop.run_in_executor(None, partial(get_tone_analysis, text))

    domain_result, urlhaus_results, ml_prob, tone = await asyncio.gather(
        domain_task,
        urlhaus_task,
        ml_task,
        tone_task,
    )

    # --- Process domain results ---
    sender_intel = domain_result if isinstance(domain_result, dict) else {}

    if sender_intel:
        age_days = sender_intel.get("domain_age_days")
        if age_days is not None:
            if age_days < 180:
                score += 20
                sender_flags.append("Very new domain — high risk")
            elif age_days < 730:
                score += 8
                sender_flags.append("Relatively new domain")

        if not sender_intel["mx_valid"]:
            score += 8
            sender_flags.append("No valid MX records")

        if not sender_intel["spf_present"]:
            score += 5
            sender_flags.append("Missing SPF record")

        if not sender_intel["dmarc_present"]:
            score += 5
            sender_flags.append("Missing DMARC record")

        if sender_intel["is_disposable"]:
            score += 25
            sender_flags.append("Disposable/temporary email provider")

        if sender_intel["lookalike_match"]:
            score += 30
            sender_flags.append(
                f"Lookalike domain — possible spoof of {sender_intel['lookalike_match']} "
                f"({sender_intel['lookalike_distance']} char difference)"
            )

    # --- Process URLhaus results ---
    urlhaus_flags = []
    for result in urlhaus_results:
        if result["is_malicious"]:
            score += 40
            threat_label = result["threat"] or "malicious"
            malware      = result["malware"]
            tags         = ", ".join(result["tags"]) if result["tags"] else ""
            flag_text    = f"🔴 LIVE THREAT: {result['url']} — {threat_label}"
            if malware:
                flag_text += f" | Malware: {malware}"
            if tags:
                flag_text += f" | Tags: {tags}"
            urlhaus_flags.append(flag_text)
            url_flags.append(flag_text)

    # --- ML score ---
    ml_score = int(ml_prob * 35)
    score   += ml_score

    # --- Tone score ---
    score += tone["tone_risk_score"]
    indicators.extend(tone["tone_flags"])

    # --- Final score ---
    capped_score = min(round(score), 100)

    if capped_score >= 70:
        risk_level = "HIGH"
    elif capped_score >= 40:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    return {
        "risk_score":      capped_score,
        "raw_score":       round(score),
        "risk_level":      risk_level,
        "indicators":      indicators,
        "sender_flags":    sender_flags,
        "url_flags":       url_flags,
        "urls_found":      urls,
        "urlhaus_results": urlhaus_results,
        "urlhaus_flags":   urlhaus_flags,
        "ml_score":        ml_score,
        "ml_probability":  ml_prob,
        "sender_intel":    sender_intel,
        "tone_analysis":   tone,
    }

# ---------------- AUDIO WEBSOCKET ----------------
@app.websocket("/api/analyze/audio")
async def analyze_audio(websocket: WebSocket):
    await websocket.accept()

    deepgram        = DeepgramClient(api_key=DEEPGRAM_API_KEY)
    full_transcript = ""
    cumulative_score = 0
    all_flags       = []

    try:
        dg_connection = deepgram.listen.websocket.v("1")
        loop          = asyncio.get_event_loop()

        async def send_to_frontend(transcript_chunk: str, is_final: bool):
            nonlocal full_transcript, cumulative_score, all_flags

            if not transcript_chunk.strip():
                return

            if is_final:
                full_transcript += " " + transcript_chunk

            analysis = analyze_transcript(
                full_transcript if is_final else transcript_chunk
            )

            if analysis["score"] > cumulative_score:
                cumulative_score = analysis["score"]

            for flag in analysis["flags"]:
                if flag not in all_flags:
                    all_flags.append(flag)

            risk_level = (
                "HIGH"   if cumulative_score >= 70 else
                "MEDIUM" if cumulative_score >= 40 else
                "LOW"
            )

            await websocket.send_json({
                "type":             "transcript",
                "transcript_chunk": transcript_chunk,
                "full_transcript":  full_transcript.strip(),
                "cumulative_score": cumulative_score,
                "risk_level":       risk_level,
                "flags":            all_flags,
                "is_final":         is_final,
                "ml_probability":   analysis["ml_probability"],
            })

        def on_message(self_ref, result, **kwargs):
            try:
                transcript = result.channel.alternatives[0].transcript
                is_final   = result.is_final
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
        dg_connection.on("Error",   on_error)

        options = {
            "model":           "nova-2",
            "language":        "en",
            "encoding":        "linear16",
            "sample_rate":     16000,
            "channels":        1,
            "interim_results": True,
            "endpointing":     300,
        }

        if not dg_connection.start(options):
            await websocket.send_json({
                "type": "error",
                "message": "Failed to connect to Deepgram"
            })
            return

        await websocket.send_json({"type": "ready", "message": "Audio shield active"})

        while True:
            try:
                data = await asyncio.wait_for(
                    websocket.receive_bytes(), timeout=30.0
                )
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
                "type":            "session_end",
                "full_transcript": full_transcript.strip(),
                "final_score":     cumulative_score,
                "all_flags":       all_flags,
            })
        except:
            pass