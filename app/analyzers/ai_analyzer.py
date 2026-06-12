# ai_analyzer.py
# Google Gemini AI વડે message નું ઊંડું analysis
# Smart fallback: એક model fail થાય (quota/deprecated) તો આપોઆપ બીજું try કરે

import os
import json
import urllib.request
import urllib.error

GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "")

# Models priority ક્રમમાં - પહેલું fail થાય તો બીજું, એમ આગળ
# GEMINI_MODEL env variable થી override પણ કરી શકાય
MODEL_CANDIDATES = [
    os.environ.get("GEMINI_MODEL", "").strip(),
    "gemini-2.5-flash",
    "gemini-flash-latest",
    "gemini-2.5-flash-lite",
    "gemini-2.0-flash",
]
MODEL_CANDIDATES = [m for m in MODEL_CANDIDATES if m]  # ખાલી હટાવો

# જે model ચાલ્યું તે યાદ રાખો - દર વખતે બધા try ન કરવા પડે
_working_model: str | None = None

GEMINI_URL = (
    "https://generativelanguage.googleapis.com/v1beta/models/"
    "{model}:generateContent?key={key}"
)

PROMPT_TEMPLATE = """You are a fraud detection expert for Indian SMS/WhatsApp scams
(KYC fraud, digital arrest, UPI scams, lottery, fake jobs, loan fraud, emotional
manipulation like fake accident/hospital messages).

Analyze this message and respond with ONLY a JSON object, no other text:
{{"is_fraud": true/false, "confidence": 0-100, "reason": "one short sentence in Gujarati explaining why"}}

Message to analyze:
{message}"""


def is_ai_available() -> bool:
    return bool(GEMINI_API_KEY)


def _call_model(model: str, text: str, timeout: int) -> dict | None:
    """એક ચોક્કસ model ને call કરો. Quota/missing model હોય તો 'SKIP' return."""
    body = json.dumps({
        "contents": [{"parts": [{"text": PROMPT_TEMPLATE.format(message=text[:2000])}]}],
        "generationConfig": {"temperature": 0.1},
    }).encode("utf-8")

    request = urllib.request.Request(
        GEMINI_URL.format(model=model, key=GEMINI_API_KEY),
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            data = json.loads(response.read().decode("utf-8"))
        ai_text = data["candidates"][0]["content"]["parts"][0]["text"].strip()
        ai_text = ai_text.replace("```json", "").replace("```", "").strip()
        result = json.loads(ai_text)
        if "is_fraud" not in result or "confidence" not in result:
            return None
        return {
            "is_fraud": bool(result["is_fraud"]),
            "confidence": max(0, min(int(result["confidence"]), 100)),
            "reason": str(result.get("reason", ""))[:200],
        }
    except urllib.error.HTTPError as e:
        try:
            detail = e.read().decode("utf-8")[:200]
        except Exception:
            detail = ""
        print(f"[AI ERROR] model={model} HTTP {e.code}: {detail}")
        if e.code in (404, 429):
            return "SKIP"  # આ model નકામું - આગળનું try કરો
        return None
    except Exception as e:
        print(f"[AI ERROR] model={model} {type(e).__name__}: {str(e)[:150]}")
        return None


def analyze_with_ai(text: str, timeout: int = 8) -> dict | None:
    """
    Models ને ક્રમમાં try કરો. જે ચાલે તે યાદ રાખો.
    બધા fail થાય તો None - app rules પર પાછી જાય, કદી તૂટે નહીં.
    """
    global _working_model
    if not GEMINI_API_KEY:
        return None

    # પહેલા યાદ રાખેલું model, પછી બાકીના
    models_to_try = ([_working_model] if _working_model else []) + \
                    [m for m in MODEL_CANDIDATES if m != _working_model]

    for model in models_to_try:
        result = _call_model(model, text, timeout)
        if result == "SKIP":
            continue  # quota/404 - આગળનું model
        if result is not None:
            if _working_model != model:
                print(f"[AI INFO] Using model: {model}")
            _working_model = model
            return result
        return None  # બીજી ભૂલ - આ request છોડી દો

    print("[AI ERROR] All models failed/quota exceeded")
    return None
