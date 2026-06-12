# ai_analyzer.py
# Google Gemini AI વડે message નું ઊંડું analysis
# API key environment variable માંથી આવે છે - code માં ક્યારેય નહીં!

import os
import json
import urllib.request
import urllib.error

# Render/computer ના environment માંથી key વાંચો
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "")

GEMINI_URL = (
    "https://generativelanguage.googleapis.com/v1beta/models/"
    "gemini-2.0-flash:generateContent?key={key}"
)

# AI ને અપાતી સૂચના - strict JSON જ માગીએ છીએ
PROMPT_TEMPLATE = """You are a fraud detection expert for Indian SMS/WhatsApp scams
(KYC fraud, digital arrest, UPI scams, lottery, fake jobs, loan fraud, emotional
manipulation like fake accident/hospital messages).

Analyze this message and respond with ONLY a JSON object, no other text:
{{"is_fraud": true/false, "confidence": 0-100, "reason": "one short sentence in Gujarati explaining why"}}

Message to analyze:
{message}"""


def is_ai_available() -> bool:
    """API key set છે કે નહીં"""
    return bool(GEMINI_API_KEY)


def analyze_with_ai(text: str, timeout: int = 8) -> dict | None:
    """
    Gemini ને message મોકલી fraud verdict મેળવો.
    કંઈપણ ખોટું થાય (network fail, quota પૂરો, ખરાબ જવાબ) તો None -
    એટલે app ક્યારેય તૂટે નહીં, ફક્ત rule-based result પર પાછી જાય.
    """
    if not GEMINI_API_KEY:
        return None

    body = json.dumps({
        "contents": [{"parts": [{"text": PROMPT_TEMPLATE.format(message=text[:2000])}]}],
        "generationConfig": {"temperature": 0.1},  # સ્થિર જવાબ માટે ઓછું temperature
    }).encode("utf-8")

    request = urllib.request.Request(
        GEMINI_URL.format(key=GEMINI_API_KEY),
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            data = json.loads(response.read().decode("utf-8"))

        # Gemini ના જવાબમાંથી text કાઢો
        ai_text = data["candidates"][0]["content"]["parts"][0]["text"].strip()

        # ક્યારેક AI જવાબને ```json ``` માં લપેટે છે - સાફ કરો
        ai_text = ai_text.replace("```json", "").replace("```", "").strip()

        result = json.loads(ai_text)

        # જવાબ માં જરૂરી fields છે કે નહીં તે ચકાસો
        if "is_fraud" not in result or "confidence" not in result:
            return None

        return {
            "is_fraud": bool(result["is_fraud"]),
            "confidence": max(0, min(int(result["confidence"]), 100)),
            "reason": str(result.get("reason", ""))[:200],
        }
    except urllib.error.HTTPError as e:
        # Gemini તરફથી error (ખોટી key, quota પૂરો વગેરે) - Logs માં છાપો
        try:
            detail = e.read().decode("utf-8")[:300]
        except Exception:
            detail = ""
        print(f"[AI ERROR] Gemini HTTP {e.code}: {detail}")
        return None
    except Exception as e:
        print(f"[AI ERROR] {type(e).__name__}: {str(e)[:200]}")
        return None
