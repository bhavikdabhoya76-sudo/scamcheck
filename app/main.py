# main.py
# ScamCheck API - hybrid fraud detection (rules + AI)
# ચલાવવા માટે: uvicorn app.main:app --reload

from fastapi import FastAPI
from fastapi.responses import FileResponse
from pydantic import BaseModel
from pathlib import Path

from app.analyzers.sms_analyzer import analyze_message
from app.analyzers.ai_analyzer import analyze_with_ai, is_ai_available

app = FastAPI(title="ScamCheck API", version="2.0")

STATIC_DIR = Path(__file__).parent.parent / "static"


class CheckRequest(BaseModel):
    text: str


@app.get("/")
def home():
    return FileResponse(STATIC_DIR / "index.html")


@app.post("/api/check")
def check_message(request: CheckRequest):
    """
    Hybrid analysis:
    Step 1: Rule-based (instant, free) - દરેક message માટે
    Step 2: AI deep analysis - ફક્ત અસ્પષ્ટ cases (score 10-59) માટે
            જેથી ઝડપ રહે અને AI quota બચે
    """
    text = request.text.strip()

    if not text:
        return {
            "score": 0, "verdict": "EMPTY", "ai_used": False,
            "reasons": ["કોઈ message આપ્યો નથી"],
            "advice": "કૃપા કરીને check કરવા માટે message paste કરો.",
        }

    # Step 1: Rule-based analysis
    result = analyze_message(text)
    result["ai_used"] = False

    # Step 2: અસ્પષ્ટ zone માં AI ને પૂછો
    if is_ai_available() and 10 <= result["score"] < 60:
        ai = analyze_with_ai(text)
        if ai is not None:
            result["ai_used"] = True
            if ai["is_fraud"] and ai["confidence"] >= 60:
                # AI ને fraud લાગે છે - score વધારો
                result["score"] = max(result["score"], min(60 + ai["confidence"] // 3, 95))
                result["reasons"].append(f"🧠 AI analysis: {ai['reason']}")
            elif not ai["is_fraud"] and ai["confidence"] >= 70:
                # AI ને safe લાગે છે - score થોડો ઘટાડો
                result["score"] = max(result["score"] - 15, 0)
                result["reasons"].append(f"🧠 AI analysis: {ai['reason']}")

            # નવા score પ્રમાણે verdict + advice ફરી ગણો
            if result["score"] >= 60:
                result["verdict"] = "DANGEROUS"
                result["advice"] = "🚫 આ message FRAUD લાગે છે! કોઈ link ન ખોલો, OTP/PIN ન આપો, જવાબ ન આપો. 1930 પર report કરો."
            elif result["score"] >= 30:
                result["verdict"] = "SUSPICIOUS"
                result["advice"] = "⚠️ સાવધાન! આ message શંકાસ્પદ છે. કોઈ પગલું લેતા પહેલા સત્તાવાર નંબર/website પર જાતે ખાતરી કરો."
            else:
                result["verdict"] = "SAFE"
                result["advice"] = "✅ આ message માં કોઈ જાણીતો fraud pattern નથી મળ્યો. છતાં OTP/PIN ક્યારેય કોઈને ન આપો."

    return result


@app.get("/api/health")
def health():
    return {"status": "ok", "ai_enabled": is_ai_available()}
