# main.py - ScamCheck API v3.2
# નવું: messages counter + feedback system

from fastapi import FastAPI
from fastapi.responses import FileResponse
from pydantic import BaseModel
from pathlib import Path
import json
import threading

from app.analyzers.sms_analyzer import analyze_message
from app.analyzers.ai_analyzer import analyze_with_ai, is_ai_available

app = FastAPI(title="ScamCheck API", version="3.2")

STATIC_DIR = Path(__file__).parent.parent / "static"
STATS_FILE = Path(__file__).parent.parent / "stats.json"
_lock = threading.Lock()  # એક સાથે બે requests આવે તો counter ન બગડે


def load_stats() -> dict:
    """stats.json માંથી આંકડા વાંચો. File ન હોય તો શૂન્યથી શરૂ."""
    try:
        return json.loads(STATS_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {"total_checks": 0, "frauds_caught": 0}


def save_stats(stats: dict) -> None:
    try:
        STATS_FILE.write_text(json.dumps(stats), encoding="utf-8")
    except Exception:
        pass  # save fail થાય તો પણ app ચાલતી રહે


class CheckRequest(BaseModel):
    text: str


class FeedbackRequest(BaseModel):
    text: str          # user એ check કરેલો message
    verdict: str       # tool એ શું કહ્યું હતું
    score: int


@app.get("/")
def home():
    return FileResponse(STATIC_DIR / "index.html")


@app.post("/api/check")
def check_message(request: CheckRequest):
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

    # Step 2: AI deep analysis (સ્પષ્ટ fraud સિવાય, meaningful messages માટે)
    if is_ai_available() and result["score"] < 60 and len(text) >= 15:
        ai = analyze_with_ai(text)
        if ai is not None:
            result["ai_used"] = True
            if ai["is_fraud"] and ai["confidence"] >= 60:
                result["score"] = max(result["score"], min(60 + ai["confidence"] // 3, 95))
                result["reasons"].append(f"🧠 AI analysis: {ai['reason']}")
            elif not ai["is_fraud"] and ai["confidence"] >= 70:
                result["score"] = max(result["score"] - 15, 0)
                result["reasons"].append(f"🧠 AI analysis: {ai['reason']}")

            if result["score"] >= 60:
                result["verdict"] = "DANGEROUS"
                result["advice"] = "🚫 આ message FRAUD લાગે છે! કોઈ link ન ખોલો, OTP/PIN ન આપો, જવાબ ન આપો. 1930 પર report કરો."
            elif result["score"] >= 30:
                result["verdict"] = "SUSPICIOUS"
                result["advice"] = "⚠️ સાવધાન! આ message શંકાસ્પદ છે. કોઈ પગલું લેતા પહેલા સત્તાવાર નંબર/website પર જાતે ખાતરી કરો."
            else:
                result["verdict"] = "SAFE"
                result["advice"] = "✅ આ message માં કોઈ જાણીતો fraud pattern નથી મળ્યો. છતાં OTP/PIN ક્યારેય કોઈને ન આપો."

    # Counter વધારો (message store નથી થતો - ફક્ત આંકડો!)
    with _lock:
        stats = load_stats()
        stats["total_checks"] += 1
        if result["verdict"] == "DANGEROUS":
            stats["frauds_caught"] += 1
        save_stats(stats)

    return result


@app.post("/api/feedback")
def feedback(request: FeedbackRequest):
    """
    User જાતે 'ખોટું result' button દબાવે ત્યારે જ આ ચાલે છે.
    Message Render ના Logs માં છપાય છે - ત્યાંથી વાંચીને engine સુધારી શકાય.
    """
    # Logs માં છાપો (Render dashboard > Logs માં દેખાશે)
    safe_text = request.text[:300].replace("\n", " ")
    print(f"[FEEDBACK] verdict={request.verdict} score={request.score} msg={safe_text}")
    return {"ok": True, "message": "આભાર! તમારો feedback અમને engine સુધારવામાં મદદ કરશે. 🙏"}


@app.get("/api/stats")
def stats():
    s = load_stats()
    return {"total_checks": s["total_checks"], "frauds_caught": s["frauds_caught"]}


@app.get("/api/health")
def health():
    return {"status": "ok", "version": "3.2", "ai_enabled": is_ai_available()}
