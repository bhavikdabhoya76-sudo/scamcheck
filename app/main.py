# main.py - ScamCheck API v3.3
# નવું: WhatsApp bot webhook (Twilio)

from fastapi import FastAPI, Form
from fastapi.responses import FileResponse, Response
from pydantic import BaseModel
from pathlib import Path
import json
import threading
import html

from app.analyzers.sms_analyzer import analyze_message
from app.analyzers.ai_analyzer import analyze_with_ai, is_ai_available

app = FastAPI(title="ScamCheck API", version="3.3")

STATIC_DIR = Path(__file__).parent.parent / "static"
STATS_FILE = Path(__file__).parent.parent / "stats.json"
_lock = threading.Lock()


def load_stats() -> dict:
    try:
        return json.loads(STATS_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {"total_checks": 0, "frauds_caught": 0}


def save_stats(stats: dict) -> None:
    try:
        STATS_FILE.write_text(json.dumps(stats), encoding="utf-8")
    except Exception:
        pass


def run_full_check(text: str) -> dict:
    """
    આખું hybrid analysis - website અને WhatsApp બંને આ જ વાપરે છે.
    (એક જ logic બે જગ્યાએ ન લખવો - એ programming નો golden rule!)
    """
    result = analyze_message(text)
    result["ai_used"] = False

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

    with _lock:
        stats = load_stats()
        stats["total_checks"] += 1
        if result["verdict"] == "DANGEROUS":
            stats["frauds_caught"] += 1
        save_stats(stats)

    return result


class CheckRequest(BaseModel):
    text: str


class FeedbackRequest(BaseModel):
    text: str
    verdict: str
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
    return run_full_check(text)


@app.post("/api/whatsapp")
def whatsapp_webhook(Body: str = Form(""), From: str = Form("")):
    """
    Twilio WhatsApp webhook.
    User WhatsApp પર message મોકલે -> Twilio અહીં POST કરે ->
    આપણે TwiML (XML) માં જવાબ આપીએ -> Twilio એ user ને WhatsApp પર પહોંચાડે.
    """
    text = Body.strip()

    if not text or text.lower() in ("hi", "hello", "hey", "start", "namaste"):
        reply = (
            "🛡️ *ScamCheck Bot માં સ્વાગત છે!*\n\n"
            "કોઈપણ શંકાસ્પદ SMS/WhatsApp message અહીં *forward* કરો "
            "અથવા paste કરો — હું તરત કહીશ કે એ fraud છે કે નહીં.\n\n"
            "ગુજરાતી · हिन्दी · English બધું ચાલે! 😊"
        )
    else:
        result = run_full_check(text)
        emoji = {"DANGEROUS": "🚫", "SUSPICIOUS": "⚠️", "SAFE": "✅"}[result["verdict"]]
        verdict_gu = {"DANGEROUS": "ખતરનાક!", "SUSPICIOUS": "શંકાસ્પદ", "SAFE": "સુરક્ષિત લાગે છે"}[result["verdict"]]

        lines = [f"{emoji} *{verdict_gu}* — Risk: {result['score']}/100", ""]
        # વધુમાં વધુ 3 કારણો (WhatsApp માં ટૂંકું સારું)
        for reason in result["reasons"][:3]:
            lines.append(f"• {reason}")
        lines += ["", result["advice"]]
        if result["verdict"] == "DANGEROUS":
            lines += ["", "📞 Report: helpline 1930 · cybercrime.gov.in"]
        reply = "\n".join(lines)

    # TwiML XML જવાબ (XML માં ખાસ અક્ષરો < > & ને escape કરવા જરૂરી)
    twiml = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        f"<Response><Message>{html.escape(reply)}</Message></Response>"
    )
    return Response(content=twiml, media_type="application/xml")


@app.post("/api/feedback")
def feedback(request: FeedbackRequest):
    safe_text = request.text[:300].replace("\n", " ")
    print(f"[FEEDBACK] verdict={request.verdict} score={request.score} msg={safe_text}")
    return {"ok": True, "message": "આભાર! તમારો feedback અમને engine સુધારવામાં મદદ કરશે. 🙏"}


@app.get("/api/stats")
def stats():
    s = load_stats()
    return {"total_checks": s["total_checks"], "frauds_caught": s["frauds_caught"]}


@app.get("/api/health")
def health():
    return {"status": "ok", "version": "3.3", "ai_enabled": is_ai_available()}
