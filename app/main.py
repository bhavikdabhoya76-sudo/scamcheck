# main.py
# ScamCheck API - FastAPI server
# ચલાવવા માટે: uvicorn app.main:app --reload

from fastapi import FastAPI
from fastapi.responses import FileResponse
from pydantic import BaseModel
from pathlib import Path

from app.analyzers.sms_analyzer import analyze_message

app = FastAPI(title="ScamCheck API", version="1.0")

# static folder નો રસ્તો (web page અહીં છે)
STATIC_DIR = Path(__file__).parent.parent / "static"


# User તરફથી આવતા data નું format
class CheckRequest(BaseModel):
    text: str


@app.get("/")
def home():
    """Web page બતાવો"""
    return FileResponse(STATIC_DIR / "index.html")


@app.post("/api/check")
def check_message(request: CheckRequest):
    """
    Message check કરવાની મુખ્ય API.
    Input:  {"text": "Your KYC expired..."}
    Output: {"score": 85, "verdict": "DANGEROUS", "reasons": [...], "advice": "..."}
    """
    text = request.text.strip()

    # ખાલી message આવે તો error ન આપો, સરસ જવાબ આપો
    if not text:
        return {
            "score": 0,
            "verdict": "EMPTY",
            "reasons": ["કોઈ message આપ્યો નથી"],
            "advice": "કૃપા કરીને check કરવા માટે message paste કરો.",
        }

    return analyze_message(text)


@app.get("/api/health")
def health():
    """Server ચાલે છે કે નહીં તે check કરવા"""
    return {"status": "ok"}
