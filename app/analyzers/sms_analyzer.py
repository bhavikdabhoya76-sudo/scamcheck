# sms_analyzer.py
# ScamCheck નું હૃદય - message માં fraud patterns શોધે છે
# ભાષાઓ: English, હિન્દી (देवनागरी + romanized), ગુજરાતી (script + romanized)

import re

# ---------------------------------------------------------
# Fraud keywords - દરેક સાથે risk weight (કેટલું ખતરનાક છે)
# ---------------------------------------------------------

FRAUD_KEYWORDS = {
    # ---------- English ----------
    "kyc expired": 30, "kyc update": 25, "kyc pending": 25,
    "account blocked": 30, "account suspended": 30,
    "lottery": 35, "you won": 30, "prize": 25, "lucky draw": 30,
    "electricity disconnect": 30, "bill overdue": 20,
    "urgent": 10, "immediately": 10, "within 24 hours": 15,
    "click link": 15, "verify now": 20, "verify immediately": 25,
    "income tax refund": 30, "tax refund": 25,
    "customs": 20, "parcel held": 25, "package stuck": 25,
    "anydesk": 40, "teamviewer": 40, "screen share": 35,
    "digital arrest": 50, "cbi officer": 40, "police case": 30,
    "upi pin": 50, "share otp": 50, "send otp": 45,
    "collect request": 35, "refund will be credited": 30,
    "pay rs 1": 30, "pay ₹1": 30, "processing fee": 25,
    "work from home earn": 30, "earn daily": 25, "part time job": 20,
    "loan approved": 25, "instant loan": 25, "pre-approved": 20,

    # ---------- હિન્દી (Devanagari) ----------
    "केवाईसी": 25, "खाता बंद": 30, "खाता ब्लॉक": 30,
    "लॉटरी": 35, "इनाम": 25, "आप जीते": 30, "लकी ड्रॉ": 30,
    "बिजली कट": 30, "तुरंत": 10, "जल्दी करें": 15,
    "ओटीपी भेजें": 50, "ओटीपी बताएं": 50, "पिन बताएं": 50,
    "डिजिटल अरेस्ट": 50, "पुलिस केस": 30, "सीबीआई": 35,
    "रिफंड": 20, "लोन मंजूर": 25, "घर बैठे कमाएं": 30,
    "प्रोसेसिंग फीस": 25, "पार्सल": 15, "कस्टम": 20,

    # ---------- હિન્દી (romanized - WhatsApp માં આમ જ લખાય છે) ----------
    "khata band": 30, "khata block": 30, "otp batao": 50,
    "otp bhejo": 50, "pin batao": 50, "turant": 10,
    "inaam jeeta": 35, "lottery lagi": 35, "paise jeete": 30,
    "ghar baithe kamao": 30, "loan manjoor": 25,

    # ---------- ગુજરાતી (script) ----------
    "કેવાયસી": 25, "ખાતું બંધ": 30, "ખાતું બ્લોક": 30,
    "લોટરી": 35, "ઇનામ": 25, "તમે જીત્યા": 30, "લકી ડ્રો": 30,
    "વીજળી કપાશે": 30, "તાત્કાલિક": 10, "જલ્દી કરો": 15,
    "ઓટીપી મોકલો": 50, "ઓટીપી આપો": 50, "પિન આપો": 50,
    "ડિજિટલ અરેસ્ટ": 50, "પોલીસ કેસ": 30,
    "રિફંડ": 20, "લોન મંજૂર": 25, "ઘરે બેઠા કમાઓ": 30,
    "પ્રોસેસિંગ ફી": 25, "પાર્સલ": 15,

    # ---------- ગુજરાતી (romanized) ----------
    "khatu bandh": 30, "khatu block": 30, "otp moklo": 50,
    "otp aapo": 50, "pin aapo": 50, "tame jitya": 30,
    "ghare betha kamao": 30, "inam jityu": 35,
}

# Genuine messages માં હોય એવા શબ્દો - score ઘટાડે (false positive અટકાવવા)
SAFE_HINTS = [
    "do not share",          # banks હંમેશા આ લખે છે
    "never share",
    "is your otp",           # "1234 is your OTP" = genuine pattern
    "otp for",
    "किसी को न बताएं",
    "કોઈને ન આપો",
]

# URL shorteners - અસલી link છુપાવે છે
SHORTENERS = ["bit.ly", "tinyurl.com", "cutt.ly", "rb.gy", "t.co", "is.gd", "shorturl.at"]

# Bank names vs official domains - fake bank site પકડવા
BANK_NAMES = ["sbi", "hdfc", "icici", "axis", "paytm", "phonepe", "gpay",
              "kotak", "pnb", "bob", "canara", "union"]
OFFICIAL_DOMAINS = ["sbi.co.in", "onlinesbi.sbi", "hdfcbank.com", "icicibank.com",
                    "axisbank.com", "paytm.com", "phonepe.com", "kotak.com",
                    "pnbindia.in", "bankofbaroda.in", "canarabank.com", "unionbankofindia.co.in"]

URL_PATTERN = re.compile(r"https?://[\w\-.]+[\w\-./?=&%]*", re.IGNORECASE)


def analyze_message(text: str) -> dict:
    """
    Message નું risk analysis કરે છે.
    Return: {"score": 0-100, "verdict": ..., "reasons": [...], "advice": ...}
    """
    lower = text.lower()
    score = 0
    reasons = []

    # Step 1: ત્રણેય ભાષાના fraud keywords શોધો
    for keyword, weight in FRAUD_KEYWORDS.items():
        if keyword in lower:
            score += weight
            reasons.append(f'શંકાસ્પદ શબ્દ મળ્યો: "{keyword}"')

    # Step 2: Links check કરો
    for url in URL_PATTERN.findall(text):
        score += 10
        reasons.append(f"Link મળી: {url}")

        if any(s in url.lower() for s in SHORTENERS):
            score += 25
            reasons.append("ટૂંકી કરેલી link (અસલી સરનામું છુપાયેલું છે)")

        url_low = url.lower()
        has_bank = any(b in url_low for b in BANK_NAMES)
        is_official = any(d in url_low for d in OFFICIAL_DOMAINS)
        if has_bank and not is_official:
            score += 40
            reasons.append("⚠️ નકલી bank website હોઈ શકે છે!")

    # Step 3: Safe hints - genuine OTP messages નો score ઘટાડો
    for hint in SAFE_HINTS:
        if hint in lower:
            score -= 25
            reasons.append(f'સુરક્ષિત સંકેત: "{hint}" (બેંકના અસલી message માં હોય છે)')

    score = max(0, min(score, 100))  # 0-100 ની વચ્ચે રાખો

    # Step 4: Verdict + સલાહ
    if score >= 60:
        verdict = "DANGEROUS"
        advice = "🚫 આ message FRAUD લાગે છે! કોઈ link ન ખોલો, OTP/PIN ન આપો, જવાબ ન આપો. 1930 પર report કરો."
    elif score >= 30:
        verdict = "SUSPICIOUS"
        advice = "⚠️ સાવધાન! આ message શંકાસ્પદ છે. કોઈ પગલું લેતા પહેલા સત્તાવાર નંબર/website પર જાતે ખાતરી કરો."
    else:
        verdict = "SAFE"
        advice = "✅ આ message માં કોઈ જાણીતો fraud pattern નથી મળ્યો. છતાં OTP/PIN ક્યારેય કોઈને ન આપો."

    return {
        "score": score,
        "verdict": verdict,
        "reasons": reasons if reasons else ["કોઈ શંકાસ્પદ pattern મળ્યો નથી"],
        "advice": advice,
    }
