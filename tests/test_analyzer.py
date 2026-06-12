# ત્રણેય ભાષાના scam + genuine messages test કરો
import sys
sys.path.insert(0, "..")
from app.analyzers.sms_analyzer import analyze_message

tests = [
    # (message, expected_verdict, ભાષા)
    ("Hi, are we meeting at 5pm today?", "SAFE", "EN-normal"),
    ("Your KYC expired. Click http://sbi-verify.xyz to update immediately", "DANGEROUS", "EN-scam"),
    ("Congratulations! You won lottery prize of Rs 25 lakh. Pay processing fee", "DANGEROUS", "EN-scam"),
    ("123456 is your OTP for SBI login. Do not share with anyone.", "SAFE", "EN-genuine-OTP"),
    ("This is CBI officer. Digital arrest warrant issued against you", "DANGEROUS", "EN-digital-arrest"),
    ("आपका खाता बंद हो जाएगा। तुरंत केवाईसी करें http://bit.ly/xyz", "DANGEROUS", "HI-scam"),
    ("बधाई हो! आपने लॉटरी में इनाम जीता है", "DANGEROUS", "HI-scam"),
    ("कल शाम 6 बजे मिलते हैं", "SAFE", "HI-normal"),
    ("Aapka khata band ho jayega, otp bhejo turant", "DANGEROUS", "HI-roman-scam"),
    ("તમારું ખાતું બંધ થઈ જશે. તાત્કાલિક કેવાયસી કરો", "DANGEROUS", "GU-scam"),
    ("તમે લોટરી માં ઇનામ જીત્યા છો!", "DANGEROUS", "GU-scam"),
    ("આજે સાંજે જમવા આવજો", "SAFE", "GU-normal"),
    ("Tame jitya cho! Inam levva otp aapo", "DANGEROUS", "GU-roman-scam"),
    ("Order shipped: https://amazon.in/track/123", "SAFE", "EN-genuine-link"),
]

passed, failed = 0, 0
for text, expected, lang in tests:
    result = analyze_message(text)
    ok = result["verdict"] == expected
    passed += ok; failed += (not ok)
    print(f"{'PASS' if ok else 'FAIL'} | {lang:18s} | score={result['score']:3d} | {result['verdict']:10s} (expected {expected})")
    if not ok:
        print(f"       reasons: {result['reasons']}")

print(f"\nResult: {passed} passed, {failed} failed")
sys.exit(0 if failed == 0 else 1)
