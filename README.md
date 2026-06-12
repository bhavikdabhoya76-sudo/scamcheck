# 🛡️ ScamCheck — Fraud Message Checker (MVP)

ગુજરાતી + હિન્દી + English માં scam SMS/WhatsApp messages detect કરે છે.

## ચલાવવાની રીત (3 steps)

1. Python 3.10+ install હોવું જોઈએ
2. Terminal માં આ ચલાવો:
   ```
   pip install fastapi uvicorn
   ```
3. Project folder માં જઈને server ચાલુ કરો:
   ```
   uvicorn app.main:app --reload
   ```
4. Browser માં ખોલો: http://localhost:8000

## Tests ચલાવવા
```
cd tests
python test_analyzer.py
```
(14 test cases — ત્રણેય ભાષાના scam + genuine messages)

## File Structure
```
scamcheck/
├── app/
│   ├── main.py                    # FastAPI server (API routes)
│   └── analyzers/
│       └── sms_analyzer.py        # ⭐ Fraud detection engine
├── static/
│   └── index.html                 # Web page (text box + Check button)
├── tests/
│   └── test_analyzer.py           # Automated tests
└── README.md
```

## નવો fraud pattern ઉમેરવો હોય તો?
`app/analyzers/sms_analyzer.py` ખોલો → `FRAUD_KEYWORDS` dictionary માં
નવી line ઉમેરો, જેમ કે:
```python
"નવો scam શબ્દ": 30,    # 30 = risk weight
```
પછી tests ચલાવી confirm કરો.

## API વાપરવાની રીત (B2B માટે)
```
POST /api/check
Body: {"text": "Your KYC expired..."}
Response: {"score": 80, "verdict": "DANGEROUS", "reasons": [...], "advice": "..."}
```

## આગળના steps (roadmap મુજબ)
- [ ] Google Safe Browsing API થી URL deep-check
- [ ] UPI ID verification
- [ ] scikit-learn ML model (Kaggle SMS Spam dataset થી)
- [ ] Railway.app / Render.com પર deploy
- [ ] WhatsApp bot

## 🌐 Online Deploy કરવું (Render.com - Free)
1. github.com પર code upload કરો
2. render.com પર "New Web Service" → GitHub repo connect કરો
3. Build Command:  pip install -r requirements.txt
4. Start Command:  uvicorn app.main:app --host 0.0.0.0 --port $PORT
5. Free plan પસંદ કરો → Deploy!
