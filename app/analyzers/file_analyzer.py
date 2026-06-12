# file_analyzer.py
# APK / PDF / Word / Excel files નું heuristic scanning
# નોંધ: આ જાણીતા જોખમી patterns શોધે છે - સંપૂર્ણ antivirus નથી.
# Files memory માં જ scan થાય છે, ક્યાંય save થતી નથી.

import io
import re
import zipfile

from app.analyzers.sms_analyzer import analyze_message

MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB

# APK માં ખતરનાક permissions (ભારતના banking trojans માં સામાન્ય)
DANGEROUS_PERMISSIONS = {
    "READ_SMS": (30, "SMS વાંચી શકે છે (OTP ચોરીનું જોખમ)"),
    "RECEIVE_SMS": (30, "આવતા SMS intercept કરી શકે છે"),
    "SEND_SMS": (25, "તમારા નામે SMS મોકલી શકે છે"),
    "READ_CALL_LOG": (20, "Call history વાંચી શકે છે"),
    "BIND_ACCESSIBILITY_SERVICE": (40, "આખી screen control કરી શકે છે (trojan નું મુખ્ય હથિયાર)"),
    "SYSTEM_ALERT_WINDOW": (25, "બીજી apps ઉપર નકલી screen બતાવી શકે છે"),
    "BIND_DEVICE_ADMIN": (35, "Device admin બની delete થતા અટકી શકે છે"),
    "REQUEST_INSTALL_PACKAGES": (30, "બીજી apps install કરી શકે છે"),
    "READ_CONTACTS": (15, "બધા contacts વાંચી શકે છે"),
    "RECORD_AUDIO": (20, "Microphone થી recording કરી શકે છે"),
}

# PDF માં જોખમી વસ્તુઓ
PDF_RISKY_MARKERS = {
    b"/JavaScript": (35, "PDF માં છુપાયેલો JavaScript code છે"),
    b"/JS": (20, "PDF માં script હોવાના સંકેત"),
    b"/OpenAction": (25, "ખોલતા જ આપોઆપ કંઈક ચાલે એવું setting છે"),
    b"/Launch": (40, "PDF બીજો program ચલાવવાનો પ્રયત્ન કરે છે"),
    b"/EmbeddedFile": (25, "PDF ની અંદર બીજી file છુપાયેલી છે"),
}

URL_BYTES_PATTERN = re.compile(rb"https?://[\w\-.]+[\w\-./?=&%]*")


def _verdict_package(score: int, reasons: list, file_type: str) -> dict:
    score = max(0, min(score, 100))
    if score >= 60:
        verdict = "DANGEROUS"
        advice = f"🚫 આ {file_type} ખતરનાક લાગે છે! Install/ખોલશો નહીં, મોકલનારને block કરો, file delete કરી દો."
    elif score >= 30:
        verdict = "SUSPICIOUS"
        advice = f"⚠️ આ {file_type} શંકાસ્પદ છે. અજાણ્યા source માંથી આવી હોય તો ખોલશો નહીં."
    else:
        verdict = "SAFE"
        advice = f"✅ આ {file_type} માં કોઈ જાણીતો જોખમી pattern નથી મળ્યો. છતાં અજાણ્યા sources ની files થી સાવધ રહો."
    if not reasons:
        reasons = ["કોઈ શંકાસ્પદ pattern મળ્યો નથી"]
    return {"score": score, "verdict": verdict, "reasons": reasons,
            "advice": advice, "file_type": file_type}


def _scan_urls_in_bytes(data: bytes) -> tuple[int, list]:
    """File ની અંદર છુપાયેલી links કાઢીને આપણા text engine થી check કરો"""
    urls = [u.decode("utf-8", "ignore") for u in URL_BYTES_PATTERN.findall(data)][:20]
    if not urls:
        return 0, []
    result = analyze_message(" ".join(urls))
    # Link-related કારણો જ લો
    reasons = [r for r in result["reasons"] if "ink" in r or "bank" in r or "ટૂંકી" in r]
    return result["score"], reasons


def scan_apk(data: bytes) -> dict:
    score = 0
    reasons = []
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
        names = zf.namelist()
    except Exception:
        return _verdict_package(70, ["File APK જેવી દેખાય છે પણ અંદરથી તૂટેલી/નકલી છે"], "APK")

    if "classes.dex" not in names and not any(n.startswith("classes") and n.endswith(".dex") for n in names):
        score += 30
        reasons.append("APK માં code (classes.dex) જ નથી - નકલી હોઈ શકે")

    # Digital signature છે? (દરેક ખરી APK signed હોય)
    signed = any(n.startswith("META-INF/") and n.endswith((".RSA", ".DSA", ".EC")) for n in names)
    v2_possible = True  # નવી APKs માં signature block zip બહાર હોય છે
    if not signed and not v2_possible:
        score += 20
        reasons.append("APK પર digital signature નથી")

    # AndroidManifest માં ખતરનાક permissions શોધો
    # (Manifest binary format માં હોય છે, એમાં permission નામો UTF-16 માં મળે છે)
    try:
        manifest = zf.read("AndroidManifest.xml")
        found = []
        for perm, (weight, desc) in DANGEROUS_PERMISSIONS.items():
            if perm.encode("utf-16-le") in manifest or perm.encode() in manifest:
                found.append((perm, weight, desc))
        # 1 permission સામાન્ય હોઈ શકે; 2+ નો સંગમ ખતરનાક
        if len(found) >= 2:
            for perm, weight, desc in found:
                score += weight
                reasons.append(f"Permission {perm}: {desc}")
        elif len(found) == 1:
            perm, weight, desc = found[0]
            score += weight // 2
            reasons.append(f"Permission {perm}: {desc}")
    except KeyError:
        score += 25
        reasons.append("APK માં AndroidManifest.xml જ નથી - અસામાન્ય")

    return _verdict_package(score, reasons, "APK")


def scan_pdf(data: bytes) -> dict:
    score = 0
    reasons = []
    if not data.startswith(b"%PDF"):
        return _verdict_package(60, ["File PDF કહેવાય છે પણ ખરેખર PDF નથી"], "PDF")

    for marker, (weight, desc) in PDF_RISKY_MARKERS.items():
        if marker in data:
            score += weight
            reasons.append(desc)

    url_score, url_reasons = _scan_urls_in_bytes(data)
    score += url_score
    reasons.extend(url_reasons)

    return _verdict_package(score, reasons, "PDF")


def scan_office(data: bytes, ext: str) -> dict:
    """Word/Excel/PowerPoint (docx/xlsx/pptx બધા અંદરથી zip હોય છે)"""
    score = 0
    reasons = []
    label = {"docx": "Word document", "docm": "Word document", "xlsx": "Excel file",
             "xlsm": "Excel file", "pptx": "PowerPoint"}.get(ext, "Document")
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
        names = zf.namelist()
    except Exception:
        return _verdict_package(55, [f"File {label} જેવી દેખાય છે પણ અંદરથી તૂટેલી/નકલી છે"], label)

    # Macros = વાયરસ ફેલાવવાનો જૂનો જાણીતો રસ્તો
    if any("vbaProject.bin" in n for n in names):
        score += 45
        reasons.append("અંદર Macro (આપોઆપ ચાલતો code) છે - અજાણી file માં આ મોટું જોખમ છે")

    # અંદરની links check કરો
    all_bytes = b""
    for n in names[:30]:
        if n.endswith((".xml", ".rels")):
            try:
                all_bytes += zf.read(n)
            except Exception:
                pass
    url_score, url_reasons = _scan_urls_in_bytes(all_bytes)
    score += url_score
    reasons.extend(url_reasons)

    return _verdict_package(score, reasons, label)


def scan_file(filename: str, data: bytes) -> dict:
    """મુખ્ય entry point - file type ઓળખીને યોગ્ય scanner પાસે મોકલે"""
    if len(data) > MAX_FILE_SIZE:
        return {"score": 0, "verdict": "ERROR",
                "reasons": ["File 10 MB થી મોટી છે"], 
                "advice": "કૃપા કરીને 10 MB થી નાની file આપો.", "file_type": "Unknown"}
    if len(data) == 0:
        return {"score": 0, "verdict": "ERROR",
                "reasons": ["File ખાલી છે"], "advice": "કૃપા કરીને file ફરી select કરો.", "file_type": "Unknown"}

    ext = (filename.rsplit(".", 1)[-1] if "." in filename else "").lower()

    if ext == "apk":
        return scan_apk(data)
    if ext == "pdf":
        return scan_pdf(data)
    if ext in ("docx", "docm", "xlsx", "xlsm", "pptx"):
        return scan_office(data, ext)

    return {"score": 0, "verdict": "ERROR",
            "reasons": [f".{ext} type હજુ support નથી"],
            "advice": "અત્યારે APK, PDF, Word (docx), Excel (xlsx), PowerPoint (pptx) scan થઈ શકે છે.",
            "file_type": ext.upper() or "Unknown"}
