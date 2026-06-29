"""
PhishGuard — Flask Backend Server
===================================
Provides the /api/analyze endpoint for phishing email detection.
Also serves the HTML templates and static assets.

Run: python server.py
"""

import re
import math
from flask import Flask, request, jsonify, send_from_directory, render_template
from flask_cors import CORS

app = Flask(
    __name__,
    template_folder="templates",
    static_folder="static"
)
CORS(app)

# ─── DETECTION SIGNALS ─────────────────────────────────────────────

SIGNALS = [
    {
        "id": "url_ip",
        "name": "IP Address in URL",
        "severity": "high",
        "pattern": re.compile(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", re.I),
        "fields": ["body"],
        "detail": "URLs with raw IP addresses instead of domain names are a strong phishing indicator.",
        "points": 20
    },
    {
        "id": "url_shortener",
        "name": "URL Shortener Detected",
        "severity": "high",
        "pattern": re.compile(r"(bit\.ly|tinyurl|ow\.ly|t\.co|goo\.gl|rb\.gy|short\.link|tiny\.cc|is\.gd)", re.I),
        "fields": ["body"],
        "detail": "Shortened URLs hide the true destination and are commonly used to mask phishing links.",
        "points": 18
    },
    {
        "id": "suspicious_tld",
        "name": "Suspicious Domain Extension",
        "severity": "high",
        "pattern": re.compile(r"https?://[^\s]*\.(tk|ml|ga|cf|gq|xyz|pw|top|click|zip|mov)\b", re.I),
        "fields": ["body", "sender"],
        "detail": "Free or obscure TLDs like .tk, .ml, .xyz are frequently abused in phishing campaigns.",
        "points": 16
    },
    {
        "id": "urgency",
        "name": "Urgency / Pressure Language",
        "severity": "medium",
        "pattern": re.compile(
            r"(urgent|immediately|act now|limited time|expires|within \d+ hours?|24 hours?|"
            r"suspended|verify now|respond now|don.t delay|final notice|last chance)", re.I
        ),
        "fields": ["subject", "body"],
        "detail": "Phishing emails often create a false sense of urgency to pressure recipients.",
        "points": 12
    },
    {
        "id": "threat_language",
        "name": "Threat / Fear Language",
        "severity": "medium",
        "pattern": re.compile(
            r"(account.*deleted|permanent.*ban|legal action|report.*authorit|arrested|"
            r"terminated|suspended permanently|disabled|close.*account)", re.I
        ),
        "fields": ["body"],
        "detail": "Threatening consequences like account deletion or legal action is a manipulation tactic.",
        "points": 10
    },
    {
        "id": "reward_language",
        "name": "Reward / Prize Language",
        "severity": "medium",
        "pattern": re.compile(
            r"(you have won|congratulations.*winner|claim your prize|free gift|"
            r"selected.*lucky|lottery|reward.*awaits)", re.I
        ),
        "fields": ["subject", "body"],
        "detail": "Fake reward offers are used to lure victims into clicking malicious links.",
        "points": 10
    },
    {
        "id": "credential_request",
        "name": "Requests Credentials / Sensitive Info",
        "severity": "high",
        "pattern": re.compile(
            r"(password|ssn|social security|credit card|cvv|pin number|"
            r"bank account|routing number|mother.?s maiden)", re.I
        ),
        "fields": ["body"],
        "detail": "Legitimate organizations never ask for passwords or full financial details via email.",
        "points": 25
    },
    {
        "id": "otp_request",
        "name": "Requests OTP / Verification Code",
        "severity": "high",
        "pattern": re.compile(
            r"(one.time.password|otp|verification code|confirm.?code|enter.*code|share.*code)", re.I
        ),
        "fields": ["body"],
        "detail": "Requests for authentication codes are used in account takeover attacks.",
        "points": 18
    },
    {
        "id": "generic_greeting",
        "name": "Generic / Impersonal Greeting",
        "severity": "low",
        "pattern": re.compile(
            r"dear (customer|user|valued (member|customer|client)|account holder|sir.?madam)", re.I
        ),
        "fields": ["body"],
        "detail": "Legitimate companies typically address you by name, not generic titles.",
        "points": 6
    },
    {
        "id": "dangerous_attachment",
        "name": "Dangerous Attachment Reference",
        "severity": "medium",
        "pattern": re.compile(
            r"\.(exe|zip|rar|js|bat|cmd|vbs|ps1|docm?x?|xlsm?x?|pdf).*attach|"
            r"attach.*\.(exe|zip|rar|js|bat|cmd|vbs|ps1)", re.I
        ),
        "fields": ["body"],
        "detail": "References to executable or macro-enabled attachments indicate potential malware delivery.",
        "points": 15
    },
    {
        "id": "click_here",
        "name": "Vague Link Text",
        "severity": "low",
        "pattern": re.compile(r"(click here|verify here|login here|click this link|click below)", re.I),
        "fields": ["body"],
        "detail": "Vague link text like 'click here' often hides the real destination URL.",
        "points": 8
    },
    {
        "id": "excessive_caps",
        "name": "Excessive Capital Letters",
        "severity": "low",
        "custom": True,
        "detail": "Multiple all-caps words are used as attention-grabbing tactics.",
        "points": 5
    },
    {
        "id": "typosquat",
        "name": "Lookalike Domain (Typosquatting)",
        "severity": "high",
        "pattern": re.compile(
            r"(paypa[l1]|pay-pal|paypall|amaz0n|amaz[o0]n-|g[o0]{2}gle|"
            r"micros[o0]ft|mlcrosoft|app[l1]e-|netfl[i1]x)", re.I
        ),
        "fields": ["body", "sender", "subject"],
        "detail": "Detected a domain that mimics a legitimate brand by substituting characters.",
        "points": 20
    },
    {
        "id": "brand_impersonation",
        "name": "Brand Name Impersonation",
        "severity": "medium",
        "custom": True,
        "detail": "The email references a well-known brand but was not sent from that brand's domain.",
        "points": 14
    },
    {
        "id": "domain_mismatch",
        "name": "Sender Domain Mismatch",
        "severity": "high",
        "custom": True,
        "detail": "Display name references a known brand but the sender's domain does not match.",
        "points": 22
    },
]

KNOWN_BRANDS = ["paypal", "amazon", "google", "apple", "microsoft", "netflix",
                "bank", "chase", "wells", "citi", "ebay", "irs", "fedex", "ups"]

MAX_SCORE = sum(s["points"] for s in SIGNALS)


def check_excessive_caps(text):
    words = re.findall(r"\b[A-Z]{3,}\b", text)
    return len(words) >= 4


def check_brand_impersonation(data):
    text = data.get("body", "") + " " + data.get("subject", "")
    brand_re = re.compile(
        r"(paypal|amazon|apple|google|microsoft|netflix|irs|fbi|fedex|ups|dhl"
        r"|bank of america|chase|wells fargo)", re.I
    )
    sender_domain = (data.get("sender", "").split("@")[-1] or "").lower()
    has_brand_in_text = bool(brand_re.search(text))
    has_brand_in_sender = any(b in sender_domain for b in KNOWN_BRANDS)
    return has_brand_in_text and not has_brand_in_sender


def check_domain_mismatch(data):
    sender_name = data.get("name", "").lower()
    subject = data.get("subject", "").lower()
    sender = data.get("sender", "")
    sender_domain = sender.split("@")[-1].lower() if "@" in sender else ""

    has_brand_in_display = any(b in sender_name or b in subject for b in KNOWN_BRANDS)
    has_brand_in_domain = any(b in sender_domain.split(".")[0] for b in KNOWN_BRANDS)
    return has_brand_in_display and not has_brand_in_domain


def analyze(data: dict) -> dict:
    triggered = []
    clean = []
    raw_points = 0

    full_text = " ".join([
        data.get("sender", ""),
        data.get("name", ""),
        data.get("subject", ""),
        data.get("body", "")
    ])

    for signal in SIGNALS:
        fired = False

        if signal.get("custom"):
            sid = signal["id"]
            if sid == "excessive_caps":
                fired = check_excessive_caps(full_text)
            elif sid == "brand_impersonation":
                fired = check_brand_impersonation(data)
            elif sid == "domain_mismatch":
                fired = check_domain_mismatch(data)
        else:
            fields_text = " ".join(data.get(f, "") for f in signal.get("fields", []))
            fired = bool(signal["pattern"].search(fields_text))

        if fired:
            raw_points += signal["points"]
            triggered.append({
                "name": signal["name"],
                "severity": signal["severity"],
                "detail": signal["detail"],
                "flagged": True
            })
        else:
            clean.append({
                "name": signal["name"],
                "severity": "safe",
                "detail": "No issues detected for this check.",
                "flagged": False
            })

    risk_score = min(100, round((raw_points / MAX_SCORE) * 100 * 1.4))

    if risk_score >= 60:
        verdict = "⚠ Likely Phishing"
        verdict_class = "danger"
        verdict_icon = "🚨"
        verdict_sub = "High probability this email is a phishing attempt. Do not click any links or reply."
    elif risk_score >= 30:
        verdict = "⚡ Suspicious Email"
        verdict_class = "warning"
        verdict_icon = "⚠️"
        verdict_sub = "This email shows some suspicious signals. Verify the sender independently."
    else:
        verdict = "✓ Appears Legitimate"
        verdict_class = "success"
        verdict_icon = "✅"
        verdict_sub = "No major phishing indicators detected. Always stay vigilant."

    recommendations = build_recommendations(triggered, risk_score)

    return {
        "riskScore": risk_score,
        "verdict": verdict,
        "verdictClass": verdict_class,
        "verdictIcon": verdict_icon,
        "verdictSub": verdict_sub,
        "indicators": triggered,
        "cleanSample": clean[:3],
        "recommendations": recommendations,
        "engine": "server"
    }


def build_recommendations(triggered, score):
    recs = []
    ids = [t["name"] for t in triggered]

    if score >= 60:
        recs.append("Do not click any links or download attachments from this email.")
        recs.append("Report this email as phishing to your email provider.")
        recs.append("If you've already clicked a link, change your passwords immediately and enable 2FA.")

    cred_signals = ["Requests Credentials / Sensitive Info", "Requests OTP / Verification Code"]
    if any(s in ids for s in cred_signals):
        recs.append("Never share passwords, OTPs, or financial details via email.")

    url_signals = ["URL Shortener Detected", "Suspicious Domain Extension", "IP Address in URL"]
    if any(s in ids for s in url_signals):
        recs.append("Hover over links to check the full URL, or use VirusTotal to scan suspicious links.")

    brand_signals = ["Sender Domain Mismatch", "Lookalike Domain (Typosquatting)", "Brand Name Impersonation"]
    if any(s in ids for s in brand_signals):
        recs.append("Contact the company directly via their official website — not through links in this email.")

    if "Urgency / Pressure Language" in ids or "Threat / Fear Language" in ids:
        recs.append("Urgency and threats are manipulation tactics. Always pause and verify before acting.")

    if score < 30:
        recs.append("This email appears legitimate, but verify any unexpected requests directly with the sender.")
        recs.append("Keep your email security software updated for ongoing protection.")

    return list(dict.fromkeys(recs))  # deduplicate while preserving order


# ─── ROUTES ─────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/analyzer")
def analyzer():
    return render_template("analyzer.html")


@app.route("/api/analyze", methods=["POST"])
def api_analyze():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Invalid JSON body"}), 400

    allowed_fields = {"sender", "name", "subject", "body"}
    clean_data = {k: str(v)[:10000] for k, v in data.items() if k in allowed_fields}

    result = analyze(clean_data)
    return jsonify(result)


@app.route("/api/health")
def health():
    return jsonify({"status": "ok", "engine": "PhishGuard v1.0"})


@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Not found"}), 404


@app.errorhandler(500)
def server_error(e):
    return jsonify({"error": "Internal server error"}), 500


# ─── ENTRY POINT ────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 50)
    print("  PhishGuard — Phishing Detection Server")
    print("  Running at: http://localhost:5000")
    print("=" * 50)
    app.run(debug=True, host="0.0.0.0", port=5000)
