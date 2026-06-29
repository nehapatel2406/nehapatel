# 🛡️ PhishGuard — Phishing Email Detector

> A cybersecurity web application that analyzes email content to detect phishing attempts using multi-signal heuristic analysis.

**Built as part of a Cybersecurity Summer Internship Project 2025**

---

## 📸 Features

- **15+ Detection Signals** — Checks for suspicious URLs, urgency language, credential harvesting, domain spoofing, typosquatting, brand impersonation, and more
- **Risk Score (0–100)** — Visual score with animated circular progress indicator
- **Detailed Breakdown** — Each detection check is explained with severity level (HIGH / MEDIUM / LOW / SAFE)
- **Actionable Recommendations** — Tailored advice based on the specific threats detected
- **Dual Engine** — Flask backend for server-side analysis with a full client-side JS fallback (works offline too)
- **Sample Emails** — Built-in phishing and legitimate email samples for demonstration
- **Dark Cybersecurity UI** — Professional terminal-inspired interface

---

## 🗂️ Project Structure

```
phishing-detector/
├── server.py               # Flask backend with phishing detection API
├── requirements.txt        # Python dependencies
├── templates/
│   ├── index.html          # Landing page
│   └── analyzer.html       # Email analyzer tool
└── static/
    ├── css/
    │   └── style.css       # Full stylesheet (dark theme)
    └── js/
        └── app.js          # Frontend detection engine + UI controller
```

---

## 🚀 Getting Started

### Prerequisites
- Python 3.8+
- pip

### Installation

```bash
# 1. Clone the repository
git clone https://github.com/YOUR_USERNAME/phishing-detector.git
cd phishing-detector

# 2. Install Python dependencies
pip install -r requirements.txt

# 3. Run the Flask server
python server.py
```

### Access the App

Open your browser and navigate to:
```
http://localhost:5000
```

---

## 🔍 How It Works

### Detection Signals

| Signal | Severity | Description |
|---|---|---|
| IP Address in URL | 🔴 HIGH | URLs using raw IPs instead of domain names |
| URL Shortener | 🔴 HIGH | Bit.ly, TinyURL, etc. used to hide destinations |
| Suspicious TLD | 🔴 HIGH | Free/abused TLDs (.tk, .ml, .xyz, etc.) |
| Domain Mismatch | 🔴 HIGH | Display name vs. sender domain conflict |
| Typosquatting | 🔴 HIGH | Lookalike domains (paypa1.com, amaz0n.com) |
| Credential Request | 🔴 HIGH | Asks for passwords, SSN, CVV, bank details |
| OTP Request | 🔴 HIGH | Asks for one-time passwords or auth codes |
| Urgency Language | 🟡 MEDIUM | "Act now", "24 hours", "verify immediately" |
| Threat Language | 🟡 MEDIUM | Account deletion, legal action threats |
| Brand Impersonation | 🟡 MEDIUM | Uses brand names not from official domain |
| Dangerous Attachments | 🟡 MEDIUM | References to .exe, .zip, macro files |
| Vague Link Text | 🔵 LOW | "Click here", "verify here" without context |
| Generic Greeting | 🔵 LOW | "Dear Customer" instead of real name |
| Excessive Caps | 🔵 LOW | MULTIPLE ALL-CAPS WORDS in subject/body |

### Scoring

```
Risk Score = min(100, (raw_points / max_possible) × 100 × 1.4)

≥ 60  →  ⚠ Likely Phishing   (RED)
30–59 →  ⚡ Suspicious Email  (YELLOW)
< 30  →  ✓ Appears Legitimate (GREEN)
```

### API

The backend exposes a REST API:

```
POST /api/analyze
Content-Type: application/json

{
  "sender":  "support@paypa1.com",
  "name":    "PayPal Security Team",
  "subject": "URGENT: Your account is suspended",
  "body":    "Dear Customer, click here to verify..."
}
```

**Response:**
```json
{
  "riskScore": 87,
  "verdict": "⚠ Likely Phishing",
  "verdictClass": "danger",
  "verdictIcon": "🚨",
  "verdictSub": "High probability this is a phishing attempt...",
  "indicators": [...],
  "cleanSample": [...],
  "recommendations": [...],
  "engine": "server"
}
```

```
GET /api/health  →  { "status": "ok", "engine": "PhishGuard v1.0" }
```

---

## 🛠️ Tech Stack

| Layer | Technology |
|---|---|
| Frontend | HTML5, CSS3, Vanilla JavaScript |
| Backend | Python 3, Flask |
| Analysis | Regex-based heuristics + rule engine |
| Fonts | Inter (UI), Share Tech Mono (terminal) |

---

## 📚 What I Learned

- Common phishing attack patterns and social engineering tactics
- Building a multi-signal rule-based detection system
- RESTful API design with Flask
- Full-stack web development with Python backend + JS frontend
- Cybersecurity awareness and email security best practices

---

## ⚠️ Disclaimer

PhishGuard is an educational tool built for a cybersecurity internship. It uses heuristic pattern matching and is **not a replacement** for professional email security solutions. No email data is stored or transmitted externally.

---

## 📄 License

MIT License — Free to use and modify for educational purposes.

---

*Built with ❤️ for Cybersecurity Awareness*
