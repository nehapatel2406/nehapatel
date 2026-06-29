/**
 * PhishGuard — Frontend Detection Engine & UI Controller
 * ========================================================
 * Performs client-side phishing analysis and communicates
 * with the Flask backend for enhanced ML-based scoring.
 */

// ─── SAMPLE DATA ────────────────────────────────────────────────

const SAMPLES = {
  phishing: {
    sender: "security-alerts@paypa1-verify.com",
    name: "PayPal Security Team",
    subject: "URGENT: Your account has been suspended! Verify NOW",
    body: `Dear Valued Customer,

We have detected unusual activity on your PayPal account. Your account has been TEMPORARILY SUSPENDED due to security concerns.

To restore access immediately, click the link below and verify your information:

http://paypal-secure-verify.tk/login?ref=security&token=abc123

You must act within 24 HOURS or your account will be permanently deleted.

Please provide the following to verify:
- Your password
- Credit card number and CVV
- Social Security Number (last 4 digits)

If you don't verify your account, we will be forced to close it permanently and report any suspicious activity to the authorities.

Click here to verify now: http://bit.ly/paypal-urgent-verify

Thank you for your cooperation.

PayPal Security Department`
  },
  legit: {
    sender: "newsletter@github.com",
    name: "GitHub",
    subject: "Your GitHub Digest for this week",
    body: `Hi there,

Here's a summary of what's been happening on GitHub this week.

🔔 Trending Repositories:
- microsoft/vscode — Visual Studio Code
- facebook/react — A declarative UI library
- torvalds/linux — Linux kernel source tree

👀 Repositories you might like based on your activity:
- python/cpython
- django/django

You're receiving this because you signed up for GitHub's weekly digest.
To unsubscribe or manage email preferences, visit: https://github.com/settings/notifications

GitHub, Inc. · 88 Colin P Kelly Jr St · San Francisco, CA 94107`
  }
};

// ─── DETECTION ENGINE ───────────────────────────────────────────

const PHISHING_SIGNALS = [
  // --- URL Checks ---
  {
    id: "url_ip",
    name: "IP Address in URL",
    severity: "high",
    check: (d) => /https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/i.test(d.body),
    detail: "URLs with raw IP addresses instead of domain names are a strong phishing indicator.",
    points: 20
  },
  {
    id: "url_shortener",
    name: "URL Shortener Detected",
    severity: "high",
    check: (d) => /(bit\.ly|tinyurl|ow\.ly|t\.co|goo\.gl|rb\.gy|short\.link|tiny\.cc|is\.gd)/i.test(d.body),
    detail: "Shortened URLs hide the true destination and are commonly used to mask phishing links.",
    points: 18
  },
  {
    id: "suspicious_tld",
    name: "Suspicious Domain Extension",
    severity: "high",
    check: (d) => /https?:\/\/[^\s]*\.(tk|ml|ga|cf|gq|xyz|pw|top|click|zip|mov)/i.test(d.body + d.sender),
    detail: "Free or obscure TLDs like .tk, .ml, .xyz are frequently abused in phishing campaigns.",
    points: 16
  },
  {
    id: "domain_mismatch",
    name: "Sender Domain Mismatch",
    severity: "high",
    check: (d) => {
      const brands = ["paypal","amazon","google","apple","microsoft","netflix","bank","chase","wells","citi","ebay"];
      const hasBrand = (s) => brands.some(b => s.toLowerCase().includes(b));
      if (!d.sender) return false;
      const domain = d.sender.split("@")[1] || "";
      return (hasBrand(d.name || "") || hasBrand(d.subject)) && !hasBrand(domain.split(".")[0]);
    },
    detail: "The display name references a known brand but the sender's email domain does not match.",
    points: 22
  },
  {
    id: "typosquat",
    name: "Lookalike Domain (Typosquatting)",
    severity: "high",
    check: (d) => {
      const patterns = [/paypa[l1]|pay-pal|paypall/i, /amaz0n|amaz[o0]n-/i, /g[o0]{2}gle/i, /micros[o0]ft|mlcrosoft/i, /app[l1]e-/i, /netfl[i1]x/i];
      const text = d.body + d.sender + d.subject;
      return patterns.some(p => p.test(text));
    },
    detail: "Detected a domain that closely mimics a legitimate brand by substituting characters.",
    points: 20
  },

  // --- Language Checks ---
  {
    id: "urgency",
    name: "Urgency / Pressure Language",
    severity: "medium",
    check: (d) => {
      const urgency = /(urgent|immediately|act now|limited time|expires|within \d+ hours|24 hours|suspended|verify now|respond now|don't delay|final notice|last chance)/i;
      return urgency.test(d.subject + " " + d.body);
    },
    detail: "Phishing emails often create a false sense of urgency to pressure recipients into acting without thinking.",
    points: 12
  },
  {
    id: "threat_language",
    name: "Threat / Fear Language",
    severity: "medium",
    check: (d) => /(account.*deleted|permanent.*ban|legal action|report.*authorities|arrested|terminated|suspended permanently|disabled)/i.test(d.body),
    detail: "Threatening consequences like account deletion or legal action is a manipulation tactic.",
    points: 10
  },
  {
    id: "reward_language",
    name: "Reward / Prize Language",
    severity: "medium",
    check: (d) => /(you have won|congratulations.*winner|claim your prize|free gift|selected.*lucky|lottery|reward.*awaits)/i.test(d.subject + d.body),
    detail: "Fake reward offers are used to lure victims into clicking malicious links.",
    points: 10
  },

  // --- Credential Harvesting ---
  {
    id: "credential_request",
    name: "Requests Credentials / Sensitive Info",
    severity: "high",
    check: (d) => /(password|ssn|social security|credit card|cvv|pin number|bank account|routing number|mother.?s maiden)/i.test(d.body),
    detail: "Legitimate organizations never ask for passwords or full financial details via email.",
    points: 25
  },
  {
    id: "otp_request",
    name: "Requests OTP / Verification Code",
    severity: "high",
    check: (d) => /(one.time.password|otp|verification code|confirm.?code|enter.*code|share.*code)/i.test(d.body),
    detail: "Requests for authentication codes are used in account takeover attacks.",
    points: 18
  },

  // --- Content Checks ---
  {
    id: "generic_greeting",
    name: "Generic / Impersonal Greeting",
    severity: "low",
    check: (d) => /dear (customer|user|valued (member|customer|client)|account holder|sir\/madam|sir or madam)/i.test(d.body),
    detail: "Legitimate companies typically address you by name, not generic titles.",
    points: 6
  },
  {
    id: "excessive_caps",
    name: "Excessive Capital Letters",
    severity: "low",
    check: (d) => {
      const words = (d.subject + " " + d.body).match(/\b[A-Z]{3,}\b/g) || [];
      return words.length >= 4;
    },
    detail: "Multiple all-caps words in subject/body are used as attention-grabbing tactics.",
    points: 5
  },
  {
    id: "html_obfuscation",
    name: "Link Text vs URL Mismatch Signal",
    severity: "medium",
    check: (d) => /(click here|verify here|login here|click this link|click below)/i.test(d.body),
    detail: "Vague link text like 'click here' often hides the real destination URL.",
    points: 8
  },

  // --- Attachment Signals ---
  {
    id: "dangerous_attachment",
    name: "Dangerous Attachment Reference",
    severity: "medium",
    check: (d) => /\.(exe|zip|rar|js|bat|cmd|vbs|ps1|doc[mx]?|xls[mx]?|pdf)\b.*attach|attach.*\.(exe|zip|rar|js|bat|cmd|vbs|ps1)/i.test(d.body),
    detail: "References to executable or macro-enabled attachments indicate potential malware delivery.",
    points: 15
  },

  // --- Brand Impersonation ---
  {
    id: "brand_impersonation",
    name: "Brand Name Impersonation",
    severity: "medium",
    check: (d) => {
      const brands = /(paypal|amazon|apple|google|microsoft|netflix|irs|fbi|fedex|ups|dhl|bank of america|chase|wells fargo)/i;
      return brands.test(d.body + d.subject) && brands.test(d.sender) === false;
    },
    detail: "The email references a well-known brand but was not sent from that brand's verified domain.",
    points: 14
  }
];

// ─── ANALYSIS FUNCTION ──────────────────────────────────────────

function runLocalAnalysis(emailData) {
  const triggered = [];
  const clean = [];

  for (const signal of PHISHING_SIGNALS) {
    try {
      const fired = signal.check(emailData);
      if (fired) {
        triggered.push(signal);
      } else {
        clean.push(signal);
      }
    } catch(e) { /* skip */ }
  }

  const rawScore = triggered.reduce((sum, s) => sum + s.points, 0);
  const maxPossible = PHISHING_SIGNALS.reduce((sum, s) => sum + s.points, 0);
  const riskScore = Math.min(100, Math.round((rawScore / maxPossible) * 100 * 1.4));

  let verdict, verdictClass, verdictIcon, verdictSub;
  if (riskScore >= 60) {
    verdict = "⚠ Likely Phishing";
    verdictClass = "danger";
    verdictIcon = "🚨";
    verdictSub = "High probability this email is a phishing attempt. Do not click any links or reply.";
  } else if (riskScore >= 30) {
    verdict = "⚡ Suspicious Email";
    verdictClass = "warning";
    verdictIcon = "⚠️";
    verdictSub = "This email shows some suspicious signals. Proceed with caution and verify the sender independently.";
  } else {
    verdict = "✓ Appears Legitimate";
    verdictClass = "success";
    verdictIcon = "✅";
    verdictSub = "No major phishing indicators detected. Always stay vigilant — no tool is 100% accurate.";
  }

  const indicators = triggered.map(s => ({
    name: s.name,
    detail: s.detail,
    severity: s.severity,
    flagged: true
  }));

  // Add a few clean checks for transparency
  const cleanSample = clean.slice(0, 3).map(s => ({
    name: s.name,
    detail: "No issues detected for this check.",
    severity: "safe",
    flagged: false
  }));

  const recommendations = generateRecommendations(triggered, riskScore);

  return { riskScore, verdict, verdictClass, verdictIcon, verdictSub, indicators, cleanSample, recommendations };
}

function generateRecommendations(triggered, score) {
  const recs = [];
  const ids = triggered.map(t => t.id);

  if (score >= 60) {
    recs.push("Do not click any links or download any attachments from this email.");
    recs.push("Report this email as phishing to your email provider.");
    recs.push("If you've already clicked a link, change your passwords immediately and enable 2FA.");
  }
  if (ids.includes("credential_request") || ids.includes("otp_request")) {
    recs.push("Never share passwords, OTPs, or financial details via email — no legitimate company asks for this.");
  }
  if (ids.includes("url_shortener") || ids.includes("suspicious_tld")) {
    recs.push("Hover over links before clicking to check the full URL. Use a URL scanner like VirusTotal.");
  }
  if (ids.includes("domain_mismatch") || ids.includes("typosquat") || ids.includes("brand_impersonation")) {
    recs.push("Contact the company directly through their official website — not through links in this email.");
  }
  if (ids.includes("urgency") || ids.includes("threat_language")) {
    recs.push("Urgency and threats are manipulation tactics. Take time to think before acting on any email.");
  }
  if (score < 30) {
    recs.push("This email appears legitimate, but always verify unexpected requests directly with the sender.");
    recs.push("Keep your email security software updated for ongoing protection.");
  }

  return [...new Set(recs)];
}

// ─── UI CONTROLLER ──────────────────────────────────────────────

function getFormData() {
  return {
    sender: document.getElementById("senderEmail")?.value.trim() || "",
    name: document.getElementById("senderName")?.value.trim() || "",
    subject: document.getElementById("emailSubject")?.value.trim() || "",
    body: document.getElementById("emailBody")?.value.trim() || ""
  };
}

async function analyzeEmail() {
  const data = getFormData();

  if (!data.body && !data.subject && !data.sender) {
    alert("Please enter at least an email subject or body to analyze.");
    return;
  }

  showScanningState();

  const scanSteps = [
    "Checking sender domain...",
    "Scanning URLs for threats...",
    "Analyzing language patterns...",
    "Checking for credential harvesting...",
    "Detecting brand impersonation...",
    "Calculating risk score..."
  ];

  const logEl = document.getElementById("scanLog");
  const stepEl = document.getElementById("scanStep");
  let stepIdx = 0;

  const stepInterval = setInterval(() => {
    if (stepIdx < scanSteps.length) {
      if (stepEl) stepEl.textContent = scanSteps[stepIdx];
      if (logEl) {
        const line = document.createElement("div");
        line.className = "scan-log-line";
        line.textContent = "✓ " + scanSteps[stepIdx];
        logEl.appendChild(line);
      }
      stepIdx++;
    }
  }, 350);

  // Simulate analysis delay for UX, then run detection
  await sleep(2200);
  clearInterval(stepInterval);

  let result;
  try {
    // Try backend first
    const resp = await fetch("/api/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(data),
      signal: AbortSignal.timeout(5000)
    });
    if (resp.ok) {
      result = await resp.json();
    } else {
      result = runLocalAnalysis(data);
    }
  } catch {
    // Fallback to client-side analysis if backend unavailable
    result = runLocalAnalysis(data);
  }

  showResults(result);
}

function showScanningState() {
  document.getElementById("placeholderState").style.display = "none";
  document.getElementById("scanningState").style.display = "flex";
  document.getElementById("resultsState").style.display = "none";
  const logEl = document.getElementById("scanLog");
  if (logEl) logEl.innerHTML = "";
}

function showResults(result) {
  document.getElementById("scanningState").style.display = "none";
  document.getElementById("resultsState").style.display = "block";

  // Verdict banner
  const banner = document.getElementById("verdictBanner");
  banner.className = "verdict-banner " + result.verdictClass;
  document.getElementById("verdictIcon").textContent = result.verdictIcon;
  document.getElementById("verdictLabel").textContent = result.verdict;
  document.getElementById("verdictSub").textContent = result.verdictSub;

  // Animate score
  animateScore(result.riskScore, result.verdictClass);

  // Indicators
  const indList = document.getElementById("indicatorsList");
  indList.innerHTML = "";

  const allIndicators = [...result.indicators, ...(result.cleanSample || [])];
  allIndicators.forEach(ind => {
    const flagClass = ind.flagged
      ? (ind.severity === "high" ? "flag-high" : ind.severity === "medium" ? "flag-medium" : "flag-low")
      : "flag-safe";
    const badge = ind.flagged
      ? (ind.severity === "high" ? "HIGH" : ind.severity === "medium" ? "MEDIUM" : "LOW")
      : "SAFE";

    const el = document.createElement("div");
    el.className = `indicator ${flagClass}`;
    el.innerHTML = `
      <div class="ind-dot"></div>
      <div class="ind-body">
        <div class="ind-name">${escHtml(ind.name)}</div>
        <div class="ind-detail">${escHtml(ind.detail)}</div>
      </div>
      <div class="ind-badge">${badge}</div>
    `;
    indList.appendChild(el);
  });

  // Recommendations
  const recoList = document.getElementById("recoList");
  recoList.innerHTML = "";
  (result.recommendations || []).forEach(rec => {
    const el = document.createElement("div");
    el.className = "reco-item";
    el.textContent = rec;
    recoList.appendChild(el);
  });
}

function animateScore(score, verdictClass) {
  const numEl = document.getElementById("scoreNum");
  const arc = document.getElementById("scoreArc");

  const circumference = 213;
  const offset = circumference - (score / 100) * circumference;
  arc.style.strokeDashoffset = offset;

  const color = verdictClass === "danger" ? "#ff4466" : verdictClass === "warning" ? "#ffab00" : "#00e676";
  arc.style.stroke = color;

  let current = 0;
  const target = score;
  const step = Math.ceil(target / 40);
  const interval = setInterval(() => {
    current = Math.min(current + step, target);
    if (numEl) numEl.textContent = current;
    if (current >= target) clearInterval(interval);
  }, 30);
}

function resetResults() {
  document.getElementById("resultsState").style.display = "none";
  document.getElementById("placeholderState").style.display = "flex";
}

function clearForm() {
  ["senderEmail","senderName","emailSubject","emailBody"].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.value = "";
  });
  resetResults();
}

function loadSample(type) {
  const s = SAMPLES[type];
  if (!s) return;
  const set = (id, val) => { const el = document.getElementById(id); if(el) el.value = val; };
  set("senderEmail", s.sender);
  set("senderName",  s.name);
  set("emailSubject", s.subject);
  set("emailBody",   s.body);
}

// ─── UTILITIES ──────────────────────────────────────────────────

const sleep = ms => new Promise(r => setTimeout(r, ms));
const escHtml = str => String(str).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");
