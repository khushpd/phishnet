import { useState, useRef, useEffect } from "react";
import axios from "axios";

const RISK = {
  HIGH: { border: "border-red-400", bg: "bg-red-50", text: "text-red-600", pill: "bg-red-100 text-red-700", dot: "#dc2626" },
  MEDIUM: { border: "border-amber-400", bg: "bg-amber-50", text: "text-amber-600", pill: "bg-amber-100 text-amber-700", dot: "#d97706" },
  LOW: { border: "border-green-400", bg: "bg-green-50", text: "text-green-600", pill: "bg-green-100 text-green-700", dot: "#16a34a" },
};

const DEMO_EMAIL_SENDER = "support@paypa1-secure.com";
const DEMO_EMAIL_BODY = `Dear Customer,

We have detected unusual activity on your PayPal account. You must verify your identity immediately or your account will be suspended within 24 hours.

Click here to confirm your account: http://sskymedia.com/YUZY

Please provide your password and bank account details to restore access as soon as possible. This is urgent and requires your immediate attention.

Act now to avoid permanent suspension.

PayPal Security Team`;

// ─── ATTACHMENT SCANNER ───────────────────────────────────────────────────────

const DANGEROUS_EXT = {
  exe: "Executable file — can run malware directly on your computer",
  bat: "Windows batch script — can execute system commands",
  cmd: "Windows command script — can execute system commands",
  ps1: "PowerShell script — commonly used in malware attacks",
  vbs: "Visual Basic script — frequently used to deliver malware",
  js: "JavaScript file — can execute malicious code",
  jar: "Java executable — can run malicious programs",
  scr: "Screensaver file — often used to disguise malware",
  msi: "Windows installer — can silently install malware",
  docm: "Macro-enabled Word document — macros can execute malicious code",
  xlsm: "Macro-enabled Excel file — macros can execute malicious code",
  pptm: "Macro-enabled PowerPoint — macros can execute malicious code",
  zip: "Compressed archive — may contain hidden malicious files",
  rar: "Compressed archive — may contain hidden malicious files",
  iso: "Disk image — can be used to bypass security scans",
  lnk: "Windows shortcut — can point to malicious executables",
  hta: "HTML application — executes scripts with system privileges",
};

const SUSPICIOUS_EXT = {
  pdf: "PDF file — can contain malicious scripts or exploit vulnerabilities",
  doc: "Word document — older format that may contain malicious macros",
  xls: "Excel spreadsheet — older format that may contain malicious macros",
  ppt: "PowerPoint — older format that may contain malicious macros",
  rtf: "Rich text file — can exploit document viewer vulnerabilities",
};

function scanAttachments(emailText) {
  const results = [];
  const text = emailText.toLowerCase();
  const regex = /\b([\w\-]+\.([a-z0-9]{2,5}))\b/gi;
  const matches = [...emailText.matchAll(regex)];
  const seen = new Set();

  for (const match of matches) {
    const filename = match[1];
    const ext = match[2].toLowerCase();
    if (seen.has(filename.toLowerCase())) continue;
    seen.add(filename.toLowerCase());
    if (["e.g", "i.e", "etc", "vs"].includes(filename.toLowerCase())) continue;

    const doubleExt = filename.match(/\.(\w+)\.(\w+)$/);
    if (doubleExt) {
      results.push({ filename, ext: doubleExt[2], risk: "HIGH", reason: `Double extension trick — looks like .${doubleExt[1]} but is actually .${doubleExt[2]}. Classic malware disguise.` });
      continue;
    }
    if (DANGEROUS_EXT[ext]) results.push({ filename, ext, risk: "HIGH", reason: DANGEROUS_EXT[ext] });
    else if (SUSPICIOUS_EXT[ext]) results.push({ filename, ext, risk: "MEDIUM", reason: SUSPICIOUS_EXT[ext] });
  }

  const attachmentKeywords = ["see attached", "please find attached", "open the attachment", "download the file", "attached document", "attached invoice"];
  const hasAttachmentRef = attachmentKeywords.some(k => text.includes(k));
  return { results, hasAttachmentRef };
}

// ─── EXPLAINABILITY ENGINE ────────────────────────────────────────────────────

function generateExplanations(result) {
  const explanations = [];

  if (result.ml_probability > 0.7) {
    explanations.push({ icon: "🤖", title: "AI model flagged this as phishing", detail: `Our machine learning model gave this a ${Math.round(result.ml_probability * 100)}% phishing probability. The writing style and structure closely matches known phishing patterns.`, severity: "high" });
  } else if (result.ml_probability > 0.4) {
    explanations.push({ icon: "🤖", title: "AI model found suspicious patterns", detail: `Our phishing detection model gave this a ${Math.round(result.ml_probability * 100)}% phishing probability — above normal for a legitimate email.`, severity: "medium" });
  }

  const tone = result.tone_analysis;
  if (tone) {
    if (tone.urgency_count >= 3) {
      explanations.push({ icon: "⏰", title: "Extreme pressure to act immediately", detail: `This email uses ${tone.urgency_count} urgency phrases. Legitimate organizations never pressure you to act within hours or threaten immediate consequences. This is a manipulation tactic designed to stop you thinking clearly.`, severity: "high" });
    } else if (tone.urgency_count >= 1) {
      explanations.push({ icon: "⏰", title: "Creates a sense of urgency", detail: "This email tries to rush you into action. Take your time — if it's genuine, the sender can wait.", severity: "medium" });
    }
    if (tone.financial_count >= 2) {
      explanations.push({ icon: "💳", title: "Requests sensitive financial information", detail: `This email asks for financial or credential information ${tone.financial_count} times. No legitimate company will ask for your password or bank details over email.`, severity: "high" });
    }
    if (tone.sentiment?.negative > 0.5) {
      explanations.push({ icon: "😨", title: "Uses fear and threats to manipulate you", detail: "The tone of this email is deliberately threatening — account suspension, legal action, or financial loss. This is designed to make you panic and act without thinking.", severity: "high" });
    }
    if (tone.authority_count >= 2) {
      explanations.push({ icon: "🎭", title: "Impersonates an authority figure", detail: `This email uses ${tone.authority_count} formal authority phrases. AI-generated phishing emails use this language to appear official while hiding malicious intent.`, severity: "medium" });
    }
  }

  const intel = result.sender_intel;
  if (intel) {
    if (intel.lookalike_match) {
      explanations.push({ icon: "🎯", title: `Domain is impersonating ${intel.lookalike_match}`, detail: `The sender's domain is only ${intel.lookalike_distance} character(s) different from ${intel.lookalike_match}. This is called typosquatting — criminals register near-identical domains to trick you.`, severity: "high" });
    }
    const ageDays = intel.domain_age_days;
    if (ageDays !== null && ageDays < 180) {
      explanations.push({ icon: "📅", title: "Sender's domain was created very recently", detail: `This domain is only ${ageDays} days old. Legitimate companies have established domains that are years old. Criminals create new domains for phishing campaigns and abandon them quickly.`, severity: "high" });
    } else if (ageDays !== null && ageDays < 730) {
      explanations.push({ icon: "📅", title: "Sender's domain is relatively new", detail: `This domain is ${ageDays} days old. Most established businesses have domains that are several years old.`, severity: "medium" });
    }
    if (!intel.spf_present && !intel.dmarc_present) {
      explanations.push({ icon: "🔓", title: "No email authentication — easy to spoof", detail: "This domain has no sender verification records. Anyone can send emails pretending to be from this domain. Legitimate companies always set this up to protect their brand.", severity: "medium" });
    }
    if (intel.is_disposable) {
      explanations.push({ icon: "🗑", title: "Sent from a throwaway email service", detail: "This email was sent from a temporary disposable email provider. These are used to send emails anonymously with no accountability. No legitimate business uses throwaway email addresses.", severity: "high" });
    }
  }

  const urlhausHit = (result.urlhaus_results ?? []).find(r => r.is_malicious);
  if (urlhausHit) {
    explanations.push({ icon: "🔴", title: "Link is in active malware database", detail: `A URL in this email is confirmed in the URLhaus real-time threat database as actively distributing malware${urlhausHit.malware ? ` (${urlhausHit.malware})` : ""}. Do not click this link.`, severity: "high" });
  }

  const hasShortUrl = (result.url_flags ?? []).some(f => f.includes("Shortened"));
  if (hasShortUrl) {
    explanations.push({ icon: "🔗", title: "Links are disguised using a URL shortener", detail: "This email hides its links using a URL shortener. This conceals the true destination. Legitimate companies always use their own branded links.", severity: "medium" });
  }

  explanations.sort((a, b) => a.severity === "high" ? -1 : 1);
  return explanations.slice(0, 5);
}

// ─── SMALL COMPONENTS ────────────────────────────────────────────────────────

function SectionLabel({ children }) { return <p className="section-label">{children}</p>; }

function Badge({ text, type = "gray" }) {
  const map = { gray: "bg-slate-100 text-slate-600", red: "bg-red-100 text-red-700", amber: "bg-amber-100 text-amber-700", green: "bg-green-100 text-green-700", blue: "bg-blue-100 text-blue-700", purple: "bg-purple-100 text-purple-700" };
  return <span className={`inline-block text-xs font-medium px-2.5 py-1 rounded-full mr-1 mb-1 ${map[type] ?? map.gray}`}>{text}</span>;
}

function PassFail({ ok, yes, no }) { return ok ? <Badge text={yes} type="green" /> : <Badge text={no} type="red" />; }
function Divider() { return <div className="border-t border-slate-100 my-4" />; }

// ─── RISK GAUGE ──────────────────────────────────────────────────────────────

function RiskGauge({ score = 0, level = "LOW", size = 130 }) {
  const r = 46, circ = 2 * Math.PI * r, fill = circ - (Math.min(score, 100) / 100) * circ;
  const col = RISK[level]?.dot ?? "#94a3b8", cx = size / 2;
  return (
    <div className="flex flex-col items-center">
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`}>
        <circle cx={cx} cy={cx} r={r} fill="none" stroke="#f1f5f9" strokeWidth="9" />
        <circle cx={cx} cy={cx} r={r} fill="none" stroke={col} strokeWidth="9" strokeDasharray={circ} strokeDashoffset={fill} strokeLinecap="round" transform={`rotate(-90 ${cx} ${cx})`} className="gauge-transition" />
        <text x={cx} y={cx - 6} textAnchor="middle" fontSize="22" fontWeight="600" fill={col}>{score}</text>
        <text x={cx} y={cx + 12} textAnchor="middle" fontSize="10" fill="#94a3b8">/100</text>
      </svg>
      <span className={`text-xs font-semibold px-3 py-1 rounded-full mt-1 ${RISK[level]?.pill ?? "bg-slate-100 text-slate-500"}`}>{level} RISK</span>
    </div>
  );
}

// ─── LIVE WAVEFORM ───────────────────────────────────────────────────────────

function LiveWaveform({ active, analyserRef }) {
  const canvasRef = useRef(null), rafRef = useRef(null);
  useEffect(() => {
    const canvas = canvasRef.current; if (!canvas) return;
    const ctx = canvas.getContext("2d");
    const draw = () => {
      rafRef.current = requestAnimationFrame(draw);
      const W = canvas.width, H = canvas.height; ctx.clearRect(0, 0, W, H);
      if (active && analyserRef.current) {
        const buf = new Uint8Array(analyserRef.current.frequencyBinCount);
        analyserRef.current.getByteTimeDomainData(buf);
        ctx.beginPath(); ctx.strokeStyle = "#3b82f6"; ctx.lineWidth = 2;
        buf.forEach((v, i) => { const x = (i / buf.length) * W, y = ((v / 128) * H) / 2; i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y); });
        ctx.lineTo(W, H / 2); ctx.stroke();
      } else {
        ctx.beginPath(); ctx.strokeStyle = "#e2e8f0"; ctx.lineWidth = 2;
        for (let x = 0; x < W; x++) { const y = H / 2 + Math.sin(x * 0.08) * 6 + Math.cos(x * 0.15) * 4; x === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y); }
        ctx.stroke();
      }
    };
    draw(); return () => cancelAnimationFrame(rafRef.current);
  }, [active, analyserRef]);
  return <canvas ref={canvasRef} width={500} height={60} className="w-full h-14 rounded-lg" />;
}

// ─── EXPLAINABILITY PANEL ────────────────────────────────────────────────────

function ExplainabilityPanel({ result }) {
  const [expanded, setExpanded] = useState(true);
  if (!result) return null;
  const explanations = generateExplanations(result);
  if (explanations.length === 0) return null;
  return (
    <div className="panel-card fade-in">
      <div className="flex items-center justify-between mb-3">
        <SectionLabel>Why is this risky?</SectionLabel>
        <button onClick={() => setExpanded(e => !e)} className="text-xs text-slate-400 hover:text-slate-600 transition-colors">{expanded ? "collapse" : "expand"}</button>
      </div>
      {expanded && (
        <div className="space-y-3">
          {explanations.map((exp, i) => (
            <div key={i} className={`rounded-lg px-3 py-3 border ${exp.severity === "high" ? "bg-red-50 border-red-200" : "bg-amber-50 border-amber-200"}`}>
              <div className="flex items-center gap-2 mb-1">
                <span className="text-base">{exp.icon}</span>
                <p className={`text-sm font-semibold ${exp.severity === "high" ? "text-red-700" : "text-amber-700"}`}>{exp.title}</p>
              </div>
              <p className={`text-xs leading-relaxed ${exp.severity === "high" ? "text-red-600" : "text-amber-600"}`}>{exp.detail}</p>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ─── ATTACHMENT SCAN CARD ────────────────────────────────────────────────────

function AttachmentScanCard({ emailText }) {
  if (!emailText) return null;
  const { results, hasAttachmentRef } = scanAttachments(emailText);
  if (results.length === 0 && !hasAttachmentRef) return null;
  return (
    <div className="panel-card fade-in">
      <div className="flex items-center gap-2 mb-3">
        <SectionLabel>Attachment scan</SectionLabel>
        <span className="text-xs bg-amber-100 text-amber-700 px-2 py-0.5 rounded-full font-medium">{results.length > 0 ? `${results.length} flagged` : "Reference detected"}</span>
      </div>
      {hasAttachmentRef && results.length === 0 && (
        <div className="bg-amber-50 border border-amber-200 rounded-lg px-3 py-2 mb-2">
          <p className="text-amber-700 text-xs">⚠ This email references an attachment but no filename was found. Be cautious before downloading any file from this sender.</p>
        </div>
      )}
      <div className="space-y-2">
        {results.map((att, i) => (
          <div key={i} className={`rounded-lg px-3 py-3 border ${att.risk === "HIGH" ? "bg-red-50 border-red-200" : "bg-amber-50 border-amber-200"}`}>
            <div className="flex items-center justify-between mb-1">
              <div className="flex items-center gap-2">
                <span className="text-sm">📎</span>
                <span className="text-xs font-mono font-semibold text-slate-700">{att.filename}</span>
              </div>
              <span className={`text-xs font-bold px-2 py-0.5 rounded-full ${att.risk === "HIGH" ? "bg-red-100 text-red-700" : "bg-amber-100 text-amber-700"}`}>.{att.ext}</span>
            </div>
            <p className={`text-xs leading-relaxed ${att.risk === "HIGH" ? "text-red-600" : "text-amber-600"}`}>{att.reason}</p>
          </div>
        ))}
      </div>
    </div>
  );
}

// ─── TONE ANALYSIS CARD ──────────────────────────────────────────────────────

function ToneAnalysisCard({ tone }) {
  if (!tone) return null;
  const { sentiment, tone_risk_score, urgency_count, authority_count, financial_count } = tone;
  const bars = [
    { label: "Negative", value: sentiment.negative, color: "bg-red-400" },
    { label: "Neutral", value: sentiment.neutral, color: "bg-slate-400" },
    { label: "Positive", value: sentiment.positive, color: "bg-green-400" },
  ];
  return (
    <div className="panel-card fade-in">
      <div className="flex items-center justify-between mb-3">
        <SectionLabel>Tone analysis</SectionLabel>
        <span className="text-xs text-slate-400">Tone risk: <span className="font-semibold text-slate-600">{tone_risk_score}/25</span></span>
      </div>
      <div className="space-y-2 mb-4">
        {bars.map((bar) => (
          <div key={bar.label} className="flex items-center gap-2">
            <span className="text-xs text-slate-500 w-14">{bar.label}</span>
            <div className="flex-1 bg-slate-100 rounded-full h-2">
              <div className={`${bar.color} h-2 rounded-full gauge-transition`} style={{ width: `${Math.round(bar.value * 100)}%` }} />
            </div>
            <span className="text-xs text-slate-400 w-8 text-right">{Math.round(bar.value * 100)}%</span>
          </div>
        ))}
      </div>
      <div className="grid grid-cols-3 gap-2">
        {[
          { label: "Urgency signals", value: urgency_count, color: urgency_count > 0 ? "text-red-600" : "text-slate-400" },
          { label: "Authority markers", value: authority_count, color: authority_count > 0 ? "text-amber-600" : "text-slate-400" },
          { label: "Financial asks", value: financial_count, color: financial_count > 0 ? "text-red-600" : "text-slate-400" },
        ].map((item) => (
          <div key={item.label} className="bg-slate-50 rounded-lg p-2 text-center">
            <p className={`text-lg font-semibold ${item.color}`}>{item.value}</p>
            <p className="text-xs text-slate-400 leading-tight">{item.label}</p>
          </div>
        ))}
      </div>
    </div>
  );
}

// ─── CONFIDENCE BREAKDOWN ────────────────────────────────────────────────────

function ConfidenceBreakdown({ result }) {
  if (!result) return null;
  const mlPct = result.ml_score ?? 0;
  const tonePct = Math.round(result.tone_analysis?.tone_risk_score ?? 0);
  const urlHit = (result.urlhaus_results ?? []).some(r => r.is_malicious);
  const domainScore = Math.min((result.sender_flags ?? []).length * 6, 30);
  const bars = [
    { label: "ML model", value: mlPct, max: 35, color: "bg-blue-400", tip: "BERT phishing classifier" },
    { label: "Tone analysis", value: tonePct, max: 25, color: "bg-purple-400", tip: "Sentiment + authority pattern" },
    { label: "Domain intel", value: domainScore, max: 30, color: "bg-amber-400", tip: "WHOIS, DNS, lookalike scoring" },
    { label: "URL threat feed", value: urlHit ? 40 : 0, max: 40, color: "bg-red-400", tip: "URLhaus live threat database" },
  ];
  return (
    <div className="panel-card fade-in">
      <SectionLabel>Score breakdown</SectionLabel>
      <div className="space-y-3 mt-1">
        {bars.map((bar) => (
          <div key={bar.label}>
            <div className="flex justify-between mb-1">
              <span className="text-xs text-slate-500">{bar.label}</span>
              <span className="text-xs text-slate-400">{bar.value} / {bar.max}</span>
            </div>
            <div className="bg-slate-100 rounded-full h-2">
              <div className={`${bar.color} h-2 rounded-full gauge-transition`} style={{ width: `${Math.round((bar.value / bar.max) * 100)}%` }} />
            </div>
            <p className="text-xs text-slate-300 mt-0.5">{bar.tip}</p>
          </div>
        ))}
      </div>
    </div>
  );
}

// ─── URLHAUS CARD ────────────────────────────────────────────────────────────

function URLhausCard({ urlhausResults }) {
  if (!urlhausResults || urlhausResults.length === 0) return null;
  return (
    <div className="panel-card fade-in">
      <div className="flex items-center gap-2 mb-3">
        <SectionLabel>Live threat intelligence</SectionLabel>
        <span className="text-xs bg-blue-100 text-blue-700 px-2 py-0.5 rounded-full font-medium">URLhaus</span>
      </div>
      <div className="space-y-3">
        {urlhausResults.map((r, i) => (
          <div key={i} className={`rounded-lg px-3 py-3 border ${r.is_malicious ? "bg-red-50 border-red-200" : "bg-green-50 border-green-200"}`}>
            <div className="flex items-center justify-between mb-1">
              <span className={`text-xs font-semibold ${r.is_malicious ? "text-red-600" : "text-green-600"}`}>{r.is_malicious ? "🔴 CONFIRMED MALICIOUS" : "✓ Not listed"}</span>
              {r.threat && <Badge text={r.threat} type="red" />}
            </div>
            <p className="text-xs font-mono text-slate-500 truncate mb-1">{r.url}</p>
            {r.malware && <p className="text-xs text-red-600">Malware family: <span className="font-semibold">{r.malware}</span></p>}
            {r.tags?.length > 0 && <div className="flex flex-wrap mt-1">{r.tags.map((tag, j) => <Badge key={j} text={tag} type="red" />)}</div>}
            {r.date_added && <p className="text-xs text-slate-400 mt-1">First seen: {r.date_added}</p>}
          </div>
        ))}
      </div>
    </div>
  );
}

// ─── SENDER INTELLIGENCE CARD ────────────────────────────────────────────────

function SenderIntelCard({ intel, senderFlags }) {
  if (!intel || Object.keys(intel).length === 0) return null;
  const ageDays = intel.domain_age_days;
  const ageFlag = intel.domain_age_flag ?? "Unable to verify";
  const ageType = ageFlag === "Unable to verify" ? "gray" : ageFlag === "Very new domain — high risk" ? "red" : ageFlag === "Relatively new domain" ? "amber" : "green";

  const rows = [
    { label: "Domain age", sublabel: "How old is the sender's website", right: <div className="flex items-center gap-2">{ageDays != null && <span className="text-xs text-slate-400">{ageDays} days</span>}<Badge text={ageFlag} type={ageType} /></div> },
    { label: "Mail server exists", sublabel: "Does the sender have a real email server set up", right: <PassFail ok={intel.mx_valid} yes="Yes — exists" no="No — suspicious" /> },
    { label: "Sender identity verified", sublabel: "Is the sender authorised to send from this domain", right: <PassFail ok={intel.spf_present} yes="Verified" no="Not verified" /> },
    { label: "Anti-spoofing protection", sublabel: "Does the domain block impersonation attempts", right: <PassFail ok={intel.dmarc_present} yes="Protected" no="Unprotected" /> },
    { label: "Throwaway email", sublabel: "Is this a temporary disposable email address", right: <PassFail ok={!intel.is_disposable} yes="Legitimate" no="Disposable — red flag" /> },
    { label: "Domain impersonation", sublabel: "Does the domain look like a known trusted brand", right: intel.lookalike_match ? <Badge text={`Spoofs ${intel.lookalike_match} — ${intel.lookalike_distance} char diff`} type="red" /> : <Badge text="No match found" type="green" /> },
  ];

  return (
    <div className="panel-card fade-in">
      <SectionLabel>Sender Intelligence</SectionLabel>
      <div className="space-y-4">
        {rows.map((row) => (
          <div key={row.label} className="flex items-start justify-between gap-3">
            <div className="flex-1 min-w-0">
              <p className="text-sm text-slate-700 font-medium">{row.label}</p>
              <p className="text-xs text-slate-400">{row.sublabel}</p>
            </div>
            <div className="flex-shrink-0 pt-0.5">{row.right}</div>
          </div>
        ))}
      </div>
      {senderFlags?.length > 0 && (<><Divider /><SectionLabel>Sender flags</SectionLabel><div className="flex flex-wrap">{senderFlags.map((f, i) => <Badge key={i} text={f} type="amber" />)}</div></>)}
    </div>
  );
}

// ─── HIGH RISK MODAL ─────────────────────────────────────────────────────────

function HighRiskModal({ title, subtitle, flags, onClose }) {
  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4">
      <div className="bg-white rounded-2xl shadow-2xl max-w-md w-full p-8 border-2 border-red-400 fade-in">
        <div className="text-center mb-6">
          <div className="text-5xl mb-3">⚠️</div>
          <h2 className="text-2xl font-bold text-red-600 mb-1">{title}</h2>
          <p className="text-slate-400 text-sm">{subtitle}</p>
        </div>
        <div className="bg-red-50 border border-red-200 rounded-xl px-4 py-3 mb-5">
          <p className="text-red-700 text-sm font-medium mb-1">Do not:</p>
          <ul className="text-red-600 text-sm list-disc list-inside space-y-1">
            <li>Click any links</li><li>Share personal or financial information</li><li>Transfer funds or reset credentials</li>
          </ul>
        </div>
        {flags.length > 0 && (<div className="mb-5"><SectionLabel>Reason flags</SectionLabel><div className="flex flex-wrap">{flags.map((f, i) => <Badge key={i} text={f} type="red" />)}</div></div>)}
        <button onClick={onClose} className="w-full bg-red-600 hover:bg-red-700 text-white py-3 rounded-xl font-semibold transition-colors">I understand — dismiss</button>
      </div>
    </div>
  );
}

// ─── EMAIL PANEL ─────────────────────────────────────────────────────────────

function EmailPanel({ simTrigger, onAnalysisComplete }) {
  const [text, setText] = useState("");
  const [sender, setSender] = useState("");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [modal, setModal] = useState(false);
  const [error, setError] = useState(null);

  useEffect(() => { if (!simTrigger) return; setText(DEMO_EMAIL_BODY); setSender(DEMO_EMAIL_SENDER); }, [simTrigger]);
  useEffect(() => { if (simTrigger && text === DEMO_EMAIL_BODY && sender === DEMO_EMAIL_SENDER) analyze(DEMO_EMAIL_BODY, DEMO_EMAIL_SENDER); }, [text, sender, simTrigger]);

  const analyze = async (t = text, s = sender) => {
    if (!t.trim() || !s.trim()) return;
    setLoading(true); setError(null); setResult(null); setModal(false);
    try {
      const res = await axios.post("http://127.0.0.1:8000/api/analyze/email", { text: t, sender: s });
      setResult(res.data);
      if (res.data.risk_level === "HIGH") setModal(true);
      onAnalysisComplete?.({ type: "email", data: res.data, timestamp: new Date() });
    } catch { setError("Backend unreachable — make sure FastAPI is running on port 8000."); }
    finally { setLoading(false); }
  };

  const level = result?.risk_level ?? "LOW", colors = RISK[level];

  return (
    <>
      {modal && result && (<HighRiskModal title="High Risk Email Detected" subtitle="This email shows strong signs of a phishing attempt" flags={[...(result.indicators ?? []), ...(result.sender_flags ?? []), ...(result.url_flags ?? [])]} onClose={() => setModal(false)} />)}
      <div className="flex flex-col gap-4">
        <div className="panel-card">
          <SectionLabel>Email Shield</SectionLabel>
          <div className="space-y-3">
            <div><label className="block text-xs text-slate-400 mb-1">Sender email</label><input type="text" placeholder="sender@domain.com" value={sender} onChange={(e) => setSender(e.target.value)} className="w-full px-3 py-2 border border-slate-200 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-blue-500" /></div>
            <div><label className="block text-xs text-slate-400 mb-1">Email body</label><textarea rows={7} placeholder="Paste email content here..." value={text} onChange={(e) => setText(e.target.value)} className="w-full px-3 py-2 border border-slate-200 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 resize-none" /></div>
            <button onClick={() => analyze()} disabled={loading || !text.trim() || !sender.trim()} className="w-full bg-blue-600 hover:bg-blue-700 disabled:bg-slate-200 disabled:text-slate-400 text-white py-2.5 rounded-lg text-sm font-semibold transition-colors">{loading ? "Analyzing..." : "Analyze Email"}</button>
            {error && <p className="text-xs text-red-500 text-center">{error}</p>}
          </div>
        </div>

        {text && !loading && <AttachmentScanCard emailText={text} />}

        {loading && (<div className="panel-card flex flex-col items-center justify-center py-10 fade-in"><div className="w-8 h-8 border-4 border-blue-500 border-t-transparent rounded-full spin mb-3" /><p className="text-sm text-slate-400">Running analysis...</p><p className="text-xs text-slate-300 mt-1">Checking URLhaus threat database...</p></div>)}

        {!result && !loading && (<div className="panel-card flex flex-col items-center justify-center py-10 text-center"><span className="text-3xl mb-3">🔍</span><p className="text-sm font-medium text-slate-500">No analysis yet</p><p className="text-xs text-slate-400 mt-1">Paste an email and click Analyze</p></div>)}

        {result && !loading && (
          <>
            <div className={`panel-card border-2 ${colors.border} fade-in`}>
              <div className="flex items-center justify-between mb-4"><SectionLabel>Threat assessment</SectionLabel><span className={`text-xs font-semibold px-2.5 py-1 rounded-full ${colors.pill}`}>{level}</span></div>
              <RiskGauge score={result.risk_score} level={level} />
              <div className="flex justify-between text-xs text-slate-400 mt-3 px-1"><span>ML confidence: {(result.ml_probability * 100).toFixed(1)}%</span><span>Raw: {result.raw_score}</span></div>
              {level === "MEDIUM" && <div className="mt-4 bg-amber-50 border border-amber-200 rounded-lg px-3 py-2"><p className="text-amber-700 text-sm">⚠ Suspicious signals — review before acting</p></div>}
              {level === "LOW" && <div className="mt-4 bg-green-50 border border-green-200 rounded-lg px-3 py-2"><p className="text-green-700 text-sm">✓ No significant threats detected</p></div>}
            </div>
            <ExplainabilityPanel result={result} />
            <ConfidenceBreakdown result={result} />
            <ToneAnalysisCard tone={result.tone_analysis} />
            <URLhausCard urlhausResults={result.urlhaus_results} />
            {(result.indicators.length > 0 || result.url_flags.length > 0) && (
              <div className="panel-card fade-in">
                <SectionLabel>Content flags</SectionLabel>
                <div className="flex flex-wrap">{result.indicators.map((f, i) => <Badge key={i} text={f} type="amber" />)}{result.url_flags.filter(f => !f.startsWith("🔴")).map((f, i) => <Badge key={i} text={f} type="red" />)}</div>
                {result.urls_found.length > 0 && (<><Divider /><SectionLabel>URLs found</SectionLabel>{result.urls_found.map((u, i) => <p key={i} className="text-xs font-mono text-slate-500 truncate">{u}</p>)}</>)}
              </div>
            )}
            <SenderIntelCard intel={result.sender_intel} senderFlags={result.sender_flags} />
          </>
        )}
      </div>
    </>
  );
}

// ─── AUDIO PANEL ─────────────────────────────────────────────────────────────

function AudioPanel({ simTrigger, onAnalysisComplete }) {
  const [listening, setListening] = useState(false);
  const [audioScore, setAudioScore] = useState(0);
  const [audioLevel, setAudioLevel] = useState("LOW");
  const [transcript, setTranscript] = useState("");
  const [audioFlags, setAudioFlags] = useState([]);
  const [audioError, setAudioError] = useState(null);
  const [showModal, setShowModal] = useState(false);
  const [sessionEnded, setSessionEnded] = useState(false);
  const [duration, setDuration] = useState(0);
  const wsRef = useRef(null), streamRef = useRef(null), audioCtxRef = useRef(null);
  const analyserRef = useRef(null), processorRef = useRef(null), sourceRef = useRef(null);
  const transcriptRef = useRef(null), timerRef = useRef(null);

  useEffect(() => { if (transcriptRef.current) transcriptRef.current.scrollTop = transcriptRef.current.scrollHeight; }, [transcript]);
  useEffect(() => {
    if (listening) { setDuration(0); timerRef.current = setInterval(() => setDuration(d => d + 1), 1000); }
    else clearInterval(timerRef.current);
    return () => clearInterval(timerRef.current);
  }, [listening]);
  useEffect(() => { if (!simTrigger) return; runSimulationAudio(); }, [simTrigger]);

  const fmt = (s) => `${String(Math.floor(s / 60)).padStart(2, "0")}:${String(s % 60).padStart(2, "0")}`;

  const setupWS = () => new Promise((resolve, reject) => {
    const ws = new WebSocket("ws://127.0.0.1:8000/api/analyze/audio"); wsRef.current = ws;
    ws.onopen = () => { setListening(true); resolve(ws); };
    ws.onmessage = (event) => {
      const msg = JSON.parse(event.data);
      if (msg.type === "transcript") { setTranscript(msg.full_transcript); setAudioScore(msg.cumulative_score); setAudioLevel(msg.risk_level); setAudioFlags(msg.flags ?? []); if (msg.risk_level === "HIGH") setShowModal(true); }
      if (msg.type === "session_end") { setTranscript(msg.full_transcript); setAudioScore(msg.final_score); setAudioFlags(msg.all_flags ?? []); setSessionEnded(true); onAnalysisComplete?.({ type: "audio", data: msg, timestamp: new Date() }); }
      if (msg.type === "error") setAudioError(msg.message);
    };
    ws.onerror = () => { setAudioError("WebSocket error — make sure backend is running."); reject(); };
    ws.onclose = () => setListening(false);
  });

  const pcmSend = (e, ws) => {
    if (!ws || ws.readyState !== WebSocket.OPEN) return;
    const f32 = e.inputBuffer.getChannelData(0), i16 = new Int16Array(f32.length);
    f32.forEach((v, i) => { const s = Math.max(-1, Math.min(1, v)); i16[i] = s < 0 ? s * 0x8000 : s * 0x7fff; });
    ws.send(i16.buffer);
  };

  const runSimulationAudio = async () => {
    setAudioError(null); setTranscript(""); setAudioFlags([]); setAudioScore(0); setAudioLevel("LOW"); setSessionEnded(false); setShowModal(false);
    try {
      const ws = await setupWS();
      const arrayBuf = await (await fetch("/scam-audio-clip1.mp3")).arrayBuffer();
      const audioCtx = new AudioContext({ sampleRate: 16000 }); audioCtxRef.current = audioCtx;
      const decoded = await audioCtx.decodeAudioData(arrayBuf);
      const analyser = audioCtx.createAnalyser(); analyser.fftSize = 1024; analyserRef.current = analyser;
      const bufSrc = audioCtx.createBufferSource(); bufSrc.buffer = decoded;
      bufSrc.connect(analyser); analyser.connect(audioCtx.destination);
      const processor = audioCtx.createScriptProcessor(4096, 1, 1);
      analyser.connect(processor); processor.connect(audioCtx.destination); processorRef.current = processor;
      processor.onaudioprocess = (e) => pcmSend(e, ws);
      bufSrc.onended = () => stopListening();
      bufSrc.start(); sourceRef.current = bufSrc;
    } catch { setAudioError("Simulation failed — check backend is running and audio file is in public folder."); }
  };

  const startListening = async () => {
    setAudioError(null); setTranscript(""); setAudioFlags([]); setAudioScore(0); setAudioLevel("LOW"); setSessionEnded(false); setShowModal(false);
    try { streamRef.current = await navigator.mediaDevices.getUserMedia({ audio: true }); } catch { setAudioError("Microphone permission denied."); return; }
    try { await setupWS(); } catch { return; }
    audioCtxRef.current = new AudioContext({ sampleRate: 16000 });
    analyserRef.current = audioCtxRef.current.createAnalyser(); analyserRef.current.fftSize = 1024;
    sourceRef.current = audioCtxRef.current.createMediaStreamSource(streamRef.current); sourceRef.current.connect(analyserRef.current);
    processorRef.current = audioCtxRef.current.createScriptProcessor(4096, 1, 1);
    analyserRef.current.connect(processorRef.current); processorRef.current.connect(audioCtxRef.current.destination);
    processorRef.current.onaudioprocess = (e) => pcmSend(e, wsRef.current);
  };

  const stopListening = () => {
    streamRef.current?.getTracks().forEach(t => t.stop()); streamRef.current = null;
    processorRef.current?.disconnect(); processorRef.current = null;
    sourceRef.current?.disconnect?.(); sourceRef.current = null;
    audioCtxRef.current?.close(); audioCtxRef.current = null;
    wsRef.current?.close(); wsRef.current = null;
    analyserRef.current = null; setListening(false);
  };

  const colors = RISK[audioLevel] ?? RISK["LOW"];

  return (
    <>
      {showModal && (<HighRiskModal title="Synthetic Voice / Social Engineering Detected" subtitle="Do not share credentials, transfer funds, or follow instructions from this call" flags={audioFlags} onClose={() => setShowModal(false)} />)}
      <div className="flex flex-col gap-4">
        <div className={`panel-card ${listening ? `border-2 ${colors.border}` : ""}`}>
          <div className="flex items-center justify-between mb-4">
            <SectionLabel>Audio Shield</SectionLabel>
            {listening && (<div className="flex items-center gap-3"><span className="text-xs font-mono text-slate-500">{fmt(duration)}</span><div className="flex items-center gap-1.5"><div className="w-2 h-2 rounded-full bg-red-500 pulse-dot" /><span className="text-xs text-red-500 font-medium">Live</span></div></div>)}
          </div>
          <div className="bg-slate-50 border border-slate-200 rounded-xl p-3 mb-4"><LiveWaveform active={listening} analyserRef={analyserRef} /></div>
          <button onClick={listening ? stopListening : startListening} className={`w-full py-2.5 rounded-lg text-sm font-semibold transition-colors flex items-center justify-center gap-2 ${listening ? "bg-red-500 hover:bg-red-600 text-white" : "bg-blue-600 hover:bg-blue-700 text-white"}`}>
            <span>{listening ? "⏹" : "🎙"}</span>{listening ? "Stop Audio Shield" : "Start Audio Shield"}
          </button>
          {audioError && <p className="text-xs text-red-500 text-center mt-2">{audioError}</p>}
          {!listening && !sessionEnded && <p className="text-xs text-slate-400 text-center mt-2">Click to start real-time audio analysis via Deepgram</p>}
        </div>

        <div className={`panel-card ${listening || sessionEnded ? `border-2 ${colors.border}` : ""}`}>
          <div className="flex items-center justify-between mb-4"><SectionLabel>Audio threat level</SectionLabel>{(listening || sessionEnded) && <span className={`text-xs font-semibold px-2.5 py-1 rounded-full ${colors.pill}`}>{audioLevel}</span>}</div>
          <div className={`flex flex-col items-center py-2 ${!listening && !sessionEnded ? "opacity-25" : ""}`}><RiskGauge score={audioScore} level={audioLevel} /></div>
          {!listening && !sessionEnded && <div className="bg-slate-50 border border-slate-200 rounded-lg px-3 py-2 text-center mt-2"><p className="text-slate-400 text-xs">Waiting for audio stream...</p></div>}
          {audioLevel === "HIGH" && (listening || sessionEnded) && <div className="mt-3 bg-red-50 border border-red-200 rounded-lg px-3 py-2"><p className="text-red-700 text-sm">⚠ High risk — stop the call immediately</p></div>}
          {audioLevel === "MEDIUM" && (listening || sessionEnded) && <div className="mt-3 bg-amber-50 border border-amber-200 rounded-lg px-3 py-2"><p className="text-amber-700 text-sm">⚠ Suspicious patterns — stay cautious</p></div>}
          {audioLevel === "LOW" && (listening || sessionEnded) && <div className="mt-3 bg-green-50 border border-green-200 rounded-lg px-3 py-2"><p className="text-green-700 text-sm">✓ No threats detected so far</p></div>}
        </div>

        <div className="panel-card">
          <SectionLabel>Live transcript</SectionLabel>
          <div ref={transcriptRef} className="bg-slate-50 border border-slate-200 rounded-xl p-4 min-h-28 max-h-48 overflow-y-auto">
            {transcript ? <p className="text-sm text-slate-700 leading-relaxed">{transcript}</p> : <p className="text-xs text-slate-400 text-center mt-6">{listening ? "Listening..." : "Transcript will appear here during audio analysis"}</p>}
          </div>
        </div>

        <div className="panel-card">
          <SectionLabel>Audio flags</SectionLabel>
          {audioFlags.length > 0
            ? <div className="flex flex-wrap">{audioFlags.map((f, i) => <Badge key={i} text={f} type={audioLevel === "HIGH" ? "red" : "amber"} />)}</div>
            : <div className="space-y-2">{["Synthetic voice detection", "Social engineering phrases", "Authority impersonation"].map(item => (<div key={item} className="flex items-center gap-2 opacity-25"><div className="w-2 h-2 rounded-full bg-slate-300" /><span className="text-xs text-slate-500">{item}</span></div>))}</div>}
        </div>
      </div>
    </>
  );
}

// ─── SESSION LOG ─────────────────────────────────────────────────────────────

function SessionLog({ events }) {
  if (events.length === 0) return (<div className="panel-card"><SectionLabel>Session threat log</SectionLabel><div className="min-h-12 flex items-center justify-center"><p className="text-xs text-slate-400">Analyzed events will appear here</p></div></div>);
  return (
    <div className="panel-card">
      <div className="flex items-center justify-between mb-3"><SectionLabel>Session threat log</SectionLabel><span className="text-xs text-slate-400">{events.length} event{events.length !== 1 ? "s" : ""}</span></div>
      <div className="space-y-2">
        {events.map((ev, i) => {
          const level = ev.type === "email" ? ev.data.risk_level : (ev.data.final_score >= 70 ? "HIGH" : ev.data.final_score >= 40 ? "MEDIUM" : "LOW");
          const colors = RISK[level], time = ev.timestamp.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
          return (
            <div key={i} className={`flex items-center justify-between px-3 py-2 rounded-lg border ${colors.bg} ${colors.border}`}>
              <div className="flex items-center gap-2"><span className="text-sm">{ev.type === "email" ? "✉️" : "🎙"}</span><span className="text-xs font-medium text-slate-600 capitalize">{ev.type} analysis</span><span className={`text-xs font-semibold ${colors.text}`}>{level}</span></div>
              <span className="text-xs text-slate-400 font-mono">{time}</span>
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ─── ROOT ────────────────────────────────────────────────────────────────────

export default function App() {
  const [simTrigger, setSimTrigger] = useState(0);
  const [simRunning, setSimRunning] = useState(false);
  const [logEvents, setLogEvents] = useState([]);

  const runSimulation = () => { setSimRunning(true); setSimTrigger(n => n + 1); setTimeout(() => setSimRunning(false), 3000); };
  const handleAnalysisComplete = (event) => setLogEvents(prev => [event, ...prev]);

  return (
    <div className="min-h-screen bg-slate-50">
      <header className="bg-white border-b border-slate-200 px-6 py-4 sticky top-0 z-40">
        <div className="max-w-6xl mx-auto flex items-center justify-between">
          <div className="flex items-center gap-3">
            <span className="text-xl">🛡️</span>
            <div><h1 className="text-base font-semibold text-slate-900 leading-tight">Phishing & Deepfake Shield</h1><p className="text-xs text-slate-400">Real-time communication threat analysis</p></div>
          </div>
          <div className="flex items-center gap-3">
            <span className="text-xs bg-green-100 text-green-700 px-2 py-1 rounded-full font-medium">⚡ Edge Mode — local inference</span>
            <button onClick={runSimulation} disabled={simRunning} className="flex items-center gap-2 bg-red-600 hover:bg-red-700 disabled:bg-red-300 text-white text-xs font-semibold px-4 py-2 rounded-lg transition-colors"><span>⚡</span>{simRunning ? "Running simulation..." : "Red Team Demo"}</button>
            <div className="flex items-center gap-2"><div className="w-2 h-2 rounded-full bg-green-400 pulse-dot" /><span className="text-xs text-slate-400">Backend live</span></div>
          </div>
        </div>
      </header>
      <main className="max-w-6xl mx-auto px-6 py-6">
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 items-start">
          <EmailPanel simTrigger={simTrigger} onAnalysisComplete={handleAnalysisComplete} />
          <AudioPanel simTrigger={simTrigger} onAnalysisComplete={handleAnalysisComplete} />
        </div>
        <div className="mt-6"><SessionLog events={logEvents} /></div>
      </main>
    </div>
  );
}