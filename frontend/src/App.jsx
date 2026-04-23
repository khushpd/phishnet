import { useState, useRef, useEffect, useCallback } from "react";
import axios from "axios";
import RainingLetters from "./components/ui/modern-animated-hero-section";
import { AnimatedSubNav } from "./components/ui/animated-nav";
import { MenuVertical } from "./components/ui/menu-vertical";
import { GlassButton } from "./components/ui/glass-button";
import { Shield } from "lucide-react";

// ─── DESIGN TOKENS ────────────────────────────────────────────────────────────
const C = { bg: "#0d0d0d", sidebar: "rgba(10,10,10,0.75)", panel: "rgba(255,255,255,0.04)", card: "rgba(255,255,255,0.06)", border: "rgba(255,255,255,0.08)", text: "#e8e8e8", muted: "#888888", dim: "#555555", accent: "#4a9eff", green: "#3d8b6e" };
const RISK = {
  HIGH: { border: "border-[#5c2626]", bg: "bg-[#2a1a1a]", text: "text-[#e06060]", pill: "bg-[#2c2020] text-[#e06060]", dot: "#e06060", label: "HIGH" },
  MEDIUM: { border: "border-[#5c4a26]", bg: "bg-[#2a2518]", text: "text-[#d4a050]", pill: "bg-[#2c2818] text-[#d4a050]", dot: "#d4a050", label: "MEDIUM" },
  LOW: { border: "border-[#264a36]", bg: "bg-[#1a2a22]", text: "text-[#3d8b6e]", pill: "bg-[#1c2c22] text-[#3d8b6e]", dot: "#3d8b6e", label: "LOW" },
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
  exe: "Executable — runs malware directly", bat: "Batch script — executes system commands",
  cmd: "Command script", ps1: "PowerShell — used in attacks", vbs: "VBScript — malware delivery",
  js: "JavaScript — executes malicious code", jar: "Java executable", scr: "Screensaver — malware disguise",
  msi: "Windows installer", docm: "Macro-enabled Word", xlsm: "Macro-enabled Excel", pptm: "Macro-enabled PowerPoint",
  zip: "Archive — may hide malicious files", rar: "Archive — may hide malicious files",
  iso: "Disk image — bypasses scans", lnk: "Shortcut — points to executables", hta: "HTML app — system privileges",
};
const SUSPICIOUS_EXT = {
  pdf: "PDF — may contain malicious scripts", doc: "Word doc — may have macros",
  xls: "Excel — may have macros", ppt: "PowerPoint — may have macros", rtf: "Rich text — viewer exploits",
};

function scanAttachments(emailText) {
  const results = [], text = emailText.toLowerCase();
  const matches = [...emailText.matchAll(/\b([\w\-]+\.([a-z0-9]{2,5}))\b/gi)];
  const seen = new Set();
  for (const match of matches) {
    const filename = match[1], ext = match[2].toLowerCase();
    if (seen.has(filename.toLowerCase())) continue;
    seen.add(filename.toLowerCase());
    if (["e.g", "i.e", "etc", "vs"].includes(filename.toLowerCase())) continue;
    const dbl = filename.match(/\.(\w+)\.(\w+)$/);
    if (dbl) { results.push({ filename, ext: dbl[2], risk: "HIGH", reason: `Double extension — .${dbl[1]} masking .${dbl[2]}` }); continue; }
    if (DANGEROUS_EXT[ext]) results.push({ filename, ext, risk: "HIGH", reason: DANGEROUS_EXT[ext] });
    else if (SUSPICIOUS_EXT[ext]) results.push({ filename, ext, risk: "MEDIUM", reason: SUSPICIOUS_EXT[ext] });
  }
  const hasRef = ["see attached", "please find attached", "open the attachment", "download the file", "attached document", "attached invoice"].some(k => text.includes(k));
  return { results, hasAttachmentRef: hasRef };
}

function scanUploadedFile(file) {
  const name = file.name, sizeMB = (file.size / (1024 * 1024)).toFixed(2), sizeKB = (file.size / 1024).toFixed(1);
  const mimeType = file.type || "unknown", ext = name.split(".").pop().toLowerCase();
  const allExts = name.split(".").slice(1).map(e => e.toLowerCase());
  const flags = []; let risk = "LOW";
  if (allExts.length >= 2) { flags.push({ severity: "HIGH", text: `Double extension — .${allExts[allExts.length - 2]}.${allExts[allExts.length - 1]}` }); risk = "HIGH"; }
  if (DANGEROUS_EXT[ext]) { flags.push({ severity: "HIGH", text: DANGEROUS_EXT[ext] }); risk = "HIGH"; }
  else if (SUSPICIOUS_EXT[ext]) { flags.push({ severity: "MEDIUM", text: SUSPICIOUS_EXT[ext] }); if (risk === "LOW") risk = "MEDIUM"; }
  if (mimeType !== "unknown" && ext) {
    const mimeMap = { pdf: "application/pdf", jpg: "image/jpeg", jpeg: "image/jpeg", png: "image/png", gif: "image/gif", mp3: "audio/mpeg", mp4: "video/mp4", txt: "text/plain", csv: "text/csv" };
    const expected = mimeMap[ext];
    if (expected && mimeType !== expected && !mimeType.includes(ext)) { flags.push({ severity: "HIGH", text: `MIME mismatch — claims "${mimeType}" but .${ext}` }); risk = "HIGH"; }
  }
  if (["exe", "bat", "ps1", "vbs", "js", "cmd"].includes(ext) && file.size < 10240) { flags.push({ severity: "HIGH", text: `Tiny executable (${sizeKB} KB) — likely dropper` }); risk = "HIGH"; }
  if (["pdf", "doc", "docx", "xls", "xlsx"].includes(ext) && file.size > 50 * 1024 * 1024) { flags.push({ severity: "MEDIUM", text: `Oversized document (${sizeMB} MB)` }); if (risk === "LOW") risk = "MEDIUM"; }
  if (file.size === 0) { flags.push({ severity: "MEDIUM", text: "Empty file (0 bytes)" }); if (risk === "LOW") risk = "MEDIUM"; }
  return { name, ext, sizeMB, sizeKB, mimeType, risk, flags };
}

// ─── EXPLAINABILITY ───────────────────────────────────────────────────────────
function generateExplanations(result) {
  const explanations = [];
  if (result.ml_probability > 0.7) explanations.push({ icon: "🤖", title: "AI model flagged as phishing", detail: `${Math.round(result.ml_probability * 100)}% phishing probability — matches known patterns.`, severity: "high" });
  else if (result.ml_probability > 0.4) explanations.push({ icon: "🤖", title: "Suspicious patterns detected", detail: `${Math.round(result.ml_probability * 100)}% phishing probability — above baseline.`, severity: "medium" });
  const tone = result.tone_analysis;
  if (tone) {
    if (tone.urgency_count >= 3) explanations.push({ icon: "⏰", title: "Extreme urgency pressure", detail: `${tone.urgency_count} urgency phrases. Designed to stop clear thinking.`, severity: "high" });
    else if (tone.urgency_count >= 1) explanations.push({ icon: "⏰", title: "Creates urgency", detail: "Designed to rush action. Legitimate senders wait.", severity: "medium" });
    if (tone.financial_count >= 2) explanations.push({ icon: "💳", title: "Requests financial info", detail: `Financial/credential asks found ${tone.financial_count} times.`, severity: "high" });
    if (tone.sentiment?.negative > 0.5) explanations.push({ icon: "😨", title: "Fear & threats used", detail: "Threatening tone designed to provoke panic.", severity: "high" });
    if (tone.authority_count >= 2) explanations.push({ icon: "🎭", title: "Authority impersonation", detail: `${tone.authority_count} authority phrases. Hides malicious intent.`, severity: "medium" });
  }
  const intel = result.sender_intel;
  if (intel) {
    if (intel.lookalike_match) explanations.push({ icon: "🎯", title: `Impersonates ${intel.lookalike_match}`, detail: `${intel.lookalike_distance} char(s) from ${intel.lookalike_match}. Near-identical domain trick.`, severity: "high" });
    const d = intel.domain_age_days;
    if (d !== null && d < 180) explanations.push({ icon: "📅", title: "Domain very recently created", detail: `${d} days old. Criminals create then abandon domains.`, severity: "high" });
    else if (d !== null && d < 730) explanations.push({ icon: "📅", title: "Relatively new domain", detail: `${d} days old. Established businesses have older domains.`, severity: "medium" });
    if (!intel.spf_present && !intel.dmarc_present) explanations.push({ icon: "🔓", title: "No email authentication", detail: "Anyone can spoof emails from this domain.", severity: "medium" });
    if (intel.is_disposable) explanations.push({ icon: "🗑", title: "Throwaway email service", detail: "No legitimate business uses temporary email addresses.", severity: "high" });
  }
  const urlhausHit = (result.urlhaus_results ?? []).find(r => r.is_malicious);
  if (urlhausHit) explanations.push({ icon: "🔴", title: "Link in malware database", detail: `URL confirmed in URLhaus${urlhausHit.malware ? ` (${urlhausHit.malware})` : ""}.`, severity: "high" });
  if ((result.url_flags ?? []).some(f => f.includes("Shortened"))) explanations.push({ icon: "🔗", title: "Disguised URLs", detail: "URL shorteners used to hide destination.", severity: "medium" });
  explanations.sort((a, b) => a.severity === "high" ? -1 : 1);
  return explanations.slice(0, 5);
}

// ─── SHARED UI ────────────────────────────────────────────────────────────────
function SectionLabel({ children, className = "" }) { return <p className={`text-[13px] font-semibold uppercase tracking-widest mb-3 ${className}`} style={{ color: C.muted }}>{children}</p>; }
function SectionTitle({ children }) { return <h2 className="text-xl font-bold mb-1" style={{ color: C.text }}>{children}</h2>; }
function Badge({ text, type = "gray" }) {
  const map = { gray: "bg-[#2c2c2c] text-[#999]", red: "bg-[#2c2020] text-[#e06060]", amber: "bg-[#2c2818] text-[#d4a050]", green: "bg-[#1c2c22] text-[#3d8b6e]", blue: "bg-[#1a2535] text-[#4a9eff]", purple: "bg-[#251a35] text-[#9a7aef]" };
  return <span className={`inline-block text-[12px] font-medium px-2.5 py-1 rounded mr-1.5 mb-1.5 ${map[type] ?? map.gray}`}>{text}</span>;
}
function PassFail({ ok, yes, no }) { return ok ? <Badge text={yes} type="green" /> : <Badge text={no} type="red" />; }
function Divider({ className = "" }) { return <div className={`my-4 ${className}`} style={{ borderTop: "1px solid rgba(255,255,255,0.06)" }} />; }
function Card({ children, className = "" }) { return <div className={`py-4 ${className}`}>{children}</div>; }

// ─── RISK GAUGE ───────────────────────────────────────────────────────────────
function RiskGauge({ score = 0, level = "LOW", size = 130 }) {
  const r = 46, circ = 2 * Math.PI * r, fill = circ - (Math.min(score, 100) / 100) * circ;
  const col = RISK[level]?.dot ?? "#555", cx = size / 2;
  return (
    <div className="flex flex-col items-center">
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`}>
        <circle cx={cx} cy={cx} r={r} fill="none" stroke="#2a2a2a" strokeWidth="9" />
        <circle cx={cx} cy={cx} r={r} fill="none" stroke={col} strokeWidth="9" strokeDasharray={circ} strokeDashoffset={fill} strokeLinecap="round" transform={`rotate(-90 ${cx} ${cx})`} style={{ transition: "stroke-dashoffset 0.6s ease" }} />
        <text x={cx} y={cx - 6} textAnchor="middle" fontSize="22" fontWeight="700" fill={col}>{score}</text>
        <text x={cx} y={cx + 12} textAnchor="middle" fontSize="10" fill="#555">/100</text>
      </svg>
      <span className={`text-[11px] font-medium px-2 py-0.5 rounded mt-1 ${RISK[level]?.pill ?? "bg-[#2c2c2c] text-[#777]"}`}>{level} RISK</span>
    </div>
  );
}

// ─── LIVE WAVEFORM ────────────────────────────────────────────────────────────
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
        ctx.beginPath(); ctx.strokeStyle = "#4a9eff"; ctx.lineWidth = 1.5;
        buf.forEach((v, i) => { const x = (i / buf.length) * W, y = ((v / 128) * H) / 2; i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y); });
        ctx.lineTo(W, H / 2); ctx.stroke();
      } else {
        ctx.beginPath(); ctx.strokeStyle = "#2a2a2a"; ctx.lineWidth = 1;
        for (let x = 0; x < W; x++) { const y = H / 2 + Math.sin(x * 0.08) * 4 + Math.cos(x * 0.15) * 2; x === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y); }
        ctx.stroke();
      }
    };
    draw(); return () => cancelAnimationFrame(rafRef.current);
  }, [active, analyserRef]);
  return <canvas ref={canvasRef} width={500} height={60} className="w-full h-14 rounded" style={{ background: "rgba(0,0,0,0.3)" }} />;
}

// ─── FILE UPLOAD SCANNER ──────────────────────────────────────────────────────
function FileUploadScanner() {
  const [scanResult, setScanResult] = useState(null), [dragging, setDragging] = useState(false);
  const inputRef = useRef(null);
  const handleFile = (file) => { if (!file) return; setScanResult(scanUploadedFile(file)); };
  const onDrop = (e) => { e.preventDefault(); setDragging(false); const f = e.dataTransfer.files?.[0]; if (f) handleFile(f); };
  const rc = { HIGH: { bg: "bg-red-950/40", border: "border-red-500/50", pill: "bg-red-500/20 text-red-400" }, MEDIUM: { bg: "bg-amber-950/40", border: "border-amber-500/50", pill: "bg-amber-500/20 text-amber-400" }, LOW: { bg: "bg-emerald-950/40", border: "border-emerald-500/50", pill: "bg-emerald-500/20 text-emerald-400" } };
  return (
    <div className="py-4">
      <div className="flex items-center gap-2 mb-4"><SectionTitle>File Scanner</SectionTitle><span className="text-[12px] px-2 py-0.5 rounded" style={{ background: "rgba(255,255,255,0.06)", color: C.muted, border: "1px solid rgba(255,255,255,0.08)" }}>metadata only</span></div>
      <div onDragOver={(e) => { e.preventDefault(); setDragging(true); }} onDragLeave={() => setDragging(false)} onDrop={onDrop} onClick={() => inputRef.current?.click()} className="rounded-xl p-8 text-center cursor-pointer transition-all" style={{ border: `1.5px dashed ${dragging ? C.accent : "rgba(255,255,255,0.12)"}`, background: dragging ? "rgba(74,158,255,0.05)" : "rgba(255,255,255,0.02)" }}>
        <span className="text-3xl block mb-3">📁</span>
        <p className="text-[16px] font-semibold" style={{ color: C.muted }}>Drop a file or click to browse</p>
        <p className="text-[13px] mt-1" style={{ color: C.dim }}>Filename, size, type only — never leaves device</p>
        <input ref={inputRef} type="file" className="hidden" onChange={(e) => handleFile(e.target.files?.[0])} />
      </div>
      {scanResult && (
        <div className={`mt-3 rounded-xl border p-4 ${rc[scanResult.risk].bg} ${rc[scanResult.risk].border}`}>
          <div className="flex items-center justify-between mb-3">
            <div className="flex items-center gap-2"><span>📎</span><span className="text-sm font-mono text-slate-300 truncate max-w-48">{scanResult.name}</span></div>
            <span className={`text-xs font-bold px-2 py-1 rounded-md ${rc[scanResult.risk].pill}`}>{scanResult.risk} RISK</span>
          </div>
          <div className="grid grid-cols-3 gap-2 mb-3">
            {[{ label: "Extension", value: `.${scanResult.ext}` }, { label: "Size", value: scanResult.sizeMB > 0 ? `${scanResult.sizeMB} MB` : `${scanResult.sizeKB} KB` }, { label: "MIME", value: scanResult.mimeType === "unknown" ? "Unknown" : scanResult.mimeType.split("/")[1] ?? scanResult.mimeType }].map(item => (
              <div key={item.label} className="bg-slate-950/60 rounded-lg p-2 text-center"><p className="text-xs text-slate-600">{item.label}</p><p className="text-xs font-semibold text-slate-300 truncate">{item.value}</p></div>
            ))}
          </div>
          {scanResult.flags.length > 0 ? (<div className="space-y-2">{scanResult.flags.map((f, i) => (<div key={i} className={`rounded-lg px-3 py-2 ${f.severity === "HIGH" ? "bg-red-950/60 border border-red-500/30" : "bg-amber-950/60 border border-amber-500/30"}`}><p className={`text-xs font-medium ${f.severity === "HIGH" ? "text-red-400" : "text-amber-400"}`}>⚠ {f.text}</p></div>))}</div>) : (<div className="bg-emerald-950/40 border border-emerald-500/30 rounded-lg px-3 py-2"><p className="text-xs text-emerald-400">✓ No suspicious indicators found</p></div>)}
          <button onClick={() => { setScanResult(null); if (inputRef.current) inputRef.current.value = ""; }} className="mt-3 text-[13px] text-slate-500 hover:text-slate-300 transition-colors">Clear</button>
        </div>
      )}
    </div>
  );
}

// ─── TONE ANALYSIS CARD ───────────────────────────────────────────────────────
function ToneAnalysisCard({ tone }) {
  if (!tone) return null;
  const { sentiment, tone_risk_score, urgency_count, authority_count, financial_count } = tone;
  const bars = [{ label: "Negative", value: sentiment.negative, color: "bg-red-500" }, { label: "Neutral", value: sentiment.neutral, color: "bg-slate-500" }, { label: "Positive", value: sentiment.positive, color: "bg-emerald-500" }];
  return (
    <div className="py-4">
      <div className="flex items-center justify-between mb-4"><SectionTitle>Tone analysis</SectionTitle><span className="text-[13px]" style={{ color: C.dim }}>Tone risk: <span className="font-bold" style={{ color: C.muted }}>{tone_risk_score}/25</span></span></div>
      <div className="space-y-3 mb-5">{bars.map(bar => (<div key={bar.label} className="flex items-center gap-3"><span className="text-[13px] font-medium w-16" style={{ color: C.muted }}>{bar.label}</span><div className="flex-1 rounded-full h-1.5" style={{ background: "rgba(255,255,255,0.08)" }}><div className={`${bar.color} h-1.5 rounded-full`} style={{ width: `${Math.round(bar.value * 100)}%`, transition: "width 0.6s ease" }} /></div><span className="text-[13px] w-9 text-right" style={{ color: C.dim }}>{Math.round(bar.value * 100)}%</span></div>))}</div>
      <div className="grid grid-cols-3 gap-3">{[{ label: "Urgency", value: urgency_count, color: urgency_count > 0 ? "#e06060" : C.dim }, { label: "Authority", value: authority_count, color: authority_count > 0 ? "#d4a050" : C.dim }, { label: "Financial", value: financial_count, color: financial_count > 0 ? "#e06060" : C.dim }].map(item => (<div key={item.label} className="text-center py-3"><p className="text-2xl font-bold" style={{ color: item.color }}>{item.value}</p><p className="text-[12px] font-medium mt-1" style={{ color: C.dim }}>{item.label}</p></div>))}</div>
    </div>
  );
}

function ConfidenceBreakdown({ result }) {
  if (!result) return null;
  const mlPct = result.ml_score ?? 0, tonePct = Math.round(result.tone_analysis?.tone_risk_score ?? 0);
  const urlHit = (result.urlhaus_results ?? []).some(r => r.is_malicious), domainScore = Math.min((result.sender_flags ?? []).length * 6, 30);
  const bars = [{ label: "ML model", value: mlPct, max: 35, color: "bg-cyan-500", tip: "BERT phishing classifier" }, { label: "Tone", value: tonePct, max: 25, color: "bg-violet-500", tip: "Sentiment + authority" }, { label: "Domain intel", value: domainScore, max: 30, color: "bg-amber-500", tip: "WHOIS, DNS, lookalike" }, { label: "URL feed", value: urlHit ? 40 : 0, max: 40, color: "bg-red-500", tip: "URLhaus live database" }];
  return (
    <Card>
      <SectionLabel>Score breakdown</SectionLabel>
      <div className="space-y-3 mt-1">{bars.map(bar => (<div key={bar.label}><div className="flex justify-between mb-1"><span className="text-xs text-slate-500">{bar.label}</span><span className="text-xs text-slate-600 font-mono">{bar.value}/{bar.max}</span></div><div className="bg-slate-800 rounded-full h-1.5"><div className={`${bar.color} h-1.5 rounded-full`} style={{ width: `${Math.round((bar.value / bar.max) * 100)}%`, transition: "width 0.6s ease" }} /></div><p className="text-xs text-slate-700 mt-0.5">{bar.tip}</p></div>))}</div>
    </Card>
  );
}

function URLhausCard({ urlhausResults }) {
  if (!urlhausResults || urlhausResults.length === 0) return null;
  return (
    <Card>
      <div className="flex items-center gap-2 mb-3"><SectionLabel>Live threat intel</SectionLabel><span className="text-xs bg-cyan-500/20 text-cyan-400 border border-cyan-500/30 px-2 py-0.5 rounded-md">URLhaus</span></div>
      <div className="space-y-3">{urlhausResults.map((r, i) => (<div key={i} className={`rounded-lg px-3 py-3 border ${r.is_malicious ? "bg-red-950/40 border-red-500/30" : "bg-emerald-950/40 border-emerald-500/30"}`}><div className="flex items-center justify-between mb-1"><span className={`text-xs font-semibold ${r.is_malicious ? "text-red-400" : "text-emerald-400"}`}>{r.is_malicious ? "🔴 CONFIRMED MALICIOUS" : "✓ Not listed"}</span>{r.threat && <Badge text={r.threat} type="red" />}</div><p className="text-xs font-mono text-slate-600 truncate mb-1">{r.url}</p>{r.malware && <p className="text-xs text-red-400">Family: <span className="font-semibold">{r.malware}</span></p>}{r.tags?.length > 0 && <div className="flex flex-wrap mt-1">{r.tags.map((t, j) => <Badge key={j} text={t} type="red" />)}</div>}{r.date_added && <p className="text-xs text-slate-600 mt-1">First seen: {r.date_added}</p>}</div>))}</div>
    </Card>
  );
}

function SenderIntelCard({ intel, senderFlags }) {
  if (!intel || Object.keys(intel).length === 0) return null;
  const ageDays = intel.domain_age_days, ageFlag = intel.domain_age_flag ?? "Unable to verify";
  const ageType = ageFlag === "Unable to verify" ? "gray" : ageFlag === "Very new domain — high risk" ? "red" : ageFlag === "Relatively new domain" ? "amber" : "green";
  const rows = [
    { label: "Domain age", sub: "How old is the sender's domain", right: <div className="flex items-center gap-2">{ageDays != null && <span className="text-xs text-slate-600">{ageDays}d</span>}<Badge text={ageFlag} type={ageType} /></div> },
    { label: "Mail server", sub: "Does sender have a real email server", right: <PassFail ok={intel.mx_valid} yes="Exists" no="Missing" /> },
    { label: "Sender verified", sub: "Authorised for this domain (SPF)", right: <PassFail ok={intel.spf_present} yes="Verified" no="Unverified" /> },
    { label: "Anti-spoofing", sub: "DMARC protection enabled", right: <PassFail ok={intel.dmarc_present} yes="Protected" no="Unprotected" /> },
    { label: "Throwaway email", sub: "Temporary/disposable provider", right: <PassFail ok={!intel.is_disposable} yes="Legitimate" no="Disposable" /> },
    { label: "Domain spoof", sub: "Impersonates a known brand", right: intel.lookalike_match ? <Badge text={`Spoofs ${intel.lookalike_match} (${intel.lookalike_distance}Δ)`} type="red" /> : <Badge text="No match" type="green" /> },
  ];
  return (
    <Card>
      <SectionLabel>Sender Intelligence</SectionLabel>
      <div className="space-y-4">{rows.map(row => (<div key={row.label} className="flex items-start justify-between gap-3"><div className="flex-1 min-w-0"><p className="text-sm text-slate-300 font-medium">{row.label}</p><p className="text-xs text-slate-600">{row.sub}</p></div><div className="flex-shrink-0 pt-0.5">{row.right}</div></div>))}</div>
      {senderFlags?.length > 0 && (<><Divider /><SectionLabel>Sender flags</SectionLabel><div className="flex flex-wrap">{senderFlags.map((f, i) => <Badge key={i} text={f} type="amber" />)}</div></>)}
    </Card>
  );
}

// ─── HIGH RISK MODAL ──────────────────────────────────────────────────────────
function HighRiskModal({ title, subtitle, flags, onClose }) {
  return (
    <div className="fixed inset-0 flex items-center justify-center z-50 p-4" style={{ background: "rgba(0,0,0,0.7)" }}>
      <div className="max-w-md w-full p-8 rounded fade-in" style={{ background: C.panel, border: "2px solid #e06060" }}>
        <div className="text-center mb-6"><div className="text-5xl mb-3">⚠️</div><h2 className="text-2xl font-bold text-red-400 mb-1">{title}</h2><p className="text-slate-500 text-sm">{subtitle}</p></div>
        <div className="bg-red-950/40 border border-red-500/30 rounded-xl px-4 py-3 mb-5"><p className="text-red-400 text-sm font-semibold mb-1">Do not:</p><ul className="text-red-300/70 text-sm list-disc list-inside space-y-1"><li>Click any links</li><li>Share personal or financial info</li><li>Transfer funds or reset credentials</li></ul></div>
        {flags.length > 0 && (<div className="mb-5"><SectionLabel>Reason flags</SectionLabel><div className="flex flex-wrap">{flags.map((f, i) => <Badge key={i} text={f} type="red" />)}</div></div>)}
        <GlassButton className="glass-button-danger w-full" size="sm" onClick={onClose} contentClassName="justify-center">I understand — dismiss</GlassButton>
      </div>
    </div>
  );
}

// ─── REPORT BUILDER ───────────────────────────────────────────────────────────
function generateEmailReport(data, sender, bodyText) {
  const explanations = generateExplanations(data);
  const attackVector = [];
  if (data.sender_intel?.lookalike_match) attackVector.push(`Domain spoofing (${data.sender_intel.lookalike_match})`);
  if ((data.urlhaus_results ?? []).some(r => r.is_malicious)) attackVector.push("Malicious URL payload");
  if (data.tone_analysis?.urgency_count >= 2) attackVector.push("Urgency manipulation");
  if (data.tone_analysis?.financial_count >= 1) attackVector.push("Credential/financial harvesting");
  if (data.sender_intel?.is_disposable) attackVector.push("Disposable sender identity");
  return {
    id: `email-${Date.now()}`, type: "email", generatedAt: new Date(),
    riskLevel: data.risk_level, riskScore: data.risk_score,
    sender, summary: `This email scored ${data.risk_score}/100 and was classified as ${data.risk_level} risk. ${explanations[0]?.title ?? "No major threat found"}.`,
    attackVector, explanations,
    indicators: data.indicators ?? [], senderFlags: data.sender_flags ?? [], urlFlags: data.url_flags ?? [],
    urlsFound: data.urls_found ?? [], urlhausResults: data.urlhaus_results ?? [],
    senderIntel: data.sender_intel ?? {}, toneAnalysis: data.tone_analysis,
    mlProbability: data.ml_probability, mlScore: data.ml_score, rawScore: data.raw_score,
    bodyPreview: bodyText?.slice(0, 300), attachments: scanAttachments(bodyText ?? ""),
    recommendation: data.risk_level === "HIGH" ? "Do not interact. Report to IT/security. Delete from inbox." : data.risk_level === "MEDIUM" ? "Exercise caution. Verify sender identity through a separate channel." : "No action required. Email appears legitimate.",
  };
}

function generateAudioReport(data) {
  const score = data.final_score ?? 0, level = score >= 70 ? "HIGH" : score >= 40 ? "MEDIUM" : "LOW";
  const attackVector = [];
  if ((data.all_flags ?? []).some(f => f.includes("wire transfer") || f.includes("bank"))) attackVector.push("Financial fraud attempt");
  if ((data.all_flags ?? []).some(f => f.includes("ceo") || f.includes("executive"))) attackVector.push("Executive impersonation");
  if ((data.all_flags ?? []).some(f => f.includes("urgent") || f.includes("immediately"))) attackVector.push("Urgency pressure tactics");
  if ((data.all_flags ?? []).some(f => f.includes("password") || f.includes("credentials"))) attackVector.push("Credential phishing");
  return {
    id: `audio-${Date.now()}`, type: "audio", generatedAt: new Date(),
    riskLevel: level, riskScore: score,
    summary: `Audio session scored ${score}/100, classified ${level} risk. ${(data.all_flags ?? []).length} social engineering signal(s) detected.`,
    attackVector, flags: data.all_flags ?? [], transcript: data.full_transcript ?? "",
    recommendation: level === "HIGH" ? "End this call immediately. Do not provide any information. Report to authorities." : level === "MEDIUM" ? "Stay cautious. Don't share personal info. Call back on a verified number." : "No significant threats detected in this audio session.",
  };
}

// ─── FULL REPORT VIEW ─────────────────────────────────────────────────────────
function FullReport({ report }) {
  if (!report) return null;
  const colors = RISK[report.riskLevel] ?? RISK.LOW, isEmail = report.type === "email";
  const ts = report.generatedAt instanceof Date ? report.generatedAt : new Date(report.generatedAt);
  return (
    <div className="space-y-5">
      {/* Header card */}
      <div className={`rounded-xl border-2 ${colors.border} ${colors.bg} p-5`}>
        <div className="flex items-start justify-between gap-4 mb-4">
          <div>
            <div className="flex items-center gap-2 mb-1"><span className="text-xl">{isEmail ? "✉️" : "🎙"}</span><span className="text-xs font-bold uppercase tracking-widest text-slate-500">{isEmail ? "Email threat report" : "Audio threat report"}</span></div>
            <p className="text-xs text-slate-600 font-mono">{ts.toLocaleString()}</p>
            {isEmail && <p className="text-xs text-slate-500 mt-1">From: <span className="text-slate-400 font-mono">{report.sender}</span></p>}
          </div>
          <RiskGauge score={report.riskScore} level={report.riskLevel} size={100} />
        </div>
        <div className="bg-slate-950/60 rounded-lg px-4 py-3"><p className="text-sm text-slate-300 leading-relaxed">{report.summary}</p></div>
      </div>

      {/* Attack vector */}
      {report.attackVector?.length > 0 && (
        <Card>
          <SectionLabel>Attack vector</SectionLabel>
          <div className="space-y-2">{report.attackVector.map((v, i) => (<div key={i} className="flex items-center gap-3 bg-slate-950/60 rounded-lg px-3 py-2"><div className="w-1.5 h-1.5 rounded-full bg-red-400 flex-shrink-0" /><span className="text-sm text-slate-300">{v}</span></div>))}</div>
        </Card>
      )}

      {/* Recommendation */}
      <Card className={`border ${report.riskLevel === "HIGH" ? "border-red-500/40 bg-red-950/20" : report.riskLevel === "MEDIUM" ? "border-amber-500/40 bg-amber-950/20" : "border-emerald-500/40 bg-emerald-950/20"}`}>
        <SectionLabel>Recommendation</SectionLabel>
        <p className={`text-sm font-medium leading-relaxed ${colors.text}`}>{report.recommendation}</p>
      </Card>

      {/* Why risky */}
      {report.explanations?.length > 0 && (
        <Card>
          <SectionLabel>Why is this risky?</SectionLabel>
          <div className="space-y-3">{report.explanations.map((exp, i) => (<div key={i} className={`rounded-lg px-3 py-3 border ${exp.severity === "high" ? "bg-red-950/40 border-red-500/30" : "bg-amber-950/40 border-amber-500/30"}`}><div className="flex items-center gap-2 mb-1"><span>{exp.icon}</span><p className={`text-sm font-semibold ${exp.severity === "high" ? "text-red-400" : "text-amber-400"}`}>{exp.title}</p></div><p className={`text-xs leading-relaxed ${exp.severity === "high" ? "text-red-300/70" : "text-amber-300/70"}`}>{exp.detail}</p></div>))}</div>
        </Card>
      )}

      {/* Tone */}
      {report.toneAnalysis && <ToneAnalysisCard tone={report.toneAnalysis} />}

      {/* Sender intel */}
      {isEmail && report.senderIntel && Object.keys(report.senderIntel).length > 0 && (<SenderIntelCard intel={report.senderIntel} senderFlags={report.senderFlags} />)}

      {/* URLhaus */}
      {isEmail && report.urlhausResults?.length > 0 && <URLhausCard urlhausResults={report.urlhausResults} />}

      {/* Score breakdown */}
      {isEmail && (<ConfidenceBreakdown result={{ ml_score: report.mlScore, ml_probability: report.mlProbability, tone_analysis: report.toneAnalysis, sender_flags: report.senderFlags, urlhaus_results: report.urlhausResults }} />)}

      {/* Audio flags */}
      {!isEmail && report.flags?.length > 0 && (<Card><SectionLabel>Social engineering signals</SectionLabel><div className="flex flex-wrap">{report.flags.map((f, i) => <Badge key={i} text={f} type={report.riskLevel === "HIGH" ? "red" : "amber"} />)}</div></Card>)}

      {/* Transcript */}
      {!isEmail && report.transcript && (<Card><SectionLabel>Call transcript</SectionLabel><div className="bg-slate-950 border border-slate-800 rounded-xl p-4 max-h-40 overflow-y-auto"><p className="text-sm text-slate-300 leading-relaxed font-mono">{report.transcript}</p></div></Card>)}

      {/* Content flags */}
      {isEmail && (report.indicators?.length > 0 || report.urlFlags?.length > 0) && (<Card><SectionLabel>Content flags</SectionLabel><div className="flex flex-wrap">{report.indicators.map((f, i) => <Badge key={i} text={f} type="amber" />)}{report.urlFlags.filter(f => !f.startsWith("🔴")).map((f, i) => <Badge key={i} text={f} type="red" />)}</div>{report.urlsFound?.length > 0 && (<><Divider /><SectionLabel>URLs found</SectionLabel>{report.urlsFound.map((u, i) => <p key={i} className="text-xs font-mono text-slate-600 truncate">{u}</p>)}</>)}</Card>)}

      {/* Body preview */}
      {isEmail && report.bodyPreview && (<Card><SectionLabel>Email body preview</SectionLabel><div className="bg-slate-950 border border-slate-800 rounded-xl p-4"><p className="text-xs text-slate-400 leading-relaxed font-mono whitespace-pre-wrap">{report.bodyPreview}{report.bodyPreview.length >= 300 ? "…" : ""}</p></div></Card>)}

      {/* Attachments */}
      {isEmail && report.attachments?.results?.length > 0 && (<Card><div className="flex items-center gap-2 mb-3"><SectionLabel>Attachments</SectionLabel><span className="text-xs bg-amber-500/20 text-amber-400 border border-amber-500/30 px-2 py-0.5 rounded-md">{report.attachments.results.length} flagged</span></div><div className="space-y-2">{report.attachments.results.map((att, i) => (<div key={i} className={`rounded-lg px-3 py-3 border ${att.risk === "HIGH" ? "bg-red-950/40 border-red-500/30" : "bg-amber-950/40 border-amber-500/30"}`}><div className="flex items-center justify-between mb-1"><span className="text-xs font-mono text-slate-300">{att.filename}</span><Badge text={`.${att.ext}`} type={att.risk === "HIGH" ? "red" : "amber"} /></div><p className={`text-xs ${att.risk === "HIGH" ? "text-red-300/70" : "text-amber-300/70"}`}>{att.reason}</p></div>))}</div></Card>)}
    </div>
  );
}

// ─── REPORT DRAWER ────────────────────────────────────────────────────────────
function ReportDrawer({ report, onClose }) {
  useEffect(() => { const h = (e) => { if (e.key === "Escape") onClose(); }; window.addEventListener("keydown", h); return () => window.removeEventListener("keydown", h); }, [onClose]);
  return (
    <>
      <div className="fixed inset-0 z-40" onClick={onClose} style={{ background: "rgba(0,0,0,0.6)", animation: "fadeInBg 0.2s ease" }} />
      <div className="fixed right-0 top-0 h-full w-full max-w-xl z-50 overflow-y-auto" style={{ background: "rgba(10,10,12,0.85)", backdropFilter: "blur(24px)", borderLeft: "1px solid rgba(255,255,255,0.08)", animation: "slideInRight 0.2s ease" }}>
        <div className="sticky top-0 px-6 py-4 flex items-center justify-between z-10" style={{ background: "rgba(10,10,12,0.9)", backdropFilter: "blur(16px)", borderBottom: "1px solid rgba(255,255,255,0.07)" }}>
          <div>
            <p className="text-sm font-bold text-slate-100">Threat Report</p>
            <p className="text-xs text-slate-600 font-mono">{(report?.generatedAt instanceof Date ? report.generatedAt : new Date(report?.generatedAt)).toLocaleString()}</p>
          </div>
          <button onClick={onClose} className="w-7 h-7 flex items-center justify-center rounded text-sm transition-colors" style={{ background: C.card, color: C.muted }}>✕</button>
        </div>
        <div className="p-6"><FullReport report={report} /></div>
      </div>
    </>
  );
}

// ─── REPORT TOAST ─────────────────────────────────────────────────────────────
function ReportToast({ report, onView, onDismiss }) {
  useEffect(() => { const t = setTimeout(onDismiss, 6000); return () => clearTimeout(t); }, [onDismiss]);
  const colors = RISK[report.riskLevel] ?? RISK.LOW;
  return (
    <div className="fixed bottom-6 right-6 z-50" style={{ animation: "slideUpToast 0.3s cubic-bezier(0.16,1,0.3,1)" }}>
      <div className="p-4 w-80 flex items-start gap-3" style={{ background: "rgba(18,18,24,0.9)", backdropFilter: "blur(20px)", border: "1px solid rgba(255,255,255,0.1)", borderRadius: "12px", boxShadow: "0 8px 32px rgba(0,0,0,0.5)", animation: "slideUpToast 0.3s ease" }}>
        <div className={`w-8 h-8 rounded-lg flex items-center justify-center flex-shrink-0 ${report.riskLevel === "HIGH" ? "bg-red-500/20" : report.riskLevel === "MEDIUM" ? "bg-amber-500/20" : "bg-emerald-500/20"}`}>
          <span className="text-base">{report.type === "email" ? "✉️" : "🎙"}</span>
        </div>
        <div className="flex-1 min-w-0">
          <p className="text-xs font-bold text-slate-200 mb-0.5">Report ready</p>
          <p className={`text-xs font-semibold ${colors.text} mb-1`}>{report.riskLevel} RISK · Score {report.riskScore}/100</p>
          <p className="text-xs text-slate-600 truncate">{report.type === "email" ? `From: ${report.sender}` : `${report.flags?.length ?? 0} flag(s) detected`}</p>
        </div>
        <div className="flex flex-col gap-1 flex-shrink-0">
          <GlassButton className="glass-button-accent" size="sm" onClick={onView}>View</GlassButton>
          <button onClick={onDismiss} className="text-xs text-slate-600 hover:text-slate-400 px-3 py-1 transition-colors">Dismiss</button>
        </div>
      </div>
    </div>
  );
}

// ─── LOG ENTRY CARD ───────────────────────────────────────────────────────────
function LogEntryCard({ report, onClick }) {
  const colors = RISK[report.riskLevel] ?? RISK.LOW;
  const ts = report.generatedAt instanceof Date ? report.generatedAt : new Date(report.generatedAt);
  const topFlags = report.type === "email" ? [...(report.senderFlags ?? []), ...(report.indicators ?? [])].slice(0, 3) : (report.flags ?? []).slice(0, 3);
  const topExp = report.explanations?.slice(0, 2) ?? [];
  return (
    <button onClick={onClick} className="w-full text-left py-4 hover:bg-white/5 px-4 -mx-4 rounded-xl transition-all group">
      <div className="flex items-start justify-between gap-3 mb-3">
        <div className="flex items-center gap-3">
          <div className={`w-9 h-9 rounded-lg flex items-center justify-center flex-shrink-0 ${report.riskLevel === "HIGH" ? "bg-red-500/15" : report.riskLevel === "MEDIUM" ? "bg-amber-500/15" : "bg-emerald-500/15"}`}>
            <span className="text-lg">{report.type === "email" ? "✉️" : "🎙"}</span>
          </div>
          <div>
            <div className="flex items-center gap-2"><span className="text-[16px] font-bold" style={{ color: C.text, textTransform: "capitalize" }}>{report.type} analysis</span><span className={`text-[12px] font-bold px-2.5 py-1 rounded-md ${colors.pill}`}>{report.riskLevel}</span></div>
            <p className="text-[12px] font-mono mt-0.5" style={{ color: C.dim }}>{ts.toLocaleString()}</p>
          </div>
        </div>
        <div className="text-right flex-shrink-0"><p className="text-3xl font-bold" style={{ color: colors.dot }}>{report.riskScore}</p><p className="text-[12px]" style={{ color: C.dim }}>/100</p></div>
      </div>

      {report.type === "email" && (<div className="mb-4"><p className="text-[14px]" style={{ color: C.muted }}>From: <span className="font-mono text-[13px]">{report.sender}</span></p>{report.senderIntel?.lookalike_match && <p className="text-[13px] text-red-400 mt-1 font-medium">⚠ Spoofs {report.senderIntel.lookalike_match}</p>}</div>)}
      {report.type === "audio" && report.transcript && (<div className="mb-4"><p className="text-[14px] font-mono leading-relaxed" style={{ color: C.dim, display: "-webkit-box", WebkitLineClamp: 2, WebkitBoxOrient: "vertical", overflow: "hidden" }}>{report.transcript.slice(0, 120)}{report.transcript.length > 120 ? "…" : ""}</p></div>)}

      <p className="text-[15px] leading-relaxed mb-4" style={{ color: C.text }}>{report.summary}</p>

      {report.attackVector?.length > 0 && (<div className="flex flex-wrap gap-2 mb-4">{report.attackVector.slice(0, 3).map((v, i) => (<span key={i} className="text-[12px] font-medium px-2.5 py-1 rounded-md" style={{ background: "rgba(255,255,255,0.05)", border: "1px solid rgba(255,255,255,0.08)", color: C.muted }}>{v}</span>))}{report.attackVector.length > 3 && <span className="text-[12px] px-1 py-1" style={{ color: C.dim }}>+{report.attackVector.length - 3} more</span>}</div>)}

      {topExp.length > 0 && (<div className="space-y-2 mb-4">{topExp.map((exp, i) => (<div key={i} className="flex items-start gap-2"><span className="text-[15px] flex-shrink-0">{exp.icon}</span><p className={`text-[14px] font-medium ${exp.severity === "high" ? "text-red-400" : "text-amber-400"}`}>{exp.title}</p></div>))}</div>)}

      {topFlags.length > 0 && (<div className="flex flex-wrap gap-1.5 mb-4">{topFlags.map((f, i) => <Badge key={i} text={f} type="amber" />)}</div>)}

      <div className="py-2">
        <p className="text-[14px] font-medium" style={{ color: colors.dot }}>{report.recommendation}</p>
      </div>

      <div className="flex items-center gap-1.5 mt-2 opacity-0 group-hover:opacity-100 transition-opacity">
        <span className="text-[13px]" style={{ color: C.accent }}>Click to open full report</span>
        <span className="text-[13px]" style={{ color: C.accent }}>→</span>
      </div>
    </button>
  );
}

// ─── LOGS PANEL ───────────────────────────────────────────────────────────────
function LogsPanel({ reports, onOpenReport }) {
  const [filter, setFilter] = useState("all");
  const filtered = filter === "all" ? reports : reports.filter(r => r.type === filter);
  const highCount = reports.filter(r => r.riskLevel === "HIGH").length;
  return (
    <div>
      <div className="flex items-center justify-between mb-6 gap-3">
        <AnimatedSubNav
          items={[
            { id: "all", label: "All", count: reports.length },
            { id: "email", label: "Email", count: reports.filter(r => r.type === "email").length },
            { id: "audio", label: "Audio", count: reports.filter(r => r.type === "audio").length },
          ]}
          activeId={filter}
          onItemClick={(id) => setFilter(id)}
        />
        {highCount > 0 && <span className="text-[13px] font-bold px-3 py-1 rounded-full" style={{ background: "rgba(224,96,96,0.15)", color: "#e06060", border: "1px solid rgba(224,96,96,0.25)" }}>{highCount} HIGH risk</span>}
      </div>

      {reports.length > 0 && (
        <div className="flex gap-8 mb-6">
          {[{ label: "Total scans", value: reports.length, color: C.accent }, { label: "High risk", value: reports.filter(r => r.riskLevel === "HIGH").length, color: "#e06060" }, { label: "Clean", value: reports.filter(r => r.riskLevel === "LOW").length, color: "#3d8b6e" }].map(item => (
            <div key={item.label}>
              <p className="text-3xl font-bold" style={{ color: item.color }}>{item.value}</p>
              <p className="text-[13px] font-medium mt-0.5" style={{ color: C.dim }}>{item.label}</p>
            </div>
          ))}
        </div>
      )}

      {filtered.length === 0 ? (
        <div className="flex flex-col items-center justify-center py-20 text-center">
          <span className="text-4xl mb-4">📋</span>
          <p className="text-[17px] font-bold" style={{ color: C.muted }}>No {filter !== "all" ? filter : ""} reports yet</p>
          <p className="text-[13px] mt-1" style={{ color: C.dim }}>Completed analyses will appear here</p>
        </div>
      ) : (
        <div>{filtered.map((report, i) => (
          <div key={report.id}>
            <LogEntryCard report={report} onClick={() => onOpenReport(report)} />
            {i < filtered.length - 1 && <Divider />}
          </div>
        ))}</div>
      )}
    </div>
  );
}

// ─── REPORT TAB ───────────────────────────────────────────────────────────────
function ReportTab({ report }) {
  if (!report) return (
    <div className="flex flex-col items-center justify-center py-24 text-center">
      <span className="text-5xl mb-4">📄</span>
      <p className="text-sm font-medium text-slate-500">No report generated yet</p>
      <p className="text-xs text-slate-700 mt-1">Run an email or audio analysis — the report will appear here</p>
    </div>
  );
  return <FullReport report={report} />;
}

// ─── EMAIL PANEL ──────────────────────────────────────────────────────────────
function EmailPanel({ simTrigger, onReportGenerated }) {
  const [text, setText] = useState(""), [sender, setSender] = useState(""), [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false), [modal, setModal] = useState(false), [error, setError] = useState(null);

  useEffect(() => { if (!simTrigger) return; setText(DEMO_EMAIL_BODY); setSender(DEMO_EMAIL_SENDER); }, [simTrigger]);
  useEffect(() => { if (simTrigger && text === DEMO_EMAIL_BODY && sender === DEMO_EMAIL_SENDER) analyze(DEMO_EMAIL_BODY, DEMO_EMAIL_SENDER); }, [text, sender, simTrigger]);

  const analyze = async (t = text, s = sender) => {
    if (!t.trim() || !s.trim()) return;
    setLoading(true); setError(null); setResult(null); setModal(false);
    try {
      const res = await axios.post("http://127.0.0.1:8000/api/analyze/email", { text: t, sender: s });
      setResult(res.data);
      if (res.data.risk_level === "HIGH") setModal(true);
      onReportGenerated(generateEmailReport(res.data, s, t));
    } catch { setError("Backend unreachable — make sure FastAPI is running on port 8000."); }
    finally { setLoading(false); }
  };

  return (
    <>
      {modal && result && (<HighRiskModal title="High Risk Email Detected" subtitle="Strong signs of a phishing attempt" flags={[...(result.indicators ?? []), ...(result.sender_flags ?? []), ...(result.url_flags ?? [])]} onClose={() => setModal(false)} />)}
      <div className="flex flex-col gap-6">

        {/* ── Input box — only bordered element ── */}
        <div className="rounded-xl p-5 space-y-4" style={{ background: "rgba(255,255,255,0.03)", border: "1px solid rgba(255,255,255,0.08)" }}>
          <SectionTitle>Email Shield</SectionTitle>
          <div><label className="block text-[13px] font-medium mb-1.5" style={{ color: C.muted }}>Sender email</label><input type="text" placeholder="sender@domain.com" value={sender} onChange={e => setSender(e.target.value)} className="w-full px-4 py-2.5 rounded-lg text-[15px] focus:outline-none" style={{ background: "rgba(0,0,0,0.4)", border: `1px solid rgba(255,255,255,0.1)`, color: C.text }} /></div>
          <div><label className="block text-[13px] font-medium mb-1.5" style={{ color: C.muted }}>Email body</label><textarea rows={7} placeholder="Paste email content here..." value={text} onChange={e => setText(e.target.value)} className="w-full px-4 py-2.5 rounded-lg text-[15px] resize-none focus:outline-none" style={{ background: "rgba(0,0,0,0.4)", border: `1px solid rgba(255,255,255,0.1)`, color: C.text }} /></div>
          <GlassButton className="glass-button-accent w-full" size="default" onClick={() => analyze()} disabled={loading || !text.trim() || !sender.trim()} contentClassName="justify-center text-[15px] font-semibold">{loading ? "Analyzing..." : "Analyze Email"}</GlassButton>
          {error && <p className="text-[13px] text-red-400 text-center">{error}</p>}
        </div>

        {/* ── File scanner — input box ── */}
        <FileUploadScanner />

        {/* ── Status — no box ── */}
        {loading && (
          <div className="flex flex-col items-center justify-center py-12">
            <div className="w-8 h-8 border-2 border-t-transparent rounded-full mb-4" style={{ borderColor: C.accent, borderTopColor: "transparent", animation: "spin 1s linear infinite" }} />
            <p className="text-[16px] font-semibold" style={{ color: C.muted }}>Running analysis...</p>
            <p className="text-[13px] mt-1" style={{ color: C.dim }}>Checking URLhaus threat database...</p>
          </div>
        )}
        {!result && !loading && (
          <div className="flex flex-col items-center justify-center py-12 text-center">
            <span className="text-4xl mb-4">🔍</span>
            <p className="text-[17px] font-bold" style={{ color: C.muted }}>No analysis yet</p>
            <p className="text-[13px] mt-1" style={{ color: C.dim }}>Paste an email above and click Analyze</p>
          </div>
        )}
        {result && !loading && (
          <div className="flex items-center justify-between py-4">
            <div>
              <SectionTitle>Analysis complete</SectionTitle>
              <p className="text-[15px] font-medium" style={{ color: C.muted }}>Report saved — switching to Report tab.</p>
              <p className="text-[13px] mt-1" style={{ color: C.dim }}>Also logged in the <span style={{ color: C.accent }}>Logs</span> tab.</p>
            </div>
            <RiskGauge score={result.risk_score} level={result.risk_level} size={100} />
          </div>
        )}
      </div>
    </>
  );
}

// ─── AUDIO PANEL ──────────────────────────────────────────────────────────────
function AudioPanel({ simTrigger, onReportGenerated }) {
  const [listening, setListening] = useState(false), [audioScore, setAudioScore] = useState(0), [audioLevel, setAudioLevel] = useState("LOW");
  const [transcript, setTranscript] = useState(""), [audioFlags, setAudioFlags] = useState([]), [audioError, setAudioError] = useState(null);
  const [showModal, setShowModal] = useState(false), [sessionEnded, setSessionEnded] = useState(false), [duration, setDuration] = useState(0);
  const wsRef = useRef(null), streamRef = useRef(null), audioCtxRef = useRef(null), analyserRef = useRef(null), processorRef = useRef(null), sourceRef = useRef(null);
  const transcriptRef = useRef(null), timerRef = useRef(null), lastSimTrigger = useRef(0);

  useEffect(() => { if (transcriptRef.current) transcriptRef.current.scrollTop = transcriptRef.current.scrollHeight; }, [transcript]);
  useEffect(() => { if (listening) { setDuration(0); timerRef.current = setInterval(() => setDuration(d => d + 1), 1000); } else clearInterval(timerRef.current); return () => clearInterval(timerRef.current); }, [listening]);
  useEffect(() => {
    // Only run simulation when simTrigger actually increments (new demo click),
    // not when the component mounts/remounts with an existing simTrigger value
    if (!simTrigger || simTrigger === lastSimTrigger.current) return;
    lastSimTrigger.current = simTrigger;
    runSimulationAudio();
  }, [simTrigger]);

  const fmt = (s) => `${String(Math.floor(s / 60)).padStart(2, "0")}:${String(s % 60).padStart(2, "0")}`;

  const setupWS = () => new Promise((resolve, reject) => {
    const ws = new WebSocket("ws://127.0.0.1:8000/api/analyze/audio"); wsRef.current = ws;
    ws.onopen = () => { setListening(true); resolve(ws); };
    ws.onmessage = (event) => {
      const msg = JSON.parse(event.data);
      if (msg.type === "transcript") { setTranscript(msg.full_transcript); setAudioScore(msg.cumulative_score); setAudioLevel(msg.risk_level); setAudioFlags(msg.flags ?? []); if (msg.risk_level === "HIGH") setShowModal(true); }
      if (msg.type === "session_end") { setTranscript(msg.full_transcript); setAudioScore(msg.final_score); setAudioFlags(msg.all_flags ?? []); setSessionEnded(true); onReportGenerated(generateAudioReport(msg)); }
      if (msg.type === "error") setAudioError(msg.message);
    };
    ws.onerror = () => { setAudioError("WebSocket error."); reject(); };
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
    } catch { setAudioError("Simulation failed."); }
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
      {showModal && (<HighRiskModal title="Social Engineering Detected" subtitle="Do not share credentials or follow call instructions" flags={audioFlags} onClose={() => setShowModal(false)} />)}
      <div className="flex flex-col gap-6">

        {/* ── Input box — waveform + button ── */}
        <div className="rounded-xl p-5" style={{ background: "rgba(255,255,255,0.03)", border: "1px solid rgba(255,255,255,0.08)" }}>
          <div className="flex items-center justify-between mb-4">
            <SectionTitle>Audio Shield</SectionTitle>
            {listening && (<div className="flex items-center gap-3"><span className="text-[13px] font-mono" style={{ color: C.dim }}>{fmt(duration)}</span><div className="flex items-center gap-1.5"><div className="w-2 h-2 rounded-full bg-red-500" style={{ animation: "pulse 1.5s ease-in-out infinite" }} /><span className="text-[13px] text-red-400 font-semibold">Live</span></div></div>)}
          </div>
          <div className="rounded-lg p-3 mb-4" style={{ background: "rgba(0,0,0,0.4)", border: "1px solid rgba(255,255,255,0.08)" }}><LiveWaveform active={listening} analyserRef={analyserRef} /></div>
          <GlassButton className={listening ? "glass-button-danger w-full" : "glass-button-accent w-full"} size="default" onClick={listening ? stopListening : startListening} contentClassName="justify-center gap-2 text-[15px] font-semibold"><span>{listening ? "⏹" : "🎙"}</span>{listening ? "Stop Audio Shield" : "Start Audio Shield"}</GlassButton>
          {audioError && <p className="text-[13px] text-red-400 text-center mt-2">{audioError}</p>}
          {!listening && !sessionEnded && <p className="text-[13px] text-center mt-2" style={{ color: C.dim }}>Real-time analysis via Deepgram nova-2</p>}
        </div>

        {/* ── Threat level — no box ── */}
        <div>
          <div className="flex items-center justify-between mb-4">
            <SectionTitle>Audio threat level</SectionTitle>
            {(listening || sessionEnded) && <span className={`text-[13px] font-bold px-3 py-1.5 rounded-full ${colors.pill}`}>{audioLevel}</span>}
          </div>
          <div className={`flex flex-col items-center py-2 ${!listening && !sessionEnded ? "opacity-20" : ""}`}><RiskGauge score={audioScore} level={audioLevel} size={140} /></div>
          {!listening && !sessionEnded && <p className="text-center text-[14px] mt-4" style={{ color: C.dim }}>Waiting for audio stream...</p>}
          {sessionEnded && <p className="text-center text-[14px] mt-4 font-medium" style={{ color: C.muted }}>Session ended — report saved to Logs tab</p>}
        </div>

        {/* ── Transcript — no outer box, scrollable inner ── */}
        <div>
          <SectionLabel>Live transcript</SectionLabel>
          <div ref={transcriptRef} className="rounded-xl p-4 min-h-28 max-h-48 overflow-y-auto" style={{ background: "rgba(0,0,0,0.35)", border: "1px solid rgba(255,255,255,0.07)" }}>
            {transcript ? <p className="text-[15px] leading-relaxed font-mono" style={{ color: C.text }}>{transcript}</p> : <p className="text-[13px] text-center mt-6" style={{ color: C.dim }}>{listening ? "Listening..." : "Transcript appears here during analysis"}</p>}
          </div>
        </div>

        {/* ── Audio flags — no box ── */}
        <div>
          <SectionLabel>Audio flags</SectionLabel>
          {audioFlags.length > 0
            ? <div className="flex flex-wrap">{audioFlags.map((f, i) => <Badge key={i} text={f} type={audioLevel === "HIGH" ? "red" : "amber"} />)}</div>
            : <div className="space-y-2">{["Synthetic voice detection", "Social engineering phrases", "Authority impersonation"].map(item => (
              <div key={item} className="flex items-center gap-2 opacity-30">
                <div className="w-1.5 h-1.5 rounded-full" style={{ background: C.dim }} />
                <span className="text-[14px]" style={{ color: C.muted }}>{item}</span>
              </div>
            ))}
            </div>
          }
        </div>
      </div>
    </>
  );
}

// ─── SVG ICONS FOR NAV ────────────────────────────────────────────────────────
const EmailIcon = (props) => <svg {...props} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect width="20" height="16" x="2" y="4" rx="2" /><path d="m22 7-8.97 5.7a1.94 1.94 0 0 1-2.06 0L2 7" /></svg>;
const MicIcon = (props) => <svg {...props} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M12 2a3 3 0 0 0-3 3v7a3 3 0 0 0 6 0V5a3 3 0 0 0-3-3Z" /><path d="M19 10v2a7 7 0 0 1-14 0v-2" /><line x1="12" x2="12" y1="19" y2="22" /></svg>;
const FileTextIcon = (props) => <svg {...props} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M15 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7Z" /><path d="M14 2v4a2 2 0 0 0 2 2h4" /><path d="M10 9H8" /><path d="M16 13H8" /><path d="M16 17H8" /></svg>;
const ClipboardIcon = (props) => <svg {...props} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect width="8" height="4" x="8" y="2" rx="1" ry="1" /><path d="M16 4h2a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h2" /><path d="M12 11h4" /><path d="M12 16h4" /><path d="M8 11h.01" /><path d="M8 16h.01" /></svg>;




// ─── ROOT ─────────────────────────────────────────────────────────────────────
export default function App() {
  const [showDashboard, setShowDashboard] = useState(false);
  const [activeTab, setActiveTab] = useState("email");
  const [simTrigger, setSimTrigger] = useState(0);
  const [simRunning, setSimRunning] = useState(false);
  const [reports, setReports] = useState([]);
  const [currentReport, setCurrentReport] = useState(null);
  const [toast, setToast] = useState(null);
  const [drawerReport, setDrawerReport] = useState(null);

  const runSimulation = () => { setSimRunning(true); setSimTrigger(n => n + 1); setTimeout(() => setSimRunning(false), 3000); };

  const handleReportGenerated = useCallback((report) => {
    setCurrentReport(report);
    setReports(prev => [report, ...prev]);
    setToast({ report });
    setActiveTab("report");
  }, []);

  // ── Landing page ──
  if (!showDashboard) {
    return <RainingLetters onStart={() => setShowDashboard(true)} />;
  }

  // ── Dashboard ──
  const sidebarItems = [
    { id: "email", icon: <EmailIcon />, label: "Email Shield", count: reports.filter(r => r.type === "email").length || null },
    { id: "audio", icon: <MicIcon />, label: "Audio Shield", count: reports.filter(r => r.type === "audio").length || null },
    { id: "report", icon: <FileTextIcon />, label: "Report", dot: currentReport ? C.accent : null },
    { id: "logs", icon: <ClipboardIcon />, label: "Logs", count: reports.length || null },
  ];

  const categories = [
    { label: "Phishing", count: reports.filter(r => r.riskLevel === "HIGH").length, color: "#e06060" },
    { label: "Suspicious", count: reports.filter(r => r.riskLevel === "MEDIUM").length, color: "#d4a050" },
    { label: "Clean", count: reports.filter(r => r.riskLevel === "LOW").length, color: "#3d8b6e" },
  ];

  return (
    <div className="h-screen flex overflow-hidden" style={{ color: C.text, fontFamily: "-apple-system, 'Segoe UI', Inter, Helvetica, Arial, sans-serif", background: "radial-gradient(ellipse 100% 70% at 50% 0%, #0a1a2e 0%, #0d0d0d 55%, #0d0d0d 100%)" }}>
      <style>{`
        @keyframes spin{to{transform:rotate(360deg);}}
        @keyframes pulse{0%,100%{opacity:1}50%{opacity:0.4}}
        @keyframes slideInRight{from{transform:translateX(100%)}to{transform:translateX(0)}}
        @keyframes slideUpToast{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:translateY(0)}}
        @keyframes fadeInBg{from{opacity:0}to{opacity:1}}
        input::placeholder,textarea::placeholder{color:#2a2a2a;}
        input:focus,textarea:focus{border-color:rgba(74,158,255,0.4)!important;box-shadow:0 0 0 3px rgba(74,158,255,0.08);}
      `}</style>

      {/* ── Left Sidebar (glass) ── */}
      <aside className="glass-sidebar flex flex-col w-52 flex-shrink-0">
        <div className="flex items-center gap-2 px-4 py-4" style={{ borderBottom: "1px solid rgba(255,255,255,0.06)" }}>
          <Shield className="w-4 h-4" style={{ color: C.accent }} />
          <span className="text-[13px] font-semibold" style={{ color: C.text }}>PhishNet</span>
          <span className="ml-auto w-1.5 h-1.5 rounded-full" style={{ background: C.green }} />
        </div>

        <nav className="flex-1 px-1 py-3 overflow-y-auto">
          <MenuVertical
            menuItems={sidebarItems}
            activeId={activeTab}
            onItemClick={(id) => setActiveTab(id)}
            color={C.accent}
          />
          <div className="!mt-3 !mb-2" style={{ borderTop: "1px solid rgba(255,255,255,0.06)" }} />
          <p className="px-2.5 text-[10px] uppercase tracking-widest font-medium mb-1.5" style={{ color: C.dim }}>Threat Overview</p>
          {categories.map(cat => (
            <div key={cat.label} className="flex items-center gap-2 px-2.5 py-1 text-[12px]" style={{ color: C.muted }}>
              <span className="w-1.5 h-1.5 rounded-full flex-shrink-0" style={{ background: cat.color }} />
              <span className="flex-1">{cat.label}</span>
              <span className="text-[11px] font-mono" style={{ color: C.dim }}>{cat.count}</span>
            </div>
          ))}
        </nav>

        <div className="px-2 py-3" style={{ borderTop: "1px solid rgba(255,255,255,0.06)" }}>
          <GlassButton
            className="glass-button-danger w-full"
            size="sm"
            onClick={runSimulation}
            disabled={simRunning}
            contentClassName="justify-center gap-1.5"
          >
            <span>⚡</span>{simRunning ? "Running..." : "Red Team Demo"}
          </GlassButton>
        </div>
      </aside>

      {/* ── Main Content ── */}
      <main className="flex-1 overflow-y-auto">
        <div className="max-w-4xl mx-auto px-6 py-5">
          <div className="fade-in" key={activeTab}>
            {activeTab === "email" && <EmailPanel simTrigger={simTrigger} onReportGenerated={handleReportGenerated} />}
            {activeTab === "audio" && <AudioPanel simTrigger={simTrigger} onReportGenerated={handleReportGenerated} />}
            {activeTab === "report" && <ReportTab report={currentReport} />}
            {activeTab === "logs" && <LogsPanel reports={reports} onOpenReport={setDrawerReport} />}
          </div>
        </div>
      </main>

      {drawerReport && <ReportDrawer report={drawerReport} onClose={() => setDrawerReport(null)} />}
      {toast && <ReportToast report={toast.report} onView={() => { setActiveTab("report"); setToast(null); }} onDismiss={() => setToast(null)} />}
    </div>
  );
}


