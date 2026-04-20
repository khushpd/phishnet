import { useState, useRef, useEffect, useCallback } from "react";
import axios from "axios";

// ─── DESIGN TOKENS ────────────────────────────────────────────────────────────
const RISK = {
  HIGH: { border: "border-red-500", bg: "bg-red-950/40", text: "text-red-400", pill: "bg-red-500/20 text-red-400 border border-red-500/30", dot: "#ef4444", label: "HIGH" },
  MEDIUM: { border: "border-amber-500", bg: "bg-amber-950/40", text: "text-amber-400", pill: "bg-amber-500/20 text-amber-400 border border-amber-500/30", dot: "#f59e0b", label: "MEDIUM" },
  LOW: { border: "border-emerald-500", bg: "bg-emerald-950/40", text: "text-emerald-400", pill: "bg-emerald-500/20 text-emerald-400 border border-emerald-500/30", dot: "#10b981", label: "LOW" },
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
function SectionLabel({ children, className = "" }) { return <p className={`text-xs font-semibold uppercase tracking-widest text-slate-500 mb-2 ${className}`}>{children}</p>; }
function Badge({ text, type = "gray" }) {
  const map = { gray: "bg-slate-800 text-slate-300 border border-slate-700", red: "bg-red-500/20 text-red-400 border border-red-500/30", amber: "bg-amber-500/20 text-amber-400 border border-amber-500/30", green: "bg-emerald-500/20 text-emerald-400 border border-emerald-500/30", blue: "bg-cyan-500/20 text-cyan-400 border border-cyan-500/30", purple: "bg-violet-500/20 text-violet-400 border border-violet-500/30" };
  return <span className={`inline-block text-xs font-medium px-2.5 py-1 rounded-md mr-1 mb-1 ${map[type] ?? map.gray}`}>{text}</span>;
}
function PassFail({ ok, yes, no }) { return ok ? <Badge text={yes} type="green" /> : <Badge text={no} type="red" />; }
function Divider({ className = "" }) { return <div className={`border-t border-slate-800 my-4 ${className}`} />; }
function Card({ children, className = "" }) { return <div className={`bg-slate-900 border border-slate-800 rounded-xl p-4 ${className}`}>{children}</div>; }

// ─── RISK GAUGE ───────────────────────────────────────────────────────────────
function RiskGauge({ score = 0, level = "LOW", size = 130 }) {
  const r = 46, circ = 2 * Math.PI * r, fill = circ - (Math.min(score, 100) / 100) * circ;
  const col = RISK[level]?.dot ?? "#64748b", cx = size / 2;
  return (
    <div className="flex flex-col items-center">
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`}>
        <circle cx={cx} cy={cx} r={r} fill="none" stroke="#1e293b" strokeWidth="9" />
        <circle cx={cx} cy={cx} r={r} fill="none" stroke={col} strokeWidth="9" strokeDasharray={circ} strokeDashoffset={fill} strokeLinecap="round" transform={`rotate(-90 ${cx} ${cx})`} style={{ transition: "stroke-dashoffset 0.6s ease" }} />
        <text x={cx} y={cx - 6} textAnchor="middle" fontSize="22" fontWeight="700" fill={col}>{score}</text>
        <text x={cx} y={cx + 12} textAnchor="middle" fontSize="10" fill="#475569">/100</text>
      </svg>
      <span className={`text-xs font-bold px-3 py-1 rounded-full mt-1 ${RISK[level]?.pill ?? "bg-slate-800 text-slate-400"}`}>{level} RISK</span>
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
        ctx.beginPath(); ctx.strokeStyle = "#06b6d4"; ctx.lineWidth = 2;
        buf.forEach((v, i) => { const x = (i / buf.length) * W, y = ((v / 128) * H) / 2; i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y); });
        ctx.lineTo(W, H / 2); ctx.stroke();
      } else {
        ctx.beginPath(); ctx.strokeStyle = "#1e293b"; ctx.lineWidth = 2;
        for (let x = 0; x < W; x++) { const y = H / 2 + Math.sin(x * 0.08) * 4 + Math.cos(x * 0.15) * 2; x === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y); }
        ctx.stroke();
      }
    };
    draw(); return () => cancelAnimationFrame(rafRef.current);
  }, [active, analyserRef]);
  return <canvas ref={canvasRef} width={500} height={60} className="w-full h-14 rounded-lg bg-slate-950" />;
}

// ─── FILE UPLOAD SCANNER ──────────────────────────────────────────────────────
function FileUploadScanner() {
  const [scanResult, setScanResult] = useState(null), [dragging, setDragging] = useState(false);
  const inputRef = useRef(null);
  const handleFile = (file) => { if (!file) return; setScanResult(scanUploadedFile(file)); };
  const onDrop = (e) => { e.preventDefault(); setDragging(false); const f = e.dataTransfer.files?.[0]; if (f) handleFile(f); };
  const rc = { HIGH: { bg: "bg-red-950/40", border: "border-red-500/50", pill: "bg-red-500/20 text-red-400" }, MEDIUM: { bg: "bg-amber-950/40", border: "border-amber-500/50", pill: "bg-amber-500/20 text-amber-400" }, LOW: { bg: "bg-emerald-950/40", border: "border-emerald-500/50", pill: "bg-emerald-500/20 text-emerald-400" } };
  return (
    <Card>
      <div className="flex items-center gap-2 mb-3"><SectionLabel>File scanner</SectionLabel><span className="text-xs bg-slate-800 text-slate-500 px-2 py-0.5 rounded-md border border-slate-700">metadata only</span></div>
      <div onDragOver={(e) => { e.preventDefault(); setDragging(true); }} onDragLeave={() => setDragging(false)} onDrop={onDrop} onClick={() => inputRef.current?.click()} className={`border-2 border-dashed rounded-xl p-6 text-center cursor-pointer transition-all ${dragging ? "border-cyan-500 bg-cyan-950/20" : "border-slate-700 hover:border-slate-600 hover:bg-slate-800/50"}`}>
        <span className="text-2xl block mb-2">📁</span>
        <p className="text-sm font-medium text-slate-400">Drop a file or click to browse</p>
        <p className="text-xs text-slate-600 mt-1">Filename, size, type only — never leaves device</p>
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
          <button onClick={() => { setScanResult(null); if (inputRef.current) inputRef.current.value = ""; }} className="mt-3 text-xs text-slate-600 hover:text-slate-400 transition-colors">Clear</button>
        </div>
      )}
    </Card>
  );
}

// ─── TONE ANALYSIS CARD ───────────────────────────────────────────────────────
function ToneAnalysisCard({ tone }) {
  if (!tone) return null;
  const { sentiment, tone_risk_score, urgency_count, authority_count, financial_count } = tone;
  const bars = [{ label: "Negative", value: sentiment.negative, color: "bg-red-500" }, { label: "Neutral", value: sentiment.neutral, color: "bg-slate-500" }, { label: "Positive", value: sentiment.positive, color: "bg-emerald-500" }];
  return (
    <Card>
      <div className="flex items-center justify-between mb-3"><SectionLabel>Tone analysis</SectionLabel><span className="text-xs text-slate-600">Tone risk: <span className="font-semibold text-slate-400">{tone_risk_score}/25</span></span></div>
      <div className="space-y-2 mb-4">{bars.map(bar => (<div key={bar.label} className="flex items-center gap-2"><span className="text-xs text-slate-500 w-14">{bar.label}</span><div className="flex-1 bg-slate-800 rounded-full h-1.5"><div className={`${bar.color} h-1.5 rounded-full`} style={{ width: `${Math.round(bar.value * 100)}%`, transition: "width 0.6s ease" }} /></div><span className="text-xs text-slate-600 w-8 text-right">{Math.round(bar.value * 100)}%</span></div>))}</div>
      <div className="grid grid-cols-3 gap-2">{[{ label: "Urgency", value: urgency_count, color: urgency_count > 0 ? "text-red-400" : "text-slate-600" }, { label: "Authority", value: authority_count, color: authority_count > 0 ? "text-amber-400" : "text-slate-600" }, { label: "Financial", value: financial_count, color: financial_count > 0 ? "text-red-400" : "text-slate-600" }].map(item => (<div key={item.label} className="bg-slate-950/60 rounded-lg p-2 text-center"><p className={`text-lg font-bold ${item.color}`}>{item.value}</p><p className="text-xs text-slate-600 leading-tight">{item.label}</p></div>))}</div>
    </Card>
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
    <div className="fixed inset-0 bg-black/80 flex items-center justify-center z-50 p-4 backdrop-blur-sm">
      <div className="bg-slate-900 border-2 border-red-500 rounded-2xl shadow-2xl shadow-red-500/20 max-w-md w-full p-8 fade-in">
        <div className="text-center mb-6"><div className="text-5xl mb-3">⚠️</div><h2 className="text-2xl font-bold text-red-400 mb-1">{title}</h2><p className="text-slate-500 text-sm">{subtitle}</p></div>
        <div className="bg-red-950/40 border border-red-500/30 rounded-xl px-4 py-3 mb-5"><p className="text-red-400 text-sm font-semibold mb-1">Do not:</p><ul className="text-red-300/70 text-sm list-disc list-inside space-y-1"><li>Click any links</li><li>Share personal or financial info</li><li>Transfer funds or reset credentials</li></ul></div>
        {flags.length > 0 && (<div className="mb-5"><SectionLabel>Reason flags</SectionLabel><div className="flex flex-wrap">{flags.map((f, i) => <Badge key={i} text={f} type="red" />)}</div></div>)}
        <button onClick={onClose} className="w-full bg-red-600 hover:bg-red-700 text-white py-3 rounded-xl font-semibold transition-colors">I understand — dismiss</button>
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
      <div className="fixed inset-0 bg-black/60 z-40 backdrop-blur-sm" onClick={onClose} style={{ animation: "fadeInBg 0.2s ease" }} />
      <div className="fixed right-0 top-0 h-full w-full max-w-xl bg-slate-950 border-l border-slate-800 z-50 overflow-y-auto shadow-2xl" style={{ animation: "slideInRight 0.25s cubic-bezier(0.16,1,0.3,1)" }}>
        <div className="sticky top-0 bg-slate-950/95 border-b border-slate-800 px-6 py-4 flex items-center justify-between backdrop-blur-sm z-10">
          <div>
            <p className="text-sm font-bold text-slate-100">Threat Report</p>
            <p className="text-xs text-slate-600 font-mono">{(report?.generatedAt instanceof Date ? report.generatedAt : new Date(report?.generatedAt)).toLocaleString()}</p>
          </div>
          <button onClick={onClose} className="w-8 h-8 flex items-center justify-center rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-slate-200 transition-colors text-lg">✕</button>
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
      <div className={`bg-slate-900 border-2 ${colors.border} rounded-xl shadow-2xl p-4 w-80 flex items-start gap-3`}>
        <div className={`w-8 h-8 rounded-lg flex items-center justify-center flex-shrink-0 ${report.riskLevel === "HIGH" ? "bg-red-500/20" : report.riskLevel === "MEDIUM" ? "bg-amber-500/20" : "bg-emerald-500/20"}`}>
          <span className="text-base">{report.type === "email" ? "✉️" : "🎙"}</span>
        </div>
        <div className="flex-1 min-w-0">
          <p className="text-xs font-bold text-slate-200 mb-0.5">Report ready</p>
          <p className={`text-xs font-semibold ${colors.text} mb-1`}>{report.riskLevel} RISK · Score {report.riskScore}/100</p>
          <p className="text-xs text-slate-600 truncate">{report.type === "email" ? `From: ${report.sender}` : `${report.flags?.length ?? 0} flag(s) detected`}</p>
        </div>
        <div className="flex flex-col gap-1 flex-shrink-0">
          <button onClick={onView} className="text-xs bg-cyan-600 hover:bg-cyan-700 text-white px-3 py-1.5 rounded-lg font-semibold transition-colors">View</button>
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
    <button onClick={onClick} className={`w-full text-left bg-slate-900 border-l-4 border border-slate-800 ${colors.border} rounded-xl p-5 hover:bg-slate-800/70 transition-all group`}>
      <div className="flex items-start justify-between gap-3 mb-3">
        <div className="flex items-center gap-3">
          <div className={`w-9 h-9 rounded-lg flex items-center justify-center flex-shrink-0 ${report.riskLevel === "HIGH" ? "bg-red-500/15" : report.riskLevel === "MEDIUM" ? "bg-amber-500/15" : "bg-emerald-500/15"}`}>
            <span className="text-lg">{report.type === "email" ? "✉️" : "🎙"}</span>
          </div>
          <div>
            <div className="flex items-center gap-2"><span className="text-sm font-semibold text-slate-200 capitalize">{report.type} analysis</span><span className={`text-xs font-bold px-2 py-0.5 rounded-md ${colors.pill}`}>{report.riskLevel}</span></div>
            <p className="text-xs text-slate-600 font-mono mt-0.5">{ts.toLocaleString()}</p>
          </div>
        </div>
        <div className="text-right flex-shrink-0"><p className={`text-2xl font-bold ${colors.text}`}>{report.riskScore}</p><p className="text-xs text-slate-700">/100</p></div>
      </div>

      {report.type === "email" && (<div className="bg-slate-950/60 rounded-lg px-3 py-2 mb-3"><p className="text-xs text-slate-600">From: <span className="text-slate-400 font-mono">{report.sender}</span></p>{report.senderIntel?.lookalike_match && <p className="text-xs text-red-400 mt-0.5">⚠ Spoofs {report.senderIntel.lookalike_match}</p>}</div>)}
      {report.type === "audio" && report.transcript && (<div className="bg-slate-950/60 rounded-lg px-3 py-2 mb-3"><p className="text-xs text-slate-500 font-mono leading-relaxed" style={{ display: "-webkit-box", WebkitLineClamp: 2, WebkitBoxOrient: "vertical", overflow: "hidden" }}>{report.transcript.slice(0, 120)}{report.transcript.length > 120 ? "…" : ""}</p></div>)}

      <p className="text-xs text-slate-400 leading-relaxed mb-3">{report.summary}</p>

      {report.attackVector?.length > 0 && (<div className="flex flex-wrap gap-1 mb-3">{report.attackVector.slice(0, 3).map((v, i) => (<span key={i} className="text-xs bg-slate-800 border border-slate-700 text-slate-400 px-2 py-0.5 rounded-md">{v}</span>))}{report.attackVector.length > 3 && <span className="text-xs text-slate-600 px-1 py-0.5">+{report.attackVector.length - 3} more</span>}</div>)}

      {topExp.length > 0 && (<div className="space-y-1.5 mb-3">{topExp.map((exp, i) => (<div key={i} className={`flex items-start gap-2 rounded-lg px-3 py-2 ${exp.severity === "high" ? "bg-red-950/30 border border-red-500/20" : "bg-amber-950/30 border border-amber-500/20"}`}><span className="text-xs flex-shrink-0">{exp.icon}</span><p className={`text-xs font-medium ${exp.severity === "high" ? "text-red-400" : "text-amber-400"}`}>{exp.title}</p></div>))}</div>)}

      {topFlags.length > 0 && (<div className="flex flex-wrap gap-1 mb-3">{topFlags.map((f, i) => <Badge key={i} text={f} type="amber" />)}</div>)}

      <div className={`rounded-lg px-3 py-2 ${report.riskLevel === "HIGH" ? "bg-red-950/30 border border-red-500/20" : report.riskLevel === "MEDIUM" ? "bg-amber-950/30 border border-amber-500/20" : "bg-emerald-950/30 border border-emerald-500/20"}`}>
        <p className={`text-xs font-medium ${colors.text}`}>{report.recommendation}</p>
      </div>

      <div className="flex items-center gap-1.5 mt-3 opacity-0 group-hover:opacity-100 transition-opacity">
        <span className="text-xs text-slate-600">Click to open full report</span>
        <span className="text-xs text-slate-700">→</span>
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
      <div className="flex items-center justify-between mb-5 gap-3">
        <div className="flex items-center gap-1 bg-slate-900 border border-slate-800 rounded-lg p-1">
          {[{ id: "all", label: `All (${reports.length})` }, { id: "email", label: `✉️ Email (${reports.filter(r => r.type === "email").length})` }, { id: "audio", label: `🎙 Audio (${reports.filter(r => r.type === "audio").length})` }].map(f => (
            <button key={f.id} onClick={() => setFilter(f.id)} className={`text-xs px-3 py-1.5 rounded-md font-semibold transition-colors ${filter === f.id ? "bg-slate-700 text-slate-100" : "text-slate-600 hover:text-slate-400"}`}>{f.label}</button>
          ))}
        </div>
        {highCount > 0 && <span className="text-xs bg-red-500/20 text-red-400 border border-red-500/30 px-2.5 py-1 rounded-full font-bold">{highCount} HIGH risk</span>}
      </div>

      {reports.length > 0 && (
        <div className="grid grid-cols-3 gap-3 mb-5">
          {[{ label: "Total scans", value: reports.length, color: "text-cyan-400" }, { label: "High risk", value: reports.filter(r => r.riskLevel === "HIGH").length, color: "text-red-400" }, { label: "Clean", value: reports.filter(r => r.riskLevel === "LOW").length, color: "text-emerald-400" }].map(item => (
            <div key={item.label} className="bg-slate-900 border border-slate-800 rounded-xl p-4 text-center">
              <p className={`text-3xl font-bold ${item.color}`}>{item.value}</p>
              <p className="text-xs text-slate-600 mt-1">{item.label}</p>
            </div>
          ))}
        </div>
      )}

      {filtered.length === 0 ? (
        <div className="flex flex-col items-center justify-center py-20 text-center"><span className="text-4xl mb-4">📋</span><p className="text-sm text-slate-500">No {filter !== "all" ? filter : ""} reports yet</p><p className="text-xs text-slate-700 mt-1">Completed analyses will appear here</p></div>
      ) : (
        <div className="space-y-4">{filtered.map(report => (<LogEntryCard key={report.id} report={report} onClick={() => onOpenReport(report)} />))}</div>
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
      <div className="flex flex-col gap-4">
        <Card>
          <SectionLabel>Email Shield</SectionLabel>
          <div className="space-y-3">
            <div><label className="block text-xs text-slate-600 mb-1">Sender email</label><input type="text" placeholder="sender@domain.com" value={sender} onChange={e => setSender(e.target.value)} className="w-full px-3 py-2 bg-slate-950 border border-slate-700 rounded-lg text-sm text-slate-200 placeholder-slate-700 focus:outline-none focus:ring-2 focus:ring-cyan-500/50 focus:border-cyan-500/50" /></div>
            <div><label className="block text-xs text-slate-600 mb-1">Email body</label><textarea rows={7} placeholder="Paste email content here..." value={text} onChange={e => setText(e.target.value)} className="w-full px-3 py-2 bg-slate-950 border border-slate-700 rounded-lg text-sm text-slate-200 placeholder-slate-700 focus:outline-none focus:ring-2 focus:ring-cyan-500/50 focus:border-cyan-500/50 resize-none" /></div>
            <button onClick={() => analyze()} disabled={loading || !text.trim() || !sender.trim()} className="w-full bg-cyan-600 hover:bg-cyan-700 disabled:bg-slate-800 disabled:text-slate-600 text-white py-2.5 rounded-lg text-sm font-semibold transition-colors">{loading ? "Analyzing..." : "Analyze Email"}</button>
            {error && <p className="text-xs text-red-400 text-center">{error}</p>}
          </div>
        </Card>
        <FileUploadScanner />
        {loading && (<Card className="flex flex-col items-center justify-center py-10"><div className="w-8 h-8 border-4 border-cyan-500 border-t-transparent rounded-full mb-3" style={{ animation: "spin 1s linear infinite" }} /><p className="text-sm text-slate-500">Running analysis...</p><p className="text-xs text-slate-700 mt-1">Checking URLhaus threat database...</p></Card>)}
        {!result && !loading && (<Card className="flex flex-col items-center justify-center py-10 text-center"><span className="text-3xl mb-3">🔍</span><p className="text-sm font-medium text-slate-500">No analysis yet</p><p className="text-xs text-slate-700 mt-1">Paste an email and click Analyze</p></Card>)}
        {result && !loading && (
          <Card className={`border ${RISK[result.risk_level ?? "LOW"].border}`}>
            <div className="flex items-center justify-between">
              <div><SectionLabel>Analysis complete</SectionLabel><p className="text-sm text-slate-400">Report saved — switching to Report tab.</p><p className="text-xs text-slate-600 mt-1">Also logged in the <span className="text-cyan-400">Logs</span> tab.</p></div>
              <RiskGauge score={result.risk_score} level={result.risk_level} size={90} />
            </div>
          </Card>
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
      <div className="flex flex-col gap-4">
        <Card className={listening ? `border-2 ${colors.border}` : ""}>
          <div className="flex items-center justify-between mb-4">
            <SectionLabel>Audio Shield</SectionLabel>
            {listening && (<div className="flex items-center gap-3"><span className="text-xs font-mono text-slate-500">{fmt(duration)}</span><div className="flex items-center gap-1.5"><div className="w-2 h-2 rounded-full bg-red-500" style={{ animation: "pulse 1.5s ease-in-out infinite" }} /><span className="text-xs text-red-400 font-medium">Live</span></div></div>)}
          </div>
          <div className="bg-slate-950 border border-slate-800 rounded-xl p-3 mb-4"><LiveWaveform active={listening} analyserRef={analyserRef} /></div>
          <button onClick={listening ? stopListening : startListening} className={`w-full py-2.5 rounded-lg text-sm font-semibold transition-colors flex items-center justify-center gap-2 ${listening ? "bg-red-600 hover:bg-red-700 text-white" : "bg-cyan-600 hover:bg-cyan-700 text-white"}`}><span>{listening ? "⏹" : "🎙"}</span>{listening ? "Stop Audio Shield" : "Start Audio Shield"}</button>
          {audioError && <p className="text-xs text-red-400 text-center mt-2">{audioError}</p>}
          {!listening && !sessionEnded && <p className="text-xs text-slate-700 text-center mt-2">Real-time analysis via Deepgram nova-2</p>}
        </Card>
        <Card className={listening || sessionEnded ? `border-2 ${colors.border}` : ""}>
          <div className="flex items-center justify-between mb-4"><SectionLabel>Audio threat level</SectionLabel>{(listening || sessionEnded) && <span className={`text-xs font-semibold px-2.5 py-1 rounded-full ${colors.pill}`}>{audioLevel}</span>}</div>
          <div className={`flex flex-col items-center py-2 ${!listening && !sessionEnded ? "opacity-20" : ""}`}><RiskGauge score={audioScore} level={audioLevel} /></div>
          {!listening && !sessionEnded && <div className="bg-slate-950/60 border border-slate-800 rounded-lg px-3 py-2 text-center mt-2"><p className="text-slate-700 text-xs">Waiting for audio stream...</p></div>}
          {sessionEnded && <div className="mt-3 bg-slate-800/60 border border-slate-700 rounded-lg px-3 py-2 text-center"><p className="text-slate-400 text-xs">Session ended — report saved to Logs tab</p></div>}
        </Card>
        <Card>
          <SectionLabel>Live transcript</SectionLabel>
          <div ref={transcriptRef} className="bg-slate-950 border border-slate-800 rounded-xl p-4 min-h-28 max-h-48 overflow-y-auto">
            {transcript ? <p className="text-sm text-slate-300 leading-relaxed font-mono">{transcript}</p> : <p className="text-xs text-slate-700 text-center mt-6">{listening ? "Listening..." : "Transcript appears here during analysis"}</p>}
          </div>
        </Card>
        <Card>
          <SectionLabel>Audio flags</SectionLabel>
          {audioFlags.length > 0 ? <div className="flex flex-wrap">{audioFlags.map((f, i) => <Badge key={i} text={f} type={audioLevel === "HIGH" ? "red" : "amber"} />)}</div> : <div className="space-y-2">{["Synthetic voice detection", "Social engineering phrases", "Authority impersonation"].map(item => (<div key={item} className="flex items-center gap-2 opacity-20"><div className="w-1.5 h-1.5 rounded-full bg-slate-500" /><span className="text-xs text-slate-500">{item}</span></div>))}</div>}
        </Card>
      </div>
    </>
  );
}

// ─── TAB BAR ──────────────────────────────────────────────────────────────────
function TabBar({ active, onChange, logCount, hasReport }) {
  const tabs = [
    { id: "email", label: "Email Shield", icon: "✉️" },
    { id: "audio", label: "Audio Shield", icon: "🎙" },
    { id: "report", label: "Report", icon: "📄", badge: hasReport ? "●" : null },
    { id: "logs", label: "Logs", icon: "📋", badge: logCount > 0 ? logCount : null },
  ];
  return (
    <div className="flex gap-1 bg-slate-950 border border-slate-800 rounded-xl p-1">
      {tabs.map(tab => {
        const isActive = active === tab.id;
        return (
          <button key={tab.id} onClick={() => onChange(tab.id)} className={`flex-1 flex items-center justify-center gap-1.5 py-2.5 px-3 rounded-lg text-xs font-semibold transition-all ${isActive ? "bg-slate-800 text-slate-100 shadow-sm" : "text-slate-600 hover:text-slate-400 hover:bg-slate-900/50"}`}>
            <span className="text-sm">{tab.icon}</span>
            <span className="hidden sm:inline">{tab.label}</span>
            {tab.badge != null && (<span className={`text-xs px-1.5 py-0.5 rounded-full font-bold ml-0.5 ${isActive ? "bg-cyan-500/30 text-cyan-400" : "bg-slate-800 text-slate-500"}`}>{tab.badge}</span>)}
          </button>
        );
      })}
    </div>
  );
}

// ─── ROOT ─────────────────────────────────────────────────────────────────────
export default function App() {
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

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100" style={{ fontFamily: "'DM Mono','Fira Code',monospace" }}>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=DM+Mono:wght@400;500&family=DM+Sans:wght@400;500;600;700&display=swap');
        *{box-sizing:border-box;}body{background:#020617;}
        @keyframes spin{to{transform:rotate(360deg);}}
        @keyframes pulse{0%,100%{opacity:1}50%{opacity:0.4}}
        @keyframes fadeIn{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:translateY(0)}}
        @keyframes fadeInBg{from{opacity:0}to{opacity:1}}
        @keyframes slideInRight{from{transform:translateX(100%)}to{transform:translateX(0)}}
        @keyframes slideUpToast{from{opacity:0;transform:translateY(16px)}to{opacity:1;transform:translateY(0)}}
        .fade-in{animation:fadeIn 0.3s ease;}
        ::-webkit-scrollbar{width:4px;}::-webkit-scrollbar-track{background:#0f172a;}::-webkit-scrollbar-thumb{background:#334155;border-radius:2px;}
      `}</style>

      <header className="bg-slate-950 border-b border-slate-800/80 px-6 py-4 sticky top-0 z-40" style={{ background: "rgba(2,6,23,0.97)" }}>
        <div className="max-w-5xl mx-auto flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center"><span className="text-base">🛡️</span></div>
            <div>
              <h1 className="text-sm font-bold text-slate-100 tracking-wide" style={{ fontFamily: "'DM Sans',sans-serif" }}>PHISHING & DEEPFAKE SHIELD</h1>
              <p className="text-xs text-slate-600">Real-time threat analysis · Edge mode</p>
            </div>
          </div>
          <div className="flex items-center gap-3">
            <span className="hidden sm:flex text-xs bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 px-2.5 py-1 rounded-full font-medium items-center gap-1.5"><span className="w-1.5 h-1.5 rounded-full bg-emerald-400" style={{ animation: "pulse 2s infinite" }} />Edge Mode</span>
            <button onClick={runSimulation} disabled={simRunning} className="flex items-center gap-2 bg-red-600 hover:bg-red-700 disabled:bg-red-900 disabled:text-red-700 text-white text-xs font-bold px-4 py-2 rounded-lg transition-colors tracking-wide"><span>⚡</span>{simRunning ? "Running..." : "Red Team Demo"}</button>
            <div className="flex items-center gap-1.5"><div className="w-1.5 h-1.5 rounded-full bg-emerald-400" style={{ animation: "pulse 2s infinite" }} /><span className="text-xs text-slate-600">Backend live</span></div>
          </div>
        </div>
      </header>

      <main className="max-w-5xl mx-auto px-6 py-6">
        <div className="mb-6"><TabBar active={activeTab} onChange={setActiveTab} logCount={reports.length} hasReport={!!currentReport} /></div>
        <div className="fade-in" key={activeTab}>
          {activeTab === "email" && <EmailPanel simTrigger={simTrigger} onReportGenerated={handleReportGenerated} />}
          {activeTab === "audio" && <AudioPanel simTrigger={simTrigger} onReportGenerated={handleReportGenerated} />}
          {activeTab === "report" && <ReportTab report={currentReport} />}
          {activeTab === "logs" && <LogsPanel reports={reports} onOpenReport={setDrawerReport} />}
        </div>
      </main>

      {drawerReport && <ReportDrawer report={drawerReport} onClose={() => setDrawerReport(null)} />}
      {toast && <ReportToast report={toast.report} onView={() => { setActiveTab("report"); setToast(null); }} onDismiss={() => setToast(null)} />}
    </div>
  );
}