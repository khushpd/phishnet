import { useState, useRef } from "react";
import axios from "axios";

// ─── CONSTANTS ───────────────────────────────────────────────────────────────

const RISK = {
  HIGH: { border: "border-red-400", bg: "bg-red-50", text: "text-red-600", pill: "bg-red-100 text-red-700", dot: "#dc2626" },
  MEDIUM: { border: "border-amber-400", bg: "bg-amber-50", text: "text-amber-600", pill: "bg-amber-100 text-amber-700", dot: "#d97706" },
  LOW: { border: "border-green-400", bg: "bg-green-50", text: "text-green-600", pill: "bg-green-100 text-green-700", dot: "#16a34a" },
};

// ─── SMALL COMPONENTS ────────────────────────────────────────────────────────

function SectionLabel({ children }) {
  return <p className="section-label">{children}</p>;
}

function Badge({ text, type = "gray" }) {
  const map = {
    gray: "bg-slate-100 text-slate-600",
    red: "bg-red-100 text-red-700",
    amber: "bg-amber-100 text-amber-700",
    green: "bg-green-100 text-green-700",
    blue: "bg-blue-100 text-blue-700",
  };
  return (
    <span className={`inline-block text-xs font-medium px-2.5 py-1 rounded-full mr-1 mb-1 ${map[type]}`}>
      {text}
    </span>
  );
}

function PassFail({ ok, yes, no }) {
  return ok
    ? <Badge text={yes} type="green" />
    : <Badge text={no} type="red" />;
}

function Divider() {
  return <div className="border-t border-slate-100 my-4" />;
}

// ─── RISK GAUGE ──────────────────────────────────────────────────────────────

function RiskGauge({ score = 0, level = "LOW", size = 130 }) {
  const r = 46;
  const circ = 2 * Math.PI * r;
  const fill = circ - (Math.min(score, 100) / 100) * circ;
  const col = RISK[level]?.dot ?? "#94a3b8";
  const cx = size / 2;

  return (
    <div className="flex flex-col items-center">
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`}>
        <circle cx={cx} cy={cx} r={r} fill="none" stroke="#f1f5f9" strokeWidth="9" />
        <circle
          cx={cx} cy={cx} r={r}
          fill="none"
          stroke={col}
          strokeWidth="9"
          strokeDasharray={circ}
          strokeDashoffset={fill}
          strokeLinecap="round"
          transform={`rotate(-90 ${cx} ${cx})`}
          className="gauge-transition"
        />
        <text x={cx} y={cx - 6} textAnchor="middle" fontSize="22" fontWeight="600" fill={col}>{score}</text>
        <text x={cx} y={cx + 12} textAnchor="middle" fontSize="10" fill="#94a3b8">/100</text>
      </svg>
      <span className={`text-xs font-semibold px-3 py-1 rounded-full mt-1 ${RISK[level]?.pill ?? "bg-slate-100 text-slate-500"}`}>
        {level} RISK
      </span>
    </div>
  );
}

// ─── WAVEFORM PLACEHOLDER ────────────────────────────────────────────────────

function WaveformPlaceholder() {
  return (
    <div className="flex items-end justify-center gap-0.5 h-12 px-2">
      {Array.from({ length: 40 }).map((_, i) => (
        <div
          key={i}
          className="w-1 rounded-full bg-slate-200"
          style={{ height: `${20 + Math.sin(i * 0.4) * 15 + Math.cos(i * 0.7) * 10}%`, minHeight: 4 }}
        />
      ))}
    </div>
  );
}

// ─── SENDER INTELLIGENCE CARD ────────────────────────────────────────────────

function SenderIntelCard({ intel, senderFlags }) {
  if (!intel || Object.keys(intel).length === 0) return null;

  const ageDays = intel.domain_age_days;
  const ageFlag = intel.domain_age_flag ?? "Unable to verify";
  const ageType =
    ageFlag === "Unable to verify" ? "gray"
      : ageFlag === "Very new domain — high risk" ? "red"
        : ageFlag === "Relatively new domain" ? "amber"
          : "green";

  const rows = [
    {
      label: "Domain age",
      right: (
        <div className="flex items-center gap-2">
          {ageDays != null && <span className="text-xs text-slate-400">{ageDays}d</span>}
          <Badge text={ageFlag} type={ageType} />
        </div>
      ),
    },
    { label: "MX records", right: <PassFail ok={intel.mx_valid} yes="Valid" no="Missing" /> },
    { label: "SPF record", right: <PassFail ok={intel.spf_present} yes="Present" no="Missing" /> },
    { label: "DMARC record", right: <PassFail ok={intel.dmarc_present} yes="Present" no="Missing" /> },
    { label: "Disposable", right: <PassFail ok={!intel.is_disposable} yes="Clean" no="Disposable" /> },
    {
      label: "Lookalike",
      right: intel.lookalike_match
        ? <Badge text={`⚠ Spoof of ${intel.lookalike_match} (${intel.lookalike_distance} char)`} type="red" />
        : <Badge text="No match" type="green" />,
    },
  ];

  return (
    <div className="panel-card fade-in">
      <SectionLabel>Sender Intelligence</SectionLabel>
      <div className="space-y-3">
        {rows.map((row) => (
          <div key={row.label} className="flex items-center justify-between">
            <span className="text-sm text-slate-500">{row.label}</span>
            {row.right}
          </div>
        ))}
      </div>

      {senderFlags?.length > 0 && (
        <>
          <Divider />
          <SectionLabel>Sender flags</SectionLabel>
          <div className="flex flex-wrap">
            {senderFlags.map((f, i) => <Badge key={i} text={f} type="amber" />)}
          </div>
        </>
      )}
    </div>
  );
}

// ─── HIGH RISK MODAL ─────────────────────────────────────────────────────────

function HighRiskModal({ result, onClose }) {
  const allFlags = [
    ...(result.indicators ?? []),
    ...(result.sender_flags ?? []),
    ...(result.url_flags ?? []),
  ];
  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4">
      <div className="bg-white rounded-2xl shadow-2xl max-w-md w-full p-8 border-2 border-red-400 fade-in">
        <div className="text-center mb-6">
          <div className="text-5xl mb-3">⚠️</div>
          <h2 className="text-2xl font-bold text-red-600 mb-1">High Risk Detected</h2>
          <p className="text-slate-400 text-sm">This email shows strong signs of a phishing attempt</p>
        </div>

        <div className="bg-red-50 border border-red-200 rounded-xl px-4 py-3 mb-5">
          <p className="text-red-700 text-sm font-medium mb-1">Do not:</p>
          <ul className="text-red-600 text-sm list-disc list-inside space-y-1">
            <li>Click any links in this email</li>
            <li>Reply with personal or financial info</li>
            <li>Download any attachments</li>
          </ul>
        </div>

        {allFlags.length > 0 && (
          <div className="mb-5">
            <SectionLabel>Reason flags</SectionLabel>
            <div className="flex flex-wrap">
              {allFlags.map((f, i) => <Badge key={i} text={f} type="red" />)}
            </div>
          </div>
        )}

        <button
          onClick={onClose}
          className="w-full bg-red-600 hover:bg-red-700 text-white py-3 rounded-xl font-semibold transition-colors"
        >
          I understand — dismiss
        </button>
      </div>
    </div>
  );
}

// ─── EMAIL PANEL ─────────────────────────────────────────────────────────────

function EmailPanel() {
  const [text, setText] = useState("");
  const [sender, setSender] = useState("");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [modal, setModal] = useState(false);
  const [error, setError] = useState(null);

  const analyze = async () => {
    if (!text.trim() || !sender.trim()) return;
    setLoading(true);
    setError(null);
    setResult(null);
    setModal(false);
    try {
      const res = await axios.post("http://127.0.0.1:8000/api/analyze/email", {
        text,
        sender,
      });
      setResult(res.data);
      if (res.data.risk_level === "HIGH") setModal(true);
    } catch {
      setError("Backend unreachable — make sure FastAPI is running on port 8000.");
    } finally {
      setLoading(false);
    }
  };

  const level = result?.risk_level ?? "LOW";
  const colors = RISK[level];

  return (
    <>
      {modal && result && (
        <HighRiskModal result={result} onClose={() => setModal(false)} />
      )}

      <div className="flex flex-col gap-4">

        {/* Input */}
        <div className="panel-card">
          <SectionLabel>Email Shield</SectionLabel>
          <div className="space-y-3">
            <div>
              <label className="block text-xs text-slate-400 mb-1">Sender email</label>
              <input
                type="text"
                placeholder="sender@domain.com"
                value={sender}
                onChange={(e) => setSender(e.target.value)}
                className="w-full px-3 py-2 border border-slate-200 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
              />
            </div>
            <div>
              <label className="block text-xs text-slate-400 mb-1">Email body</label>
              <textarea
                rows={7}
                placeholder="Paste email content here..."
                value={text}
                onChange={(e) => setText(e.target.value)}
                className="w-full px-3 py-2 border border-slate-200 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 resize-none"
              />
            </div>
            <button
              onClick={analyze}
              disabled={loading || !text.trim() || !sender.trim()}
              className="w-full bg-blue-600 hover:bg-blue-700 disabled:bg-slate-200 disabled:text-slate-400 text-white py-2.5 rounded-lg text-sm font-semibold transition-colors"
            >
              {loading ? "Analyzing..." : "Analyze Email"}
            </button>
            {error && <p className="text-xs text-red-500 text-center">{error}</p>}
          </div>
        </div>

        {/* Loading */}
        {loading && (
          <div className="panel-card flex flex-col items-center justify-center py-10 fade-in">
            <div className="w-8 h-8 border-4 border-blue-500 border-t-transparent rounded-full spin mb-3" />
            <p className="text-sm text-slate-400">Running analysis...</p>
          </div>
        )}

        {/* Empty state */}
        {!result && !loading && (
          <div className="panel-card flex flex-col items-center justify-center py-10 text-center">
            <span className="text-3xl mb-3">🔍</span>
            <p className="text-sm font-medium text-slate-500">No analysis yet</p>
            <p className="text-xs text-slate-400 mt-1">Paste an email and click Analyze</p>
          </div>
        )}

        {/* Results */}
        {result && !loading && (
          <>
            <div className={`panel-card border-2 ${colors.border} fade-in`}>
              <div className="flex items-center justify-between mb-4">
                <SectionLabel>Threat assessment</SectionLabel>
                <span className={`text-xs font-semibold px-2.5 py-1 rounded-full ${colors.pill}`}>
                  {level}
                </span>
              </div>

              <RiskGauge score={result.risk_score} level={level} />

              <div className="flex justify-between text-xs text-slate-400 mt-3 px-1">
                <span>ML confidence: {(result.ml_probability * 100).toFixed(1)}%</span>
                <span>Raw: {result.raw_score}</span>
              </div>

              {level === "MEDIUM" && (
                <div className="mt-4 bg-amber-50 border border-amber-200 rounded-lg px-3 py-2">
                  <p className="text-amber-700 text-sm">⚠ Suspicious signals — review before acting</p>
                </div>
              )}
              {level === "LOW" && (
                <div className="mt-4 bg-green-50 border border-green-200 rounded-lg px-3 py-2">
                  <p className="text-green-700 text-sm">✓ No significant threats detected</p>
                </div>
              )}
            </div>

            {(result.indicators.length > 0 || result.url_flags.length > 0) && (
              <div className="panel-card fade-in">
                <SectionLabel>Content flags</SectionLabel>
                <div className="flex flex-wrap">
                  {result.indicators.map((f, i) => <Badge key={i} text={f} type="amber" />)}
                  {result.url_flags.map((f, i) => <Badge key={i} text={f} type="red" />)}
                </div>
                {result.urls_found.length > 0 && (
                  <>
                    <Divider />
                    <SectionLabel>URLs found</SectionLabel>
                    {result.urls_found.map((u, i) => (
                      <p key={i} className="text-xs font-mono text-slate-500 truncate">{u}</p>
                    ))}
                  </>
                )}
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

function AudioPanel() {
  return (
    <div className="flex flex-col gap-4">

      {/* Controls */}
      <div className="panel-card">
        <div className="flex items-center justify-between mb-4">
          <SectionLabel>Audio Shield</SectionLabel>
          <span className="text-xs bg-slate-100 text-slate-400 px-2 py-1 rounded-full">Day 5</span>
        </div>

        <div className="bg-slate-50 border border-slate-200 rounded-xl p-4 mb-4">
          <WaveformPlaceholder />
        </div>

        <button
          disabled
          className="w-full bg-slate-100 text-slate-400 py-2.5 rounded-lg text-sm font-semibold cursor-not-allowed flex items-center justify-center gap-2"
        >
          <span>🎙</span>
          Start Audio Shield
        </button>
        <p className="text-xs text-slate-400 text-center mt-2">
          Deepgram + Resemblyzer — coming Day 5
        </p>
      </div>

      {/* Audio gauge skeleton */}
      <div className="panel-card">
        <SectionLabel>Audio threat level</SectionLabel>
        <div className="flex flex-col items-center py-4 opacity-25">
          <RiskGauge score={0} level="LOW" />
        </div>
        <div className="bg-slate-50 border border-slate-200 rounded-lg px-3 py-2 text-center">
          <p className="text-slate-400 text-xs">Waiting for audio stream...</p>
        </div>
      </div>

      {/* Transcript skeleton */}
      <div className="panel-card">
        <SectionLabel>Live transcript</SectionLabel>
        <div className="bg-slate-50 border border-slate-200 rounded-xl p-4 min-h-28 flex items-center justify-center">
          <p className="text-xs text-slate-400 text-center">
            Transcript will appear here during audio analysis
          </p>
        </div>
      </div>

      {/* Audio flags skeleton */}
      <div className="panel-card">
        <SectionLabel>Audio flags</SectionLabel>
        <div className="space-y-2">
          {["Synthetic voice detection", "Social engineering phrases", "Authority impersonation"].map((item) => (
            <div key={item} className="flex items-center gap-2 opacity-25">
              <div className="w-2 h-2 rounded-full bg-slate-300" />
              <span className="text-xs text-slate-500">{item}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

// ─── SESSION LOG ─────────────────────────────────────────────────────────────

function SessionLog() {
  return (
    <div className="panel-card">
      <SectionLabel>Session threat log</SectionLabel>
      <div className="min-h-12 flex items-center justify-center">
        <p className="text-xs text-slate-400">Analyzed events will appear here</p>
      </div>
    </div>
  );
}

// ─── ROOT ────────────────────────────────────────────────────────────────────

export default function App() {
  return (
    <div className="min-h-screen bg-slate-50">

      <header className="bg-white border-b border-slate-200 px-6 py-4 sticky top-0 z-40">
        <div className="max-w-6xl mx-auto flex items-center justify-between">
          <div className="flex items-center gap-3">
            <span className="text-xl">🛡️</span>
            <div>
              <h1 className="text-base font-semibold text-slate-900 leading-tight">
                Phishing & Deepfake Shield
              </h1>
              <p className="text-xs text-slate-400">Real-time communication threat analysis</p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <div className="w-2 h-2 rounded-full bg-green-400 pulse-dot" />
            <span className="text-xs text-slate-400">Backend live</span>
          </div>
        </div>
      </header>

      <main className="max-w-6xl mx-auto px-6 py-6">
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 items-start">
          <EmailPanel />
          <AudioPanel />
        </div>
        <div className="mt-6">
          <SessionLog />
        </div>
      </main>

    </div>
  );
}