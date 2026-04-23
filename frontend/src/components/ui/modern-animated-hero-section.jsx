import { useState, useEffect, useCallback, useRef } from "react";

class TextScramble {
  constructor(el) {
    this.el = el;
    this.chars = "!<>-_\\/[]{}—=+*^?#";
    this.queue = [];
    this.frame = 0;
    this.frameRequest = 0;
    this.resolve = () => {};
    this.update = this.update.bind(this);
  }

  setText(newText) {
    const oldText = this.el.innerText;
    const length = Math.max(oldText.length, newText.length);
    const promise = new Promise((resolve) => (this.resolve = resolve));
    this.queue = [];

    for (let i = 0; i < length; i++) {
      const from = oldText[i] || "";
      const to = newText[i] || "";
      const start = Math.floor(Math.random() * 40);
      const end = start + Math.floor(Math.random() * 40);
      this.queue.push({ from, to, start, end });
    }

    cancelAnimationFrame(this.frameRequest);
    this.frame = 0;
    this.update();
    return promise;
  }

  update() {
    let output = "";
    let complete = 0;

    for (let i = 0, n = this.queue.length; i < n; i++) {
      let { from, to, start, end, char } = this.queue[i];
      if (this.frame >= end) {
        complete++;
        output += to;
      } else if (this.frame >= start) {
        if (!char || Math.random() < 0.28) {
          char = this.chars[Math.floor(Math.random() * this.chars.length)];
          this.queue[i].char = char;
        }
        output += `<span class="dud">${char}</span>`;
      } else {
        output += from;
      }
    }

    this.el.innerHTML = output;
    if (complete === this.queue.length) {
      this.resolve();
    } else {
      this.frameRequest = requestAnimationFrame(this.update);
      this.frame++;
    }
  }
}

function ScrambledTitle() {
  const elementRef = useRef(null);
  const scramblerRef = useRef(null);
  const [mounted, setMounted] = useState(false);

  useEffect(() => {
    if (elementRef.current && !scramblerRef.current) {
      scramblerRef.current = new TextScramble(elementRef.current);
      setMounted(true);
    }
  }, []);

  useEffect(() => {
    if (mounted && scramblerRef.current) {
      const phrases = [
        "PhishNet",
        "Phishing Shield",
        "Deepfake Detection",
        "Real-time Protection",
        "AI-Powered Security",
        "Stay Protected",
      ];

      let counter = 0;
      const next = () => {
        if (scramblerRef.current) {
          scramblerRef.current.setText(phrases[counter]).then(() => {
            setTimeout(next, 2000);
          });
          counter = (counter + 1) % phrases.length;
        }
      };

      next();
    }
  }, [mounted]);

  return (
    <h1
      ref={elementRef}
      className="text-white text-5xl sm:text-6xl md:text-7xl font-bold tracking-wider"
      style={{ fontFamily: "monospace" }}
    >
      PhishNet
    </h1>
  );
}

export default function RainingLetters({ onStart }) {
  const [characters, setCharacters] = useState([]);
  const [activeIndices, setActiveIndices] = useState(new Set());
  const [buttonHover, setButtonHover] = useState(false);
  const [entering, setEntering] = useState(false);

  const createCharacters = useCallback(() => {
    const allChars =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;:,.<>?";
    const charCount = 300;
    const newCharacters = [];

    for (let i = 0; i < charCount; i++) {
      newCharacters.push({
        char: allChars[Math.floor(Math.random() * allChars.length)],
        x: Math.random() * 100,
        y: Math.random() * 100,
        speed: 0.1 + Math.random() * 0.3,
      });
    }

    return newCharacters;
  }, []);

  useEffect(() => {
    setCharacters(createCharacters());
  }, [createCharacters]);

  useEffect(() => {
    const updateActiveIndices = () => {
      const newActiveIndices = new Set();
      const numActive = Math.floor(Math.random() * 3) + 3;
      for (let i = 0; i < numActive; i++) {
        newActiveIndices.add(Math.floor(Math.random() * characters.length));
      }
      setActiveIndices(newActiveIndices);
    };

    const flickerInterval = setInterval(updateActiveIndices, 50);
    return () => clearInterval(flickerInterval);
  }, [characters.length]);

  useEffect(() => {
    let animationFrameId;

    const updatePositions = () => {
      setCharacters((prevChars) =>
        prevChars.map((char) => ({
          ...char,
          y: char.y + char.speed,
          ...(char.y >= 100 && {
            y: -5,
            x: Math.random() * 100,
            char: "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;:,.<>?"[
              Math.floor(
                Math.random() *
                  "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;:,.<>?"
                    .length
              )
            ],
          }),
        }))
      );
      animationFrameId = requestAnimationFrame(updatePositions);
    };

    animationFrameId = requestAnimationFrame(updatePositions);
    return () => cancelAnimationFrame(animationFrameId);
  }, []);

  const handleStart = () => {
    setEntering(true);
    setTimeout(() => {
      if (onStart) onStart();
    }, 600);
  };

  return (
    <div
      className={`relative w-full h-screen bg-black overflow-hidden transition-opacity duration-500 ${entering ? "opacity-0 scale-105" : "opacity-100"}`}
      style={{ transition: "opacity 0.5s ease, transform 0.5s ease" }}
    >
      {/* ── Header Nav ── */}
      <header className="absolute top-0 left-0 right-0 z-30">
        <div className="mx-auto max-w-6xl px-6 lg:px-12">
          <div className="flex items-center justify-between py-4 lg:py-5">
            {/* Brand */}
            <div className="flex items-center gap-2">
              <svg viewBox="0 0 24 24" fill="none" stroke="#06b6d4" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="w-6 h-6">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10" />
              </svg>
              <span className="text-white font-bold text-lg tracking-wide" style={{ fontFamily: "monospace" }}>PhishNet</span>
            </div>
            {/* Nav links */}
            <nav className="hidden lg:flex items-center gap-8">
              {["Features", "Solution", "Pricing", "About"].map(item => (
                <a key={item} href="#" className="text-sm text-slate-400 hover:text-white transition-colors duration-200" style={{ fontFamily: "monospace" }}>{item}</a>
              ))}
            </nav>
            {/* CTA */}
            <div className="flex items-center gap-3">
              <a href="#" className="hidden sm:inline text-sm text-slate-400 hover:text-white transition-colors px-3 py-1.5" style={{ fontFamily: "monospace" }}>Login</a>
              <button
                onClick={handleStart}
                className="text-sm font-semibold px-4 py-2 rounded-lg transition-all duration-300"
                style={{
                  fontFamily: "monospace",
                  background: "rgba(6,182,212,0.15)",
                  border: "1px solid rgba(6,182,212,0.3)",
                  color: "#22d3ee",
                }}
              >
                Get Started
              </button>
            </div>
          </div>
        </div>
      </header>

      {/* Center content */}
      <div className="absolute top-1/2 left-1/2 transform -translate-x-1/2 -translate-y-1/2 z-20 flex flex-col items-center gap-8">
        <ScrambledTitle />

        {/* Subtitle */}
        <p
          className="text-slate-500 text-sm sm:text-base tracking-[0.3em] uppercase"
          style={{ fontFamily: "monospace" }}
        >
          Phishing & Deepfake Shield
        </p>

        {/* Start button */}
        <button
          onClick={handleStart}
          onMouseEnter={() => setButtonHover(true)}
          onMouseLeave={() => setButtonHover(false)}
          className="relative mt-4 group"
        >
          {/* Glow ring */}
          <div
            className="absolute inset-0 rounded-full transition-all duration-500"
            style={{
              background: buttonHover
                ? "radial-gradient(circle, rgba(0,255,100,0.15) 0%, transparent 70%)"
                : "radial-gradient(circle, rgba(0,255,100,0.05) 0%, transparent 70%)",
              transform: "scale(2.5)",
            }}
          />
          {/* Button */}
          <div
            className="relative px-10 py-4 rounded-full border transition-all duration-300"
            style={{
              borderColor: buttonHover
                ? "rgba(0,255,100,0.6)"
                : "rgba(0,255,100,0.2)",
              background: buttonHover
                ? "rgba(0,255,100,0.08)"
                : "rgba(0,255,100,0.02)",
              boxShadow: buttonHover
                ? "0 0 30px rgba(0,255,100,0.15), inset 0 0 30px rgba(0,255,100,0.05)"
                : "0 0 15px rgba(0,255,100,0.05)",
            }}
          >
            <span
              className="text-sm sm:text-base tracking-[0.4em] uppercase transition-colors duration-300"
              style={{
                color: buttonHover ? "#00ff64" : "rgba(0,255,100,0.5)",
                fontFamily: "monospace",
                textShadow: buttonHover
                  ? "0 0 10px rgba(0,255,100,0.4)"
                  : "none",
              }}
            >
              ▶ ENTER SHIELD
            </span>
          </div>
        </button>

        {/* Bottom tag */}
        <p
          className="text-slate-700 text-xs tracking-widest mt-2"
          style={{ fontFamily: "monospace" }}
        >
          AI-powered · Real-time · Edge mode
        </p>
      </div>

      {/* Raining Characters */}
      {characters.map((char, index) => (
        <span
          key={index}
          className="absolute text-xs transition-colors duration-100"
          style={{
            left: `${char.x}%`,
            top: `${char.y}%`,
            transform: `translate(-50%, -50%) ${activeIndices.has(index) ? "scale(1.25)" : "scale(1)"}`,
            color: activeIndices.has(index) ? "#00ff00" : "#334155",
            fontWeight: activeIndices.has(index) ? "bold" : "300",
            textShadow: activeIndices.has(index)
              ? "0 0 8px rgba(0,255,0,0.8), 0 0 12px rgba(0,255,0,0.4)"
              : "none",
            opacity: activeIndices.has(index) ? 1 : 0.4,
            transition: "color 0.1s, transform 0.1s, text-shadow 0.1s",
            willChange: "transform, top",
            fontSize: "1.8rem",
            zIndex: activeIndices.has(index) ? 10 : 1,
          }}
        >
          {char.char}
        </span>
      ))}

      {/* Dud style */}
      <style>{`
        .dud {
          color: #0f0;
          opacity: 0.7;
        }
      `}</style>
    </div>
  );
}
