'use client';

import { useState, useEffect } from 'react';
import Link from 'next/link';

export default function LandingPage() {
  const [scrolled, setScrolled] = useState(false);

  useEffect(() => {
    const onScroll = () => setScrolled(window.scrollY > 40);
    window.addEventListener('scroll', onScroll, { passive: true });
    return () => window.removeEventListener('scroll', onScroll);
  }, []);

  return (
    <>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=Syne:wght@400;600;700;800&family=Plus+Jakarta+Sans:wght@300;400;500;600;700&display=swap');

        *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

        :root {
          --bg:        #07070E;
          --surface:   #0E0E18;
          --surface2:  #13131F;
          --border:    rgba(255,255,255,0.07);
          --border-hi: rgba(99,139,255,0.35);
          --blue:      #4F72FF;
          --blue-dim:  rgba(79,114,255,0.12);
          --cyan:      #22D3EE;
          --text:      #F0F0FF;
          --muted:     #6B6B85;
          --muted2:    #9090AA;
          --radius:    14px;
        }

        html { scroll-behavior: smooth; }
        body {
          background: var(--bg);
          color: var(--text);
          font-family: 'Plus Jakarta Sans', sans-serif;
          -webkit-font-smoothing: antialiased;
          overflow-x: hidden;
        }
        ::-webkit-scrollbar { width: 5px; }
        ::-webkit-scrollbar-track { background: var(--bg); }
        ::-webkit-scrollbar-thumb { background: #22223a; border-radius: 3px; }

        /* NAV */
        .lp-nav {
          position: fixed; top: 0; left: 0; right: 0; z-index: 100;
          display: flex; align-items: center; justify-content: space-between;
          padding: 0 48px; height: 64px;
          transition: background 0.3s, border-color 0.3s, backdrop-filter 0.3s;
        }
        .lp-nav.scrolled {
          background: rgba(7,7,14,0.88);
          border-bottom: 1px solid var(--border);
          backdrop-filter: blur(18px);
        }
        .lp-logo {
          display: flex; align-items: center; gap: 10px;
          font-family: 'Syne', sans-serif; font-weight: 700; font-size: 18px;
          color: var(--text); text-decoration: none; letter-spacing: -0.3px;
        }
        .lp-logo-mark {
          width: 33px; height: 33px; border-radius: 9px;
          background: linear-gradient(135deg, var(--blue), var(--cyan));
          display: flex; align-items: center; justify-content: center; flex-shrink: 0;
        }
        .lp-logo-mark svg { width: 17px; height: 17px; }
        .lp-nav-links { display: flex; align-items: center; gap: 32px; list-style: none; }
        .lp-nav-links a {
          color: var(--muted2); font-size: 14px; font-weight: 500;
          text-decoration: none; transition: color 0.2s;
        }
        .lp-nav-links a:hover { color: var(--text); }
        .lp-nav-actions { display: flex; align-items: center; gap: 10px; }
        .lp-btn-ghost {
          padding: 8px 16px; border-radius: 8px; font-size: 14px; font-weight: 500;
          color: var(--muted2); background: transparent; border: none;
          cursor: pointer; text-decoration: none; transition: color 0.2s;
          font-family: 'Plus Jakarta Sans', sans-serif;
        }
        .lp-btn-ghost:hover { color: var(--text); }
        .lp-btn-primary {
          padding: 9px 18px; border-radius: 8px; font-size: 13.5px; font-weight: 600;
          color: #fff; background: var(--blue); border: none; cursor: pointer;
          text-decoration: none; font-family: 'Plus Jakarta Sans', sans-serif;
          display: inline-flex; align-items: center; gap: 6px;
          transition: opacity 0.2s, transform 0.15s;
        }
        .lp-btn-primary:hover { opacity: 0.87; transform: translateY(-1px); }

        /* HERO */
        .lp-hero {
          position: relative; min-height: 100vh;
          display: flex; flex-direction: column; align-items: center; justify-content: center;
          text-align: center; padding: 130px 24px 80px; overflow: hidden;
        }
        .lp-hero-grid {
          position: absolute; inset: 0; pointer-events: none;
          background-image:
            linear-gradient(rgba(79,114,255,0.055) 1px, transparent 1px),
            linear-gradient(90deg, rgba(79,114,255,0.055) 1px, transparent 1px);
          background-size: 56px 56px;
          mask-image: radial-gradient(ellipse 90% 75% at 50% 35%, black 20%, transparent 100%);
        }
        .lp-hero-glow {
          position: absolute; top: 5%; left: 50%; transform: translateX(-50%);
          width: 800px; height: 420px; pointer-events: none;
          background: radial-gradient(ellipse at 50% 50%, rgba(79,114,255,0.15) 0%, transparent 65%);
          filter: blur(50px);
        }
        .lp-eyebrow {
          display: inline-flex; align-items: center; gap: 8px;
          padding: 5px 14px; border-radius: 100px;
          background: rgba(79,114,255,0.09); border: 1px solid rgba(79,114,255,0.22);
          font-size: 11.5px; font-weight: 700; letter-spacing: 0.09em; text-transform: uppercase;
          color: #8BA4FF; margin-bottom: 28px;
          animation: lpFadeUp 0.65s ease both;
        }
        .lp-eyebrow-dot {
          width: 6px; height: 6px; border-radius: 50%;
          background: var(--blue); animation: lpPulse 2s ease infinite;
        }
        .lp-h1 {
          font-family: 'Syne', sans-serif;
          font-size: clamp(44px, 6.8vw, 88px);
          font-weight: 800; line-height: 1.03; letter-spacing: -0.03em;
          color: var(--text); max-width: 880px; margin-bottom: 22px;
          animation: lpFadeUp 0.65s 0.1s ease both;
        }
        .lp-accent {
          background: linear-gradient(100deg, var(--blue) 0%, var(--cyan) 100%);
          -webkit-background-clip: text; -webkit-text-fill-color: transparent; background-clip: text;
        }
        .lp-sub {
          font-size: clamp(15px, 1.9vw, 18.5px); color: var(--muted2); line-height: 1.75;
          max-width: 520px; margin-bottom: 44px;
          animation: lpFadeUp 0.65s 0.18s ease both;
        }
        .lp-hero-btns {
          display: flex; align-items: center; justify-content: center;
          gap: 12px; flex-wrap: wrap;
          animation: lpFadeUp 0.65s 0.26s ease both;
        }
        .lp-btn-hero-p {
          padding: 14px 28px; border-radius: 10px; font-size: 15px; font-weight: 700;
          color: #fff; background: var(--blue); border: none; cursor: pointer;
          text-decoration: none; display: inline-flex; align-items: center; gap: 8px;
          font-family: 'Plus Jakarta Sans', sans-serif;
          transition: opacity 0.2s, transform 0.15s, box-shadow 0.2s;
        }
        .lp-btn-hero-p:hover { opacity: 0.88; transform: translateY(-2px); box-shadow: 0 8px 30px rgba(79,114,255,0.32); }
        .lp-btn-hero-o {
          padding: 14px 28px; border-radius: 10px; font-size: 15px; font-weight: 600;
          color: var(--text); background: transparent;
          border: 1.5px solid rgba(99,139,255,0.3); cursor: pointer;
          text-decoration: none; display: inline-flex; align-items: center; gap: 8px;
          font-family: 'Plus Jakarta Sans', sans-serif;
          transition: background 0.2s, border-color 0.2s, transform 0.15s;
        }
        .lp-btn-hero-o:hover { background: var(--blue-dim); border-color: var(--blue); transform: translateY(-2px); }

        /* MOCK DASHBOARD */
        .lp-dash-wrap {
          width: 100%; max-width: 880px; margin-top: 72px;
          animation: lpFadeUp 0.7s 0.35s ease both;
        }
        .lp-dash {
          border-radius: 16px; background: var(--surface2);
          border: 1px solid var(--border);
          overflow: hidden;
          box-shadow: 0 0 0 1px rgba(79,114,255,0.08), 0 40px 80px rgba(0,0,0,0.55);
        }
        .lp-dash-bar {
          display: flex; align-items: center; gap: 8px; padding: 13px 18px;
          border-bottom: 1px solid var(--border); background: rgba(255,255,255,0.02);
        }
        .lp-dot { width: 10px; height: 10px; border-radius: 50%; }
        .lp-dot-r { background: #FF5F57; } .lp-dot-y { background: #FEBC2E; } .lp-dot-g { background: #28C840; }
        .lp-url { flex: 1; text-align: center; font-size: 12px; color: var(--muted); }
        .lp-live {
          display: inline-flex; align-items: center; gap: 5px;
          padding: 3px 9px; border-radius: 100px;
          background: rgba(34,197,94,0.1); border: 1px solid rgba(34,197,94,0.2);
          font-size: 10px; font-weight: 700; color: #4ADE80; letter-spacing: 0.06em;
        }
        .lp-live-dot { width: 5px; height: 5px; border-radius: 50%; background: #4ADE80; animation: lpPulse 1.4s ease infinite; }
        .lp-dash-grid {
          display: grid; grid-template-columns: 1fr 1fr 1fr;
          gap: 1px; background: var(--border); min-height: 268px;
        }
        .lp-cell {
          background: var(--surface); padding: 18px 16px;
          display: flex; flex-direction: column; gap: 9px;
        }
        .lp-cell-label {
          font-size: 10.5px; font-weight: 700; letter-spacing: 0.07em; text-transform: uppercase; color: var(--muted);
        }
        .lp-cell-name { font-size: 12px; font-weight: 600; color: var(--muted2); }
        .lp-face {
          flex: 1; border-radius: 8px; min-height: 110px;
          background: linear-gradient(135deg, #11112A 0%, #1a1a38 100%);
          display: flex; align-items: center; justify-content: center;
          position: relative; overflow: hidden;
        }
        .lp-face-icon {
          width: 46px; height: 46px; border-radius: 50%;
          background: rgba(79,114,255,0.12); border: 1.5px solid rgba(79,114,255,0.25);
          display: flex; align-items: center; justify-content: center;
        }
        .lp-scan { position: absolute; left: 0; right: 0; height: 2px; background: linear-gradient(90deg, transparent, #4F72FF, #22D3EE, transparent); animation: lpScan 2.4s ease-in-out infinite; opacity: 0.7; }
        .lp-corner { position: absolute; width: 12px; height: 12px; border-color: var(--blue); border-style: solid; opacity: 0.55; }
        .lp-corner.tl { top: 7px; left: 7px; border-width: 1.5px 0 0 1.5px; }
        .lp-corner.tr { top: 7px; right: 7px; border-width: 1.5px 1.5px 0 0; }
        .lp-corner.bl { bottom: 7px; left: 7px; border-width: 0 0 1.5px 1.5px; }
        .lp-corner.br { bottom: 7px; right: 7px; border-width: 0 1.5px 1.5px 0; }
        .lp-badge-row { display: flex; gap: 6px; flex-wrap: wrap; }
        .lp-badge {
          font-size: 10.5px; font-weight: 600; padding: 3px 7px; border-radius: 5px;
        }
        .lp-badge-g { background: rgba(34,197,94,0.1); color: #4ADE80; }
        .lp-badge-b { background: rgba(79,114,255,0.1); color: #8BA4FF; }
        .lp-alerts { display: flex; flex-direction: column; gap: 5px; }
        .lp-alert { display: flex; align-items: center; gap: 7px; padding: 5px 7px; border-radius: 6px; font-size: 10.5px; }
        .lp-alert.ok  { background: rgba(34,197,94,0.07);  color: #4ADE80; }
        .lp-alert.wrn { background: rgba(251,191,36,0.07); color: #FBBF24; }
        .lp-alert.err { background: rgba(239,68,68,0.07);  color: #F87171; }
        .lp-adot { width: 5px; height: 5px; border-radius: 50%; background: currentColor; flex-shrink: 0; }
        .lp-stat-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 5px; }
        .lp-stat-box {
          background: rgba(255,255,255,0.025); border-radius: 7px;
          padding: 8px 10px; border: 1px solid var(--border);
        }
        .lp-stat-val { font-family: 'Syne', sans-serif; font-size: 19px; font-weight: 700; color: var(--text); line-height: 1; }
        .lp-stat-lbl { font-size: 9.5px; color: var(--muted); margin-top: 2px; }
        .lp-risk-rows { display: flex; flex-direction: column; gap: 5px; margin-top: 2px; }
        .lp-risk-row { display: flex; align-items: center; gap: 7px; }
        .lp-risk-lbl { font-size: 9.5px; color: var(--muted); width: 60px; flex-shrink: 0; }
        .lp-risk-track { flex: 1; height: 3.5px; border-radius: 2px; background: rgba(255,255,255,0.05); overflow: hidden; }
        .lp-risk-fill { height: 100%; border-radius: 2px; }
        .lp-risk-num { font-size: 9.5px; color: var(--muted2); width: 22px; text-align: right; }

        /* TRUST BAR */
        .lp-trust {
          display: flex; align-items: center; justify-content: center; flex-wrap: wrap;
          border-top: 1px solid var(--border); border-bottom: 1px solid var(--border);
          background: var(--surface); padding: 28px 24px;
        }
        .lp-trust-item { display: flex; flex-direction: column; align-items: center; gap: 2px; padding: 0 40px; position: relative; }
        .lp-trust-item + .lp-trust-item::before {
          content: ''; position: absolute; left: 0; top: 10%; height: 80%; width: 1px; background: var(--border);
        }
        .lp-trust-val {
          font-family: 'Syne', sans-serif; font-size: 27px; font-weight: 800;
          color: var(--text); letter-spacing: -0.02em;
        }
        .lp-trust-val .u { font-size: 17px; color: var(--blue); }
        .lp-trust-lbl { font-size: 11.5px; color: var(--muted); font-weight: 500; }

        /* SECTION SCAFFOLD */
        .lp-section { padding: 96px 24px; max-width: 1100px; margin: 0 auto; }
        .lp-s-eyebrow {
          display: inline-flex; align-items: center; gap: 8px;
          font-size: 11.5px; font-weight: 700; letter-spacing: 0.1em; text-transform: uppercase;
          color: var(--blue); margin-bottom: 14px;
        }
        .lp-s-eyebrow::before { content: ''; width: 22px; height: 1.5px; background: var(--blue); border-radius: 1px; }
        .lp-s-h2 {
          font-family: 'Syne', sans-serif; font-size: clamp(30px, 3.8vw, 50px);
          font-weight: 800; letter-spacing: -0.025em; line-height: 1.1; color: var(--text); margin-bottom: 14px;
        }
        .lp-s-sub { font-size: 16.5px; color: var(--muted2); line-height: 1.72; max-width: 500px; }

        /* FEATURE GRID */
        .lp-feat-grid {
          display: grid; grid-template-columns: repeat(auto-fill, minmax(295px, 1fr));
          gap: 1px; background: var(--border);
          border: 1px solid var(--border); border-radius: 18px; overflow: hidden; margin-top: 52px;
        }
        .lp-feat-card {
          background: var(--surface); padding: 34px 30px;
          transition: background 0.25s; position: relative; overflow: hidden; cursor: default;
        }
        .lp-feat-card::after {
          content: ''; position: absolute; inset: 0;
          background: radial-gradient(circle at 70% -5%, rgba(79,114,255,0.1) 0%, transparent 55%);
          opacity: 0; transition: opacity 0.3s; pointer-events: none;
        }
        .lp-feat-card:hover { background: var(--surface2); }
        .lp-feat-card:hover::after { opacity: 1; }
        .lp-feat-icon {
          width: 42px; height: 42px; border-radius: 11px;
          display: flex; align-items: center; justify-content: center;
          margin-bottom: 18px; font-size: 20px;
          background: var(--blue-dim); border: 1px solid rgba(79,114,255,0.18);
          position: relative; z-index: 1;
        }
        .lp-feat-h3 {
          font-family: 'Syne', sans-serif; font-size: 16px; font-weight: 700;
          color: var(--text); margin-bottom: 9px; position: relative; z-index: 1;
        }
        .lp-feat-p { font-size: 13.5px; color: var(--muted2); line-height: 1.7; position: relative; z-index: 1; }

        /* STEPS */
        .lp-steps {
          display: grid; grid-template-columns: repeat(3, 1fr);
          gap: 20px; margin-top: 52px; position: relative;
        }
        .lp-steps::before {
          content: ''; position: absolute; top: 27px; left: calc(16.66% + 28px); right: calc(16.66% + 28px);
          height: 1px; background: linear-gradient(90deg, var(--blue), var(--cyan)); opacity: 0.25; pointer-events: none;
        }
        .lp-step {
          display: flex; flex-direction: column; align-items: center;
          text-align: center; gap: 14px; padding: 30px 22px;
          border-radius: 14px; background: var(--surface); border: 1px solid var(--border);
          transition: border-color 0.25s, background 0.25s;
        }
        .lp-step:hover { border-color: rgba(99,139,255,0.35); background: var(--surface2); }
        .lp-step-num {
          width: 54px; height: 54px; border-radius: 50%;
          background: var(--blue-dim); border: 1.5px solid rgba(79,114,255,0.28);
          display: flex; align-items: center; justify-content: center;
          font-family: 'Syne', sans-serif; font-size: 19px; font-weight: 800; color: var(--blue);
        }
        .lp-step-h3 { font-family: 'Syne', sans-serif; font-size: 15.5px; font-weight: 700; color: var(--text); }
        .lp-step-p { font-size: 13px; color: var(--muted2); line-height: 1.65; }

        /* SPLIT CTA */
        .lp-split {
          display: grid; grid-template-columns: 1fr 1fr;
          gap: 1px; background: var(--border);
          border: 1px solid var(--border); border-radius: 20px; overflow: hidden; margin-top: 52px;
        }
        .lp-cta-panel {
          background: var(--surface); padding: 50px 44px;
          display: flex; flex-direction: column; gap: 18px;
          transition: background 0.25s; position: relative; overflow: hidden;
        }
        .lp-cta-panel::before {
          content: ''; position: absolute; top: -70px; right: -70px;
          width: 240px; height: 240px; border-radius: 50%;
          background: radial-gradient(circle, var(--blue-dim) 0%, transparent 70%); pointer-events: none;
        }
        .lp-cta-panel.teacher::before {
          background: radial-gradient(circle, rgba(34,211,238,0.07) 0%, transparent 70%);
        }
        .lp-cta-panel:hover { background: var(--surface2); }
        .lp-chip {
          display: inline-flex; align-items: center; gap: 6px;
          padding: 4px 12px; border-radius: 100px; font-size: 10.5px;
          font-weight: 700; letter-spacing: 0.08em; text-transform: uppercase; width: fit-content;
        }
        .lp-chip-b { background: var(--blue-dim); color: #8BA4FF; border: 1px solid rgba(79,114,255,0.2); }
        .lp-chip-c { background: rgba(34,211,238,0.08); color: var(--cyan); border: 1px solid rgba(34,211,238,0.2); }
        .lp-cta-h3 {
          font-family: 'Syne', sans-serif; font-size: 25px; font-weight: 800;
          color: var(--text); letter-spacing: -0.02em; line-height: 1.2;
        }
        .lp-cta-p { font-size: 13.5px; color: var(--muted2); line-height: 1.72; }
        .lp-cta-ul { list-style: none; display: flex; flex-direction: column; gap: 7px; }
        .lp-cta-ul li { display: flex; align-items: center; gap: 9px; font-size: 13px; color: var(--muted2); }
        .lp-cta-ul li::before { content: ''; width: 5px; height: 5px; border-radius: 50%; background: var(--blue); flex-shrink: 0; }
        .lp-cta-panel.teacher .lp-cta-ul li::before { background: var(--cyan); }
        .lp-cta-actions { display: flex; gap: 10px; flex-wrap: wrap; }
        .lp-btn-cyan {
          padding: 13px 26px; border-radius: 10px; font-size: 14px; font-weight: 700;
          color: #07070E; background: var(--cyan); border: none; cursor: pointer;
          text-decoration: none; display: inline-flex; align-items: center; gap: 6px;
          font-family: 'Plus Jakarta Sans', sans-serif;
          transition: opacity 0.2s, transform 0.15s;
        }
        .lp-btn-cyan:hover { opacity: 0.88; transform: translateY(-2px); }
        .lp-btn-blue {
          padding: 13px 26px; border-radius: 10px; font-size: 14px; font-weight: 700;
          color: #fff; background: var(--blue); border: none; cursor: pointer;
          text-decoration: none; display: inline-flex; align-items: center; gap: 6px;
          font-family: 'Plus Jakarta Sans', sans-serif;
          transition: opacity 0.2s, transform 0.15s;
        }
        .lp-btn-blue:hover { opacity: 0.88; transform: translateY(-2px); }
        .lp-btn-ol {
          padding: 13px 22px; border-radius: 10px; font-size: 14px; font-weight: 600;
          color: var(--text); background: transparent;
          border: 1.5px solid rgba(99,139,255,0.28); cursor: pointer;
          text-decoration: none; display: inline-flex; align-items: center; gap: 6px;
          font-family: 'Plus Jakarta Sans', sans-serif;
          transition: background 0.2s, border-color 0.2s;
        }
        .lp-btn-ol:hover { background: var(--blue-dim); border-color: var(--blue); }

        /* FOOTER */
        .lp-footer {
          border-top: 1px solid var(--border); background: var(--surface);
          padding: 36px 60px; display: flex; align-items: center;
          justify-content: space-between; flex-wrap: wrap; gap: 20px;
        }
        .lp-footer-copy { font-size: 12.5px; color: var(--muted); }
        .lp-footer-links { display: flex; gap: 24px; list-style: none; }
        .lp-footer-links a { font-size: 12.5px; color: var(--muted); text-decoration: none; transition: color 0.2s; }
        .lp-footer-links a:hover { color: var(--text); }

        /* ANIMATIONS */
        @keyframes lpFadeUp {
          from { opacity: 0; transform: translateY(20px); }
          to   { opacity: 1; transform: translateY(0); }
        }
        @keyframes lpPulse {
          0%, 100% { opacity: 1; } 50% { opacity: 0.45; }
        }
        @keyframes lpScan {
          0%   { top: -2px; } 100% { top: 100%; }
        }

        /* RESPONSIVE */
        @media (max-width: 860px) {
          .lp-nav { padding: 0 20px; }
          .lp-nav-links { display: none; }
          .lp-dash-grid { grid-template-columns: 1fr 1fr; }
          .lp-dash-grid .lp-cell:nth-child(3) { display: none; }
          .lp-trust-item { padding: 0 18px; }
          .lp-steps { grid-template-columns: 1fr; }
          .lp-steps::before { display: none; }
          .lp-split { grid-template-columns: 1fr; }
          .lp-footer { flex-direction: column; text-align: center; padding: 28px 24px; }
          .lp-feat-grid { grid-template-columns: 1fr; }
          .lp-cta-panel { padding: 36px 28px; }
        }
      `}</style>

      {/* NAV */}
      <nav className={`lp-nav${scrolled ? ' scrolled' : ''}`}>
        <a href="#" className="lp-logo">
          <div className="lp-logo-mark">
            <svg viewBox="0 0 24 24" fill="none" stroke="white" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round" width="17" height="17">
              <path d="M12 2a5 5 0 0 1 5 5v1a5 5 0 0 1-10 0V7a5 5 0 0 1 5-5Z"/>
              <path d="M3 20a9 9 0 0 1 18 0"/>
            </svg>
          </div>
          ProctorAI
        </a>
        <ul className="lp-nav-links">
          <li><a href="#features">Features</a></li>
          <li><a href="#how-it-works">How it Works</a></li>
          <li><a href="#get-started">Get Started</a></li>
        </ul>
        <div className="lp-nav-actions">
          <Link href="/auth/login" className="lp-btn-ghost">Sign In</Link>
          <Link href="/auth/teacher-apply" className="lp-btn-primary">
            Apply as Teacher →
          </Link>
        </div>
      </nav>

      {/* HERO */}
      <section className="lp-hero">
        <div className="lp-hero-grid" />
        <div className="lp-hero-glow" />

        <div className="lp-eyebrow">
          <span className="lp-eyebrow-dot" />
          AI-Powered Exam Proctoring
        </div>

        <h1 className="lp-h1">
          Academic Integrity,<br />
          <span className="lp-accent">Ensured by AI.</span>
        </h1>

        <p className="lp-sub">
          Real-time face detection, gaze tracking, object recognition, and identity verification — all in one platform built for institutions that take fairness seriously.
        </p>

        <div className="lp-hero-btns">
          <Link href="/auth/login" className="lp-btn-hero-p">
            Sign In to Your Account
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
              <path d="M5 12h14M12 5l7 7-7 7"/>
            </svg>
          </Link>
          <Link href="/auth/teacher-apply" className="lp-btn-hero-o">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
              <rect x="2" y="7" width="20" height="14" rx="2" ry="2"/>
              <path d="M16 21V5a2 2 0 0 0-2-2h-4a2 2 0 0 0-2 2v16"/>
            </svg>
            Apply as Teacher
          </Link>
        </div>

        {/* MOCK DASHBOARD */}
        <div className="lp-dash-wrap">
          <div className="lp-dash">
            <div className="lp-dash-bar">
              <span className="lp-dot lp-dot-r"/><span className="lp-dot lp-dot-y"/><span className="lp-dot lp-dot-g"/>
              <span className="lp-url">proctoring.examai.com — Live Session Monitor</span>
              <span className="lp-live"><span className="lp-live-dot"/>LIVE</span>
            </div>
            <div className="lp-dash-grid">
              {/* Cell 1 */}
              <div className="lp-cell">
                <div className="lp-cell-label">Student Feed</div>
                <div className="lp-cell-name">Arjun Sharma — CS301</div>
                <div className="lp-face">
                  <div className="lp-face-icon">
                    <svg width="23" height="23" viewBox="0 0 24 24" fill="none" stroke="#4F72FF" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                      <circle cx="12" cy="8" r="4"/><path d="M4 20c0-4 3.6-7 8-7s8 3 8 7"/>
                    </svg>
                  </div>
                  <div className="lp-scan"/>
                  <div className="lp-corner tl"/><div className="lp-corner tr"/>
                  <div className="lp-corner bl"/><div className="lp-corner br"/>
                </div>
                <div className="lp-badge-row">
                  <span className="lp-badge lp-badge-g">✓ Identity Match</span>
                  <span className="lp-badge lp-badge-b">On Camera</span>
                </div>
              </div>

              {/* Cell 2 */}
              <div className="lp-cell">
                <div className="lp-cell-label">Live Alerts</div>
                <div className="lp-cell-name">Real-time Events</div>
                <div className="lp-alerts">
                  <div className="lp-alert ok"><span className="lp-adot"/>Face centred &amp; visible</div>
                  <div className="lp-alert wrn"><span className="lp-adot"/>Gaze deviation — 2.1s</div>
                  <div className="lp-alert ok"><span className="lp-adot"/>No foreign objects</div>
                  <div className="lp-alert ok"><span className="lp-adot"/>Single person detected</div>
                  <div className="lp-alert wrn"><span className="lp-adot"/>Tab switch ×1</div>
                </div>
              </div>

              {/* Cell 3 */}
              <div className="lp-cell">
                <div className="lp-cell-label">Risk Analysis</div>
                <div className="lp-cell-name">Session Score</div>
                <div className="lp-stat-grid">
                  <div className="lp-stat-box">
                    <div className="lp-stat-val" style={{color:'#FBBF24'}}>14</div>
                    <div className="lp-stat-lbl">Risk Score</div>
                  </div>
                  <div className="lp-stat-box">
                    <div className="lp-stat-val" style={{color:'#4ADE80'}}>LOW</div>
                    <div className="lp-stat-lbl">Status</div>
                  </div>
                  <div className="lp-stat-box">
                    <div className="lp-stat-val">38m</div>
                    <div className="lp-stat-lbl">Elapsed</div>
                  </div>
                  <div className="lp-stat-box">
                    <div className="lp-stat-val" style={{color:'#22D3EE'}}>3</div>
                    <div className="lp-stat-lbl">Flags</div>
                  </div>
                </div>
                <div className="lp-risk-rows">
                  {[
                    {label:'Gaze', pct:'20%', color:'#4F72FF'},
                    {label:'Objects', pct:'0%', color:'#EF4444'},
                    {label:'Tab Switch', pct:'8%', color:'#FBBF24'},
                  ].map(r => (
                    <div key={r.label} className="lp-risk-row">
                      <span className="lp-risk-lbl">{r.label}</span>
                      <div className="lp-risk-track"><div className="lp-risk-fill" style={{width:r.pct,background:r.color}}/></div>
                      <span className="lp-risk-num">{parseInt(r.pct)}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* TRUST BAR */}
      <div className="lp-trust">
        {[
          {val: '99', unit: '%', label: 'Detection Accuracy'},
          {val: '<200', unit: 'ms', label: 'Alert Latency'},
          {val: '6', unit: '+', label: 'AI Detection Modules'},
          {val: 'E2E', unit: '', label: 'Encrypted Streams'},
          {val: '24', unit: '/7', label: 'Automated Monitoring'},
        ].map(t => (
          <div key={t.label} className="lp-trust-item">
            <div className="lp-trust-val">{t.val}{t.unit && <span className="u">{t.unit}</span>}</div>
            <div className="lp-trust-lbl">{t.label}</div>
          </div>
        ))}
      </div>

      {/* FEATURES */}
      <div id="features">
        <div className="lp-section">
          <div className="lp-s-eyebrow">Capabilities</div>
          <h2 className="lp-s-h2">Every angle of integrity,<br />covered.</h2>
          <p className="lp-s-sub">ProctorAI runs multiple AI models in parallel so nothing slips through during a live exam.</p>

          <div className="lp-feat-grid">
            {[
              { icon: '🎯', title: 'Real-time Face Detection', desc: 'Continuously verifies the enrolled student is physically present. Alerts fire the moment a face is absent, hidden, or obstructed.' },
              { icon: '👁️', title: 'Gaze & Head Tracking', desc: 'Tracks head pose and eye-gaze direction. Sustained looks away from screen are flagged with fully configurable thresholds.' },
              { icon: '📱', title: 'Object Detection', desc: 'Detects phones, textbooks, earbuds, and headphones using a fine-tuned YOLOv8 model with temporal voting to eliminate false positives.' },
              { icon: '🔐', title: 'Identity Verification', desc: 'Mid-exam checks compare live snapshots to enrolled face embeddings. Identity mismatches trigger prompts or automatic termination.' },
              { icon: '⚡', title: 'Automated Risk Scoring', desc: 'Each violation contributes to a live risk score. Configurable thresholds move sessions through Warning → High Risk → Admin Review.' },
              { icon: '🛡️', title: 'Secure WebRTC Streams', desc: 'All video travels peer-to-peer via encrypted WebRTC. No raw footage is stored — only compressed JPEG frames for flagged events.' },
            ].map(f => (
              <div key={f.title} className="lp-feat-card">
                <div className="lp-feat-icon">{f.icon}</div>
                <h3 className="lp-feat-h3">{f.title}</h3>
                <p className="lp-feat-p">{f.desc}</p>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* HOW IT WORKS */}
      <div id="how-it-works" style={{background:'var(--surface)',borderTop:'1px solid var(--border)',borderBottom:'1px solid var(--border)'}}>
        <div className="lp-section">
          <div className="lp-s-eyebrow">Process</div>
          <h2 className="lp-s-h2">Up and running<br />in three steps.</h2>
          <p className="lp-s-sub">From invitation to submission, every step is guided and automated.</p>

          <div className="lp-steps">
            {[
              { n: '01', title: 'Schedule & Invite', desc: 'Admins create an exam, configure detection sensitivity, and send secure invite tokens directly to enrolled students.' },
              { n: '02', title: 'Verify & Connect', desc: 'Students complete a system check, verify their face against their enrolled photo, and join a secure proctored session.' },
              { n: '03', title: 'Monitor & Report', desc: 'AI monitors in real time. Admins see live risk scores, intervene if needed, and receive a full violation report on completion.' },
            ].map(s => (
              <div key={s.n} className="lp-step">
                <div className="lp-step-num">{s.n}</div>
                <h3 className="lp-step-h3">{s.title}</h3>
                <p className="lp-step-p">{s.desc}</p>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* GET STARTED / SPLIT CTA */}
      <div id="get-started">
        <div className="lp-section">
          <div className="lp-s-eyebrow">Get Started</div>
          <h2 className="lp-s-h2">Your role on<br />the platform.</h2>
          <p className="lp-s-sub">Whether you're running exams or sitting them, ProctorAI has a purpose-built experience for you.</p>

          <div className="lp-split">
            {/* Teacher */}
            <div className="lp-cta-panel teacher">
              <span className="lp-chip lp-chip-c">
                <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                  <rect x="2" y="7" width="20" height="14" rx="2"/><path d="M16 21V5a2 2 0 0 0-2-2h-4a2 2 0 0 0-2 2v16"/>
                </svg>
                For Teachers &amp; Admins
              </span>
              <h3 className="lp-cta-h3">Apply for an<br />admin account.</h3>
              <p className="lp-cta-p">Submit your application and get approved by the system admin. Once in, you'll have full access to create exams, invite students, and review proctoring reports.</p>
              <ul className="lp-cta-ul">
                <li>Create and schedule exams with custom detection settings</li>
                <li>Invite students via secure single-use email tokens</li>
                <li>Monitor live sessions with real-time risk overlays</li>
                <li>Review full AI-generated violation reports per student</li>
              </ul>
              <div className="lp-cta-actions">
                <Link href="/auth/teacher-apply" className="lp-btn-cyan">
                  Apply as Teacher →
                </Link>
              </div>
            </div>

            {/* Student */}
            <div className="lp-cta-panel">
              <span className="lp-chip lp-chip-b">
                <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                  <path d="M22 10v6M2 10l10-5 10 5-10 5z"/><path d="M6 12v5c3 3 9 3 12 0v-5"/>
                </svg>
                For Students
              </span>
              <h3 className="lp-cta-h3">Already enrolled?<br />Sign in to continue.</h3>
              <p className="lp-cta-p">If your institution uses ProctorAI, you'll receive an exam invite via email. Use your registered account to access upcoming and past exams.</p>
              <ul className="lp-cta-ul">
                <li>View upcoming exams with live countdown timers</li>
                <li>Register your face once for all identity checks</li>
                <li>Take exams from any supported desktop device</li>
                <li>Review your exam history, scores, and session status</li>
              </ul>
              <div className="lp-cta-actions">
                <Link href="/auth/login" className="lp-btn-blue">
                  Sign In →
                </Link>
                <Link href="/auth/register" className="lp-btn-ol">
                  Register
                </Link>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* FOOTER */}
      <footer className="lp-footer">
        <div className="lp-logo">
          <div className="lp-logo-mark">
            <svg viewBox="0 0 24 24" fill="none" stroke="white" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round" width="17" height="17">
              <path d="M12 2a5 5 0 0 1 5 5v1a5 5 0 0 1-10 0V7a5 5 0 0 1 5-5Z"/>
              <path d="M3 20a9 9 0 0 1 18 0"/>
            </svg>
          </div>
          ProctorAI
        </div>
        <p className="lp-footer-copy">© {new Date().getFullYear()} ProctorAI. Built with integrity.</p>
        <ul className="lp-footer-links">
          <li><Link href="/auth/login">Sign In</Link></li>
          <li><Link href="/auth/register">Register</Link></li>
          <li><Link href="/auth/teacher-apply">Apply as Teacher</Link></li>
        </ul>
      </footer>
    </>
  );
}
