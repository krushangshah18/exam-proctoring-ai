"use client";

import React from "react";
import { GraduationCap, CheckCircle2, ArrowLeft } from "lucide-react";

export interface AuthShellProps {
  children: React.ReactNode;
  title: string;
  subtitle?: string;
  backHref?: string;
  backLabel?: string;
  footer?: React.ReactNode;
  // Left panel
  eyebrow?: string;
  leftHeading?: string;
  leftBody?: string;
  features?: string[];
  maxWidth?: string;
}

export function AuthShell({
  children,
  title,
  subtitle,
  backHref,
  backLabel = "Back",
  footer,
  eyebrow = "AI-Powered Proctoring",
  leftHeading = "Exam Integrity,\nReliably Ensured.",
  leftBody = "ProctorAI uses advanced AI to monitor exams in real-time — ensuring fair, secure assessments for every student.",
  features,
  maxWidth = "420px",
}: AuthShellProps) {
  return (
    <div
      style={{
        minHeight: "100vh",
        display: "flex",
        fontFamily: "'Plus Jakarta Sans', sans-serif",
        background: "#F8FAFC",
      }}
    >
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:ital,wght@0,400;0,500;0,600;0,700;0,800&display=swap');

        .auth-root * { box-sizing: border-box; }

        .auth-input {
          display: block; width: 100%;
          padding: 10px 14px;
          border: 1.5px solid #E2E8F0;
          border-radius: 8px;
          font-size: 14px;
          font-family: 'Plus Jakarta Sans', sans-serif;
          color: #0F172A;
          background: #fff;
          line-height: 1.5;
          transition: border-color 150ms ease, box-shadow 150ms ease;
          outline: none;
        }
        .auth-input:focus {
          border-color: #38A3A5;
          box-shadow: 0 0 0 3px rgba(56,163,165,0.12);
        }
        .auth-input::placeholder { color: #64748B; }
        .auth-input.has-error { border-color: #EF4444 !important; }
        .auth-input.has-error:focus {
          border-color: #EF4444 !important;
          box-shadow: 0 0 0 3px rgba(239,68,68,0.08) !important;
        }

        .auth-textarea {
          display: block; width: 100%;
          padding: 10px 14px;
          border: 1.5px solid #E2E8F0;
          border-radius: 8px;
          font-size: 14px;
          font-family: 'Plus Jakarta Sans', sans-serif;
          color: #0F172A;
          background: #fff;
          line-height: 1.6;
          resize: vertical;
          min-height: 100px;
          transition: border-color 150ms ease, box-shadow 150ms ease;
          outline: none;
        }
        .auth-textarea:focus {
          border-color: #38A3A5;
          box-shadow: 0 0 0 3px rgba(56,163,165,0.12);
        }
        .auth-textarea::placeholder { color: #64748B; }

        .auth-btn {
          display: flex; align-items: center; justify-content: center; gap: 8px;
          width: 100%; padding: 11px 20px;
          border-radius: 8px; border: none;
          font-size: 14px;
          font-family: 'Plus Jakarta Sans', sans-serif;
          font-weight: 700; cursor: pointer; letter-spacing: 0.01em;
          background: #22577A; color: #fff;
          transition: background 150ms ease, transform 80ms ease;
        }
        .auth-btn:hover:not(:disabled) { background: #2C6A91; }
        .auth-btn:active:not(:disabled) { background: #1B455F; transform: scale(0.99); }
        .auth-btn:disabled { background: #64748B !important; cursor: not-allowed; }

        .auth-btn-ghost {
          display: flex; align-items: center; gap: 6px;
          padding: 9px 14px; border-radius: 8px;
          border: 1.5px solid #E2E8F0; background: #fff;
          font-size: 13px; font-family: 'Plus Jakarta Sans', sans-serif;
          font-weight: 600; cursor: pointer; color: #475569;
          transition: background 150ms, border-color 150ms;
        }
        .auth-btn-ghost:hover { background: #F8FAFC; border-color: #CBD5E1; }

        .auth-btn-accent {
          display: flex; align-items: center; gap: 6px;
          padding: 9px 14px; border-radius: 8px; border: none;
          font-size: 13px; font-family: 'Plus Jakarta Sans', sans-serif;
          font-weight: 600; cursor: pointer;
          background: rgba(87,204,153,0.12); color: #22577A;
          transition: background 150ms;
        }
        .auth-btn-accent:hover { background: rgba(87,204,153,0.2); }

        .auth-link { color: #38A3A5; text-decoration: none; font-weight: 600; transition: color 150ms; }
        .auth-link:hover { color: #22577A; }

        .auth-otp-box {
          width: 48px; height: 56px;
          border-radius: 10px; border: 1.5px solid #94A3B8;
          text-align: center; font-size: 22px; font-weight: 700;
          color: #0F172A; font-family: 'Plus Jakarta Sans', sans-serif;
          background: #fff; outline: none;
          transition: border-color 150ms, box-shadow 150ms;
          caret-color: #38A3A5;
        }
        .auth-otp-box:focus {
          border-color: #38A3A5;
          box-shadow: 0 0 0 3px rgba(56,163,165,0.12);
        }
        .auth-otp-box.filled {
          border-color: #22577A;
          background: #EFF6FF;
        }

        @keyframes auth-fadein {
          from { opacity: 0; transform: translateY(10px); }
          to   { opacity: 1; transform: translateY(0); }
        }
        .auth-form-area {
          animation: auth-fadein 0.3s ease both;
        }
      `}</style>

      {/* ── Left brand panel (desktop only) ─────────────────────────── */}
      <div
        className="hidden lg:flex auth-root"
        style={{
          width: "44%",
          minHeight: "100vh",
          background: "#22577A",
          position: "relative",
          overflow: "hidden",
          flexDirection: "column",
        }}
      >
        {/* Dot grid */}
        <div
          style={{
            position: "absolute",
            inset: 0,
            pointerEvents: "none",
            backgroundImage:
              "radial-gradient(rgba(255,255,255,0.09) 1px, transparent 1px)",
            backgroundSize: "26px 26px",
          }}
        />

        {/* Glow blobs */}
        <div
          style={{
            position: "absolute",
            top: "-100px",
            right: "-80px",
            width: "360px",
            height: "360px",
            borderRadius: "50%",
            background: "rgba(56,163,165,0.22)",
            filter: "blur(80px)",
            pointerEvents: "none",
          }}
        />
        <div
          style={{
            position: "absolute",
            bottom: "-80px",
            left: "-50px",
            width: "260px",
            height: "260px",
            borderRadius: "50%",
            background: "rgba(87,204,153,0.18)",
            filter: "blur(60px)",
            pointerEvents: "none",
          }}
        />

        {/* Watermark icon */}
        <div
          style={{
            position: "absolute",
            bottom: "16px",
            right: "-24px",
            opacity: 0.05,
            pointerEvents: "none",
          }}
        >
          <GraduationCap
            style={{ width: "260px", height: "260px", color: "#fff" }}
          />
        </div>

        {/* Logo */}
        <div
          style={{ position: "relative", zIndex: 1, padding: "30px 36px 0" }}
        >
          <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
            <div
              style={{
                width: "34px",
                height: "34px",
                borderRadius: "9px",
                background: "rgba(87,204,153,0.18)",
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
              }}
            >
              <GraduationCap
                style={{ width: "18px", height: "18px", color: "#57CC99" }}
              />
            </div>
            <span
              style={{
                color: "#fff",
                fontWeight: 800,
                fontSize: "17px",
                letterSpacing: "-0.01em",
              }}
            >
              ProctorAI
            </span>
          </div>
          {/* Thin accent divider */}
          <div
            style={{
              marginTop: "28px",
              height: "1px",
              background:
                "linear-gradient(90deg, rgba(87,204,153,0.5) 0%, rgba(87,204,153,0) 100%)",
            }}
          />
        </div>

        {/* Main content */}
        <div
          style={{
            position: "relative",
            zIndex: 1,
            flex: 1,
            display: "flex",
            flexDirection: "column",
            justifyContent: "center",
            padding: "36px 36px",
          }}
        >
          <p
            style={{
              color: "rgba(255,255,255,0.38)",
              fontSize: "11px",
              fontWeight: 700,
              letterSpacing: "0.15em",
              textTransform: "uppercase",
              marginBottom: "14px",
            }}
          >
            {eyebrow}
          </p>

          <h2
            style={{
              color: "#fff",
              fontSize: "29px",
              fontWeight: 800,
              lineHeight: 1.2,
              letterSpacing: "-0.02em",
              marginBottom: "14px",
              whiteSpace: "pre-line",
            }}
          >
            {leftHeading}
          </h2>

          <p
            style={{
              color: "rgba(255,255,255,0.52)",
              fontSize: "14px",
              lineHeight: 1.65,
              marginBottom: features?.length ? "34px" : 0,
            }}
          >
            {leftBody}
          </p>

          {features && features.length > 0 && (
            <div
              style={{ display: "flex", flexDirection: "column", gap: "12px" }}
            >
              {features.map((f, i) => (
                <div
                  key={i}
                  style={{
                    display: "flex",
                    alignItems: "flex-start",
                    gap: "10px",
                  }}
                >
                  <div
                    style={{
                      width: "20px",
                      height: "20px",
                      borderRadius: "50%",
                      flexShrink: 0,
                      background: "rgba(87,204,153,0.15)",
                      display: "flex",
                      alignItems: "center",
                      justifyContent: "center",
                      marginTop: "1px",
                    }}
                  >
                    <CheckCircle2
                      style={{
                        width: "11px",
                        height: "11px",
                        color: "#57CC99",
                      }}
                    />
                  </div>
                  <span
                    style={{
                      color: "rgba(255,255,255,0.62)",
                      fontSize: "13.5px",
                      lineHeight: 1.5,
                    }}
                  >
                    {f}
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Footer */}
        <div
          style={{ position: "relative", zIndex: 1, padding: "0 36px 26px" }}
        >
          <p style={{ color: "rgba(255,255,255,0.18)", fontSize: "11px" }}>
            © 2026 ProctorAI · All rights reserved
          </p>
        </div>
      </div>

      {/* ── Right form panel ─────────────────────────────────────────── */}
      <div
        className="auth-root"
        style={{
          flex: 1,
          display: "flex",
          flexDirection: "column",
          background: "#fff",
          overflowY: "auto",
        }}
      >
        {/* Gradient top bar */}
        <div
          style={{
            height: "3px",
            flexShrink: 0,
            background:
              "linear-gradient(90deg, #22577A 0%, #38A3A5 55%, #57CC99 100%)",
          }}
        />

        {/* Mobile logo bar */}
        <div
          className="lg:hidden"
          style={{
            padding: "14px 24px",
            borderBottom: "1px solid #F1F5F9",
            flexShrink: 0,
          }}
        >
          <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
            <div
              style={{
                width: "28px",
                height: "28px",
                borderRadius: "7px",
                background: "#EFF6FF",
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
              }}
            >
              <GraduationCap
                style={{ width: "15px", height: "15px", color: "#22577A" }}
              />
            </div>
            <span
              style={{
                color: "#22577A",
                fontWeight: 800,
                fontSize: "15px",
                letterSpacing: "-0.01em",
              }}
            >
              ProctorAI
            </span>
          </div>
        </div>

        {/* Centered form area */}
        <div
          style={{
            flex: 1,
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            padding: "40px 24px",
          }}
        >
          <div className="auth-form-area" style={{ width: "100%", maxWidth }}>
            {/* Back link */}
            {backHref && (
              <a
                href={backHref}
                style={{
                  display: "inline-flex",
                  alignItems: "center",
                  gap: "5px",
                  color: "#64748B",
                  fontSize: "13px",
                  fontWeight: 500,
                  textDecoration: "none",
                  marginBottom: "22px",
                  transition: "color 150ms",
                }}
                onMouseEnter={(e) =>
                  ((e.currentTarget as HTMLElement).style.color = "#475569")
                }
                onMouseLeave={(e) =>
                  ((e.currentTarget as HTMLElement).style.color = "#64748B")
                }
              >
                <ArrowLeft style={{ width: "14px", height: "14px" }} />
                {backLabel}
              </a>
            )}

            {/* Title */}
            <h1
              style={{
                color: "#0F172A",
                fontSize: "24px",
                fontWeight: 800,
                letterSpacing: "-0.025em",
                marginBottom: subtitle ? "6px" : "24px",
              }}
            >
              {title}
            </h1>
            {subtitle && (
              <p
                style={{
                  color: "#64748B",
                  fontSize: "14px",
                  lineHeight: 1.6,
                  marginBottom: "26px",
                }}
              >
                {subtitle}
              </p>
            )}

            {children}

            {footer && (
              <div
                style={{
                  marginTop: "20px",
                  textAlign: "center",
                  fontSize: "13px",
                  color: "#64748B",
                  lineHeight: 1.7,
                }}
              >
                {footer}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

// ── AuthField: label + input wrapper + error ──────────────────────────────────

export function AuthField({
  label,
  error,
  children,
  required,
}: {
  label: React.ReactNode;
  error?: string;
  children: React.ReactNode;
  required?: boolean;
}) {
  const renderedLabel =
    typeof label === "string" ? (
      <span
        style={{
          display: "inline-flex",
          alignItems: "baseline",
          gap: "3px",
          maxWidth: "100%",
        }}
      >
        <span>{label}</span>
        {required && (
          <span style={{ color: "#EF4444", whiteSpace: "nowrap" }}>*</span>
        )}
      </span>
    ) : (
      label
    );

  return (
    <div style={{ marginBottom: "16px" }}>
      <label
        style={{
          display: "block",
          fontSize: "13px",
          fontWeight: 600,
          color: "#475569",
          marginBottom: "6px",
          fontFamily: "'Plus Jakarta Sans', sans-serif",
        }}
      >
        {renderedLabel}
      </label>
      {children}
      {error && (
        <p
          style={{
            marginTop: "5px",
            fontSize: "12px",
            color: "#EF4444",
            fontFamily: "'Plus Jakarta Sans', sans-serif",
          }}
        >
          {error}
        </p>
      )}
    </div>
  );
}

// ── PasswordInput: input with show/hide toggle ────────────────────────────────

export function PasswordInput({
  placeholder = "••••••••",
  hasError,
  ...props
}: React.InputHTMLAttributes<HTMLInputElement> & { hasError?: boolean }) {
  const [show, setShow] = React.useState(false);
  return (
    <div style={{ position: "relative" }}>
      <input
        type={show ? "text" : "password"}
        placeholder={placeholder}
        className={`auth-input${hasError ? " has-error" : ""}`}
        style={{ paddingRight: "42px" }}
        {...props}
      />
      <button
        type="button"
        tabIndex={-1}
        onClick={() => setShow((s) => !s)}
        style={{
          position: "absolute",
          right: "12px",
          top: "50%",
          transform: "translateY(-50%)",
          background: "none",
          border: "none",
          cursor: "pointer",
          padding: "2px",
          color: "#64748B",
          display: "flex",
          alignItems: "center",
          transition: "color 150ms",
        }}
        onMouseEnter={(e) =>
          ((e.currentTarget as HTMLElement).style.color = "#475569")
        }
        onMouseLeave={(e) =>
          ((e.currentTarget as HTMLElement).style.color = "#64748B")
        }
      >
        {show ? (
          // EyeOff SVG inline
          <svg
            width="16"
            height="16"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="2"
            strokeLinecap="round"
            strokeLinejoin="round"
          >
            <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94" />
            <path d="M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19" />
            <line x1="1" y1="1" x2="23" y2="23" />
          </svg>
        ) : (
          // Eye SVG inline
          <svg
            width="16"
            height="16"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="2"
            strokeLinecap="round"
            strokeLinejoin="round"
          >
            <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z" />
            <circle cx="12" cy="12" r="3" />
          </svg>
        )}
      </button>
    </div>
  );
}
