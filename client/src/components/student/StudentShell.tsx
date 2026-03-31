'use client';

import React from 'react';
import { GraduationCap, LogOut, ChevronDown, User, ChevronLeft, ShieldCheck } from 'lucide-react';
import { useRouter } from 'next/navigation';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';

// ── Shared CSS injected once ─────────────────────────────────────────────────

export function StudentStyles() {
  return (
    <style>{`
      @import url('https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&display=swap');

      .st-root, .st-root * { box-sizing: border-box; font-family: 'Plus Jakarta Sans', sans-serif; }

      /* ── Buttons ── */
      .st-btn {
        display: inline-flex; align-items: center; justify-content: center; gap: 7px;
        padding: 9px 18px; border-radius: 8px; border: none;
        font-size: 13.5px; font-weight: 700; cursor: pointer; letter-spacing: 0.01em;
        font-family: 'Plus Jakarta Sans', sans-serif;
        background: #22577A; color: #fff;
        transition: background 150ms ease, transform 80ms ease;
        white-space: nowrap;
      }
      .st-btn:hover:not(:disabled) { background: #2C6A91; }
      .st-btn:active:not(:disabled) { background: #1B455F; transform: scale(0.99); }
      .st-btn:disabled { background: #94A3B8 !important; cursor: not-allowed; }

      .st-btn-lg {
        padding: 12px 24px; font-size: 14.5px; border-radius: 10px;
      }

      .st-btn-ghost {
        display: inline-flex; align-items: center; gap: 6px;
        padding: 8px 14px; border-radius: 8px;
        border: 1.5px solid #E2E8F0; background: #fff;
        font-size: 13px; font-family: 'Plus Jakarta Sans', sans-serif;
        font-weight: 600; cursor: pointer; color: #475569;
        transition: background 150ms, border-color 150ms;
      }
      .st-btn-ghost:hover { background: #F8FAFC; border-color: #CBD5E1; }
      .st-btn-ghost:disabled { opacity: 0.5; cursor: not-allowed; }

      .st-btn-danger {
        background: #EF4444; color: #fff;
      }
      .st-btn-danger:hover:not(:disabled) { background: #DC2626; }

      .st-btn-success {
        background: #22C55E; color: #fff;
      }
      .st-btn-success:hover:not(:disabled) { background: #16A34A; }

      .st-btn-warning {
        background: #F59E0B; color: #fff;
      }
      .st-btn-warning:hover:not(:disabled) { background: #D97706; }

      .st-btn-teal {
        background: #38A3A5; color: #fff;
      }
      .st-btn-teal:hover:not(:disabled) { background: #2E8789; }

      /* ── Cards ── */
      .st-card {
        background: #fff;
        border: 1.5px solid #CBD5E1;
        border-radius: 12px;
        overflow: hidden;
        box-shadow: 0 10px 30px rgba(15, 23, 42, 0.04);
      }

      /* ── Inputs ── */
      .st-input {
        display: block; width: 100%;
        padding: 9px 13px;
        border: 1.5px solid #E2E8F0;
        border-radius: 8px;
        font-size: 14px;
        font-family: 'Plus Jakarta Sans', sans-serif;
        color: #0F172A; background: #fff; line-height: 1.5;
        transition: border-color 150ms, box-shadow 150ms;
        outline: none;
      }
      .st-input:focus {
        border-color: #38A3A5;
        box-shadow: 0 0 0 3px rgba(56,163,165,0.12);
      }
      .st-input::placeholder { color: #CBD5E1; }
      .st-input:disabled { background: #F8FAFC; color: #94A3B8; cursor: not-allowed; }

      .st-textarea {
        display: block; width: 100%;
        padding: 9px 13px;
        border: 1.5px solid #E2E8F0;
        border-radius: 8px;
        font-size: 14px;
        font-family: 'Plus Jakarta Sans', sans-serif;
        color: #0F172A; background: #fff; line-height: 1.6;
        resize: vertical; min-height: 100px;
        transition: border-color 150ms, box-shadow 150ms;
        outline: none;
      }
      .st-textarea:focus {
        border-color: #38A3A5;
        box-shadow: 0 0 0 3px rgba(56,163,165,0.12);
      }
      .st-textarea::placeholder { color: #CBD5E1; }

      /* ── Badges ── */
      .st-badge {
        display: inline-flex; align-items: center; gap: 5px;
        padding: 3px 9px; border-radius: 20px;
        font-size: 11.5px; font-weight: 700; letter-spacing: 0.02em;
        border: 1px solid transparent; white-space: nowrap;
      }
      .st-badge-live    { background: rgba(34,197,94,0.1);  color: #16A34A; border-color: rgba(34,197,94,0.25); }
      .st-badge-scheduled { background: rgba(34,87,122,0.08); color: #22577A; border-color: rgba(34,87,122,0.2); }
      .st-badge-ended   { background: rgba(59,130,246,0.08); color: #2563EB; border-color: rgba(59,130,246,0.2); }
      .st-badge-terminated { background: rgba(239,68,68,0.08); color: #DC2626; border-color: rgba(239,68,68,0.2); }
      .st-badge-warning { background: rgba(245,158,11,0.1); color: #D97706; border-color: rgba(245,158,11,0.25); }
      .st-badge-muted   { background: #F1F5F9; color: #64748B; border-color: #E2E8F0; }
      .st-badge-active  { background: rgba(56,163,165,0.1); color: #38A3A5; border-color: rgba(56,163,165,0.25); }

      /* ── Animations ── */
      @keyframes st-fadein {
        from { opacity: 0; transform: translateY(8px); }
        to   { opacity: 1; transform: translateY(0); }
      }
      .st-fadein { animation: st-fadein 0.35s ease both; }

      @keyframes st-pulse-dot {
        0%, 100% { opacity: 1; transform: scale(1); }
        50% { opacity: 0.7; transform: scale(1.2); }
      }

      /* ── Link ── */
      .st-link { color: #38A3A5; text-decoration: none; font-weight: 600; transition: color 150ms; }
      .st-link:hover { color: #22577A; }

      /* ── Select (native) ── */
      .st-select {
        display: block; width: 100%;
        padding: 9px 13px;
        border: 1.5px solid #E2E8F0;
        border-radius: 8px;
        font-size: 14px;
        font-family: 'Plus Jakarta Sans', sans-serif;
        color: #0F172A; background: #fff;
        outline: none; cursor: pointer;
        transition: border-color 150ms, box-shadow 150ms;
        appearance: none;
        background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='12' viewBox='0 0 24 24' fill='none' stroke='%2394A3B8' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'%3E%3Cpolyline points='6 9 12 15 18 9'%3E%3C/polyline%3E%3C/svg%3E");
        background-repeat: no-repeat;
        background-position: right 12px center;
        padding-right: 36px;
      }
      .st-select:focus {
        border-color: #38A3A5;
        box-shadow: 0 0 0 3px rgba(56,163,165,0.12);
      }
    `}</style>
  );
}

// ── Student Page Shell (for dashboard, history, profile) ────────────────────

interface StudentPageShellProps {
  children: React.ReactNode;
  user?: any;
  onLogout?: () => void;
  backHref?: string;
  backLabel?: string;
  title?: string;
  loading?: boolean;
}

export function StudentPageShell({
  children,
  user,
  onLogout,
  backHref,
  backLabel = 'Back',
  title,
  loading,
}: StudentPageShellProps) {
  const router = useRouter();
  const initials = user?.full_name
    ? user.full_name.split(' ').map((n: string) => n[0]).join('').slice(0, 2).toUpperCase()
    : 'S';

  return (
    <div className="st-root" style={{ minHeight: '100vh', background: '#EEF4F8', fontFamily: "'Plus Jakarta Sans', sans-serif" }}>
      <StudentStyles />

      {/* Header */}
      <header style={{
        background: '#fff',
        borderBottom: '1px solid #E2E8F0',
        position: 'sticky', top: 0, zIndex: 40,
      }}>
        {/* Gradient accent bar */}
        <div style={{
          height: '3px',
          background: 'linear-gradient(90deg, #22577A 0%, #38A3A5 55%, #57CC99 100%)',
        }} />

        <div style={{ maxWidth: '1200px', margin: '0 auto', padding: '0 24px' }}>
          <div style={{ height: '60px', display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '16px' }}>
            {/* Left: logo or back */}
            {backHref ? (
              <button
                onClick={() => router.push(backHref)}
                className="st-btn-ghost"
                style={{ gap: '6px', padding: '7px 12px' }}
              >
                <ChevronLeft style={{ width: '15px', height: '15px' }} />
                {backLabel}
              </button>
            ) : (
              <div style={{ display: 'flex', alignItems: 'center', gap: '9px' }}>
                <div style={{
                  width: '32px', height: '32px', borderRadius: '8px',
                  background: '#22577A', display: 'flex', alignItems: 'center', justifyContent: 'center',
                }}>
                  <GraduationCap style={{ width: '16px', height: '16px', color: '#57CC99' }} />
                </div>
                <span style={{ fontWeight: 800, fontSize: '16px', color: '#0F172A', letterSpacing: '-0.01em' }}>ProctorAI</span>
              </div>
            )}

            {/* Right: nav actions */}
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              {onLogout && (
                <DropdownMenu>
                  <DropdownMenuTrigger asChild>
                    <button
                      type="button"
                      style={{
                        display: 'flex', alignItems: 'center', gap: '8px',
                        padding: '6px 10px', borderRadius: '10px', cursor: 'pointer',
                        background: 'transparent', border: 'none', transition: 'background 150ms',
                      }}
                      onMouseEnter={e => (e.currentTarget as HTMLElement).style.background = '#F1F5F9'}
                      onMouseLeave={e => (e.currentTarget as HTMLElement).style.background = 'transparent'}
                    >
                      <div style={{
                        width: '30px', height: '30px', borderRadius: '50%',
                        background: '#22577A', display: 'flex', alignItems: 'center', justifyContent: 'center',
                        fontSize: '12px', fontWeight: 700, color: '#fff', flexShrink: 0,
                      }}>
                        {loading ? '·' : initials}
                      </div>
                      <span style={{ fontSize: '13px', fontWeight: 600, color: '#475569' }}>
                        {loading ? '…' : user?.full_name?.split(' ')[0] || 'Student'}
                      </span>
                      <ChevronDown style={{ width: '14px', height: '14px', color: '#94A3B8' }} />
                    </button>
                  </DropdownMenuTrigger>

                  <DropdownMenuContent align="end" className="w-44">
                    <DropdownMenuItem
                      onClick={() => router.push('/student/profile')}
                      className="cursor-pointer"
                    >
                      <User />
                      Profile
                    </DropdownMenuItem>
                    <DropdownMenuItem
                      onClick={onLogout}
                      className="cursor-pointer text-red-600 focus:text-red-600"
                    >
                      <LogOut />
                      Logout
                    </DropdownMenuItem>
                  </DropdownMenuContent>
                </DropdownMenu>
              )}
            </div>
          </div>
        </div>
      </header>

      {/* Main content */}
      <main style={{ maxWidth: '1200px', margin: '0 auto', padding: '32px 24px' }}>
        {title && (
          <div style={{ marginBottom: '28px' }}>
            <h1 style={{ fontSize: '22px', fontWeight: 800, color: '#0F172A', letterSpacing: '-0.02em' }}>{title}</h1>
          </div>
        )}
        {children}
      </main>
    </div>
  );
}

// ── Secure Exam Shell (for exam flow pages) ──────────────────────────────────

export function ExamSecureShell({ children }: { children: React.ReactNode }) {
  return (
    <div className="st-root" style={{ minHeight: '100vh', background: '#F8FAFC', display: 'flex', flexDirection: 'column', fontFamily: "'Plus Jakarta Sans', sans-serif" }}>
      <StudentStyles />

      {/* Secure header */}
      <header style={{
        background: '#fff', borderBottom: '1px solid #E2E8F0',
        padding: '0 24px', height: '56px',
        display: 'flex', alignItems: 'center', justifyContent: 'space-between',
        position: 'sticky', top: 0, zIndex: 50,
        boxShadow: '0 1px 3px rgba(0,0,0,0.05)',
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <div style={{
            width: '30px', height: '30px', borderRadius: '7px',
            background: 'rgba(34,87,122,0.1)', display: 'flex', alignItems: 'center', justifyContent: 'center',
          }}>
            <ShieldCheck style={{ width: '15px', height: '15px', color: '#22577A' }} />
          </div>
          <span style={{ fontWeight: 800, fontSize: '14.5px', color: '#0F172A', letterSpacing: '-0.01em' }}>
            ProctorAI Secure Environment
          </span>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '7px' }}>
          <span style={{ position: 'relative', display: 'flex', width: '10px', height: '10px' }}>
            <span style={{
              position: 'absolute', inset: 0, borderRadius: '50%',
              background: '#22C55E', opacity: 0.6,
              animation: 'ping 1s cubic-bezier(0,0,.2,1) infinite',
            }} />
            <style>{`@keyframes ping{75%,100%{transform:scale(2);opacity:0}}`}</style>
            <span style={{ position: 'relative', borderRadius: '50%', background: '#22C55E', width: '10px', height: '10px' }} />
          </span>
          <span style={{
            fontSize: '12px', fontWeight: 700, color: '#16A34A',
            background: 'rgba(34,197,94,0.08)', padding: '4px 10px',
            borderRadius: '20px', border: '1px solid rgba(34,197,94,0.2)',
          }}>
            Secure Connection
          </span>
        </div>
      </header>

      <main style={{ flex: 1, display: 'flex', flexDirection: 'column' }}>
        {children}
      </main>
    </div>
  );
}
