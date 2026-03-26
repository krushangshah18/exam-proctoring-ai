'use client';

import { useState, useEffect, useCallback } from 'react';
import Link from 'next/link';
import {
  Users, Shield, FileText, Activity, Cpu, BarChart2, Lock,
  ArrowUpRight, BookOpen, RefreshCw, Loader2,
} from 'lucide-react';
import api from '@/lib/axios';

interface Stats {
  total_users: number;
  active_exams: number;
  live_sessions: number;
  pending_applications: number;
  locked_users: number;
  active_containers: number;
  total_exams: number;
}

// ── Shared card wrapper ────────────────────────────────────────────────────────
function Panel({ children, className = '' }: { children: React.ReactNode; className?: string }) {
  return (
    <div className={`bg-white rounded-xl border p-5 ${className}`}
      style={{ borderColor: '#E2E8F0', boxShadow: '0 1px 3px rgba(15,23,42,0.04)' }}>
      {children}
    </div>
  );
}

export default function SystemDashboard() {
  const [stats, setStats]   = useState<Stats | null>(null);
  const [loading, setLoading] = useState(true);

  const fetchStats = useCallback(async () => {
    try {
      const res = await api.get('/admin/stats');
      setStats(res.data);
    } catch {}
    finally { setLoading(false); }
  }, []);

  useEffect(() => {
    fetchStats();
    const id = setInterval(fetchStats, 30000);
    return () => clearInterval(id);
  }, [fetchStats]);

  const v = (key: keyof Stats) => (loading ? null : (stats?.[key] ?? 0));

  const STATS = [
    { label: 'Live Sessions',    value: v('live_sessions'),        icon: Activity,  iconBg: '#ECFDF5', iconColor: '#16A34A', href: '/sys/dashboard/sessions'  },
    { label: 'Active Exams',     value: v('active_exams'),         icon: BookOpen,  iconBg: '#EFF6FF', iconColor: '#2563EB', href: null                       },
    { label: 'Total Users',      value: v('total_users'),          icon: Users,     iconBg: '#F0F9FF', iconColor: '#0284C7', href: '/sys/dashboard/users'     },
    { label: 'Pending Apps',     value: v('pending_applications'), icon: FileText,  iconBg: '#FFFBEB', iconColor: '#D97706', href: '/sys/dashboard/applications' },
    { label: 'Locked Accounts',  value: v('locked_users'),         icon: Lock,      iconBg: '#FFF1F2', iconColor: '#E11D48', href: '/sys/dashboard/users'     },
    { label: 'Engine Nodes',     value: v('active_containers'),    icon: Cpu,       iconBg: '#F5F3FF', iconColor: '#7C3AED', href: '/sys/dashboard/engine'    },
  ];

  const NAV_CARDS = [
    {
      href: '/sys/dashboard/applications',
      icon: FileText, accent: '#D97706',
      title: 'Applications',
      desc: 'Review and approve incoming teacher and admin account applications.',
    },
    {
      href: '/sys/dashboard/users',
      icon: Users, accent: '#22577A',
      title: 'User Management',
      desc: 'Search, filter, and manage all platform accounts. Unlock locked users.',
    },
    {
      href: '/sys/dashboard/sessions',
      icon: Activity, accent: '#16A34A',
      title: 'Live Sessions',
      desc: 'Monitor all active exam sessions across every exam in real-time.',
    },
    {
      href: '/sys/dashboard/engine',
      icon: Cpu, accent: '#7C3AED',
      title: 'Engine Monitor',
      desc: 'AI proctoring engine health, GPU utilisation, and inference performance.',
    },
    {
      href: '/sys/dashboard/reports',
      icon: BarChart2, accent: '#2563EB',
      title: 'Reports',
      desc: 'Browse all session reports grouped by exam. Download or delete archives.',
    },
    {
      href: '/sys/dashboard/system-settings',
      icon: Shield, accent: '#38A3A5',
      title: 'Engine Settings',
      desc: 'Configure AI detection thresholds, risk scoring, and termination rules.',
    },
  ];

  return (
    <div className="space-y-8 max-w-6xl">

      {/* ── Page header ─────────────────────────────────────────── */}
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold" style={{ color: '#0F172A', letterSpacing: '-0.025em' }}>
            System Overview
          </h1>
          <p className="text-sm mt-1" style={{ color: '#94A3B8' }}>
            Platform health and live activity
          </p>
        </div>
        <button
          onClick={fetchStats}
          className="flex items-center gap-2 px-3 py-2 rounded-lg text-sm font-medium border transition-all duration-150"
          style={{ borderColor: '#E2E8F0', color: '#475569', background: '#fff' }}
          onMouseEnter={e => { (e.currentTarget as HTMLElement).style.borderColor = '#38A3A5'; (e.currentTarget as HTMLElement).style.color = '#22577A'; }}
          onMouseLeave={e => { (e.currentTarget as HTMLElement).style.borderColor = '#E2E8F0'; (e.currentTarget as HTMLElement).style.color = '#475569'; }}
        >
          {loading
            ? <Loader2 className="h-3.5 w-3.5 animate-spin" />
            : <RefreshCw className="h-3.5 w-3.5" />}
          Refresh
        </button>
      </div>

      {/* ── Stat grid ───────────────────────────────────────────── */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-4">
        {STATS.map(({ label, value, icon: Icon, iconBg, iconColor, href }) => {
          const card = (
            <Panel key={label} className={href ? 'hover:shadow-md transition-shadow cursor-pointer' : ''}>
              <div className="flex items-center justify-between mb-3">
                <div className="h-8 w-8 rounded-lg flex items-center justify-center shrink-0"
                  style={{ background: iconBg }}>
                  <Icon className="h-4 w-4" style={{ color: iconColor }} />
                </div>
                {href && <ArrowUpRight className="h-3.5 w-3.5" style={{ color: '#CBD5E1' }} />}
              </div>
              <p className="text-2xl font-bold tabular-nums" style={{ color: '#0F172A' }}>
                {value === null
                  ? <span className="text-xl" style={{ color: '#CBD5E1' }}>—</span>
                  : value}
              </p>
              <p className="text-xs mt-0.5" style={{ color: '#94A3B8' }}>{label}</p>
            </Panel>
          );
          return href ? <Link key={label} href={href}>{card}</Link> : <div key={label}>{card}</div>;
        })}
      </div>

      {/* ── Alert pills ─────────────────────────────────────────── */}
      {!loading && stats && (
        <div className="flex flex-wrap gap-2">
          {stats.pending_applications > 0 && (
            <Link href="/sys/dashboard/applications">
              <span className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full text-xs font-semibold border cursor-pointer transition-all duration-150 hover:opacity-80"
                style={{ background: '#FFFBEB', borderColor: '#FDE68A', color: '#B45309' }}>
                <span className="h-1.5 w-1.5 rounded-full bg-amber-400 animate-pulse" />
                {stats.pending_applications} pending application{stats.pending_applications !== 1 ? 's' : ''}
              </span>
            </Link>
          )}
          {stats.locked_users > 0 && (
            <Link href="/sys/dashboard/users">
              <span className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full text-xs font-semibold border cursor-pointer transition-all duration-150 hover:opacity-80"
                style={{ background: '#FFF1F2', borderColor: '#FECDD3', color: '#BE123C' }}>
                <span className="h-1.5 w-1.5 rounded-full bg-rose-400" />
                {stats.locked_users} locked account{stats.locked_users !== 1 ? 's' : ''}
              </span>
            </Link>
          )}
          {stats.live_sessions > 0 && (
            <Link href="/sys/dashboard/sessions">
              <span className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full text-xs font-semibold border cursor-pointer transition-all duration-150 hover:opacity-80"
                style={{ background: '#ECFDF5', borderColor: '#A7F3D0', color: '#065F46' }}>
                <span className="h-1.5 w-1.5 rounded-full bg-emerald-400 animate-pulse" />
                {stats.live_sessions} live session{stats.live_sessions !== 1 ? 's' : ''} in progress
              </span>
            </Link>
          )}
        </div>
      )}

      {/* ── Divider ─────────────────────────────────────────────── */}
      <div className="flex items-center gap-3">
        <div className="flex-1 h-px" style={{ background: '#E2E8F0' }} />
        <p className="text-[10px] font-semibold tracking-widest uppercase" style={{ color: '#CBD5E1' }}>Quick Access</p>
        <div className="flex-1 h-px" style={{ background: '#E2E8F0' }} />
      </div>

      {/* ── Quick nav cards ──────────────────────────────────────── */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
        {NAV_CARDS.map(({ href, icon: Icon, accent, title, desc }) => (
          <Link key={href} href={href}>
            <div
              className="bg-white rounded-xl border p-5 h-full flex flex-col gap-3 transition-all duration-200 group"
              style={{ borderColor: '#E2E8F0', boxShadow: '0 1px 3px rgba(15,23,42,0.04)' }}
              onMouseEnter={e => { (e.currentTarget as HTMLElement).style.boxShadow = `0 4px 16px rgba(15,23,42,0.08), 0 0 0 1px ${accent}33`; (e.currentTarget as HTMLElement).style.borderColor = `${accent}55`; }}
              onMouseLeave={e => { (e.currentTarget as HTMLElement).style.boxShadow = '0 1px 3px rgba(15,23,42,0.04)'; (e.currentTarget as HTMLElement).style.borderColor = '#E2E8F0'; }}
            >
              <div className="flex items-start justify-between">
                <div className="h-9 w-9 rounded-lg flex items-center justify-center shrink-0"
                  style={{ background: `${accent}14` }}>
                  <Icon className="h-4.5 w-4.5" style={{ color: accent }} />
                </div>
                <ArrowUpRight className="h-4 w-4 mt-0.5 opacity-0 group-hover:opacity-100 transition-opacity" style={{ color: accent }} />
              </div>
              <div className="flex-1">
                <p className="text-sm font-semibold mb-1" style={{ color: '#0F172A' }}>{title}</p>
                <p className="text-xs leading-relaxed" style={{ color: '#94A3B8' }}>{desc}</p>
              </div>
            </div>
          </Link>
        ))}
      </div>
    </div>
  );
}
