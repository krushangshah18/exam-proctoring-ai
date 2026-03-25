'use client';

import { useState, useEffect, useCallback } from 'react';
import Link from 'next/link';
import {
  Users, Shield, FileText, Activity, Cpu, BarChart2, Lock,
  ArrowRight, BookOpen, RefreshCw, Loader2,
} from 'lucide-react';
import { Card, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
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

export default function SystemDashboard() {
  const [stats, setStats] = useState<Stats | null>(null);
  const [loading, setLoading] = useState(true);

  const fetchStats = useCallback(async () => {
    try {
      const res = await api.get('/admin/stats');
      setStats(res.data);
    } catch {
      // silently fail — don't block page
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchStats();
    const id = setInterval(fetchStats, 30000);
    return () => clearInterval(id);
  }, [fetchStats]);

  const stat = (key: keyof Stats) => (loading ? '—' : (stats?.[key] ?? 0));

  return (
    <div className="space-y-8 pb-12">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-slate-900">System Overview</h1>
          <p className="text-sm text-slate-500 mt-0.5">Real-time platform health and activity</p>
        </div>
        <Button variant="outline" size="sm" onClick={fetchStats} className="gap-2 border-slate-200">
          {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : <RefreshCw className="h-4 w-4" />}
          Refresh
        </Button>
      </div>

      {/* Live stats row */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-4">
        {[
          { label: 'Live Sessions',   value: stat('live_sessions'),        icon: Activity,  color: 'emerald', href: '/sys/dashboard/sessions'  },
          { label: 'Active Exams',    value: stat('active_exams'),         icon: BookOpen,  color: 'indigo',  href: null                       },
          { label: 'Total Users',     value: stat('total_users'),          icon: Users,     color: 'blue',    href: '/sys/dashboard/users'     },
          { label: 'Pending Apps',    value: stat('pending_applications'), icon: FileText,  color: 'amber',   href: '/sys/dashboard/applications' },
          { label: 'Locked Accounts', value: stat('locked_users'),         icon: Lock,      color: 'rose',    href: '/sys/dashboard/users'     },
          { label: 'Engine Nodes',    value: stat('active_containers'),    icon: Cpu,       color: 'purple',  href: '/sys/dashboard/engine'    },
        ].map(({ label, value, icon: Icon, color, href }) => {
          const card = (
            <Card key={label} className={`shadow-none border-slate-200 ${href ? 'cursor-pointer hover:shadow-md transition-shadow' : ''}`}>
              <CardContent className="pt-5 pb-4">
                <div className={`inline-flex p-2 rounded-lg bg-${color}-100 mb-3`}>
                  <Icon className={`h-5 w-5 text-${color}-600`} />
                </div>
                <p className="text-2xl font-bold text-slate-900 tabular-nums">{value}</p>
                <p className="text-xs text-slate-500 mt-0.5">{label}</p>
              </CardContent>
            </Card>
          );
          return href ? <Link key={label} href={href}>{card}</Link> : card;
        })}
      </div>

      {/* Alerts row */}
      {!loading && stats && (
        <div className="flex flex-wrap gap-3">
          {stats.pending_applications > 0 && (
            <Link href="/sys/dashboard/applications">
              <Badge variant="outline" className="text-amber-700 bg-amber-50 border-amber-200 px-3 py-1.5 text-sm cursor-pointer hover:bg-amber-100">
                {stats.pending_applications} pending application{stats.pending_applications !== 1 ? 's' : ''} need review
              </Badge>
            </Link>
          )}
          {stats.locked_users > 0 && (
            <Link href="/sys/dashboard/users">
              <Badge variant="outline" className="text-rose-700 bg-rose-50 border-rose-200 px-3 py-1.5 text-sm cursor-pointer hover:bg-rose-100">
                {stats.locked_users} locked account{stats.locked_users !== 1 ? 's' : ''}
              </Badge>
            </Link>
          )}
          {stats.live_sessions > 0 && (
            <Link href="/sys/dashboard/sessions">
              <Badge variant="outline" className="text-emerald-700 bg-emerald-50 border-emerald-200 px-3 py-1.5 text-sm cursor-pointer hover:bg-emerald-100">
                {stats.live_sessions} live session{stats.live_sessions !== 1 ? 's' : ''} in progress
              </Badge>
            </Link>
          )}
        </div>
      )}

      {/* Quick nav cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-5">
        {[
          {
            href: '/sys/dashboard/applications',
            icon: FileText, iconColor: 'text-amber-500', border: 'border-l-amber-400',
            title: 'Applications',
            desc: 'Review and approve pending teacher and admin account applications.',
            cta: 'Manage Applications',
          },
          {
            href: '/sys/dashboard/users',
            icon: Users, iconColor: 'text-blue-500', border: 'border-l-blue-400',
            title: 'User Management',
            desc: 'Search users, view profiles, manage permissions, and unlock accounts.',
            cta: 'Manage Users',
          },
          {
            href: '/sys/dashboard/sessions',
            icon: Activity, iconColor: 'text-emerald-500', border: 'border-l-emerald-400',
            title: 'Live Sessions',
            desc: 'Monitor all active exam sessions across every exam in real-time.',
            cta: 'View Sessions',
          },
          {
            href: '/sys/dashboard/engine',
            icon: Cpu, iconColor: 'text-purple-500', border: 'border-l-purple-400',
            title: 'Engine Monitor',
            desc: 'Check AI proctoring engine health, GPU usage, and inference performance.',
            cta: 'Open Monitor',
          },
          {
            href: '/sys/dashboard/reports',
            icon: BarChart2, iconColor: 'text-indigo-500', border: 'border-l-indigo-400',
            title: 'Reports',
            desc: 'Browse all session reports grouped by exam. Download or delete reports.',
            cta: 'View Reports',
          },
          {
            href: '/sys/dashboard/system-settings',
            icon: Shield, iconColor: 'text-slate-500', border: 'border-l-slate-400',
            title: 'Engine Settings',
            desc: 'Configure AI proctoring thresholds, scoring, and termination rules.',
            cta: 'Adjust Settings',
          },
        ].map(({ href, icon: Icon, iconColor, border, title, desc, cta }) => (
          <Card key={href} className={`border-l-4 ${border} hover:shadow-md transition-shadow`}>
            <CardContent className="pt-5 pb-5 space-y-3">
              <div className="flex items-center gap-2">
                <Icon className={`h-5 w-5 ${iconColor}`} />
                <p className="font-semibold text-slate-900">{title}</p>
              </div>
              <p className="text-sm text-slate-500">{desc}</p>
              <Button asChild variant="outline" size="sm" className="w-full">
                <Link href={href}>
                  {cta} <ArrowRight className="ml-2 h-4 w-4" />
                </Link>
              </Button>
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  );
}
