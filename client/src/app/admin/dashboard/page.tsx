'use client';

import { useState, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import {
  PlusCircle,
  Users,
  ClipboardCheck,
  Activity,
  ArrowRight,
  FileText,
  Loader2,
  BookOpen,
} from 'lucide-react';
import { useRouter } from 'next/navigation';
import api from '@/lib/axios';

interface Stats {
  total_exams: number;
  live_exams: number;
  total_sessions: number;
  live_sessions: number;
  pending_appeals: number;
  total_students: number;
}

interface RecentExam {
  id: string;
  title: string;
  status: string;
  start_window: string | null;
  duration_minutes: number;
  invite_count: number;
}

const STATUS_STYLES: Record<string, string> = {
  LIVE: 'bg-emerald-100 text-emerald-700',
  SCHEDULED: 'bg-blue-100 text-blue-700',
  ENDED: 'bg-slate-100 text-slate-500',
  CANCELLED: 'bg-rose-100 text-rose-600',
};

function fmtWindow(iso: string | null) {
  if (!iso) return '—';
  return new Date(iso).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' });
}

export default function AdminDashboard() {
  const router = useRouter();
  const [user, setUser] = useState<any>(null);
  const [stats, setStats] = useState<Stats | null>(null);
  const [recentExams, setRecentExams] = useState<RecentExam[]>([]);
  const [loadingStats, setLoadingStats] = useState(true);

  useEffect(() => {
    Promise.all([
      api.get('/auth/me'),
      api.get('/admin/exams/stats'),
      api.get('/admin/exams'),
    ]).then(([userRes, statsRes, examsRes]) => {
      setUser(userRes.data);
      setStats(statsRes.data);
      setRecentExams((examsRes.data as RecentExam[]).slice(0, 5));
    }).catch(() => {}).finally(() => setLoadingStats(false));
  }, []);

  const metrics = stats ? [
    {
      title: 'Live Sessions',
      value: stats.live_sessions,
      icon: Activity,
      description: `${stats.total_sessions} total sessions`,
      color: 'text-emerald-600',
      bg: 'bg-emerald-100',
      alert: stats.live_sessions > 0,
    },
    {
      title: 'Active Exams',
      value: stats.live_exams,
      icon: BookOpen,
      description: `${stats.total_exams} total exams created`,
      color: 'text-blue-600',
      bg: 'bg-blue-100',
      alert: false,
    },
    {
      title: 'Total Students',
      value: stats.total_students,
      icon: Users,
      description: 'Invited across all exams',
      color: 'text-purple-600',
      bg: 'bg-purple-100',
      alert: false,
    },
    {
      title: 'Pending Appeals',
      value: stats.pending_appeals,
      icon: ClipboardCheck,
      description: 'Termination appeals awaiting review',
      color: 'text-amber-600',
      bg: 'bg-amber-100',
      alert: stats.pending_appeals > 0,
    },
  ] : [];

  return (
    <div className="space-y-8">

      {/* Welcome banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 bg-gradient-to-r from-indigo-500 to-purple-600 rounded-2xl p-8 text-white shadow-lg">
        <div>
          <h1 className="text-3xl font-bold mb-2">
            Welcome back, {user?.full_name?.split(' ')[0] || 'Admin'}!
          </h1>
          <p className="text-indigo-100 max-w-xl">
            {stats?.pending_appeals
              ? `You have ${stats.pending_appeals} pending appeal${stats.pending_appeals !== 1 ? 's' : ''} awaiting review.`
              : stats?.live_sessions
              ? `${stats.live_sessions} student${stats.live_sessions !== 1 ? 's' : ''} currently taking exams.`
              : 'Monitor your exams and review proctoring reports.'}
          </p>
        </div>
        <Button
          onClick={() => router.push('/admin/dashboard/exams/new')}
          className="bg-white text-indigo-600 hover:bg-indigo-50 shadow-md font-semibold px-6 py-6"
        >
          <PlusCircle className="mr-2 h-5 w-5" />
          Create New Exam
        </Button>
      </div>

      {/* Metrics Grid */}
      {loadingStats ? (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
          {[1,2,3,4].map(i => (
            <Card key={i} className="border-none shadow-md">
              <CardContent className="pt-6 flex items-center justify-center h-24">
                <Loader2 className="h-6 w-6 animate-spin text-slate-300" />
              </CardContent>
            </Card>
          ))}
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
          {metrics.map((metric, i) => (
            <Card key={i} className="border-none shadow-md hover:shadow-lg transition-shadow">
              <CardHeader className="flex flex-row items-center justify-between pb-2">
                <CardTitle className="text-sm font-medium text-muted-foreground">{metric.title}</CardTitle>
                <div className={`p-2 rounded-full ${metric.bg} relative`}>
                  <metric.icon className={`h-4 w-4 ${metric.color}`} />
                  {metric.alert && (
                    <span className="absolute -top-1 -right-1 h-2.5 w-2.5 rounded-full bg-amber-400 border-2 border-white" />
                  )}
                </div>
              </CardHeader>
              <CardContent>
                <div className="text-3xl font-bold">{metric.value}</div>
                <p className="text-xs text-muted-foreground mt-1">{metric.description}</p>
              </CardContent>
            </Card>
          ))}
        </div>
      )}

      {/* Recent Exams */}
      <Card className="shadow-sm">
        <CardHeader className="flex flex-row items-center justify-between border-b pb-4">
          <div>
            <CardTitle>Recent Exams</CardTitle>
            <CardDescription>Your latest exams</CardDescription>
          </div>
          <Button variant="ghost" className="text-indigo-600" onClick={() => router.push('/admin/dashboard/exams')}>
            View All <ArrowRight className="ml-2 h-4 w-4" />
          </Button>
        </CardHeader>
        <CardContent className="p-0">
          {recentExams.length === 0 ? (
            <div className="py-12 text-center text-slate-400 text-sm">No exams yet</div>
          ) : (
            <div className="divide-y">
              {recentExams.map((exam) => (
                <div key={exam.id} className="flex items-center justify-between p-5 hover:bg-gray-50 transition-colors">
                  <div className="flex items-center gap-4">
                    <div className="h-10 w-10 rounded-lg bg-indigo-100 flex items-center justify-center shrink-0">
                      <FileText className="h-5 w-5 text-indigo-600" />
                    </div>
                    <div>
                      <h4 className="font-semibold text-sm">{exam.title}</h4>
                      <div className="flex items-center gap-2 mt-0.5">
                        <span className={`text-xs px-1.5 py-0.5 rounded font-medium ${STATUS_STYLES[exam.status] ?? 'bg-slate-100 text-slate-500'}`}>
                          {exam.status}
                        </span>
                        <span className="text-xs text-muted-foreground">{exam.invite_count} students · {exam.duration_minutes}m</span>
                      </div>
                    </div>
                  </div>
                  <div className="flex items-center gap-3">
                    <p className="text-xs text-muted-foreground hidden md:block">{fmtWindow(exam.start_window)}</p>
                    <Button variant="outline" size="sm" onClick={() => router.push(`/admin/dashboard/exams/${exam.id}`)}>
                      Manage
                    </Button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
