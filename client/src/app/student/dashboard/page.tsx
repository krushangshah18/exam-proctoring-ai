'use client';

import { useState, useEffect } from 'react';
import RoleGuard from '@/components/auth/role-guard';
import DeviceManagement from '@/components/auth/device-management';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import {
  Calendar, Clock, LogOut, User, ArrowRight, History,
  Loader2, BookOpen, ShieldAlert, AlertTriangle
} from 'lucide-react';
import { useRouter } from 'next/navigation';
import api from '@/lib/axios';
import { toast } from 'sonner';
import { parseUTC, fmtTimeTZ } from '@/lib/fmt-date';

interface UpcomingExam {
  id: string;
  title: string;
  exam_mode: string;
  start_window: string;
  end_window: string;
  duration_minutes: number;
  hard_join_deadline: string | null;
  status: string;
}

const STATUS_CONFIG: Record<string, { label: string; classes: string; dot: string }> = {
  LIVE: {
    label: 'Live Now',
    classes: 'bg-emerald-50 text-emerald-700 border-emerald-200',
    dot: 'bg-emerald-500',
  },
  SCHEDULED: {
    label: 'Upcoming',
    classes: 'bg-indigo-50 text-indigo-700 border-indigo-200',
    dot: 'bg-indigo-400',
  },
};

function ExamCard({ exam, onClick }: { exam: UpcomingExam; onClick: () => void }) {
  const cfg = STATUS_CONFIG[exam.status] ?? STATUS_CONFIG.SCHEDULED;
  const startDate = parseUTC(exam.start_window);
  const isToday = startDate.toDateString() === new Date().toDateString();
  const isTomorrow =
    startDate.toDateString() === new Date(Date.now() + 86400000).toDateString();

  const dateLabel = isToday
    ? 'Today'
    : isTomorrow
    ? 'Tomorrow'
    : startDate.toLocaleDateString(undefined, { month: 'short', day: 'numeric' });

  return (
    <div
      onClick={onClick}
      className="group p-5 rounded-xl border border-slate-200 bg-white hover:border-indigo-400 hover:shadow-md transition-all cursor-pointer"
    >
      <div className="flex items-start justify-between gap-3 mb-3">
        <h3 className="font-bold text-slate-900 group-hover:text-indigo-600 transition-colors leading-tight line-clamp-2">
          {exam.title}
        </h3>
        <Badge variant="outline" className={`shrink-0 text-xs font-semibold ${cfg.classes}`}>
          <span className={`inline-block h-1.5 w-1.5 rounded-full mr-1.5 ${cfg.dot}`} />
          {cfg.label}
        </Badge>
      </div>

      <div className="space-y-1.5 text-sm text-slate-500">
        <div className="flex items-center gap-2">
          <Calendar className="h-3.5 w-3.5 shrink-0 text-slate-400" />
          <span>
            <strong className={`${isToday ? 'text-emerald-600' : 'text-slate-700'}`}>{dateLabel}</strong>{' '}
            at {fmtTimeTZ(exam.start_window)}
          </span>
        </div>
        <div className="flex items-center gap-2">
          <Clock className="h-3.5 w-3.5 shrink-0 text-slate-400" />
          <span>{exam.duration_minutes} minutes</span>
        </div>
        {exam.hard_join_deadline && (
          <div className="flex items-center gap-2">
            <AlertTriangle className="h-3.5 w-3.5 shrink-0 text-amber-400" />
            <span>
              Deadline:{' '}
              {parseUTC(exam.hard_join_deadline).toLocaleDateString(undefined, {
                month: 'short',
                day: 'numeric',
              })}{' '}
              at{' '}
              {fmtTimeTZ(exam.hard_join_deadline)}
            </span>
          </div>
        )}
      </div>

      <div className="mt-4 flex items-center justify-between">
        <Badge variant="secondary" className="text-[10px] uppercase font-semibold">
          {exam.exam_mode}
        </Badge>
        <span className="text-xs text-indigo-500 font-semibold flex items-center gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
          Open <ArrowRight className="h-3.5 w-3.5" />
        </span>
      </div>
    </div>
  );
}

export default function StudentDashboard() {
  const router = useRouter();
  const [user, setUser] = useState<any>(null);
  const [exams, setExams] = useState<UpcomingExam[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchData();
  }, []);

  const fetchData = async () => {
    try {
      const [userRes, examsRes] = await Promise.all([
        api.get('/auth/me'),
        api.get('/exam/upcoming'),
      ]);
      setUser(userRes.data);
      setExams(examsRes.data);
    } catch {
      toast.error('Failed to load dashboard');
    } finally {
      setLoading(false);
    }
  };

  const handleLogout = async () => {
    try {
      const refreshToken = localStorage.getItem('refresh_token');
      if (refreshToken) {
        await api.post('/auth/logout', { refresh_token: refreshToken });
      }
    } catch {}
    finally {
      localStorage.removeItem('access_token');
      localStorage.removeItem('refresh_token');
      toast.success('Logged out successfully');
      router.push('/auth/login');
    }
  };

  const liveExams = exams.filter((e) => e.status === 'LIVE');
  const scheduledExams = exams.filter((e) => e.status === 'SCHEDULED');

  return (
    <RoleGuard allowedRoles={['STUDENT']}>
      <div className="min-h-screen bg-slate-50">
        {/* Header */}
        <header className="bg-white border-b border-slate-200 sticky top-0 z-10">
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
            <div className="flex justify-between items-center h-16">
              <div className="flex items-center gap-2">
                <ShieldAlert className="h-6 w-6 text-indigo-600" />
                <h1 className="text-xl font-bold text-slate-900">Proctor AI</h1>
              </div>
              <div className="flex items-center gap-2">
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => router.push('/student/history')}
                  className="gap-2 text-slate-600 hover:text-slate-900"
                >
                  <History className="h-4 w-4" />
                  <span className="hidden sm:inline">Exam History</span>
                </Button>
                <button
                  onClick={() => router.push('/student/profile')}
                  className="flex items-center gap-2 hover:bg-slate-100 px-3 py-2 rounded-md transition-colors"
                >
                  <div className="p-1.5 bg-gradient-to-br from-indigo-500 to-purple-600 rounded-full">
                    <User className="h-3.5 w-3.5 text-white" />
                  </div>
                  <span className="text-sm font-medium text-slate-700 hidden sm:block">
                    {loading ? '…' : user?.full_name || 'Student'}
                  </span>
                </button>
                <Button variant="ghost" size="sm" onClick={handleLogout} className="text-slate-500">
                  <LogOut className="h-4 w-4" />
                </Button>
              </div>
            </div>
          </div>
        </header>

        {/* Main */}
        <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-8">

          {/* Welcome */}
          <div>
            <h2 className="text-2xl font-bold text-slate-900">
              Welcome back, {loading ? '…' : user?.full_name?.split(' ')[0] || 'Student'}!
            </h2>
            <p className="text-slate-500 mt-1 text-sm">
              Your upcoming and live exams are listed below.
            </p>
          </div>

          {/* Live Exams — shown prominently when any exist */}
          {!loading && liveExams.length > 0 && (
            <div>
              <div className="flex items-center gap-2 mb-3">
                <span className="relative flex h-3 w-3">
                  <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75" />
                  <span className="relative inline-flex rounded-full h-3 w-3 bg-emerald-500" />
                </span>
                <h3 className="text-base font-bold text-slate-900">Live Now</h3>
                <Badge className="bg-emerald-100 text-emerald-700 border-0 text-xs">{liveExams.length}</Badge>
              </div>
              <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
                {liveExams.map((exam) => (
                  <ExamCard
                    key={exam.id}
                    exam={exam}
                    onClick={() => router.push(`/student/exam/${exam.id}/info`)}
                  />
                ))}
              </div>
            </div>
          )}

          {/* Upcoming Exams */}
          <Card className="shadow-sm border-slate-200 bg-white">
            <CardHeader className="border-b border-slate-100 pb-4">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <div className="bg-indigo-50 p-2 rounded-lg">
                    <Calendar className="h-5 w-5 text-indigo-600" />
                  </div>
                  <div>
                    <CardTitle className="text-lg">Upcoming Exams</CardTitle>
                    <CardDescription className="text-sm">
                      Scheduled exams assigned to you
                    </CardDescription>
                  </div>
                </div>
                {!loading && scheduledExams.length > 0 && (
                  <Badge variant="outline" className="border-slate-200 text-slate-600">
                    {scheduledExams.length} scheduled
                  </Badge>
                )}
              </div>
            </CardHeader>
            <CardContent className="pt-5">
              {loading ? (
                <div className="flex items-center justify-center py-12 gap-3 text-slate-400">
                  <Loader2 className="h-5 w-5 animate-spin" />
                  <span>Loading exams…</span>
                </div>
              ) : scheduledExams.length === 0 ? (
                <div className="text-center py-12">
                  <BookOpen className="h-12 w-12 mx-auto mb-4 text-slate-200" />
                  <p className="text-slate-500 font-medium">No upcoming exams</p>
                  <p className="text-sm text-slate-400 mt-1">
                    You'll be notified when a new exam is assigned to you.
                  </p>
                  <Button
                    variant="outline"
                    size="sm"
                    className="mt-4 gap-2"
                    onClick={() => router.push('/student/history')}
                  >
                    <History className="h-4 w-4" /> View Exam History
                  </Button>
                </div>
              ) : (
                <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
                  {scheduledExams.map((exam) => (
                    <ExamCard
                      key={exam.id}
                      exam={exam}
                      onClick={() => router.push(`/student/exam/${exam.id}/info`)}
                    />
                  ))}
                </div>
              )}
            </CardContent>
          </Card>

          {/* History quick-link when no upcoming exams */}
          {!loading && exams.length === 0 && (
            <div className="flex justify-center">
              <Button
                variant="outline"
                onClick={() => router.push('/student/history')}
                className="gap-2"
              >
                <History className="h-4 w-4" /> View Past Exams
              </Button>
            </div>
          )}

          {/* Device Management */}
          <DeviceManagement />
        </main>
      </div>
    </RoleGuard>
  );
}
