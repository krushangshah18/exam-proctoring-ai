'use client';

import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import {
  ArrowLeft, CheckCircle2, XCircle, Clock, AlertTriangle,
  ShieldAlert, Calendar, Loader2, Ban, History
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { toast } from 'sonner';
import api from '@/lib/axios';
import RoleGuard from '@/components/auth/role-guard';

// ──────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────

function formatDuration(seconds: number): string {
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const s = seconds % 60;
  if (h > 0) return `${h}h ${m}m`;
  if (m > 0) return `${m}m ${s}s`;
  return `${s}s`;
}

const EXAM_STATUS_CONFIG: Record<string, { label: string; classes: string }> = {
  ENDED: { label: 'Ended', classes: 'bg-blue-50 text-blue-700 border-blue-200' },
  CANCELLED: { label: 'Cancelled', classes: 'bg-slate-50 text-slate-500 border-slate-200' },
  LIVE: { label: 'Live', classes: 'bg-emerald-50 text-emerald-700 border-emerald-200' },
  SCHEDULED: { label: 'Scheduled', classes: 'bg-amber-50 text-amber-700 border-amber-200' },
};

const SESSION_STATUS_CONFIG: Record<string, { label: string; icon: React.ReactNode; classes: string }> = {
  ENDED: {
    label: 'Submitted',
    icon: <CheckCircle2 className="h-3.5 w-3.5" />,
    classes: 'bg-emerald-50 text-emerald-700 border-emerald-200',
  },
  TERMINATED: {
    label: 'Terminated',
    icon: <Ban className="h-3.5 w-3.5" />,
    classes: 'bg-rose-50 text-rose-700 border-rose-200',
  },
  ACTIVE: {
    label: 'In Progress',
    icon: <Clock className="h-3.5 w-3.5 animate-pulse" />,
    classes: 'bg-indigo-50 text-indigo-700 border-indigo-200',
  },
  DISCONNECTED: {
    label: 'Disconnected',
    icon: <AlertTriangle className="h-3.5 w-3.5" />,
    classes: 'bg-amber-50 text-amber-700 border-amber-200',
  },
};

interface ExamHistoryItem {
  id: string;
  title: string;
  exam_mode: string;
  exam_status: string;
  start_window: string;
  end_window: string;
  duration_minutes: number;
  invite_used: boolean;
  session_status: string | null;
  session_start_time: string | null;
  session_end_time: string | null;
  duration_taken_seconds: number | null;
  risk_score: number;
  violation_count: number;
  time_extension_seconds: number;
  terminated_reason: string | null;
}

export default function ExamHistoryPage() {
  const router = useRouter();
  const [exams, setExams] = useState<ExamHistoryItem[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchHistory = async () => {
      try {
        const res = await api.get('/exam/history');
        setExams(res.data);
      } catch {
        toast.error('Failed to load exam history');
      } finally {
        setLoading(false);
      }
    };
    fetchHistory();
  }, []);

  return (
    <RoleGuard allowedRoles={['STUDENT']}>
      <div className="min-h-screen bg-slate-50">
        {/* Header */}
        <header className="bg-white border-b border-slate-200 sticky top-0 z-10">
          <div className="max-w-5xl mx-auto px-4 sm:px-6 lg:px-8">
            <div className="flex items-center gap-4 h-16">
              <Button
                variant="ghost"
                size="icon"
                onClick={() => router.push('/student/dashboard')}
                className="h-9 w-9"
              >
                <ArrowLeft className="h-4 w-4" />
              </Button>
              <div className="flex items-center gap-2">
                <History className="h-5 w-5 text-indigo-600" />
                <h1 className="text-xl font-bold text-slate-900">Exam History</h1>
              </div>
            </div>
          </div>
        </header>

        {/* Content */}
        <main className="max-w-5xl mx-auto px-4 sm:px-6 lg:px-8 py-8">

          {loading ? (
            <div className="flex items-center justify-center py-24">
              <Loader2 className="h-8 w-8 animate-spin text-slate-300" />
            </div>
          ) : exams.length === 0 ? (
            <div className="text-center py-24">
              <History className="h-14 w-14 text-slate-200 mx-auto mb-4" />
              <h2 className="text-xl font-semibold text-slate-700 mb-2">No exam history yet</h2>
              <p className="text-slate-400 text-sm">
                Completed and past exams will appear here after they have ended.
              </p>
              <Button
                variant="outline"
                className="mt-6"
                onClick={() => router.push('/student/dashboard')}
              >
                Back to Dashboard
              </Button>
            </div>
          ) : (
            <div className="space-y-4">
              <p className="text-sm text-slate-500">{exams.length} exam{exams.length !== 1 ? 's' : ''} found</p>

              {exams.map((exam) => {
                const sessionCfg = exam.session_status ? SESSION_STATUS_CONFIG[exam.session_status] : null;
                const examStatusCfg = EXAM_STATUS_CONFIG[exam.exam_status] ?? {
                  label: exam.exam_status,
                  classes: 'bg-slate-100 text-slate-500 border-slate-200',
                };
                const submittedAt = exam.session_end_time
                  ? new Date(exam.session_end_time)
                  : null;

                return (
                  <Card
                    key={exam.id}
                    className="bg-white shadow-sm border-slate-200 hover:shadow-md transition-shadow"
                  >
                    <CardContent className="p-6">
                      <div className="flex items-start justify-between gap-4 flex-wrap">
                        {/* Left: title + badges */}
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2 flex-wrap mb-1">
                            <h3 className="text-lg font-bold text-slate-900 truncate">{exam.title}</h3>
                            <Badge variant="secondary" className="text-[10px] uppercase font-semibold">
                              {exam.exam_mode}
                            </Badge>
                          </div>
                          <div className="flex items-center gap-2 flex-wrap">
                            <Badge variant="outline" className={`text-xs ${examStatusCfg.classes}`}>
                              {examStatusCfg.label}
                            </Badge>
                            {sessionCfg && (
                              <Badge variant="outline" className={`text-xs flex items-center gap-1 ${sessionCfg.classes}`}>
                                {sessionCfg.icon} {sessionCfg.label}
                              </Badge>
                            )}
                            {!exam.session_status && exam.exam_status === 'CANCELLED' && (
                              <Badge variant="outline" className="text-xs bg-slate-50 text-slate-500 border-slate-200">
                                Not Attempted
                              </Badge>
                            )}
                            {!exam.session_status && exam.exam_status !== 'CANCELLED' && (
                              <Badge variant="outline" className="text-xs bg-slate-50 text-slate-500 border-slate-200">
                                No Session
                              </Badge>
                            )}
                          </div>
                        </div>

                        {/* Right: date */}
                        <div className="text-right shrink-0">
                          <p className="text-xs text-slate-400 uppercase tracking-wider font-semibold">Exam Date</p>
                          <p className="text-sm font-semibold text-slate-700 mt-0.5">
                            {new Date(exam.start_window).toLocaleDateString(undefined, {
                              month: 'short',
                              day: 'numeric',
                              year: 'numeric',
                            })}
                          </p>
                          <p className="text-xs text-slate-400">
                            {new Date(exam.start_window).toLocaleTimeString(undefined, {
                              hour: '2-digit',
                              minute: '2-digit',
                            })}
                          </p>
                        </div>
                      </div>

                      {/* Stats row */}
                      <div className="mt-5 pt-4 border-t border-slate-100 grid grid-cols-2 sm:grid-cols-4 gap-4">
                        <div>
                          <p className="text-xs text-slate-400 uppercase tracking-wider font-semibold">Allotted Time</p>
                          <p className="text-sm font-semibold text-slate-800 mt-0.5">
                            {exam.duration_minutes} min
                            {exam.time_extension_seconds > 0 && (
                              <span className="text-emerald-600 font-normal ml-1">
                                (+{Math.round(exam.time_extension_seconds / 60)}m)
                              </span>
                            )}
                          </p>
                        </div>

                        <div>
                          <p className="text-xs text-slate-400 uppercase tracking-wider font-semibold">Time Taken</p>
                          <p className="text-sm font-semibold text-slate-800 mt-0.5">
                            {exam.duration_taken_seconds != null
                              ? formatDuration(exam.duration_taken_seconds)
                              : '—'}
                          </p>
                        </div>

                        <div>
                          <p className="text-xs text-slate-400 uppercase tracking-wider font-semibold">Violations</p>
                          <p className={`text-sm font-semibold mt-0.5 flex items-center gap-1 ${exam.violation_count > 0 ? 'text-rose-600' : 'text-slate-800'}`}>
                            {exam.violation_count > 0 && <AlertTriangle className="h-3.5 w-3.5" />}
                            {exam.violation_count}
                          </p>
                        </div>

                        <div>
                          <p className="text-xs text-slate-400 uppercase tracking-wider font-semibold">Risk Score</p>
                          <p className={`text-sm font-semibold mt-0.5 ${exam.risk_score >= 70 ? 'text-rose-600' : exam.risk_score >= 40 ? 'text-amber-600' : 'text-slate-800'}`}>
                            {exam.risk_score}
                          </p>
                        </div>
                      </div>

                      {/* Submitted at */}
                      {submittedAt && (
                        <div className="mt-3 flex items-center gap-1.5 text-xs text-slate-400">
                          <Clock className="h-3.5 w-3.5" />
                          Submitted at {submittedAt.toLocaleString()}
                        </div>
                      )}

                      {/* Termination reason */}
                      {exam.terminated_reason && (
                        <div className="mt-3 p-3 bg-rose-50 border border-rose-100 rounded-lg flex items-start gap-2">
                          <ShieldAlert className="h-4 w-4 text-rose-500 mt-0.5 shrink-0" />
                          <p className="text-xs text-rose-700 leading-relaxed">{exam.terminated_reason}</p>
                        </div>
                      )}

                      {/* Cancelled notice */}
                      {exam.exam_status === 'CANCELLED' && (
                        <div className="mt-3 p-3 bg-slate-50 border border-slate-200 rounded-lg">
                          <p className="text-xs text-slate-500">This exam was cancelled by the administrator.</p>
                        </div>
                      )}
                    </CardContent>
                  </Card>
                );
              })}
            </div>
          )}
        </main>
      </div>
    </RoleGuard>
  );
}
