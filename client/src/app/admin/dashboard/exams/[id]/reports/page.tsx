'use client';

import { useEffect, useState, useCallback } from 'react';
import { useParams, useRouter } from 'next/navigation';
import {
  ArrowLeft, Loader2, RefreshCw, ShieldAlert, CheckCircle2,
  AlertTriangle, FileText, Users, Clock, HardDrive
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { toast } from 'sonner';
import api from '@/lib/axios';

// ── Types ─────────────────────────────────────────────────────────────────────

interface SessionReport {
  session_id: string;
  report_id: string | null;
  engine_url: string | null;
  student_name: string;
  student_email: string;
  session_status: string;
  terminated_by: string | null;
  terminated_reason: string | null;
  risk_score: number;
  start_time: string | null;
  end_time: string | null;
  // Engine report metadata
  risk_state: string | null;
  final_score: number | null;
  alert_count: number | null;
  warning_count: number | null;
  size_kb: number | null;
  proof_count: number | null;
  duration_s: number | null;
  terminated: boolean | null;
}

// ── Helpers ───────────────────────────────────────────────────────────────────

const RISK_COLORS: Record<string, string> = {
  NORMAL: '#22c55e', WARNING: '#f59e0b', HIGH_RISK: '#ef4444',
  ADMIN_REVIEW: '#dc2626', TERMINATED: '#7f1d1d',
};

function RiskBadge({ state }: { state: string | null }) {
  if (!state) return <span className="text-xs text-slate-400">—</span>;
  const color = RISK_COLORS[state] ?? '#64748b';
  const labels: Record<string, string> = {
    NORMAL: 'Normal', WARNING: 'Warning', HIGH_RISK: 'High Risk',
    ADMIN_REVIEW: 'Admin Review', TERMINATED: 'Terminated',
  };
  return (
    <span className="text-xs font-bold px-2 py-0.5 rounded border"
      style={{ background: `${color}22`, color, borderColor: `${color}44` }}>
      {labels[state] ?? state}
    </span>
  );
}

function StatusBadge({ status }: { status: string }) {
  const map: Record<string, { label: string; cls: string }> = {
    ACTIVE:       { label: 'Active',       cls: 'bg-emerald-100 text-emerald-700 border-emerald-200' },
    ENDED:        { label: 'Ended',        cls: 'bg-slate-100 text-slate-600 border-slate-200' },
    TERMINATED:   { label: 'Terminated',   cls: 'bg-rose-100 text-rose-700 border-rose-200' },
    DISCONNECTED: { label: 'Disconnected', cls: 'bg-amber-100 text-amber-700 border-amber-200' },
    CREATED:      { label: 'Created',      cls: 'bg-indigo-100 text-indigo-700 border-indigo-200' },
  };
  const { label, cls } = map[status] ?? { label: status, cls: 'bg-slate-100 text-slate-600 border-slate-200' };
  return <Badge variant="outline" className={`text-xs ${cls}`}>{label}</Badge>;
}

function fmtDuration(s: number | null): string {
  if (s == null) return '—';
  const m = Math.floor(s / 60);
  const h = Math.floor(m / 60);
  if (h > 0) return `${h}h ${m % 60}m`;
  return `${m}m ${s % 60}s`;
}

function fmtDateTime(iso: string | null): string {
  if (!iso) return '—';
  const d = new Date(iso.endsWith('Z') || /[+-]\d{2}:\d{2}$/.test(iso) ? iso : iso + 'Z');
  return d.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' });
}

// ── Page ─────────────────────────────────────────────────────────────────────

export default function ExamReportsPage() {
  const router = useRouter();
  const params = useParams();
  const examId = params.id as string;

  const [reports, setReports] = useState<SessionReport[]>([]);
  const [loading, setLoading] = useState(true);
  const [examTitle, setExamTitle] = useState('');

  const fetchReports = useCallback(async () => {
    try {
      const [reportsRes, statusRes] = await Promise.all([
        api.get(`/admin/exams/${examId}/reports`),
        api.get(`/admin/exams/${examId}`).catch(() => null),
      ]);
      setReports(reportsRes.data);
      if (statusRes?.data?.title) setExamTitle(statusRes.data.title);
    } catch {
      toast.error('Failed to load reports');
    } finally {
      setLoading(false);
    }
  }, [examId]);

  useEffect(() => {
    fetchReports();
  }, [fetchReports]);

  // ── Stats ──────────────────────────────────────────────────────────────────

  const withReports = reports.filter(r => r.report_id);
  const totalAlerts = withReports.reduce((s, r) => s + (r.alert_count ?? 0), 0);
  const totalSize = withReports.reduce((s, r) => s + (r.size_kb ?? 0), 0);
  const terminated = withReports.filter(r => r.terminated).length;

  if (loading) {
    return (
      <div className="flex items-center justify-center p-24">
        <Loader2 className="h-8 w-8 animate-spin text-slate-400" />
      </div>
    );
  }

  return (
    <div className="space-y-6 pb-12">
      {/* Header */}
      <div className="flex items-center gap-4">
        <Button variant="outline" size="icon" onClick={() => router.back()} className="h-10 w-10 border-slate-200">
          <ArrowLeft className="h-4 w-4" />
        </Button>
        <div className="flex-1">
          <h1 className="text-2xl font-bold text-slate-900">Session Reports</h1>
          {examTitle && <p className="text-sm text-slate-500 mt-0.5">{examTitle}</p>}
        </div>
        <Button variant="outline" size="sm" onClick={fetchReports} className="gap-2 border-slate-200">
          <RefreshCw className="h-4 w-4" /> Refresh
        </Button>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        {[
          { label: 'Total Sessions', value: reports.length, icon: Users, color: 'indigo' },
          { label: 'Reports Available', value: withReports.length, icon: FileText, color: 'emerald' },
          { label: 'Total Alerts', value: totalAlerts, icon: ShieldAlert, color: 'rose' },
          { label: 'Storage Used', value: `${(totalSize / 1024).toFixed(1)} MB`, icon: HardDrive, color: 'amber' },
        ].map(({ label, value, icon: Icon, color }) => (
          <Card key={label} className="shadow-none border-slate-200">
            <CardContent className="pt-5 pb-4">
              <div className="flex items-center gap-3">
                <div className={`bg-${color}-100 p-2 rounded-lg`}>
                  <Icon className={`h-5 w-5 text-${color}-600`} />
                </div>
                <div>
                  <p className="text-2xl font-bold text-slate-900">{value}</p>
                  <p className="text-xs text-slate-500">{label}</p>
                </div>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Sessions table */}
      {reports.length === 0 ? (
        <Card className="border-slate-200 shadow-none">
          <CardContent className="py-16 text-center">
            <FileText className="h-12 w-12 text-slate-300 mx-auto mb-3" />
            <p className="text-slate-500">No sessions found for this exam.</p>
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-3">
          {reports.map((r) => (
            <Card key={r.session_id} className={`border shadow-none ${r.report_id ? 'border-slate-200' : 'border-dashed border-slate-200 opacity-70'}`}>
              <CardContent className="p-5">
                <div className="flex flex-col sm:flex-row sm:items-start gap-4">
                  {/* Student info */}
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap mb-1">
                      <p className="font-semibold text-slate-900">{r.student_name}</p>
                      <StatusBadge status={r.session_status} />
                      {r.terminated && (
                        <Badge variant="outline" className="text-xs bg-rose-50 text-rose-600 border-rose-200">
                          Terminated
                        </Badge>
                      )}
                    </div>
                    <p className="text-sm text-slate-500">{r.student_email}</p>
                    <div className="flex items-center gap-4 mt-2 text-xs text-slate-400">
                      <span className="flex items-center gap-1">
                        <Clock className="h-3.5 w-3.5" />
                        {fmtDateTime(r.start_time)}
                      </span>
                      {r.end_time && (
                        <span>→ {fmtDateTime(r.end_time)}</span>
                      )}
                      {r.duration_s != null && (
                        <span>{fmtDuration(r.duration_s)}</span>
                      )}
                    </div>
                    {r.terminated_reason && (
                      <p className="text-xs text-rose-500 mt-1">
                        Reason: {r.terminated_reason}
                      </p>
                    )}
                  </div>

                  {/* Report metrics */}
                  {r.report_id ? (
                    <div className="flex items-center gap-5 shrink-0">
                      <div className="text-center">
                        <RiskBadge state={r.risk_state} />
                        <p className="text-xs text-slate-400 mt-1">Risk State</p>
                      </div>
                      <div className="text-center">
                        <p className="text-xl font-bold text-slate-800">{r.final_score?.toFixed(0) ?? r.risk_score}</p>
                        <p className="text-xs text-slate-400">Score</p>
                      </div>
                      <div className="text-center">
                        <p className="text-xl font-bold text-rose-500">{r.alert_count ?? 0}</p>
                        <p className="text-xs text-slate-400">Alerts</p>
                      </div>
                      <div className="text-center">
                        <p className="text-xl font-bold text-amber-500">{r.warning_count ?? 0}</p>
                        <p className="text-xs text-slate-400">Warnings</p>
                      </div>
                      <div className="text-center">
                        <p className="text-sm font-semibold text-slate-500">{r.size_kb ? `${r.size_kb.toFixed(0)} KB` : '—'}</p>
                        <p className="text-xs text-slate-400">Size</p>
                      </div>
                      {r.proof_count != null && r.proof_count > 0 && (
                        <div className="text-center">
                          <p className="text-sm font-semibold text-slate-500">{r.proof_count}</p>
                          <p className="text-xs text-slate-400">Proofs</p>
                        </div>
                      )}
                    </div>
                  ) : (
                    <div className="flex items-center gap-2 text-slate-400 shrink-0">
                      <AlertTriangle className="h-4 w-4" />
                      <span className="text-sm">No engine report</span>
                    </div>
                  )}
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}
