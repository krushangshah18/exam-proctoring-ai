'use client';

import { useEffect, useState, useCallback } from 'react';
import { useParams, useRouter } from 'next/navigation';
import {
  ArrowLeft, Loader2, RefreshCw, ShieldAlert, CheckCircle2,
  AlertTriangle, FileText, Users, Clock, HardDrive, Eye, X, AlertCircle, ChevronRight, ChevronDown,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { toast } from 'sonner';
import api from '@/lib/axios';

// ── Types ─────────────────────────────────────────────────────────────────────

interface SessionReport {
  row_id?: string;
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
  report_start_time?: string | null;
  report_end_time?: string | null;
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

interface StudentGroup {
  studentKey: string;
  studentName: string;
  studentEmail: string;
  reports: SessionReport[];
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

function fmtElapsed(s: number): string {
  const m = Math.floor(s / 60);
  const sec = Math.round(s % 60);
  return `${m}:${String(sec).padStart(2, '0')}`;
}

// ── Full Report Modal ─────────────────────────────────────────────────────────

function FullReportModal({
  examId,
  session,
  onClose,
}: {
  examId: string;
  session: SessionReport;
  onClose: () => void;
}) {
  const [data, setData] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [deleted, setDeleted] = useState(false);

  useEffect(() => {
    setLoading(true);
    setError(null);
    setDeleted(false);
    setData(null);
    api.get(`/admin/exams/${examId}/sessions/${session.session_id}/report/full`, {
      params: {
        report_id: session.report_id,
        engine_url: session.engine_url,
      },
    })
      .then(r => setData(r.data))
      .catch(e => {
        const detail = e.response?.data?.detail;
        const status = e.response?.status;
        if (status === 410) {
          setDeleted(true);
          setError('Report no longer exists and has been deleted.');
          return;
        }
        setError(detail || 'Failed to load report');
      })
      .finally(() => setLoading(false));
  }, [examId, session.engine_url, session.report_id, session.session_id]);

  function proofUrl(raw: string): string {
    if (!raw || !session.engine_url) return raw;
    const base = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';
    // If raw is an absolute URL, return as-is
    if (raw.startsWith('http')) return `${base}/admin/proxy-proof?engine_url=${encodeURIComponent(session.engine_url)}&path=${encodeURIComponent(new URL(raw).pathname)}`;
    // Engine-relative path like /proofs/xxx.jpg
    return `${base}/admin/proxy-proof?engine_url=${encodeURIComponent(session.engine_url)}&path=${encodeURIComponent(raw)}`;
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4">
      <div className="bg-white rounded-xl shadow-xl w-full max-w-3xl max-h-[90vh] flex flex-col">
        {/* Header */}
        <div className="flex items-center justify-between p-5 border-b border-slate-200">
          <div>
            <p className="font-bold text-slate-900">{session.student_name}</p>
            <p className="text-xs text-slate-400 mt-0.5">{session.student_email}</p>
            {session.report_id && (
              <p className="text-xs text-slate-300 font-mono mt-0.5">{session.report_id}</p>
            )}
          </div>
          <button onClick={onClose} className="text-slate-400 hover:text-slate-600">
            <X className="h-5 w-5" />
          </button>
        </div>

        {/* Content */}
        <div className="flex-1 overflow-y-auto p-5 space-y-5">
          {loading && (
            <div className="flex items-center justify-center py-16">
              <Loader2 className="h-8 w-8 animate-spin text-slate-300" />
            </div>
          )}
          {error && (
            <div className={`flex items-center gap-2 p-4 rounded-lg border ${
              deleted
                ? 'bg-amber-50 border-amber-200 text-amber-800'
                : 'bg-rose-50 border-rose-200 text-rose-700'
            }`}>
              <AlertCircle className="h-4 w-4 shrink-0" /> {error}
            </div>
          )}
          {data && (
            <>
              {/* Summary grid */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                {[
                  { label: 'Risk State', value: <RiskBadge state={data.risk_state} /> },
                  { label: 'Final Score', value: <span className="font-bold text-slate-800">{data.final_score?.toFixed(0) ?? '—'}</span> },
                  { label: 'Alerts', value: <span className="font-bold text-rose-500">{data.alert_count ?? 0}</span> },
                  { label: 'Warnings', value: <span className="font-bold text-amber-500">{data.warning_count ?? 0}</span> },
                  { label: 'Duration', value: fmtDuration(data.duration_s) },
                  { label: 'Size', value: data.size_kb ? `${data.size_kb.toFixed(0)} KB` : '—' },
                  { label: 'Proofs', value: data.proof_count ?? 0 },
                  { label: 'Terminated', value: data.terminated ? <span className="text-rose-500 font-semibold">Yes</span> : 'No' },
                ].map(({ label, value }) => (
                  <div key={label} className="bg-slate-50 rounded-lg p-3 border border-slate-100">
                    <p className="text-xs text-slate-400 uppercase tracking-wider mb-1">{label}</p>
                    <div className="text-sm">{value}</div>
                  </div>
                ))}
              </div>

              {/* Events */}
              {(() => {
                const alerts: any[] = (data.alert_log ?? []).map((e: any) => ({ ...e, _type: 'alert' }));
                const warnings: any[] = (data.warning_log ?? []).map((e: any) => ({ ...e, _type: 'warning' }));
                const legacy: any[] = (data.events ?? []).map((e: any) => ({ ...e, _type: e.type ?? 'alert' }));
                const all = alerts.length || warnings.length ? [...alerts, ...warnings] : legacy;
                if (!all.length) return null;
                return (
                  <div>
                    <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">
                      Events ({all.length})
                    </p>
                    <div className="space-y-1.5 max-h-64 overflow-y-auto">
                      {all.map((ev: any, i: number) => (
                        <div key={i} className={`flex items-start gap-2 px-3 py-2 rounded-lg text-xs border ${
                          ev._type === 'alert'
                            ? 'bg-rose-50/50 border-rose-100 text-rose-700'
                            : 'bg-amber-50/50 border-amber-100 text-amber-700'
                        }`}>
                          <AlertTriangle className="h-3.5 w-3.5 shrink-0 mt-0.5" />
                          <div className="flex-1 min-w-0">
                            <p className="font-medium">{ev.message || ev.key || ev._type}</p>
                            {ev.score_added > 0 && (
                              <p className="text-xs opacity-75">+{(ev.score_added as number).toFixed(1)} pts</p>
                            )}
                            {ev.proof_url && (
                              <button
                                type="button"
                                onClick={async (e) => {
                                  e.preventDefault();
                                  try {
                                    const res = await api.get(proofUrl(ev.proof_url), { responseType: 'blob' });
                                    const url = URL.createObjectURL(res.data);
                                    window.open(url, '_blank');
                                  } catch {
                                    toast.error('Failed to load proof image');
                                  }
                                }}
                                className="text-blue-500 underline text-xs text-left"
                              >
                                View proof
                              </button>
                            )}
                          </div>
                          <span className="text-xs opacity-60 shrink-0">
                            {ev.elapsed_s != null ? fmtElapsed(ev.elapsed_s) : ev.time ?? ''}
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>
                );
              })()}

              {/* Raw JSON toggle */}
              <details>
                <summary className="text-xs text-slate-400 cursor-pointer hover:text-slate-600">View raw JSON</summary>
                <pre className="mt-2 text-xs bg-slate-50 border border-slate-200 rounded-lg p-3 overflow-auto max-h-48">
                  {JSON.stringify(data, null, 2)}
                </pre>
              </details>
            </>
          )}
        </div>
      </div>
    </div>
  );
}

// ── Page ─────────────────────────────────────────────────────────────────────

export default function ExamReportsPage() {
  const router = useRouter();
  const params = useParams();
  const examId = params.id as string;

  const [reports, setReports] = useState<SessionReport[]>([]);
  const [loading, setLoading] = useState(true);
  const [examTitle, setExamTitle] = useState('');
  const [viewSession, setViewSession] = useState<SessionReport | null>(null);
  const [collapsedGroups, setCollapsedGroups] = useState<Record<string, boolean>>({});

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
  const studentGroups: StudentGroup[] = Object.values(
    reports.reduce<Record<string, StudentGroup>>((acc, report) => {
      const key = report.student_email || report.session_id;
      if (!acc[key]) {
        acc[key] = {
          studentKey: key,
          studentName: report.student_name,
          studentEmail: report.student_email,
          reports: [],
        };
      }
      acc[key].reports.push(report);
      return acc;
    }, {})
  );

  const toggleGroup = useCallback((studentKey: string) => {
    setCollapsedGroups(prev => ({
      ...prev,
      [studentKey]: !prev[studentKey],
    }));
  }, []);

  if (loading) {
    return (
      <div className="flex items-center justify-center p-24">
        <Loader2 className="h-8 w-8 animate-spin text-slate-400" />
      </div>
    );
  }

  return (
    <div className="space-y-6 pb-12">
      {/* Full report modal */}
      {viewSession && (
        <FullReportModal
          examId={examId}
          session={viewSession}
          onClose={() => setViewSession(null)}
        />
      )}

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
          { label: 'Students', value: studentGroups.length, icon: Users, color: 'indigo' },
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

      {/* Student groups */}
      {reports.length === 0 ? (
        <Card className="border-slate-200 shadow-none">
          <CardContent className="py-16 text-center">
            <FileText className="h-12 w-12 text-slate-300 mx-auto mb-3" />
            <p className="text-slate-500">No sessions found for this exam.</p>
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-3">
          {studentGroups.map((group) => (
            <Card key={group.studentKey} className="border-slate-200 shadow-none overflow-hidden">
              <button
                type="button"
                onClick={() => toggleGroup(group.studentKey)}
                className="w-full p-5 border-b border-slate-100 bg-slate-50/70 text-left"
              >
                <div className="flex items-center justify-between gap-4">
                  <div className="min-w-0 flex items-start gap-3">
                    <span className="mt-0.5 text-slate-400 shrink-0">
                      {collapsedGroups[group.studentKey] ? (
                        <ChevronRight className="h-4 w-4" />
                      ) : (
                        <ChevronDown className="h-4 w-4" />
                      )}
                    </span>
                    <div className="min-w-0">
                      <p className="font-semibold text-slate-900">{group.studentName}</p>
                      <p className="text-sm text-slate-500 truncate">{group.studentEmail}</p>
                    </div>
                  </div>
                  <Badge variant="outline" className="text-xs border-slate-200 text-slate-600 shrink-0">
                    {group.reports.length} segment{group.reports.length !== 1 ? 's' : ''}
                  </Badge>
                </div>
              </button>
              {!collapsedGroups[group.studentKey] && (
                <CardContent className="p-4 space-y-3">
                  {group.reports.map((r, idx) => (
                    <div key={r.row_id || `${r.session_id}:${r.report_id || idx}`} className={`border rounded-xl p-4 ${r.report_id ? 'border-slate-200' : 'border-dashed border-slate-200 opacity-70'}`}>
                      <div className="flex flex-col sm:flex-row sm:items-start gap-4">
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2 flex-wrap mb-1">
                            <p className="font-medium text-slate-900">Segment {group.reports.length - idx}</p>
                            <StatusBadge status={r.session_status} />
                            {r.terminated && (
                              <Badge variant="outline" className="text-xs bg-rose-50 text-rose-600 border-rose-200">
                                Terminated
                              </Badge>
                            )}
                          </div>
                          <div className="flex items-center gap-4 mt-2 text-xs text-slate-400 flex-wrap">
                            <span className="flex items-center gap-1">
                              <Clock className="h-3.5 w-3.5" />
                              {fmtDateTime(r.report_start_time || r.start_time)}
                            </span>
                            {(r.report_end_time || r.end_time) && (
                              <span>→ {fmtDateTime(r.report_end_time || r.end_time)}</span>
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

                        {r.report_id ? (
                          <div className="flex items-center gap-4 shrink-0 flex-wrap">
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
                            <Button
                              variant="outline"
                              size="sm"
                              className="gap-1.5 border-slate-200 text-slate-600 hover:text-indigo-600 hover:border-indigo-200"
                              onClick={() => setViewSession(r)}
                            >
                              <Eye className="h-3.5 w-3.5" /> View
                            </Button>
                          </div>
                        ) : (
                          <div className="flex items-center gap-2 text-slate-400 shrink-0">
                            <AlertTriangle className="h-4 w-4" />
                            <span className="text-sm">No engine report</span>
                          </div>
                        )}
                      </div>
                    </div>
                  ))}
                </CardContent>
              )}
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}
