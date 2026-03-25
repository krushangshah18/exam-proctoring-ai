'use client';

import { useEffect, useState, useCallback } from 'react';
import {
  Loader2, RefreshCw, ShieldAlert, FileText, HardDrive,
  Trash2, AlertTriangle, Clock, Server, ChevronDown, ChevronRight,
  Eye, X, AlertCircle, BookOpen,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import {
  AlertDialog, AlertDialogAction, AlertDialogCancel,
  AlertDialogContent, AlertDialogDescription,
  AlertDialogFooter, AlertDialogHeader, AlertDialogTitle,
} from '@/components/ui/alert-dialog';
import { toast } from 'sonner';
import api from '@/lib/axios';

// ── Types ─────────────────────────────────────────────────────────────────────

interface EngineReport {
  report_id: string;
  engine_url: string;
  risk_state: string | null;
  final_score: number | null;
  alert_count: number | null;
  warning_count: number | null;
  size_kb: number | null;
  proof_count: number | null;
  duration_s: number | null;
  terminated: boolean | null;
  session_start: string | null;
  session_end: string | null;
  session_id: string | null;
  exam_id: string | null;
  exam_title: string | null;
  student_name: string | null;
  student_email: string | null;
  session_status: string | null;
}

interface ExamGroup {
  exam_id: string | null;
  exam_title: string;
  reports: EngineReport[];
  totalAlerts: number;
  totalSize: number;
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
    ADMIN_REVIEW: 'Review', TERMINATED: 'Terminated',
  };
  return (
    <span className="text-xs font-bold px-2 py-0.5 rounded border"
      style={{ background: `${color}22`, color, borderColor: `${color}44` }}>
      {labels[state] ?? state}
    </span>
  );
}

function SessionStatusBadge({ status }: { status: string | null }) {
  if (!status) return null;
  const map: Record<string, string> = {
    ACTIVE: 'bg-emerald-100 text-emerald-700 border-emerald-200',
    ENDED: 'bg-slate-100 text-slate-600 border-slate-200',
    TERMINATED: 'bg-rose-100 text-rose-700 border-rose-200',
    DISCONNECTED: 'bg-amber-100 text-amber-700 border-amber-200',
    CREATED: 'bg-indigo-100 text-indigo-700 border-indigo-200',
  };
  return (
    <Badge variant="outline" className={`text-xs ${map[status] ?? 'bg-slate-100 text-slate-600'}`}>
      {status.charAt(0) + status.slice(1).toLowerCase()}
    </Badge>
  );
}

function fmtDuration(s: number | null) {
  if (s == null) return '—';
  const m = Math.floor(s / 60);
  const h = Math.floor(m / 60);
  return h > 0 ? `${h}h ${m % 60}m` : `${m}m ${s % 60}s`;
}

function fmtDateTime(iso: string | null) {
  if (!iso) return '—';
  const d = new Date(iso.endsWith('Z') || /[+-]\d{2}:\d{2}$/.test(iso) ? iso : iso + 'Z');
  return d.toLocaleString(undefined, { dateStyle: 'short', timeStyle: 'short' });
}

function shortenUrl(url: string) {
  try { const u = new URL(url); return u.hostname + (u.port ? `:${u.port}` : ''); } catch { return url; }
}

// Group reports by exam
function groupByExam(reports: EngineReport[]): ExamGroup[] {
  const map = new Map<string, ExamGroup>();
  for (const r of reports) {
    const key = r.exam_id ?? '__orphan__';
    if (!map.has(key)) {
      map.set(key, {
        exam_id: r.exam_id,
        exam_title: r.exam_title ?? 'Unknown Exam',
        reports: [],
        totalAlerts: 0,
        totalSize: 0,
      });
    }
    const g = map.get(key)!;
    g.reports.push(r);
    g.totalAlerts += r.alert_count ?? 0;
    g.totalSize += r.size_kb ?? 0;
  }
  // Sort groups: named exams first, orphan last
  return Array.from(map.values()).sort((a, b) =>
    a.exam_id === null ? 1 : b.exam_id === null ? -1 : a.exam_title.localeCompare(b.exam_title)
  );
}

// ── Full Report Modal ─────────────────────────────────────────────────────────

function FullReportModal({ report, onClose }: { report: EngineReport; onClose: () => void }) {
  const [data, setData] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api.get(`/admin/report/${report.report_id}/full`, { params: { engine_url: report.engine_url } })
      .then(r => setData(r.data))
      .catch(e => setError(e.response?.data?.detail || 'Failed to load report'))
      .finally(() => setLoading(false));
  }, [report.report_id, report.engine_url]);

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4">
      <div className="bg-white rounded-xl shadow-xl w-full max-w-3xl max-h-[90vh] flex flex-col">
        {/* Header */}
        <div className="flex items-center justify-between p-5 border-b border-slate-200">
          <div>
            <p className="font-bold text-slate-900">{report.student_name ?? 'Unknown Student'}</p>
            <p className="text-xs text-slate-400 mt-0.5 font-mono">{report.report_id}</p>
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
            <div className="flex items-center gap-2 p-4 bg-rose-50 rounded-lg border border-rose-200 text-rose-700">
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

              {/* Events — handle alert_log/warning_log or legacy events array */}
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
                            {ev.score_added > 0 && <p className="text-xs opacity-75">+{(ev.score_added as number).toFixed(1)} pts</p>}
                            {ev.proof_url && (() => {
                              const raw: string = ev.proof_url;
                              const eu = report.engine_url ?? '';
                              let proxyHref: string;
                              try {
                                const p = raw.startsWith('http') ? new URL(raw).pathname : raw;
                                proxyHref = `/api/admin/proxy-proof?engine_url=${encodeURIComponent(eu)}&path=${encodeURIComponent(p)}`;
                              } catch { proxyHref = raw; }
                              return (
                                <a href={proxyHref} target="_blank" rel="noreferrer" className="text-blue-500 underline text-xs">View proof</a>
                              );
                            })()}
                          </div>
                          <span className="text-xs opacity-60 shrink-0">
                            {ev.elapsed_s != null ? `${Math.floor(ev.elapsed_s / 60)}:${String(Math.round(ev.elapsed_s % 60)).padStart(2, '0')}` : ev.time ?? ''}
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

// ── Exam Group Card ───────────────────────────────────────────────────────────

function ExamGroupCard({
  group,
  onDelete,
  deleting,
  onView,
}: {
  group: ExamGroup;
  onDelete: (r: EngineReport) => void;
  deleting: string | null;
  onView: (r: EngineReport) => void;
}) {
  const [open, setOpen] = useState(false);

  return (
    <Card className="border-slate-200 shadow-none overflow-hidden">
      {/* Group header */}
      <button
        className="w-full flex items-center justify-between p-4 hover:bg-slate-50 transition-colors"
        onClick={() => setOpen(o => !o)}
      >
        <div className="flex items-center gap-3 min-w-0">
          <BookOpen className="h-4 w-4 text-indigo-500 shrink-0" />
          <div className="text-left min-w-0">
            <p className="font-semibold text-slate-900 truncate">{group.exam_title}</p>
            <p className="text-xs text-slate-400">
              {group.reports.length} report{group.reports.length !== 1 ? 's' : ''}
              {' · '}
              <span className="text-rose-500">{group.totalAlerts} alerts</span>
              {' · '}
              {(group.totalSize / 1024).toFixed(1)} MB
            </p>
          </div>
        </div>
        {open ? <ChevronDown className="h-4 w-4 text-slate-400 shrink-0" /> : <ChevronRight className="h-4 w-4 text-slate-400 shrink-0" />}
      </button>

      {/* Reports list */}
      {open && (
        <div className="border-t border-slate-100 divide-y divide-slate-50">
          {group.reports.map(r => (
            <div key={`${r.engine_url}:${r.report_id}`} className="p-4 flex flex-col sm:flex-row sm:items-center gap-4">
              {/* Student info */}
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 flex-wrap mb-1">
                  <p className="font-medium text-slate-800 text-sm">
                    {r.student_name ?? <span className="text-slate-400 italic text-xs">Unknown student</span>}
                  </p>
                  <SessionStatusBadge status={r.session_status} />
                  {r.terminated && (
                    <Badge variant="outline" className="text-xs bg-rose-50 text-rose-600 border-rose-200">Terminated</Badge>
                  )}
                </div>
                {r.student_email && <p className="text-xs text-slate-400">{r.student_email}</p>}
                <div className="flex items-center gap-3 text-xs text-slate-400 mt-1 flex-wrap">
                  <span className="flex items-center gap-1"><Clock className="h-3 w-3" />{fmtDateTime(r.session_end)}</span>
                  <span>{fmtDuration(r.duration_s)}</span>
                  <span className="flex items-center gap-1"><Server className="h-3 w-3" />{shortenUrl(r.engine_url)}</span>
                  <span className="font-mono text-slate-300 text-xs">{r.report_id.slice(0, 12)}…</span>
                </div>
              </div>

              {/* Metrics */}
              <div className="flex items-center gap-4 shrink-0 flex-wrap">
                <div className="text-center"><RiskBadge state={r.risk_state} /><p className="text-xs text-slate-400 mt-1">Risk</p></div>
                <div className="text-center"><p className="text-lg font-bold text-rose-500">{r.alert_count ?? 0}</p><p className="text-xs text-slate-400">Alerts</p></div>
                <div className="text-center"><p className="text-lg font-bold text-amber-500">{r.warning_count ?? 0}</p><p className="text-xs text-slate-400">Warns</p></div>
                <div className="text-center"><p className="text-sm font-semibold text-slate-500">{r.size_kb ? `${r.size_kb.toFixed(0)} KB` : '—'}</p><p className="text-xs text-slate-400">Size</p></div>

                {/* Actions */}
                <div className="flex gap-1">
                  <Button
                    variant="outline" size="icon"
                    className="h-8 w-8 border-slate-200 text-slate-500 hover:bg-slate-50"
                    onClick={() => onView(r)}
                  >
                    <Eye className="h-4 w-4" />
                  </Button>
                  <Button
                    variant="outline" size="icon"
                    className="h-8 w-8 border-rose-200 text-rose-500 hover:bg-rose-50"
                    disabled={deleting === r.report_id}
                    onClick={() => onDelete(r)}
                  >
                    {deleting === r.report_id ? <Loader2 className="h-4 w-4 animate-spin" /> : <Trash2 className="h-4 w-4" />}
                  </Button>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </Card>
  );
}

// ── Page ─────────────────────────────────────────────────────────────────────

export default function SysAdminReportsPage() {
  const [reports, setReports] = useState<EngineReport[]>([]);
  const [loading, setLoading] = useState(true);
  const [deleting, setDeleting] = useState<string | null>(null);
  const [confirmDelete, setConfirmDelete] = useState<EngineReport | null>(null);
  const [confirmDeleteAll, setConfirmDeleteAll] = useState(false);
  const [deletingAll, setDeletingAll] = useState(false);
  const [viewReport, setViewReport] = useState<EngineReport | null>(null);

  const fetchReports = useCallback(async () => {
    try {
      const res = await api.get('/admin/reports');
      setReports(res.data);
    } catch {
      toast.error('Failed to load reports');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { fetchReports(); }, [fetchReports]);

  const handleDelete = async (report: EngineReport) => {
    setDeleting(report.report_id);
    try {
      await api.delete(`/admin/reports/${report.report_id}`, { params: { engine_url: report.engine_url } });
      setReports(prev => prev.filter(r => r.report_id !== report.report_id));
      toast.success('Report deleted');
    } catch {
      toast.error('Failed to delete report');
    } finally {
      setDeleting(null);
      setConfirmDelete(null);
    }
  };

  const handleDeleteAll = async () => {
    setDeletingAll(true);
    try {
      const res = await api.delete('/admin/reports');
      setReports([]);
      toast.success(`Deleted ${res.data.deleted} report${res.data.deleted !== 1 ? 's' : ''}`);
      if (res.data.errors?.length > 0) {
        toast.warning(`${res.data.errors.length} error(s) during deletion`);
      }
    } catch {
      toast.error('Failed to delete all reports');
    } finally {
      setDeletingAll(false);
      setConfirmDeleteAll(false);
    }
  };

  const groups = groupByExam(reports);
  const totalAlerts = reports.reduce((s, r) => s + (r.alert_count ?? 0), 0);
  const totalSize = reports.reduce((s, r) => s + (r.size_kb ?? 0), 0);
  const engineCount = new Set(reports.map(r => r.engine_url)).size;

  if (loading) {
    return (
      <div className="flex items-center justify-center p-24">
        <Loader2 className="h-8 w-8 animate-spin text-slate-400" />
      </div>
    );
  }

  return (
    <>
      <div className="space-y-6 pb-12">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold text-slate-900">Engine Reports</h1>
            <p className="text-sm text-slate-500 mt-0.5">All proctoring session reports, grouped by exam</p>
          </div>
          <div className="flex gap-2">
            <Button variant="outline" size="sm" onClick={fetchReports} className="gap-2 border-slate-200">
              <RefreshCw className="h-4 w-4" /> Refresh
            </Button>
            {reports.length > 0 && (
              <Button
                variant="outline" size="sm"
                className="gap-2 border-rose-200 text-rose-600 hover:bg-rose-50"
                onClick={() => setConfirmDeleteAll(true)}
              >
                <Trash2 className="h-4 w-4" /> Delete All
              </Button>
            )}
          </div>
        </div>

        {/* Stats */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
          {[
            { label: 'Total Reports',  value: reports.length,                      icon: FileText,   color: 'indigo'  },
            { label: 'Total Alerts',   value: totalAlerts,                          icon: ShieldAlert, color: 'rose'   },
            { label: 'Storage Used',   value: `${(totalSize / 1024).toFixed(1)} MB`, icon: HardDrive,  color: 'amber'  },
            { label: 'Exam Groups',    value: groups.length,                        icon: BookOpen,   color: 'emerald' },
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

        {/* Grouped reports */}
        {groups.length === 0 ? (
          <Card className="border-slate-200 shadow-none">
            <CardContent className="py-16 text-center">
              <FileText className="h-12 w-12 text-slate-300 mx-auto mb-3" />
              <p className="text-slate-500">No reports found across any engine.</p>
            </CardContent>
          </Card>
        ) : (
          <div className="space-y-3">
            {groups.map(g => (
              <ExamGroupCard
                key={g.exam_id ?? '__orphan__'}
                group={g}
                onDelete={r => setConfirmDelete(r)}
                deleting={deleting}
                onView={setViewReport}
              />
            ))}
          </div>
        )}
      </div>

      {/* Full report modal */}
      {viewReport && (
        <FullReportModal report={viewReport} onClose={() => setViewReport(null)} />
      )}

      {/* Delete single confirmation */}
      <AlertDialog open={!!confirmDelete} onOpenChange={open => { if (!open) setConfirmDelete(null); }}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete Report</AlertDialogTitle>
            <AlertDialogDescription>
              This will permanently delete the report for{' '}
              <strong>{confirmDelete?.student_name ?? 'this student'}</strong> and all proof files. Cannot be undone.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction className="bg-rose-600 hover:bg-rose-700"
              onClick={() => confirmDelete && handleDelete(confirmDelete)}>
              Delete
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      {/* Delete all confirmation */}
      <AlertDialog open={confirmDeleteAll} onOpenChange={setConfirmDeleteAll}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete All Reports</AlertDialogTitle>
            <AlertDialogDescription>
              This will permanently delete all <strong>{reports.length} reports</strong> from all engine containers, including all proof files and screenshots. This action cannot be undone.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              className="bg-rose-600 hover:bg-rose-700"
              onClick={handleDeleteAll}
              disabled={deletingAll}
            >
              {deletingAll ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : null}
              Delete All Reports
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  );
}
