'use client';

import { useEffect, useState, useCallback } from 'react';
import {
  Loader2, RefreshCw, ShieldAlert, FileText, HardDrive,
  Trash2, AlertTriangle, Clock, Server, ChevronDown, ChevronRight,
  Eye, X, AlertCircle, BookOpen,
} from 'lucide-react';
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
  if (!state) return <span className="text-xs" style={{ color: '#94A3B8' }}>—</span>;
  const color = RISK_COLORS[state] ?? '#64748b';
  const labels: Record<string, string> = {
    NORMAL: 'Normal', WARNING: 'Warning', HIGH_RISK: 'High Risk',
    ADMIN_REVIEW: 'Review', TERMINATED: 'Terminated',
  };
  return (
    <span className="text-xs font-bold px-2 py-0.5 rounded-md border"
      style={{ background: `${color}18`, color, borderColor: `${color}40` }}>
      {labels[state] ?? state}
    </span>
  );
}

function SessionStatusBadge({ status }: { status: string | null }) {
  if (!status) return null;
  const map: Record<string, { bg: string; color: string; border: string }> = {
    ACTIVE:       { bg: '#ECFDF5', color: '#15803D', border: '#BBF7D0' },
    ENDED:        { bg: '#F8FAFC', color: '#475569', border: '#E2E8F0' },
    TERMINATED:   { bg: '#FFF1F2', color: '#BE123C', border: '#FECDD3' },
    DISCONNECTED: { bg: '#FFFBEB', color: '#B45309', border: '#FDE68A' },
    CREATED:      { bg: '#EFF6FF', color: '#1D4ED8', border: '#BFDBFE' },
  };
  const s = map[status] ?? { bg: '#F8FAFC', color: '#475569', border: '#E2E8F0' };
  return (
    <span className="inline-flex items-center px-2 py-0.5 rounded-md text-xs font-semibold border"
      style={{ background: s.bg, color: s.color, borderColor: s.border }}>
      {status.charAt(0) + status.slice(1).toLowerCase()}
    </span>
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
      .catch(e => {
        const d = e.response?.data?.detail;
        setError(typeof d === 'string' ? d : Array.isArray(d) ? d[0]?.msg : 'Failed to load report');
      })
      .finally(() => setLoading(false));
  }, [report.report_id, report.engine_url]);

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4" style={{ background: 'rgba(15,23,42,0.5)' }}>
      <div className="bg-white rounded-xl w-full max-w-3xl max-h-[90vh] flex flex-col overflow-hidden"
        style={{ boxShadow: '0 20px 60px rgba(15,23,42,0.25)', border: '1px solid #E2E8F0' }}>
        {/* Header */}
        <div className="flex items-center justify-between px-5 py-4" style={{ borderBottom: '1px solid #F1F5F9' }}>
          <div>
            <p className="font-bold text-sm" style={{ color: '#0F172A' }}>{report.student_name ?? 'Unknown Student'}</p>
            <p className="text-xs mt-0.5 font-mono" style={{ color: '#94A3B8' }}>{report.report_id}</p>
          </div>
          <button onClick={onClose}
            className="p-1.5 rounded-lg transition-colors"
            style={{ color: '#94A3B8' }}
            onMouseEnter={e => (e.currentTarget as HTMLElement).style.color = '#475569'}
            onMouseLeave={e => (e.currentTarget as HTMLElement).style.color = '#94A3B8'}>
            <X className="h-4 w-4" />
          </button>
        </div>

        {/* Content */}
        <div className="flex-1 overflow-y-auto p-5 space-y-5">
          {loading && (
            <div className="flex items-center justify-center py-16">
              <Loader2 className="h-7 w-7 animate-spin" style={{ color: '#CBD5E1' }} />
            </div>
          )}
          {error && (
            <div className="flex items-center gap-2 p-4 rounded-lg border text-sm"
              style={{ background: '#FFF1F2', borderColor: '#FECDD3', color: '#BE123C' }}>
              <AlertCircle className="h-4 w-4 shrink-0" /> {error}
            </div>
          )}
          {data && (
            <>
              {/* Summary grid */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                {[
                  { label: 'Risk State',  value: <RiskBadge state={data.risk_state} /> },
                  { label: 'Final Score', value: <span className="font-bold" style={{ color: '#0F172A' }}>{data.final_score?.toFixed(0) ?? '—'}</span> },
                  { label: 'Alerts',      value: <span className="font-bold" style={{ color: '#BE123C' }}>{data.alert_count ?? 0}</span> },
                  { label: 'Warnings',    value: <span className="font-bold" style={{ color: '#B45309' }}>{data.warning_count ?? 0}</span> },
                  { label: 'Duration',    value: <span style={{ color: '#475569' }}>{fmtDuration(data.duration_s)}</span> },
                  { label: 'Size',        value: <span style={{ color: '#475569' }}>{data.size_kb ? `${data.size_kb.toFixed(0)} KB` : '—'}</span> },
                  { label: 'Proofs',      value: <span style={{ color: '#475569' }}>{data.proof_count ?? 0}</span> },
                  { label: 'Terminated',  value: data.terminated ? <span className="font-semibold" style={{ color: '#BE123C' }}>Yes</span> : <span style={{ color: '#475569' }}>No</span> },
                ].map(({ label, value }) => (
                  <div key={label} className="rounded-lg p-3 border"
                    style={{ background: '#F8FAFC', borderColor: '#E2E8F0' }}>
                    <p className="text-[10px] font-semibold uppercase tracking-wider mb-1" style={{ color: '#94A3B8' }}>{label}</p>
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
                    <p className="text-[10px] font-semibold uppercase tracking-wider mb-2" style={{ color: '#94A3B8' }}>
                      Events ({all.length})
                    </p>
                    <div className="space-y-1.5 max-h-64 overflow-y-auto">
                      {all.map((ev: any, i: number) => (
                        <div key={i} className="flex items-start gap-2 px-3 py-2 rounded-lg text-xs border"
                          style={ev._type === 'alert'
                            ? { background: '#FFF1F2', borderColor: '#FECDD3' }
                            : { background: '#FFFBEB', borderColor: '#FDE68A' }}>
                          <AlertTriangle className="h-3.5 w-3.5 shrink-0 mt-0.5"
                            style={{ color: ev._type === 'alert' ? '#BE123C' : '#B45309' }} />
                          <div className="flex-1 min-w-0">
                            <p className="font-medium" style={{ color: ev._type === 'alert' ? '#BE123C' : '#B45309' }}>
                              {ev.message || ev.key || ev._type}
                            </p>
                            {ev.score_added > 0 && (
                              <p className="text-xs mt-0.5 opacity-75" style={{ color: ev._type === 'alert' ? '#BE123C' : '#B45309' }}>
                                +{(ev.score_added as number).toFixed(1)} pts
                              </p>
                            )}
                            {ev.proof_url && (() => {
                              const raw: string = ev.proof_url;
                              const eu = report.engine_url ?? '';
                              let proxyHref: string;
                              try {
                                const p = raw.startsWith('http') ? new URL(raw).pathname : raw;
                                proxyHref = `/admin/proxy-proof?engine_url=${encodeURIComponent(eu)}&path=${encodeURIComponent(p)}`;
                              } catch { proxyHref = raw; }
                              return (
                                <button type="button" onClick={async (e) => {
                                  e.preventDefault();
                                  try {
                                    const res = await api.get(proxyHref, { responseType: 'blob' });
                                    const url = URL.createObjectURL(res.data);
                                    window.open(url, '_blank');
                                  } catch { toast.error('Failed to load proof image'); }
                                }} className="underline text-xs text-left mt-0.5" style={{ color: '#22577A' }}>
                                  View proof
                                </button>
                              );
                            })()}
                          </div>
                          <span className="text-xs shrink-0 opacity-60" style={{ color: ev._type === 'alert' ? '#BE123C' : '#B45309' }}>
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
                <summary className="text-xs cursor-pointer transition-colors" style={{ color: '#94A3B8' }}
                  onMouseEnter={e => (e.currentTarget as HTMLElement).style.color = '#475569'}
                  onMouseLeave={e => (e.currentTarget as HTMLElement).style.color = '#94A3B8'}>
                  View raw JSON
                </summary>
                <pre className="mt-2 text-xs rounded-lg p-3 overflow-auto max-h-48"
                  style={{ background: '#F8FAFC', border: '1px solid #E2E8F0', color: '#475569' }}>
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
    <div className="bg-white rounded-xl border overflow-hidden"
      style={{ borderColor: '#E2E8F0', boxShadow: '0 1px 3px rgba(15,23,42,0.04)' }}>
      {/* Group header */}
      <button
        className="w-full flex items-center justify-between px-5 py-4 transition-colors text-left"
        style={{ background: open ? '#F8FAFC' : '#fff' }}
        onMouseEnter={e => { if (!open) (e.currentTarget as HTMLElement).style.background = '#F8FAFC'; }}
        onMouseLeave={e => { if (!open) (e.currentTarget as HTMLElement).style.background = '#fff'; }}
        onClick={() => setOpen(o => !o)}
      >
        <div className="flex items-center gap-3 min-w-0">
          <div className="p-1.5 rounded-lg shrink-0" style={{ background: '#EFF6FF' }}>
            <BookOpen className="h-4 w-4" style={{ color: '#22577A' }} />
          </div>
          <div className="text-left min-w-0">
            <p className="font-semibold text-sm truncate" style={{ color: '#0F172A' }}>{group.exam_title}</p>
            <p className="text-xs mt-0.5" style={{ color: '#94A3B8' }}>
              {group.reports.length} report{group.reports.length !== 1 ? 's' : ''}
              {' · '}
              <span style={{ color: '#BE123C' }}>{group.totalAlerts} alerts</span>
              {' · '}
              {(group.totalSize / 1024).toFixed(1)} MB
            </p>
          </div>
        </div>
        {open
          ? <ChevronDown className="h-4 w-4 shrink-0" style={{ color: '#94A3B8' }} />
          : <ChevronRight className="h-4 w-4 shrink-0" style={{ color: '#94A3B8' }} />
        }
      </button>

      {/* Reports list */}
      {open && (
        <div style={{ borderTop: '1px solid #F1F5F9' }}>
          {group.reports.map((r, idx) => (
            <div key={`${r.engine_url}:${r.report_id}`}
              className="flex flex-col sm:flex-row sm:items-center gap-4 px-5 py-4"
              style={{ borderTop: idx > 0 ? '1px solid #F8FAFC' : undefined }}>
              {/* Student info */}
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 flex-wrap mb-1">
                  <p className="font-medium text-sm" style={{ color: '#0F172A' }}>
                    {r.student_name ?? <span className="italic text-xs" style={{ color: '#94A3B8' }}>Unknown student</span>}
                  </p>
                  <SessionStatusBadge status={r.session_status} />
                  {r.terminated && (
                    <span className="inline-flex items-center px-2 py-0.5 rounded-md text-xs font-semibold border"
                      style={{ background: '#FFF1F2', color: '#BE123C', borderColor: '#FECDD3' }}>
                      Terminated
                    </span>
                  )}
                </div>
                {r.student_email && <p className="text-xs" style={{ color: '#94A3B8' }}>{r.student_email}</p>}
                <div className="flex items-center gap-3 text-xs mt-1 flex-wrap" style={{ color: '#94A3B8' }}>
                  <span className="flex items-center gap-1">
                    <Clock className="h-3 w-3" />
                    {fmtDateTime(r.session_end)}
                  </span>
                  <span>{fmtDuration(r.duration_s)}</span>
                  <span className="flex items-center gap-1">
                    <Server className="h-3 w-3" />
                    {shortenUrl(r.engine_url)}
                  </span>
                  <span className="font-mono" style={{ color: '#CBD5E1' }}>{r.report_id.slice(0, 12)}…</span>
                </div>
              </div>

              {/* Metrics */}
              <div className="flex items-center gap-4 shrink-0 flex-wrap">
                <div className="text-center">
                  <RiskBadge state={r.risk_state} />
                  <p className="text-xs mt-1" style={{ color: '#94A3B8' }}>Risk</p>
                </div>
                <div className="text-center">
                  <p className="text-lg font-bold" style={{ color: '#BE123C' }}>{r.alert_count ?? 0}</p>
                  <p className="text-xs" style={{ color: '#94A3B8' }}>Alerts</p>
                </div>
                <div className="text-center">
                  <p className="text-lg font-bold" style={{ color: '#B45309' }}>{r.warning_count ?? 0}</p>
                  <p className="text-xs" style={{ color: '#94A3B8' }}>Warns</p>
                </div>
                <div className="text-center">
                  <p className="text-sm font-semibold" style={{ color: '#475569' }}>
                    {r.size_kb ? `${r.size_kb.toFixed(0)} KB` : '—'}
                  </p>
                  <p className="text-xs" style={{ color: '#94A3B8' }}>Size</p>
                </div>

                {/* Actions */}
                <div className="flex gap-1">
                  <button
                    onClick={() => onView(r)}
                    className="h-8 w-8 flex items-center justify-center rounded-lg border transition-all duration-150"
                    style={{ borderColor: '#E2E8F0', color: '#475569', background: '#fff' }}
                    onMouseEnter={e => { (e.currentTarget as HTMLElement).style.background = '#F8FAFC'; }}
                    onMouseLeave={e => { (e.currentTarget as HTMLElement).style.background = '#fff'; }}
                  >
                    <Eye className="h-4 w-4" />
                  </button>
                  <button
                    className="h-8 w-8 flex items-center justify-center rounded-lg border transition-all duration-150"
                    style={{ borderColor: '#FECDD3', color: '#BE123C', background: '#fff' }}
                    disabled={deleting === r.report_id}
                    onClick={() => onDelete(r)}
                    onMouseEnter={e => { (e.currentTarget as HTMLElement).style.background = '#FFF1F2'; }}
                    onMouseLeave={e => { (e.currentTarget as HTMLElement).style.background = '#fff'; }}
                  >
                    {deleting === r.report_id
                      ? <Loader2 className="h-4 w-4 animate-spin" />
                      : <Trash2 className="h-4 w-4" />}
                  </button>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
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

  if (loading) {
    return (
      <div className="flex items-center justify-center p-24">
        <Loader2 className="h-7 w-7 animate-spin" style={{ color: '#CBD5E1' }} />
      </div>
    );
  }

  return (
    <>
      <div className="space-y-6 pb-12">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold" style={{ color: '#0F172A', letterSpacing: '-0.025em' }}>Engine Reports</h1>
            <p className="text-sm mt-1" style={{ color: '#94A3B8' }}>All proctoring session reports, grouped by exam</p>
          </div>
          <div className="flex gap-2">
            <button
              onClick={fetchReports}
              className="flex items-center gap-2 px-3 py-2 rounded-lg text-sm font-medium border transition-all duration-150"
              style={{ borderColor: '#E2E8F0', color: '#475569', background: '#fff' }}
            >
              <RefreshCw className="h-3.5 w-3.5" /> Refresh
            </button>
            {reports.length > 0 && (
              <button
                onClick={() => setConfirmDeleteAll(true)}
                className="flex items-center gap-2 px-3 py-2 rounded-lg text-sm font-medium border transition-all duration-150"
                style={{ borderColor: '#FECDD3', color: '#BE123C', background: '#fff' }}
                onMouseEnter={e => { (e.currentTarget as HTMLElement).style.background = '#FFF1F2'; }}
                onMouseLeave={e => { (e.currentTarget as HTMLElement).style.background = '#fff'; }}
              >
                <Trash2 className="h-3.5 w-3.5" /> Delete All
              </button>
            )}
          </div>
        </div>

        {/* Stats */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
          {[
            { label: 'Total Reports', value: reports.length,                         iconBg: '#EFF6FF', iconColor: '#22577A', Icon: FileText   },
            { label: 'Total Alerts',  value: totalAlerts,                             iconBg: '#FFF1F2', iconColor: '#BE123C', Icon: ShieldAlert },
            { label: 'Storage Used',  value: `${(totalSize / 1024).toFixed(1)} MB`,  iconBg: '#FFFBEB', iconColor: '#B45309', Icon: HardDrive   },
            { label: 'Exam Groups',   value: groups.length,                           iconBg: '#ECFDF5', iconColor: '#15803D', Icon: BookOpen    },
          ].map(({ label, value, iconBg, iconColor, Icon }) => (
            <div key={label} className="bg-white rounded-xl border p-5"
              style={{ borderColor: '#E2E8F0', boxShadow: '0 1px 3px rgba(15,23,42,0.04)' }}>
              <div className="flex items-center gap-3">
                <div className="p-2 rounded-lg shrink-0" style={{ background: iconBg }}>
                  <Icon className="h-5 w-5" style={{ color: iconColor }} />
                </div>
                <div>
                  <p className="text-2xl font-bold" style={{ color: '#0F172A', letterSpacing: '-0.02em' }}>{value}</p>
                  <p className="text-xs" style={{ color: '#94A3B8' }}>{label}</p>
                </div>
              </div>
            </div>
          ))}
        </div>

        {/* Grouped reports */}
        {groups.length === 0 ? (
          <div className="bg-white rounded-xl border py-16 text-center"
            style={{ borderColor: '#E2E8F0', boxShadow: '0 1px 3px rgba(15,23,42,0.04)' }}>
            <FileText className="h-12 w-12 mx-auto mb-3" style={{ color: '#E2E8F0' }} />
            <p className="text-sm" style={{ color: '#94A3B8' }}>No reports found across any engine.</p>
          </div>
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
            <AlertDialogAction
              style={{ background: '#DC2626' }}
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
              style={{ background: '#DC2626' }}
              onClick={handleDeleteAll}
              disabled={deletingAll}
            >
              {deletingAll ? <Loader2 className="h-4 w-4 animate-spin mr-2 inline" /> : null}
              Delete All Reports
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  );
}
