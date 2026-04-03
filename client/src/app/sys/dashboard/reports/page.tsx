'use client';

import { useEffect, useState, useCallback } from 'react';
import {
  Loader2, RefreshCw, ShieldAlert, FileText, HardDrive,
  Trash2, AlertTriangle, Clock, Server, ChevronDown, ChevronRight,
  Eye, X, AlertCircle, BookOpen, UserRound,
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
  students: StudentGroup[];
  totalAlerts: number;
  totalSize: number;
}

interface StudentGroup {
  key: string;
  student_name: string;
  student_email: string | null;
  reports: EngineReport[];
  totalAlerts: number;
  totalSize: number;
}

interface ReportEvent {
  _type?: 'alert' | 'warning';
  key?: string;
  message?: string;
  score_added?: number;
  elapsed_s?: number | null;
  time?: string | null;
  proof_url?: string | null;
  proof_type?: string | null;
  type?: string;
}

interface FullReportData {
  risk_state: string | null;
  final_score: number | null;
  alert_count: number | null;
  warning_count: number | null;
  size_kb: number | null;
  proof_count: number | null;
  duration_s: number | null;
  terminated: boolean;
  alert_log?: ReportEvent[];
  warning_log?: ReportEvent[];
  events?: ReportEvent[];
}

// ── Helpers ───────────────────────────────────────────────────────────────────

const RISK_COLORS: Record<string, string> = {
  NORMAL: '#22c55e', WARNING: '#f59e0b', HIGH_RISK: '#ef4444',
  ADMIN_REVIEW: '#dc2626', TERMINATED: '#7f1d1d', ENDED: '#475569',
};

function RiskBadge({ state }: { state: string | null }) {
  if (!state) return <span className="text-xs font-medium" style={{ color: '#64748B' }}>—</span>;
  const color = RISK_COLORS[state] ?? '#64748b';
  const labels: Record<string, string> = {
    NORMAL: 'Normal', WARNING: 'Warning', HIGH_RISK: 'High Risk',
    ADMIN_REVIEW: 'Review', TERMINATED: 'Terminated', ENDED: 'Ended',
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
  const totalSeconds = Math.max(0, Math.round(s));
  const m = Math.floor(totalSeconds / 60);
  const h = Math.floor(m / 60);
  const secs = totalSeconds % 60;
  return h > 0 ? `${h}h ${m % 60}m ${secs}s` : `${m}m ${secs}s`;
}

function fmtDateTime(iso: string | null) {
  if (!iso) return '—';
  const d = new Date(iso.endsWith('Z') || /[+-]\d{2}:\d{2}$/.test(iso) ? iso : iso + 'Z');
  return d.toLocaleString(undefined, { dateStyle: 'short', timeStyle: 'short' });
}

function shortenUrl(url: string) {
  try { const u = new URL(url); return u.hostname + (u.port ? `:${u.port}` : ''); } catch { return url; }
}

function formatStorage(kb: number | null | undefined) {
  const safe = kb ?? 0;
  if (safe >= 1024) return `${(safe / 1024).toFixed(1)} MB`;
  return `${safe.toFixed(1)} KB`;
}

function groupByExam(reports: EngineReport[]): ExamGroup[] {
  const map = new Map<string, ExamGroup>();
  for (const r of reports) {
    const key = r.exam_id ?? '__orphan__';
    if (!map.has(key)) {
      map.set(key, {
        exam_id: r.exam_id,
        exam_title: r.exam_title ?? 'Unknown Exam',
        students: [],
        totalAlerts: 0,
        totalSize: 0,
      });
    }
    const g = map.get(key)!;
    g.totalAlerts += r.alert_count ?? 0;
    g.totalSize += r.size_kb ?? 0;

    const studentKey = r.student_email?.toLowerCase() || r.student_name || r.report_id;
    let studentGroup = g.students.find((student) => student.key === studentKey);
    if (!studentGroup) {
      studentGroup = {
        key: studentKey,
        student_name: r.student_name ?? 'Unknown student',
        student_email: r.student_email,
        reports: [],
        totalAlerts: 0,
        totalSize: 0,
      };
      g.students.push(studentGroup);
    }

    studentGroup.reports.push(r);
    studentGroup.totalAlerts += r.alert_count ?? 0;
    studentGroup.totalSize += r.size_kb ?? 0;
  }
  return Array.from(map.values())
    .map((group) => ({
      ...group,
      students: group.students
        .map((student) => ({
          ...student,
          reports: student.reports.sort((a, b) => {
            const aTime = a.session_end ?? a.session_start ?? '';
            const bTime = b.session_end ?? b.session_start ?? '';
            return bTime.localeCompare(aTime);
          }),
        }))
        .sort((a, b) => a.student_name.localeCompare(b.student_name)),
    }))
    .sort((a, b) =>
      a.exam_id === null ? 1 : b.exam_id === null ? -1 : a.exam_title.localeCompare(b.exam_title)
    );
}

// ── Full Report Modal ─────────────────────────────────────────────────────────

function FullReportModal({ report, onClose }: { report: EngineReport; onClose: () => void }) {
  const [data, setData] = useState<FullReportData | null>(null);
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
            <p className="text-xs mt-0.5 font-mono" style={{ color: '#64748B' }}>{report.report_id}</p>
          </div>
          <button onClick={onClose}
            className="p-1.5 rounded-lg transition-colors"
            style={{ color: '#64748B' }}
            onMouseEnter={e => (e.currentTarget as HTMLElement).style.color = '#475569'}
            onMouseLeave={e => (e.currentTarget as HTMLElement).style.color = '#64748B'}>
            <X className="h-4 w-4" />
          </button>
        </div>

        {/* Content */}
        <div className="flex-1 overflow-y-auto p-5 space-y-5">
          {loading && (
            <div className="flex items-center justify-center py-16">
              <Loader2 className="h-7 w-7 animate-spin" style={{ color: '#94A3B8' }} />
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
                  { label: 'Photos',      value: <span style={{ color: '#475569' }}>{formatStorage(data.size_kb)}</span> },
                  { label: 'Proofs',      value: <span style={{ color: '#475569' }}>{data.proof_count ?? 0}</span> },
                  { label: 'Terminated',  value: data.terminated ? <span className="font-semibold" style={{ color: '#BE123C' }}>Yes</span> : <span style={{ color: '#475569' }}>No</span> },
                ].map(({ label, value }) => (
                  <div key={label} className="rounded-lg p-3 border"
                    style={{ background: '#F8FAFC', borderColor: '#E2E8F0' }}>
                    <p className="text-[10px] font-semibold uppercase tracking-wider mb-1" style={{ color: '#64748B' }}>{label}</p>
                    <div className="text-sm">{value}</div>
                  </div>
                ))}
              </div>

              {/* Events */}
              {(() => {
                const alerts: ReportEvent[] = (data.alert_log ?? []).map((e: ReportEvent) => ({ ...e, _type: 'alert' }));
                const warnings: ReportEvent[] = (data.warning_log ?? []).map((e: ReportEvent) => ({ ...e, _type: 'warning' }));
                const legacy: ReportEvent[] = (data.events ?? []).map((e: ReportEvent) => ({ ...e, _type: (e.type as 'alert' | 'warning' | undefined) ?? 'alert' }));
                const all = alerts.length || warnings.length ? [...alerts, ...warnings] : legacy;
                if (!all.length) return null;
                return (
                  <div>
                    <p className="text-[10px] font-semibold uppercase tracking-wider mb-2" style={{ color: '#64748B' }}>
                      Events ({all.length})
                    </p>
                    <div className="space-y-1.5 max-h-64 overflow-y-auto">
                      {all.map((ev: ReportEvent, i: number) => (
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
                            {ev.proof_url && (
                              <a href={ev.proof_url} target="_blank" rel="noopener noreferrer"
                                className="underline text-xs mt-0.5 block" style={{ color: '#22577A' }}>
                                View proof {ev.proof_type === 'audio' ? '(audio)' : '(image)'}
                              </a>
                            )}
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
                <summary className="text-xs cursor-pointer transition-colors font-medium" style={{ color: '#64748B' }}
                  onMouseEnter={e => (e.currentTarget as HTMLElement).style.color = '#475569'}
                  onMouseLeave={e => (e.currentTarget as HTMLElement).style.color = '#64748B'}>
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

function ReportRow({
  report,
  onDelete,
  deleting,
  onView,
}: {
  report: EngineReport;
  onDelete: (r: EngineReport) => void;
  deleting: string | null;
  onView: (r: EngineReport) => void;
}) {
  return (
    <div
      className="flex flex-col gap-4 px-5 py-4 sm:flex-row sm:items-center"
      style={{ borderTop: '1px solid #F8FAFC' }}
    >
      <div className="flex-1 min-w-0">
        <div className="mb-1 flex items-center gap-2 flex-wrap">
          <p className="font-medium text-sm" style={{ color: '#0F172A' }}>
            {report.student_name ?? <span className="italic text-xs font-medium" style={{ color: '#64748B' }}>Unknown student</span>}
          </p>
          <SessionStatusBadge status={report.session_status} />
        </div>
        {report.student_email && <p className="text-xs font-medium" style={{ color: '#64748B' }}>{report.student_email}</p>}
        <div className="mt-1 flex items-center gap-3 flex-wrap text-xs font-medium" style={{ color: '#64748B' }}>
          <span className="flex items-center gap-1">
            <Clock className="h-3 w-3" />
            {fmtDateTime(report.session_end)}
          </span>
          <span>{fmtDuration(report.duration_s)}</span>
          <span className="flex items-center gap-1">
            <Server className="h-3 w-3" />
            {shortenUrl(report.engine_url)}
          </span>
        </div>
      </div>

      <div className="flex items-center gap-4 shrink-0 flex-wrap">
        <div className="text-center">
          <RiskBadge state={report.risk_state} />
          <p className="text-xs mt-1 font-medium" style={{ color: '#64748B' }}>Risk</p>
        </div>
        <div className="text-center">
          <p className="text-lg font-bold" style={{ color: '#BE123C' }}>{report.alert_count ?? 0}</p>
          <p className="text-xs font-medium" style={{ color: '#64748B' }}>Alerts</p>
        </div>
        <div className="text-center">
          <p className="text-lg font-bold" style={{ color: '#B45309' }}>{report.warning_count ?? 0}</p>
          <p className="text-xs font-medium" style={{ color: '#64748B' }}>Warns</p>
        </div>
        <div className="text-center">
          <p className="text-sm font-semibold" style={{ color: '#475569' }}>
            {formatStorage(report.size_kb)}
          </p>
          <p className="text-xs font-medium" style={{ color: '#64748B' }}>Photos</p>
        </div>

        <div className="flex gap-1">
          <button
            onClick={() => onView(report)}
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
            disabled={deleting === report.report_id}
            onClick={() => onDelete(report)}
            onMouseEnter={e => { (e.currentTarget as HTMLElement).style.background = '#FFF1F2'; }}
            onMouseLeave={e => { (e.currentTarget as HTMLElement).style.background = '#fff'; }}
            title="Delete proof images"
          >
            {deleting === report.report_id
              ? <Loader2 className="h-4 w-4 animate-spin" />
              : <Trash2 className="h-4 w-4" />}
          </button>
        </div>
      </div>
    </div>
  );
}

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
  const [openStudents, setOpenStudents] = useState<Record<string, boolean>>({});

  const toggleStudent = (key: string) => {
    setOpenStudents((prev) => ({ ...prev, [key]: !prev[key] }));
  };

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
            <p className="text-xs mt-0.5 font-medium" style={{ color: '#64748B' }}>
              {group.students.reduce((sum, student) => sum + student.reports.length, 0)} report{group.students.reduce((sum, student) => sum + student.reports.length, 0) !== 1 ? 's' : ''}
              {' · '}
              {group.students.length} student{group.students.length !== 1 ? 's' : ''}
              {' · '}
              <span style={{ color: '#BE123C' }}>{group.totalAlerts} alerts</span>
              {' · '}
              {formatStorage(group.totalSize)}
            </p>
          </div>
        </div>
        {open
          ? <ChevronDown className="h-4 w-4 shrink-0" style={{ color: '#64748B' }} />
          : <ChevronRight className="h-4 w-4 shrink-0" style={{ color: '#64748B' }} />
        }
      </button>

      {/* Reports list */}
      {open && (
        <div style={{ borderTop: '1px solid #F1F5F9' }}>
          {group.students.map((student, idx) => {
            const studentOpen = openStudents[student.key] ?? idx === 0;
            return (
              <div key={student.key} style={{ borderTop: idx > 0 ? '1px solid #F8FAFC' : undefined }}>
                <button
                  className="flex w-full items-center justify-between px-5 py-4 text-left transition-colors"
                  style={{ background: studentOpen ? '#FCFDFE' : '#fff' }}
                  onClick={() => toggleStudent(student.key)}
                >
                  <div className="flex min-w-0 items-center gap-3">
                    <div className="rounded-lg p-1.5 shrink-0" style={{ background: '#F5F3FF' }}>
                      <UserRound className="h-4 w-4" style={{ color: '#7C3AED' }} />
                    </div>
                    <div className="min-w-0">
                      <p className="truncate text-sm font-semibold" style={{ color: '#0F172A' }}>
                        {student.student_name}
                      </p>
                      <p className="mt-0.5 text-xs font-medium" style={{ color: '#64748B' }}>
                        {student.student_email ?? 'No email'}
                        {' · '}
                        {student.reports.length} session{student.reports.length !== 1 ? 's' : ''}
                        {' · '}
                        <span style={{ color: '#BE123C' }}>{student.totalAlerts} alerts</span>
                        {' · '}
                        {formatStorage(student.totalSize)}
                      </p>
                    </div>
                  </div>
                  {studentOpen
                    ? <ChevronDown className="h-4 w-4 shrink-0" style={{ color: '#64748B' }} />
                    : <ChevronRight className="h-4 w-4 shrink-0" style={{ color: '#64748B' }} />
                  }
                </button>

                {studentOpen && (
                  <div className="pb-1">
                    {student.reports.map((report) => (
                      <ReportRow
                        key={`${report.engine_url}:${report.report_id}`}
                        report={report}
                        onDelete={onDelete}
                        deleting={deleting}
                        onView={onView}
                      />
                    ))}
                  </div>
                )}
              </div>
            );
          })}
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
      const res = await api.delete(`/admin/reports/${report.report_id}`);
      await fetchReports();
      toast.success(
        res.data.deleted_proofs > 0
          ? `Deleted ${res.data.deleted_proofs} proof image${res.data.deleted_proofs !== 1 ? 's' : ''}`
          : 'No proof images were stored for this report',
      );
    } catch {
      toast.error('Failed to delete proof images');
    } finally {
      setDeleting(null);
      setConfirmDelete(null);
    }
  };

  const handleDeleteAll = async () => {
    setDeletingAll(true);
    try {
      const res = await api.delete('/admin/reports');
      await fetchReports();
      toast.success(
        `Deleted ${res.data.deleted_proofs} proof image${res.data.deleted_proofs !== 1 ? 's' : ''} across ${res.data.affected_reports} report${res.data.affected_reports !== 1 ? 's' : ''}`,
      );
      if (res.data.errors?.length > 0) {
        toast.warning(`${res.data.errors.length} error(s) during deletion`);
      }
    } catch {
      toast.error('Failed to delete all proof images');
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
        <Loader2 className="h-7 w-7 animate-spin" style={{ color: '#94A3B8' }} />
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
            <p className="text-sm mt-1 font-medium" style={{ color: '#64748B' }}>All proctoring session reports, grouped by exam and student</p>
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
                <Trash2 className="h-3.5 w-3.5" /> Delete All Proofs
              </button>
            )}
          </div>
        </div>

        {/* Stats */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
          {[
            { label: 'Total Reports', value: reports.length,                         iconBg: '#EFF6FF', iconColor: '#22577A', Icon: FileText   },
            { label: 'Total Alerts',  value: totalAlerts,                             iconBg: '#FFF1F2', iconColor: '#BE123C', Icon: ShieldAlert },
            { label: 'Photo Storage', value: formatStorage(totalSize),                iconBg: '#FFFBEB', iconColor: '#B45309', Icon: HardDrive   },
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
                  <p className="text-xs font-medium" style={{ color: '#64748B' }}>{label}</p>
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
            <p className="text-sm font-medium" style={{ color: '#64748B' }}>No completed sessions found. Reports appear here once a session ends or is terminated.</p>
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
            <AlertDialogTitle>Delete Proof Images</AlertDialogTitle>
            <AlertDialogDescription>
              This will delete only the stored proof images for{' '}
              <strong>{confirmDelete?.student_name ?? 'this student'}</strong>. The report, alerts, and session history will remain available.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              style={{ background: '#DC2626' }}
              onClick={() => confirmDelete && handleDelete(confirmDelete)}>
              Delete Proofs
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      {/* Delete all confirmation */}
      <AlertDialog open={confirmDeleteAll} onOpenChange={setConfirmDeleteAll}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete All Proof Images</AlertDialogTitle>
            <AlertDialogDescription>
              This will delete proof images from all <strong>{reports.length} reports</strong>. The reports, alert history, and session metadata will stay intact.
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
              Delete All Proofs
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  );
}
