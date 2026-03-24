'use client';

import { useEffect, useState, useCallback } from 'react';
import {
  Loader2, RefreshCw, ShieldAlert, FileText, HardDrive,
  Trash2, AlertTriangle, CheckCircle2, Clock, Server,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardContent } from '@/components/ui/card';
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
  // DB-enriched (null if orphaned)
  session_id: string | null;
  exam_id: string | null;
  exam_title: string | null;
  student_name: string | null;
  student_email: string | null;
  session_status: string | null;
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

function SessionStatusBadge({ status }: { status: string | null }) {
  if (!status) return <Badge variant="outline" className="text-xs bg-slate-50 text-slate-400 border-slate-200">Unknown</Badge>;
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

function shortenUrl(url: string): string {
  try {
    const u = new URL(url);
    return u.hostname + (u.port ? `:${u.port}` : '');
  } catch {
    return url;
  }
}

// ── Page ─────────────────────────────────────────────────────────────────────

export default function SysAdminReportsPage() {
  const [reports, setReports] = useState<EngineReport[]>([]);
  const [loading, setLoading] = useState(true);
  const [deleting, setDeleting] = useState<string | null>(null);
  const [confirmDelete, setConfirmDelete] = useState<EngineReport | null>(null);

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

  useEffect(() => {
    fetchReports();
  }, [fetchReports]);

  const handleDelete = async (report: EngineReport) => {
    setDeleting(report.report_id);
    try {
      await api.delete(`/admin/reports/${report.report_id}`, {
        params: { engine_url: report.engine_url },
      });
      setReports(prev => prev.filter(r => r.report_id !== report.report_id));
      toast.success('Report deleted');
    } catch {
      toast.error('Failed to delete report');
    } finally {
      setDeleting(null);
      setConfirmDelete(null);
    }
  };

  // ── Stats ──────────────────────────────────────────────────────────────────

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
            <p className="text-sm text-slate-500 mt-0.5">All proctoring session reports across all engines</p>
          </div>
          <Button variant="outline" size="sm" onClick={fetchReports} className="gap-2 border-slate-200">
            <RefreshCw className="h-4 w-4" /> Refresh
          </Button>
        </div>

        {/* Stats */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
          {[
            { label: 'Total Reports', value: reports.length, icon: FileText, color: 'indigo' },
            { label: 'Total Alerts', value: totalAlerts, icon: ShieldAlert, color: 'rose' },
            { label: 'Storage Used', value: `${(totalSize / 1024).toFixed(1)} MB`, icon: HardDrive, color: 'amber' },
            { label: 'Active Engines', value: engineCount, icon: Server, color: 'emerald' },
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

        {/* Reports list */}
        {reports.length === 0 ? (
          <Card className="border-slate-200 shadow-none">
            <CardContent className="py-16 text-center">
              <FileText className="h-12 w-12 text-slate-300 mx-auto mb-3" />
              <p className="text-slate-500">No reports found across any engine.</p>
            </CardContent>
          </Card>
        ) : (
          <div className="space-y-3">
            {reports.map((r) => (
              <Card key={`${r.engine_url}:${r.report_id}`} className="border-slate-200 shadow-none">
                <CardContent className="p-5">
                  <div className="flex flex-col sm:flex-row sm:items-start gap-4">
                    {/* Student / exam info */}
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 flex-wrap mb-1">
                        <p className="font-semibold text-slate-900">
                          {r.student_name ?? <span className="text-slate-400 font-normal italic">Unknown student</span>}
                        </p>
                        {r.terminated && (
                          <Badge variant="outline" className="text-xs bg-rose-50 text-rose-600 border-rose-200">
                            Terminated
                          </Badge>
                        )}
                        {r.session_status && <SessionStatusBadge status={r.session_status} />}
                      </div>

                      {r.student_email && (
                        <p className="text-sm text-slate-500">{r.student_email}</p>
                      )}

                      {r.exam_title && (
                        <p className="text-xs text-slate-400 mt-0.5">
                          Exam: <span className="font-medium text-slate-600">{r.exam_title}</span>
                        </p>
                      )}

                      <div className="flex items-center gap-4 mt-2 text-xs text-slate-400 flex-wrap">
                        <span className="flex items-center gap-1">
                          <Clock className="h-3.5 w-3.5" />
                          {fmtDateTime(r.session_start)}
                          {r.session_end && <> → {fmtDateTime(r.session_end)}</>}
                        </span>
                        {r.duration_s != null && (
                          <span>{fmtDuration(r.duration_s)}</span>
                        )}
                        <span className="flex items-center gap-1">
                          <Server className="h-3.5 w-3.5" />
                          {shortenUrl(r.engine_url)}
                        </span>
                      </div>

                      <p className="text-xs text-slate-300 mt-1 font-mono">{r.report_id}</p>
                    </div>

                    {/* Metrics */}
                    <div className="flex items-center gap-4 shrink-0 flex-wrap">
                      <div className="text-center">
                        <RiskBadge state={r.risk_state} />
                        <p className="text-xs text-slate-400 mt-1">Risk State</p>
                      </div>
                      <div className="text-center">
                        <p className="text-xl font-bold text-slate-800">{r.final_score?.toFixed(0) ?? '—'}</p>
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

                      {/* Delete button */}
                      <Button
                        variant="outline"
                        size="icon"
                        className="h-8 w-8 border-rose-200 text-rose-500 hover:bg-rose-50 hover:text-rose-600 shrink-0"
                        disabled={deleting === r.report_id}
                        onClick={() => setConfirmDelete(r)}
                      >
                        {deleting === r.report_id
                          ? <Loader2 className="h-4 w-4 animate-spin" />
                          : <Trash2 className="h-4 w-4" />}
                      </Button>
                    </div>
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        )}
      </div>

      {/* Delete confirmation dialog */}
      <AlertDialog open={!!confirmDelete} onOpenChange={(open) => { if (!open) setConfirmDelete(null); }}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete Report</AlertDialogTitle>
            <AlertDialogDescription>
              This will permanently delete the report{' '}
              <span className="font-mono text-slate-800">{confirmDelete?.report_id}</span>
              {confirmDelete?.student_name && (
                <> for <strong>{confirmDelete.student_name}</strong></>
              )}
              {' '}from the engine. This action cannot be undone and will also remove all associated proof files.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              className="bg-rose-600 hover:bg-rose-700"
              onClick={() => confirmDelete && handleDelete(confirmDelete)}
            >
              Delete Report
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  );
}
