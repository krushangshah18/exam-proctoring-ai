"use client";

import { useEffect, useState, useCallback } from "react";
import { useParams, useRouter } from "next/navigation";
import {
  ArrowLeft,
  Loader2,
  RefreshCw,
  ShieldAlert,
  AlertTriangle,
  FileText,
  Users,
  Clock,
  Eye,
  X,
  AlertCircle,
  ChevronRight,
  ChevronDown,
} from "lucide-react";
import { toast } from "sonner";
import api from "@/lib/axios";

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
  NORMAL: "#22c55e",
  WARNING: "#f59e0b",
  HIGH_RISK: "#ef4444",
  ADMIN_REVIEW: "#dc2626",
  TERMINATED: "#7f1d1d",
};

const SESSION_STATUS_STYLES: Record<
  string,
  { bg: string; color: string; border: string; label: string }
> = {
  ACTIVE: {
    bg: "#ECFDF5",
    color: "#15803D",
    border: "#BBF7D0",
    label: "Active",
  },
  ENDED: { bg: "#F8FAFC", color: "#475569", border: "#E2E8F0", label: "Ended" },
  TERMINATED: {
    bg: "#FFF1F2",
    color: "#BE123C",
    border: "#FECDD3",
    label: "Terminated",
  },
  DISCONNECTED: {
    bg: "#FFFBEB",
    color: "#B45309",
    border: "#FDE68A",
    label: "Disconnected",
  },
  CREATED: {
    bg: "#EFF6FF",
    color: "#1D4ED8",
    border: "#BFDBFE",
    label: "Created",
  },
};

function RiskBadge({ state }: { state: string | null }) {
  if (!state)
    return (
      <span className="text-xs" style={{ color: "#64748B" }}>
        —
      </span>
    );
  const color = RISK_COLORS[state] ?? "#64748b";
  const labels: Record<string, string> = {
    NORMAL: "Normal",
    WARNING: "Warning",
    HIGH_RISK: "High Risk",
    ADMIN_REVIEW: "Admin Review",
    TERMINATED: "Terminated",
  };
  return (
    <span
      className="text-xs font-bold px-2 py-0.5 rounded border"
      style={{ background: `${color}22`, color, borderColor: `${color}44` }}
    >
      {labels[state] ?? state}
    </span>
  );
}

function StatusBadge({ status }: { status: string }) {
  const s = SESSION_STATUS_STYLES[status] ?? {
    bg: "#F8FAFC",
    color: "#475569",
    border: "#E2E8F0",
    label: status,
  };
  return (
    <span
      className="inline-flex items-center px-2 py-0.5 rounded-md text-xs font-semibold border"
      style={{ background: s.bg, color: s.color, borderColor: s.border }}
    >
      {s.label}
    </span>
  );
}

function fmtDuration(s: number | null): string {
  if (s == null) return "—";
  const total = Math.floor(s);
  const h = Math.floor(total / 3600);
  const m = Math.floor((total % 3600) / 60);
  const sec = total % 60;
  if (h > 0)
    return `${String(h).padStart(2, "0")}:${String(m).padStart(2, "0")}:${String(sec).padStart(2, "0")}`;
  return `${String(m).padStart(2, "0")}:${String(sec).padStart(2, "0")}`;
}

function fmtDateTime(iso: string | null): string {
  if (!iso) return "—";
  const d = new Date(
    iso.endsWith("Z") || /[+-]\d{2}:\d{2}$/.test(iso) ? iso : iso + "Z",
  );
  return d.toLocaleString(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  });
}

function fmtElapsed(s: number): string {
  const m = Math.floor(s / 60);
  const sec = Math.round(s % 60);
  return `${m}:${String(sec).padStart(2, "0")}`;
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
    api
      .get(
        `/admin/exams/${examId}/sessions/${session.session_id}/report/full`,
        {
          params: {
            report_id: session.report_id,
            engine_url: session.engine_url,
          },
        },
      )
      .then((r) => setData(r.data))
      .catch((e) => {
        const detail = e.response?.data?.detail;
        const status = e.response?.status;
        if (status === 410) {
          setDeleted(true);
          setError("Report no longer exists and has been deleted.");
          return;
        }
        setError(detail || "Failed to load report");
      })
      .finally(() => setLoading(false));
  }, [examId, session.engine_url, session.report_id, session.session_id]);

  function proofUrl(raw: string): string {
    if (!raw) return raw;
    // S3 presigned URLs are self-authenticated — use them directly
    if (raw.includes("amazonaws.com")) return raw;
    // Engine-hosted proofs need to be proxied through the backend
    if (!session.engine_url) return raw;
    const base = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";
    if (raw.startsWith("http"))
      return `${base}/admin/proxy-proof?engine_url=${encodeURIComponent(session.engine_url)}&path=${encodeURIComponent(new URL(raw).pathname)}`;
    return `${base}/admin/proxy-proof?engine_url=${encodeURIComponent(session.engine_url)}&path=${encodeURIComponent(raw)}`;
  }

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center p-4"
      style={{ background: "rgba(15,23,42,0.5)" }}
    >
      <div className="bg-white rounded-xl shadow-2xl w-full max-w-3xl max-h-[90vh] flex flex-col overflow-hidden">
        {/* Header */}
        <div
          className="flex items-center justify-between px-5 py-4"
          style={{ borderBottom: "1px solid #E2E8F0" }}
        >
          <div>
            <p className="font-bold" style={{ color: "#0F172A" }}>
              {session.student_name}
            </p>
            <p className="text-xs mt-0.5" style={{ color: "#64748B" }}>
              {session.student_email}
            </p>
            {session.report_id && (
              <p
                className="text-xs font-mono mt-0.5"
                style={{ color: "#CBD5E1" }}
              >
                {session.report_id}
              </p>
            )}
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg transition-colors"
            style={{ color: "#64748B" }}
            onMouseEnter={(e) =>
              ((e.currentTarget as HTMLElement).style.color = "#475569")
            }
            onMouseLeave={(e) =>
              ((e.currentTarget as HTMLElement).style.color = "#64748B")
            }
          >
            <X className="h-5 w-5" />
          </button>
        </div>

        {/* Content */}
        <div className="flex-1 overflow-y-auto p-5 space-y-5">
          {loading && (
            <div className="flex items-center justify-center py-16">
              <Loader2
                className="h-7 w-7 animate-spin"
                style={{ color: "#CBD5E1" }}
              />
            </div>
          )}
          {error && (
            <div
              className="flex items-center gap-2 p-4 rounded-lg border"
              style={
                deleted
                  ? {
                      background: "#FFFBEB",
                      borderColor: "#FDE68A",
                      color: "#B45309",
                    }
                  : {
                      background: "#FFF1F2",
                      borderColor: "#FECDD3",
                      color: "#BE123C",
                    }
              }
            >
              <AlertCircle className="h-4 w-4 shrink-0" /> {error}
            </div>
          )}
          {data && (
            <>
              {/* Summary grid */}
              {(() => {
                const riskState = data.risk_state ?? session.risk_state;
                const finalScore =
                  data.final_score ?? session.final_score ?? session.risk_score;
                const isTerminated =
                  data.terminated ?? session.terminated ?? false;
                const rows = [
                  {
                    label: "Risk State",
                    value: <RiskBadge state={riskState} />,
                  },
                  {
                    label: "Final Score",
                    value: (
                      <span className="font-bold" style={{ color: "#0F172A" }}>
                        {finalScore != null
                          ? Number(finalScore).toFixed(0)
                          : "—"}
                      </span>
                    ),
                  },
                  {
                    label: "Alerts",
                    value: (
                      <span className="font-bold" style={{ color: "#EF4444" }}>
                        {data.alert_count ?? 0}
                      </span>
                    ),
                  },
                  {
                    label: "Warnings",
                    value: (
                      <span className="font-bold" style={{ color: "#F59E0B" }}>
                        {data.warning_count ?? 0}
                      </span>
                    ),
                  },
                  {
                    label: "Duration",
                    value: fmtDuration(data.duration_s ?? session.duration_s),
                  },
                  {
                    label: "Terminated",
                    value: isTerminated ? (
                      <span
                        className="font-semibold"
                        style={{ color: "#EF4444" }}
                      >
                        Yes
                      </span>
                    ) : (
                      <span style={{ color: "#475569" }}>No</span>
                    ),
                  },
                ];
                return (
                  <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
                    {rows.map(({ label, value }) => (
                      <div
                        key={label}
                        className="rounded-lg border p-3"
                        style={{
                          background: "#F8FAFC",
                          borderColor: "#E2E8F0",
                        }}
                      >
                        <p
                          className="text-[10px] font-semibold uppercase tracking-wider mb-1"
                          style={{ color: "#64748B" }}
                        >
                          {label}
                        </p>
                        <div className="text-sm">{value}</div>
                      </div>
                    ))}
                  </div>
                );
              })()}

              {/* Events */}
              {(() => {
                const alerts: any[] = (data.alert_log ?? []).map((e: any) => ({
                  ...e,
                  _type: "alert",
                }));
                const warnings: any[] = (data.warning_log ?? []).map(
                  (e: any) => ({ ...e, _type: "warning" }),
                );
                const legacy: any[] = (data.events ?? []).map((e: any) => ({
                  ...e,
                  _type: e.type ?? "alert",
                }));
                const all =
                  alerts.length || warnings.length
                    ? [...alerts, ...warnings]
                    : legacy;
                if (!all.length) return null;
                return (
                  <div>
                    <p
                      className="text-[10px] font-semibold uppercase tracking-wider mb-2"
                      style={{ color: "#64748B" }}
                    >
                      Events ({all.length})
                    </p>
                    <div className="space-y-1.5 max-h-64 overflow-y-auto">
                      {all.map((ev: any, i: number) => (
                        <div
                          key={i}
                          className="flex items-start gap-2 px-3 py-2 rounded-lg text-xs border"
                          style={
                            ev._type === "alert"
                              ? {
                                  background: "rgba(254,242,242,0.5)",
                                  borderColor: "#FECDD3",
                                  color: "#BE123C",
                                }
                              : {
                                  background: "rgba(255,251,235,0.5)",
                                  borderColor: "#FDE68A",
                                  color: "#B45309",
                                }
                          }
                        >
                          <AlertTriangle className="h-3.5 w-3.5 shrink-0 mt-0.5" />
                          <div className="flex-1 min-w-0">
                            <p className="font-medium">
                              {ev.message || ev.key || ev._type}
                            </p>
                            {ev.score_added > 0 && (
                              <p className="text-xs opacity-75">
                                +{(ev.score_added as number).toFixed(1)} pts
                              </p>
                            )}
                            {ev.proof_url && (
                              <button
                                type="button"
                                onClick={async (e) => {
                                  e.preventDefault();
                                  const url = proofUrl(ev.proof_url);
                                  // S3 presigned URLs are self-authenticated — open directly
                                  if (url.includes("amazonaws.com")) {
                                    window.open(url, "_blank");
                                    return;
                                  }
                                  try {
                                    const res = await api.get(url, {
                                      responseType: "blob",
                                    });
                                    const blobUrl = URL.createObjectURL(
                                      res.data,
                                    );
                                    window.open(blobUrl, "_blank");
                                  } catch {
                                    toast.error("Failed to load proof image");
                                  }
                                }}
                                className="underline text-xs text-left"
                                style={{ color: "#22577A" }}
                              >
                                View proof
                              </button>
                            )}
                          </div>
                          <span className="text-xs opacity-60 shrink-0">
                            {ev.elapsed_s != null
                              ? fmtElapsed(ev.elapsed_s)
                              : (ev.time ?? "")}
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>
                );
              })()}

              {/* Raw JSON */}
              <details>
                <summary
                  className="text-xs cursor-pointer hover:underline"
                  style={{ color: "#64748B" }}
                >
                  View raw JSON
                </summary>
                <pre
                  className="mt-2 text-xs rounded-lg p-3 overflow-auto max-h-48"
                  style={{
                    background: "#F8FAFC",
                    border: "1px solid #E2E8F0",
                    color: "#475569",
                  }}
                >
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
  const [examTitle, setExamTitle] = useState("");
  const [viewSession, setViewSession] = useState<SessionReport | null>(null);
  const [collapsedGroups, setCollapsedGroups] = useState<
    Record<string, boolean>
  >({});

  const fetchReports = useCallback(async () => {
    try {
      const [reportsRes, statusRes] = await Promise.all([
        api.get(`/admin/exams/${examId}/reports`),
        api.get(`/admin/exams/${examId}`).catch(() => null),
      ]);
      setReports(reportsRes.data);
      if (statusRes?.data?.title) setExamTitle(statusRes.data.title);
    } catch {
      toast.error("Failed to load reports");
    } finally {
      setLoading(false);
    }
  }, [examId]);

  useEffect(() => {
    fetchReports();
  }, [fetchReports]);

  const withReports = reports.filter((r) => r.report_id);
  const totalAlerts = withReports.reduce((s, r) => s + (r.alert_count ?? 0), 0);
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
    }, {}),
  );

  const toggleGroup = useCallback((studentKey: string) => {
    setCollapsedGroups((prev) => ({
      ...prev,
      [studentKey]: !prev[studentKey],
    }));
  }, []);

  if (loading) {
    return (
      <div className="flex items-center justify-center p-24">
        <Loader2
          className="h-7 w-7 animate-spin"
          style={{ color: "#CBD5E1" }}
        />
      </div>
    );
  }

  const totalWarnings = withReports.reduce(
    (s, r) => s + (r.warning_count ?? 0),
    0,
  );

  const statCards = [
    {
      label: "Students",
      value: studentGroups.length,
      icon: Users,
      iconBg: "#EFF6FF",
      iconColor: "#22577A",
    },
    {
      label: "Reports Available",
      value: withReports.length,
      icon: FileText,
      iconBg: "#ECFDF5",
      iconColor: "#15803D",
    },
    {
      label: "Total Alerts",
      value: totalAlerts,
      icon: ShieldAlert,
      iconBg: "#FFF1F2",
      iconColor: "#BE123C",
    },
    {
      label: "Total Warnings",
      value: totalWarnings,
      icon: AlertTriangle,
      iconBg: "#FFFBEB",
      iconColor: "#B45309",
    },
  ];

  return (
    <div className="space-y-6 pb-12">
      {viewSession && (
        <FullReportModal
          examId={examId}
          session={viewSession}
          onClose={() => setViewSession(null)}
        />
      )}

      {/* Header */}
      <div className="flex items-center gap-4">
        <button
          onClick={() => router.back()}
          className="h-9 w-9 flex items-center justify-center rounded-lg border shrink-0 transition-all duration-150"
          style={{
            borderColor: "#E2E8F0",
            color: "#475569",
            background: "#fff",
          }}
          onMouseEnter={(e) =>
            ((e.currentTarget as HTMLElement).style.background = "#F8FAFC")
          }
          onMouseLeave={(e) =>
            ((e.currentTarget as HTMLElement).style.background = "#fff")
          }
        >
          <ArrowLeft className="h-4 w-4" />
        </button>
        <div className="flex-1">
          <h1
            className="text-2xl font-bold"
            style={{ color: "#0F172A", letterSpacing: "-0.025em" }}
          >
            Session Reports
          </h1>
          {examTitle && (
            <p className="text-sm mt-0.5" style={{ color: "#64748B" }}>
              {examTitle}
            </p>
          )}
        </div>
        <button
          onClick={fetchReports}
          className="flex items-center gap-2 px-3 py-2 rounded-lg text-sm font-medium border transition-all duration-150"
          style={{
            borderColor: "#E2E8F0",
            color: "#475569",
            background: "#fff",
          }}
          onMouseEnter={(e) =>
            ((e.currentTarget as HTMLElement).style.background = "#F8FAFC")
          }
          onMouseLeave={(e) =>
            ((e.currentTarget as HTMLElement).style.background = "#fff")
          }
        >
          <RefreshCw className="h-3.5 w-3.5" /> Refresh
        </button>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        {statCards.map(({ label, value, icon: Icon, iconBg, iconColor }) => (
          <div
            key={label}
            className="bg-white rounded-xl border p-5"
            style={{
              borderColor: "#E2E8F0",
              boxShadow: "0 1px 3px rgba(15,23,42,0.04)",
            }}
          >
            <div className="flex items-center gap-3">
              <div
                className="p-2 rounded-lg shrink-0"
                style={{ background: iconBg }}
              >
                <Icon className="h-5 w-5" style={{ color: iconColor }} />
              </div>
              <div>
                <p
                  className="text-2xl font-bold"
                  style={{ color: "#0F172A", letterSpacing: "-0.03em" }}
                >
                  {value}
                </p>
                <p className="text-xs" style={{ color: "#64748B" }}>
                  {label}
                </p>
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* Student groups */}
      {reports.length === 0 ? (
        <div
          className="bg-white rounded-xl border py-16 text-center"
          style={{
            borderColor: "#E2E8F0",
            boxShadow: "0 1px 3px rgba(15,23,42,0.04)",
          }}
        >
          <FileText
            className="h-12 w-12 mx-auto mb-3"
            style={{ color: "#E2E8F0" }}
          />
          <p className="text-sm font-medium" style={{ color: "#475569" }}>
            No sessions found for this exam.
          </p>
        </div>
      ) : (
        <div className="space-y-3">
          {studentGroups.map((group) => (
            <div
              key={group.studentKey}
              className="bg-white rounded-xl border overflow-hidden"
              style={{
                borderColor: "#E2E8F0",
                boxShadow: "0 1px 3px rgba(15,23,42,0.04)",
              }}
            >
              {/* Group header */}
              <button
                type="button"
                onClick={() => toggleGroup(group.studentKey)}
                className="w-full px-5 py-4 text-left transition-colors"
                style={{
                  borderBottom: "1px solid #F1F5F9",
                  background: "#F8FAFC",
                }}
                onMouseEnter={(e) =>
                  ((e.currentTarget as HTMLElement).style.background =
                    "#F1F5F9")
                }
                onMouseLeave={(e) =>
                  ((e.currentTarget as HTMLElement).style.background =
                    "#F8FAFC")
                }
              >
                <div className="flex items-center justify-between gap-4">
                  <div className="min-w-0 flex items-center gap-3">
                    <span style={{ color: "#64748B" }}>
                      {collapsedGroups[group.studentKey] ? (
                        <ChevronRight className="h-4 w-4" />
                      ) : (
                        <ChevronDown className="h-4 w-4" />
                      )}
                    </span>
                    <div className="min-w-0">
                      <p
                        className="font-semibold text-sm"
                        style={{ color: "#0F172A" }}
                      >
                        {group.studentName}
                      </p>
                      <p
                        className="text-xs truncate"
                        style={{ color: "#64748B" }}
                      >
                        {group.studentEmail}
                      </p>
                    </div>
                  </div>
                  <span
                    className="inline-flex items-center px-2 py-0.5 rounded-md text-xs font-semibold border shrink-0"
                    style={{
                      background: "#F8FAFC",
                      color: "#475569",
                      borderColor: "#E2E8F0",
                    }}
                  >
                    {group.reports.length} segment
                    {group.reports.length !== 1 ? "s" : ""}
                  </span>
                </div>
              </button>

              {/* Group content */}
              {!collapsedGroups[group.studentKey] && (
                <div className="p-4 space-y-3">
                  {group.reports.map((r, idx) => (
                    <div
                      key={r.row_id || `${r.session_id}:${r.report_id || idx}`}
                      className="rounded-xl border p-4"
                      style={
                        r.report_id
                          ? { borderColor: "#E2E8F0", background: "#fff" }
                          : {
                              borderColor: "#E2E8F0",
                              borderStyle: "dashed",
                              background: "#fff",
                              opacity: 0.7,
                            }
                      }
                    >
                      <div className="flex flex-col sm:flex-row sm:items-start gap-4">
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2 flex-wrap mb-1">
                            <p
                              className="font-semibold text-sm"
                              style={{ color: "#0F172A" }}
                            >
                              Segment {group.reports.length - idx}
                            </p>
                            <StatusBadge
                              status={
                                r.terminated
                                  ? "TERMINATED"
                                  : r.session_status === "TERMINATED"
                                    ? "ENDED"
                                    : r.session_status
                              }
                            />
                          </div>
                          <div
                            className="flex items-center gap-4 mt-2 text-xs flex-wrap"
                            style={{ color: "#64748B" }}
                          >
                            <span className="flex items-center gap-1">
                              <Clock className="h-3.5 w-3.5" />
                              {fmtDateTime(r.report_start_time || r.start_time)}
                            </span>
                            {(r.report_end_time || r.end_time) && (
                              <span>
                                → {fmtDateTime(r.report_end_time || r.end_time)}
                              </span>
                            )}
                            {r.duration_s != null && (
                              <span>{fmtDuration(r.duration_s)}</span>
                            )}
                          </div>
                          {r.terminated && r.terminated_reason && (
                            <p
                              className="text-xs mt-1"
                              style={{ color: "#EF4444" }}
                            >
                              Reason: {r.terminated_reason}
                            </p>
                          )}
                        </div>

                        {r.report_id ? (
                          <div className="flex items-center gap-4 shrink-0 flex-wrap">
                            <div className="text-center">
                              <RiskBadge state={r.risk_state} />
                              <p
                                className="text-xs mt-1"
                                style={{ color: "#64748B" }}
                              >
                                Risk
                              </p>
                            </div>
                            <div className="text-center">
                              <p
                                className="text-xl font-bold"
                                style={{ color: "#0F172A" }}
                              >
                                {r.final_score?.toFixed(0) ?? r.risk_score}
                              </p>
                              <p
                                className="text-xs"
                                style={{ color: "#64748B" }}
                              >
                                Score
                              </p>
                            </div>
                            <div className="text-center">
                              <p
                                className="text-xl font-bold"
                                style={{ color: "#EF4444" }}
                              >
                                {r.alert_count ?? 0}
                              </p>
                              <p
                                className="text-xs"
                                style={{ color: "#64748B" }}
                              >
                                Alerts
                              </p>
                            </div>
                            <div className="text-center">
                              <p
                                className="text-xl font-bold"
                                style={{ color: "#F59E0B" }}
                              >
                                {r.warning_count ?? 0}
                              </p>
                              <p
                                className="text-xs"
                                style={{ color: "#64748B" }}
                              >
                                Warnings
                              </p>
                            </div>
                            <button
                              onClick={() => setViewSession(r)}
                              className="flex items-center gap-1.5 px-3 py-2 rounded-lg text-xs font-semibold border transition-all duration-150"
                              style={{
                                borderColor: "#E2E8F0",
                                color: "#22577A",
                                background: "#fff",
                              }}
                              onMouseEnter={(e) => {
                                (
                                  e.currentTarget as HTMLElement
                                ).style.background = "#EFF6FF";
                                (
                                  e.currentTarget as HTMLElement
                                ).style.borderColor = "#BFDBFE";
                              }}
                              onMouseLeave={(e) => {
                                (
                                  e.currentTarget as HTMLElement
                                ).style.background = "#fff";
                                (
                                  e.currentTarget as HTMLElement
                                ).style.borderColor = "#E2E8F0";
                              }}
                            >
                              <Eye className="h-3.5 w-3.5" /> View
                            </button>
                          </div>
                        ) : (
                          <div
                            className="flex items-center gap-2 shrink-0"
                            style={{ color: "#64748B" }}
                          >
                            <AlertTriangle className="h-4 w-4" />
                            <span className="text-sm">No engine report</span>
                          </div>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
