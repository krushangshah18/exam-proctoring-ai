"use client";

import { useEffect, useState, useCallback, useRef } from "react";
import { useParams, useRouter } from "next/navigation";
import {
  ArrowLeft, Loader2, RefreshCw, Users, Activity,
  ShieldAlert, Clock, CheckCircle2, XCircle, AlertTriangle,
  Eye, Timer, MessageSquare, ChevronRight, Bot, Ban
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Textarea } from "@/components/ui/textarea";
import { Input } from "@/components/ui/input";
import { toast } from "sonner";
import api from "@/lib/axios";

// ──────────────────────────────────────────────
// Types
// ──────────────────────────────────────────────

interface RiskInfo {
  score: number;
  fixed: number;
  decaying?: number;
  state: string;
  terminated?: boolean;
}

interface AlertEntry {
  message: string;
  key?: string;
  score_added?: number;
  proof_url?: string;
  proof_type?: string;
  ts: number;
}

interface WarningEntry {
  message: string;
  ts: number;
}

interface SessionCard {
  session_id: string;
  user_id: string;
  student_name: string;
  student_email: string;
  status: string;
  start_time: string | null;
  end_time: string | null;
  risk_score: number;
  violation_count: number;
  last_heartbeat: string | null;
  terminated_reason: string | null;
  terminated_by: string | null;
  time_extension_seconds: number;
  has_pending_appeal: boolean;
}

interface ResumeRequest {
  id: string;
  session_id: string;
  student_name: string;
  student_email: string;
  reason: string;
  status: string;
  review_note: string | null;
  time_extension_minutes: number | null;
  reviewed_at: string | null;
  created_at: string;
  termination_type: "DISCONNECT" | "VIOLATION" | "ADMIN" | "LATE_JOIN";
  suggested_extension_minutes: number | null;
  time_since_disconnect_seconds: number | null;
}

// ──────────────────────────────────────────────
// Status helpers
// ──────────────────────────────────────────────

const STATUS_CONFIG: Record<string, { label: string; classes: string }> = {
  ACTIVE: { label: "Active", classes: "bg-emerald-500/10 text-emerald-700 border-emerald-200" },
  DISCONNECTED: { label: "Disconnected", classes: "bg-amber-500/10 text-amber-700 border-amber-200" },
  TERMINATED: { label: "Terminated", classes: "bg-rose-500/10 text-rose-700 border-rose-200" },
  ENDED: { label: "Submitted", classes: "bg-blue-500/10 text-blue-700 border-blue-200" },
  CREATED: { label: "Pending", classes: "bg-slate-500/10 text-slate-600 border-slate-200" },
};

function StatusBadge({ status }: { status: string }) {
  const cfg = STATUS_CONFIG[status] ?? { label: status, classes: "bg-slate-100 text-slate-600 border-slate-200" };
  return (
    <Badge variant="outline" className={`text-xs font-semibold ${cfg.classes}`}>
      {cfg.label}
    </Badge>
  );
}

function RiskBar({ score }: { score: number }) {
  const color = score >= 70 ? "bg-rose-500" : score >= 40 ? "bg-amber-400" : "bg-emerald-500";
  return (
    <div className="flex items-center gap-2">
      <div className="flex-1 h-2 bg-slate-100 rounded-full overflow-hidden">
        <div className={`h-full ${color} transition-all`} style={{ width: `${Math.min(score, 100)}%` }} />
      </div>
      <span className="text-xs font-mono font-bold text-slate-600 w-8 text-right">{score}</span>
    </div>
  );
}

// SSE helper (fetch-based, supports Authorization header)
function openSSE(url: string, token: string, handlers: Record<string, (d: any) => void>): () => void {
  let cancelled = false;
  const controller = new AbortController();
  (async () => {
    try {
      const res = await fetch(url, { headers: { Authorization: `Bearer ${token}` }, signal: controller.signal });
      if (!res.body) return;
      const reader = res.body.getReader();
      const dec = new TextDecoder();
      let buf = '';
      while (!cancelled) {
        const { done, value } = await reader.read();
        if (done) break;
        buf += dec.decode(value, { stream: true });
        const lines = buf.split('\n');
        buf = lines.pop() ?? '';
        let ev = 'message';
        for (const line of lines) {
          if (line.startsWith('event: ')) ev = line.slice(7).trim();
          else if (line.startsWith('data: ')) {
            try { handlers[ev]?.(JSON.parse(line.slice(6))); } catch {}
            ev = 'message';
          }
        }
      }
    } catch {}
  })();
  return () => { cancelled = true; controller.abort(); };
}

// ──────────────────────────────────────────────
// Live Monitor panel
// ──────────────────────────────────────────────

const RISK_COLORS: Record<string, string> = {
  NORMAL      : '#22c55e',
  WARNING     : '#f59e0b',
  HIGH_RISK   : '#ef4444',
  ADMIN_REVIEW: '#dc2626',
  TERMINATED  : '#7f1d1d',
};

function RiskBadge({ state }: { state: string }) {
  const color = RISK_COLORS[state] ?? '#22c55e';
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

function ExpandableAlertRow({ entry, index }: { entry: AlertEntry; index: number }) {
  const [expanded, setExpanded] = useState(false);
  const base = process.env.NEXT_PUBLIC_ENGINE_URL || 'http://localhost:8001';
  return (
    <div className="rounded-lg overflow-hidden border border-rose-100 bg-rose-50/50">
      <button className="w-full px-3 py-2.5 flex items-start gap-2 text-left" onClick={() => setExpanded(e => !e)}>
        <span className="text-xs font-mono text-slate-400 mt-0.5 shrink-0">{String(index + 1).padStart(2, '0')}</span>
        <div className="flex-1 min-w-0">
          <p className="text-sm font-medium text-rose-700 leading-snug">{entry.message}</p>
          {entry.score_added !== undefined && entry.score_added > 0 && (
            <p className="text-xs text-rose-400 mt-0.5">+{entry.score_added.toFixed(1)} pts · {new Date(entry.ts).toLocaleTimeString()}</p>
          )}
        </div>
        {entry.proof_url && (
          <span className="text-xs text-slate-400 shrink-0">{expanded ? '▲' : '▼'}</span>
        )}
      </button>
      {expanded && entry.proof_url && (
        <div className="px-3 pb-3">
          {entry.proof_type === 'audio' ? (
            <audio controls className="w-full h-8 mt-1">
              <source src={`${base}${entry.proof_url}`} type="audio/wav" />
            </audio>
          ) : (
            // eslint-disable-next-line @next/next/no-img-element
            <img src={`${base}${entry.proof_url}`} alt="Proof" className="w-full rounded-lg object-cover mt-1" style={{ maxHeight: 160 }} />
          )}
        </div>
      )}
    </div>
  );
}

function LiveMonitorPanel({ session, examId, onScoreUpdate, onSessionTerminated }: { session: SessionCard; examId: string; onScoreUpdate: (sessionId: string, score: number) => void; onSessionTerminated: () => void }) {
  const [extMinutes, setExtMinutes] = useState("");
  const [extending, setExtending] = useState(false);
  const [terminating, setTerminating] = useState(false);
  const [frameUrl, setFrameUrl] = useState<string | null>(null);
  const [alerts, setAlerts] = useState<AlertEntry[]>([]);
  const [warnings, setWarnings] = useState<WarningEntry[]>([]);
  const [historyLoaded, setHistoryLoaded] = useState(false);
  const [liveRisk, setLiveRisk] = useState<RiskInfo>({ score: session.risk_score, fixed: 0, state: 'NORMAL' });
  const [alertTab, setAlertTab] = useState<'alerts' | 'warnings'>('alerts');
  const [debugMode, setDebugMode] = useState(false);
  const [togglingDebug, setTogglingDebug] = useState(false);
  const sseCloseRef = useRef<(() => void) | null>(null);
  const frameIntervalRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const prevFrameUrl = useRef<string | null>(null);

  const fetchFrame = useCallback(async () => {
    const token = localStorage.getItem('access_token') || '';
    const base = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';
    try {
      const res = await fetch(
        `${base}/admin/exams/${examId}/sessions/${session.session_id}/live-frame`,
        { headers: { Authorization: `Bearer ${token}` } }
      );
      // 204 = student hasn't connected to engine yet — keep showing placeholder
      if (res.status === 204 || !res.ok) return;
      const blob = await res.blob();
      if (!blob.size) return;
      const url = URL.createObjectURL(blob);
      if (prevFrameUrl.current) URL.revokeObjectURL(prevFrameUrl.current);
      prevFrameUrl.current = url;
      setFrameUrl(url);
    } catch {}
  }, [examId, session.session_id]);

  // Fetch historical alerts/warnings from the engine log on mount
  useEffect(() => {
    api.get(`/admin/exams/${examId}/sessions/${session.session_id}/alert-history`)
      .then((res) => {
        const data = res.data;
        const now = Date.now();
        if (data.alerts?.length) {
          const histAlerts: AlertEntry[] = data.alerts.map((e: any) => ({
            message: e.message,
            proof_url: e.proof_url ?? undefined,
            proof_type: e.proof_type ?? 'image',
            score_added: e.score_added ?? 0,
            ts: now - (e.elapsed_s ?? 0) * 1000,
          }));
          // Prepend any live SSE alerts that arrived before history loaded
          setAlerts(prev => [...prev, ...histAlerts]);
        }
        if (data.warnings?.length) {
          const histWarnings: WarningEntry[] = data.warnings.map((e: any) => ({
            message: e.message,
            ts: now - (e.elapsed_s ?? 0) * 1000,
          }));
          setWarnings(prev => [...prev, ...histWarnings]);
        }
      })
      .catch(() => {/* silently ignore — SSE will still work */})
      .finally(() => setHistoryLoaded(true));
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [examId, session.session_id]);

  useEffect(() => {
    if (session.status !== 'ACTIVE') return;

    fetchFrame();
    frameIntervalRef.current = setInterval(fetchFrame, 2000);

    const token = localStorage.getItem('access_token') || '';
    const base = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';
    sseCloseRef.current = openSSE(
      `${base}/admin/exams/${examId}/sessions/${session.session_id}/live-stream`,
      token,
      {
        message: (d: any) => {
          // Update live risk info on every alert/warning
          if (d?.risk) {
            const risk: RiskInfo = {
              score: d.risk.score ?? 0,
              fixed: d.risk.fixed ?? 0,
              decaying: d.risk.decaying,
              state: d.risk.state ?? 'NORMAL',
              terminated: d.risk.terminated,
            };
            setLiveRisk(risk);
            onScoreUpdate(session.session_id, Math.round(risk.score));
          }
          if (d?.type === 'alert') {
            setAlerts(prev => [{
              message: d.message || d.key || 'Alert',
              key: d.key,
              score_added: d.score_added,
              proof_url: d.proof_url,
              proof_type: d.proof_type,
              ts: Date.now(),
            }, ...prev].slice(0, 100));
          } else if (d?.type === 'warning') {
            setWarnings(prev => [{
              message: d.message || 'Warning',
              ts: Date.now(),
            }, ...prev].slice(0, 100));
          } else if (d?.type === 'session_end') {
            // Engine ended the session — trigger immediate refresh of session list
            onSessionTerminated();
          }
        },
      }
    );

    return () => {
      if (frameIntervalRef.current) clearInterval(frameIntervalRef.current);
      sseCloseRef.current?.();
      if (prevFrameUrl.current) URL.revokeObjectURL(prevFrameUrl.current);
    };
  }, [session.session_id, session.status, fetchFrame]);

  const handleExtend = async () => {
    const m = parseInt(extMinutes);
    if (!m || m <= 0) return toast.error("Enter a valid number of minutes");
    setExtending(true);
    try {
      await api.post(`/admin/exams/${examId}/sessions/${session.session_id}/extend`, { minutes: m });
      toast.success(`Extended by ${m} minute(s)`);
      setExtMinutes("");
    } catch (err: any) {
      toast.error(err.response?.data?.detail || "Failed to extend time");
    } finally {
      setExtending(false);
    }
  };

  const handleDebugToggle = async () => {
    setTogglingDebug(true);
    try {
      await api.post(`/admin/exams/${examId}/sessions/${session.session_id}/debug-mode`, { enabled: !debugMode });
      setDebugMode(d => !d);
      toast.success(`Debug overlay ${!debugMode ? 'enabled' : 'disabled'}`);
    } catch {
      toast.error('Failed to toggle debug mode');
    } finally {
      setTogglingDebug(false);
    }
  };

  const handleTerminate = async () => {
    if (!confirm(`Terminate ${session.student_name}'s session? This cannot be undone.`)) return;
    setTerminating(true);
    try {
      await api.post(`/admin/exams/${examId}/sessions/${session.session_id}/terminate`);
      toast.success(`Session terminated for ${session.student_name}`);
      onSessionTerminated();
    } catch (err: any) {
      toast.error(err.response?.data?.detail || "Failed to terminate session");
    } finally {
      setTerminating(false);
    }
  };

  return (
    <div className="space-y-5">
      {/* Live Camera Feed */}
      <Card className="bg-slate-900 border-slate-800">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm text-slate-300 flex items-center gap-2">
              <Bot className="h-4 w-4 text-indigo-400" /> AI Proctoring Feed
            </CardTitle>
            {session.status === 'ACTIVE' && (
              <Button
                size="sm"
                variant="outline"
                onClick={handleDebugToggle}
                disabled={togglingDebug}
                className={`text-xs h-7 ${debugMode ? 'bg-indigo-900/50 border-indigo-700 text-indigo-300' : 'border-slate-700 text-slate-400'}`}
              >
                {togglingDebug ? <Loader2 className="h-3 w-3 animate-spin" /> : debugMode ? 'Debug: ON' : 'Debug: OFF'}
              </Button>
            )}
          </div>
        </CardHeader>
        <CardContent>
          {frameUrl ? (
            <img
              src={frameUrl}
              alt="Live proctoring frame"
              className="w-full aspect-video rounded-lg object-cover bg-slate-800"
            />
          ) : (
            <div className="aspect-video bg-slate-800 rounded-lg flex flex-col items-center justify-center gap-3 border border-slate-700">
              <Bot className="h-12 w-12 text-slate-600" />
              <p className="text-slate-500 text-sm text-center max-w-xs">
                {session.status === 'ACTIVE' ? 'Waiting for engine frame…' : 'Session not active'}
              </p>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Risk Score Card */}
      <Card>
        <CardHeader className="pb-3 border-b border-slate-100">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold text-slate-700 flex items-center gap-2">
              <Activity className="h-4 w-4 text-indigo-500" /> Risk Assessment
            </CardTitle>
            <RiskBadge state={liveRisk.state} />
          </div>
        </CardHeader>
        <CardContent className="pt-4 space-y-3">
          {/* Big score */}
          <div className="flex items-end gap-3">
            <p className="text-5xl font-bold tabular-nums transition-all"
              style={{ color: RISK_COLORS[liveRisk.state] ?? '#22c55e' }}>
              {Math.round(liveRisk.score)}
            </p>
            <span className="text-xs text-slate-400 mb-1.5">/ 100</span>
          </div>
          {/* Progress bar */}
          <div className="h-2 rounded-full overflow-hidden bg-slate-100">
            <div className="h-2 rounded-full transition-all duration-700"
              style={{ width: `${Math.min(liveRisk.score, 100)}%`, background: RISK_COLORS[liveRisk.state] ?? '#22c55e' }} />
          </div>
          {/* Fixed / Decaying breakdown */}
          <div className="flex gap-4 text-xs text-slate-500">
            <span>Fixed <span className="font-semibold text-slate-700">{Math.round(liveRisk.fixed)}</span></span>
            {liveRisk.decaying !== undefined && (
              <span>Decaying <span className="font-semibold text-slate-700">{Math.round(liveRisk.decaying)}</span></span>
            )}
          </div>
          {liveRisk.terminated && (
            <div className="text-xs font-bold text-center py-1.5 rounded bg-red-50 text-red-600 border border-red-200">
              EXAM TERMINATED BY ENGINE
            </div>
          )}
          {/* Stats row */}
          <div className="grid grid-cols-3 gap-3 pt-1 border-t border-slate-100">
            <div className="text-center">
              <p className="text-lg font-bold text-rose-500">{alerts.length}</p>
              <p className="text-xs text-slate-400">Alerts</p>
            </div>
            <div className="text-center">
              <p className="text-lg font-bold text-amber-500">{warnings.length}</p>
              <p className="text-xs text-slate-400">Warnings</p>
            </div>
            <div className="text-center">
              <p className="text-lg font-bold text-slate-700">
                {session.time_extension_seconds > 0 ? `+${Math.round(session.time_extension_seconds / 60)}m` : '–'}
              </p>
              <p className="text-xs text-slate-400">Time Ext.</p>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Alert / Warning log with tabs */}
      <Card>
        <CardHeader className="pb-0 border-b border-slate-100">
          <div className="flex gap-1">
            <button
              onClick={() => setAlertTab('alerts')}
              className={`px-4 py-2.5 text-sm font-semibold border-b-2 transition-colors -mb-px ${alertTab === 'alerts' ? 'border-rose-500 text-rose-600' : 'border-transparent text-slate-400 hover:text-slate-600'}`}
            >
              Alerts
              {alerts.length > 0 && (
                <span className="ml-1.5 text-xs px-1.5 py-0.5 rounded-full bg-rose-100 text-rose-600">{alerts.length}</span>
              )}
            </button>
            <button
              onClick={() => setAlertTab('warnings')}
              className={`px-4 py-2.5 text-sm font-semibold border-b-2 transition-colors -mb-px ${alertTab === 'warnings' ? 'border-amber-500 text-amber-600' : 'border-transparent text-slate-400 hover:text-slate-600'}`}
            >
              Warnings
              {warnings.length > 0 && (
                <span className="ml-1.5 text-xs px-1.5 py-0.5 rounded-full bg-amber-100 text-amber-600">{warnings.length}</span>
              )}
            </button>
          </div>
        </CardHeader>
        <CardContent className="pt-3">
          <div className="space-y-2 max-h-56 overflow-y-auto">
            {!historyLoaded ? (
              <div className="flex items-center justify-center gap-2 py-6 text-slate-400 text-sm">
                <Loader2 className="h-4 w-4 animate-spin" /> Loading history…
              </div>
            ) : alertTab === 'alerts' ? (
              alerts.length === 0
                ? <p className="text-sm text-slate-400 text-center py-6">No alerts yet</p>
                : alerts.map((a, i) => <ExpandableAlertRow key={i} entry={a} index={alerts.length - 1 - i} />)
            ) : (
              warnings.length === 0
                ? <p className="text-sm text-slate-400 text-center py-6">No warnings yet</p>
                : warnings.map((w, i) => (
                  <div key={i} className="flex items-start gap-2 px-3 py-2 bg-amber-50/50 rounded-lg border border-amber-100 text-xs">
                    <AlertTriangle className="h-3.5 w-3.5 text-amber-500 shrink-0 mt-0.5" />
                    <div>
                      <p className="text-amber-700">{w.message}</p>
                      <p className="text-amber-400 mt-0.5">{new Date(w.ts).toLocaleTimeString()}</p>
                    </div>
                  </div>
                ))
            )}
          </div>
        </CardContent>
      </Card>

      {/* Manual time extension */}
      {session.status === "ACTIVE" && (
        <Card>
          <CardHeader className="pb-3 border-b border-slate-100">
            <CardTitle className="text-sm font-semibold text-slate-700 flex items-center gap-2">
              <Timer className="h-4 w-4 text-emerald-500" /> Grant Extra Time
            </CardTitle>
          </CardHeader>
          <CardContent className="pt-4 flex gap-3">
            <Input
              type="number"
              min={1}
              placeholder="Minutes"
              value={extMinutes}
              onChange={(e) => setExtMinutes(e.target.value)}
              className="w-32"
            />
            <Button onClick={handleExtend} disabled={extending} className="bg-emerald-600 hover:bg-emerald-700">
              {extending ? <Loader2 className="h-4 w-4 animate-spin" /> : "Grant Extension"}
            </Button>
          </CardContent>
        </Card>
      )}

      {/* Admin termination — available when session is ACTIVE and risk score >= 100 */}
      {session.status === "ACTIVE" && (
        <Card className={`border-2 transition-colors ${liveRisk.score >= 100 ? "border-rose-400 bg-rose-50/30" : "border-slate-200"}`}>
          <CardHeader className="pb-3 border-b border-slate-100">
            <div className="flex items-center justify-between">
              <CardTitle className="text-sm font-semibold text-rose-700 flex items-center gap-2">
                <Ban className="h-4 w-4" /> Terminate Session
              </CardTitle>
              {liveRisk.score < 100 && (
                <span className="text-xs text-slate-400">Available at risk ≥ 100</span>
              )}
            </div>
          </CardHeader>
          <CardContent className="pt-4 space-y-3">
            {liveRisk.score >= 100 ? (
              <>
                <p className="text-sm text-rose-700">
                  Risk score has reached <strong>{Math.round(liveRisk.score)}</strong>. You may terminate
                  this student's session. They will be notified and can submit an appeal.
                </p>
                <Button
                  onClick={handleTerminate}
                  disabled={terminating}
                  className="w-full bg-rose-600 hover:bg-rose-700 text-white font-bold"
                >
                  {terminating
                    ? <Loader2 className="h-4 w-4 animate-spin mr-2" />
                    : <Ban className="h-4 w-4 mr-2" />}
                  Terminate {session.student_name}'s Session
                </Button>
              </>
            ) : (
              <p className="text-sm text-slate-400">
                The terminate button unlocks when the student's risk score reaches 100.
                Current score: <strong>{Math.round(liveRisk.score)}</strong>.
              </p>
            )}
          </CardContent>
        </Card>
      )}
    </div>
  );
}

// ──────────────────────────────────────────────
// Appeals panel
// ──────────────────────────────────────────────

function AppealsPanel({ examId, onUpdate }: { examId: string; onUpdate: () => void }) {
  const [appeals, setAppeals] = useState<ResumeRequest[]>([]);
  const [loading, setLoading] = useState(true);
  const [reviewing, setReviewing] = useState<string | null>(null);
  const [notes, setNotes] = useState<Record<string, string>>({});
  const [extMins, setExtMins] = useState<Record<string, string>>({});

  const fetchAppeals = useCallback(async () => {
    try {
      const res = await api.get(`/admin/exams/${examId}/resume-requests`);
      const data: ResumeRequest[] = res.data;
      setAppeals(data);
      // Pre-fill suggested extension for DISCONNECT appeals that haven't been manually edited
      setExtMins((prev) => {
        const next = { ...prev };
        for (const rr of data) {
          if (rr.status === "PENDING" && rr.termination_type === "DISCONNECT" && rr.suggested_extension_minutes && !(rr.id in prev)) {
            next[rr.id] = String(rr.suggested_extension_minutes);
          }
        }
        return next;
      });
    } catch {
      toast.error("Failed to load appeals");
    } finally {
      setLoading(false);
    }
  }, [examId]);

  useEffect(() => {
    fetchAppeals();
    const id = setInterval(fetchAppeals, 10000);
    return () => clearInterval(id);
  }, [fetchAppeals]);

  const handleReview = async (rrId: string, decision: "APPROVED" | "DENIED") => {
    setReviewing(rrId);
    try {
      await api.post(`/admin/exams/${examId}/resume-requests/${rrId}/review`, {
        decision,
        review_note: notes[rrId] || null,
        time_extension_minutes: extMins[rrId] ? parseInt(extMins[rrId]) : null,
      });
      toast.success(`Appeal ${decision.toLowerCase()}`);
      fetchAppeals();
      onUpdate();
    } catch (err: any) {
      toast.error(err.response?.data?.detail || "Failed to review appeal");
    } finally {
      setReviewing(null);
    }
  };

  const pending = appeals.filter((a) => a.status === "PENDING");
  const reviewed = appeals.filter((a) => a.status !== "PENDING");

  if (loading) {
    return (
      <div className="flex items-center justify-center p-12">
        <Loader2 className="h-6 w-6 animate-spin text-slate-300" />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {pending.length === 0 && (
        <div className="text-center py-12">
          <CheckCircle2 className="h-10 w-10 text-emerald-300 mx-auto mb-3" />
          <p className="text-slate-500">No pending appeals</p>
        </div>
      )}

      {pending.map((rr) => {
        const isDisconnect = rr.termination_type === "DISCONNECT";
        const typeBadgeClass = isDisconnect
          ? "bg-blue-50 text-blue-700 border-blue-200"
          : rr.termination_type === "ADMIN"
          ? "bg-rose-50 text-rose-700 border-rose-200"
          : "bg-purple-50 text-purple-700 border-purple-200";
        const typeLabel = isDisconnect ? "Disconnect" : rr.termination_type === "ADMIN" ? "Admin Terminated" : "Violation";

        return (
        <Card key={rr.id} className="border-amber-200 bg-amber-50/30">
          <CardHeader className="pb-3 border-b border-amber-100">
            <div className="flex items-start justify-between">
              <div>
                <CardTitle className="text-base font-semibold text-slate-900">{rr.student_name}</CardTitle>
                <CardDescription>{rr.student_email}</CardDescription>
              </div>
              <div className="flex items-center gap-2">
                <Badge variant="outline" className={`text-xs ${typeBadgeClass}`}>
                  {typeLabel}
                </Badge>
                <Badge variant="outline" className="bg-amber-100 text-amber-700 border-amber-300 text-xs">
                  Pending Review
                </Badge>
              </div>
            </div>
          </CardHeader>
          <CardContent className="pt-4 space-y-4">
            <div className="bg-white p-3 rounded-lg border border-slate-200">
              <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1">Student's Reason</p>
              <p className="text-sm text-slate-700 leading-relaxed">"{rr.reason}"</p>
            </div>

            {isDisconnect && rr.time_since_disconnect_seconds != null && (
              <div className="flex items-center gap-2 p-2.5 bg-blue-50 border border-blue-200 rounded-lg text-xs text-blue-700">
                <Clock className="h-3.5 w-3.5 shrink-0" />
                Appeal filed <strong>
                  {rr.time_since_disconnect_seconds < 60
                    ? `${rr.time_since_disconnect_seconds}s`
                    : `${Math.floor(rr.time_since_disconnect_seconds / 60)}m ${rr.time_since_disconnect_seconds % 60}s`}
                </strong> after disconnection
              </div>
            )}

            {!isDisconnect && (
              <div className="flex items-start gap-2 p-2.5 bg-slate-50 border border-slate-200 rounded-lg">
                <AlertTriangle className="h-4 w-4 text-slate-400 mt-0.5 shrink-0" />
                <p className="text-xs text-slate-500">
                  Timer continued running during this appeal. No extra time is typically granted for {rr.termination_type === "ADMIN" ? "admin-terminated" : "violation"} sessions, but you may still add minutes if appropriate.
                </p>
              </div>
            )}

            <div className="grid sm:grid-cols-2 gap-3">
              <div>
                <label className="text-xs font-semibold text-slate-500 block mb-1">Review Note (optional)</label>
                <Textarea
                  placeholder="Add a note for the student…"
                  rows={2}
                  value={notes[rr.id] ?? ""}
                  onChange={(e) => setNotes((n) => ({ ...n, [rr.id]: e.target.value }))}
                  className="text-sm"
                />
              </div>
              <div>
                <label className="text-xs font-semibold text-slate-500 block mb-1">
                  {isDisconnect ? "Extra Minutes if Approved" : "Extra Minutes (optional)"}
                </label>
                <Input
                  type="number"
                  min={1}
                  placeholder="e.g. 10"
                  value={extMins[rr.id] ?? ""}
                  onChange={(e) => setExtMins((m) => ({ ...m, [rr.id]: e.target.value }))}
                />
                {isDisconnect && rr.suggested_extension_minutes && (
                  <p className="text-xs text-slate-400 mt-1">
                    Suggested: {rr.suggested_extension_minutes} min (based on time disconnected)
                  </p>
                )}
              </div>
            </div>

            <div className="flex gap-3 pt-1">
              <Button
                onClick={() => handleReview(rr.id, "APPROVED")}
                disabled={reviewing === rr.id}
                className="flex-1 bg-emerald-600 hover:bg-emerald-700"
              >
                {reviewing === rr.id ? <Loader2 className="h-4 w-4 animate-spin" /> : <CheckCircle2 className="h-4 w-4 mr-2" />}
                Approve
              </Button>
              <Button
                onClick={() => handleReview(rr.id, "DENIED")}
                disabled={reviewing === rr.id}
                variant="outline"
                className="flex-1 border-rose-200 text-rose-700 hover:bg-rose-50"
              >
                <XCircle className="h-4 w-4 mr-2" /> Deny
              </Button>
            </div>
          </CardContent>
        </Card>
        );
      })}

      {reviewed.length > 0 && (
        <div>
          <p className="text-sm font-semibold text-slate-400 mb-3 uppercase tracking-wider">Reviewed</p>
          <div className="space-y-3">
            {reviewed.slice(0, 10).map((rr) => (
              <div key={rr.id} className="flex items-center justify-between p-3 bg-white rounded-lg border border-slate-200">
                <div>
                  <p className="text-sm font-medium text-slate-900">{rr.student_name}</p>
                  <p className="text-xs text-slate-400 line-clamp-1 mt-0.5">"{rr.reason}"</p>
                </div>
                <Badge
                  variant="outline"
                  className={rr.status === "APPROVED" ? "bg-emerald-50 text-emerald-700 border-emerald-200" : "bg-rose-50 text-rose-700 border-rose-200"}
                >
                  {rr.status === "APPROVED" ? <CheckCircle2 className="h-3 w-3 mr-1" /> : <XCircle className="h-3 w-3 mr-1" />}
                  {rr.status}
                </Badge>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

// ──────────────────────────────────────────────
// Main Page
// ──────────────────────────────────────────────

export default function MonitoringDashboard() {
  const params = useParams();
  const router = useRouter();
  const examId = params.id as string;

  const [sessions, setSessions] = useState<SessionCard[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedSession, setSelectedSession] = useState<SessionCard | null>(null);
  const [activeTab, setActiveTab] = useState<"sessions" | "appeals">("sessions");
  const [bulkMinutes, setBulkMinutes] = useState("");
  const [bulkExtending, setBulkExtending] = useState(false);

  // Keep selectedSession in sync with latest session data from polls
  useEffect(() => {
    if (!selectedSession) return;
    const latest = sessions.find(s => s.session_id === selectedSession.session_id);
    if (latest) setSelectedSession(latest);
  }, [sessions]);

  const handleScoreUpdate = useCallback((sessionId: string, score: number) => {
    setSessions(prev => prev.map(s => s.session_id === sessionId ? { ...s, risk_score: score } : s));
  }, []);

  const fetchSessions = useCallback(async () => {
    try {
      const res = await api.get(`/admin/exams/${examId}/sessions`);
      setSessions(res.data);
    } catch {
      // silent
    } finally {
      setLoading(false);
    }
  }, [examId]);

  // Poll faster when there are active sessions (5s), slower otherwise (20s)
  const hasActive = sessions.some(s => s.status === 'ACTIVE' || s.status === 'DISCONNECTED');
  useEffect(() => {
    fetchSessions();
    const interval = hasActive ? 5000 : 20000;
    const id = setInterval(fetchSessions, interval);
    return () => clearInterval(id);
  }, [fetchSessions, hasActive]);

  const handleBulkExtend = async () => {
    const m = parseInt(bulkMinutes);
    if (!m || m <= 0) return toast.error("Enter valid minutes");
    setBulkExtending(true);
    try {
      const res = await api.post(`/admin/exams/${examId}/extend-time`, { minutes: m });
      toast.success(res.data.message);
      setBulkMinutes("");
      fetchSessions();
    } catch (err: any) {
      toast.error(err.response?.data?.detail || "Failed to extend time");
    } finally {
      setBulkExtending(false);
    }
  };

  const activeSessions = sessions.filter((s) => s.status === "ACTIVE");
  const pendingAppeals = sessions.filter((s) => s.has_pending_appeal).length;

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
          <h1 className="text-2xl font-bold text-slate-900">Live Monitoring</h1>
          <p className="text-sm text-slate-500 mt-0.5">Real-time session overview and appeal management</p>
        </div>
        <Button
          variant="outline"
          size="sm"
          onClick={fetchSessions}
          className="gap-2 border-slate-200"
        >
          <RefreshCw className="h-4 w-4" /> Refresh
        </Button>
      </div>

      {/* Stats row */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        <Card className="shadow-none border-slate-200">
          <CardContent className="pt-5 pb-4">
            <div className="flex items-center gap-3">
              <div className="bg-emerald-100 p-2 rounded-lg"><Users className="h-5 w-5 text-emerald-600" /></div>
              <div>
                <p className="text-2xl font-bold text-slate-900">{activeSessions.length}</p>
                <p className="text-xs text-slate-500">Active Students</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card className="shadow-none border-slate-200">
          <CardContent className="pt-5 pb-4">
            <div className="flex items-center gap-3">
              <div className="bg-blue-100 p-2 rounded-lg"><CheckCircle2 className="h-5 w-5 text-blue-600" /></div>
              <div>
                <p className="text-2xl font-bold text-slate-900">{sessions.filter((s) => s.status === "ENDED").length}</p>
                <p className="text-xs text-slate-500">Submitted</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card className="shadow-none border-slate-200">
          <CardContent className="pt-5 pb-4">
            <div className="flex items-center gap-3">
              <div className={`p-2 rounded-lg ${pendingAppeals > 0 ? "bg-amber-100" : "bg-slate-100"}`}>
                <MessageSquare className={`h-5 w-5 ${pendingAppeals > 0 ? "text-amber-600" : "text-slate-400"}`} />
              </div>
              <div>
                <p className="text-2xl font-bold text-slate-900">{pendingAppeals}</p>
                <p className="text-xs text-slate-500">Pending Appeals</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card className="shadow-none border-slate-200">
          <CardContent className="pt-5 pb-4">
            <div className="flex items-center gap-3">
              <div className="bg-rose-100 p-2 rounded-lg"><ShieldAlert className="h-5 w-5 text-rose-600" /></div>
              <div>
                <p className="text-2xl font-bold text-slate-900">{sessions.filter((s) => s.status === "TERMINATED").length}</p>
                <p className="text-xs text-slate-500">Terminated</p>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Bulk time extension */}
      {activeSessions.length > 0 && (
        <Card className="bg-emerald-50 border-emerald-100 shadow-none">
          <CardContent className="pt-4 pb-4 flex flex-wrap items-center gap-4">
            <div className="flex items-center gap-2 text-sm font-semibold text-emerald-800">
              <Timer className="h-4 w-4" />
              Bulk Time Extension for All Active Students
            </div>
            <div className="flex items-center gap-2 ml-auto">
              <Input
                type="number"
                min={1}
                placeholder="Minutes"
                value={bulkMinutes}
                onChange={(e) => setBulkMinutes(e.target.value)}
                className="w-28 h-8 text-sm bg-white"
              />
              <Button
                size="sm"
                onClick={handleBulkExtend}
                disabled={bulkExtending}
                className="bg-emerald-600 hover:bg-emerald-700"
              >
                {bulkExtending ? <Loader2 className="h-4 w-4 animate-spin" /> : "Grant to All"}
              </Button>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Tab nav */}
      <div className="flex gap-1 p-1 bg-slate-100 rounded-lg w-fit">
        <button
          onClick={() => setActiveTab("sessions")}
          className={`px-5 py-2 rounded-md text-sm font-medium transition-all ${activeTab === "sessions" ? "bg-white shadow-sm text-slate-900" : "text-slate-500 hover:text-slate-700"}`}
        >
          <div className="flex items-center gap-2">
            <Users className="h-4 w-4" /> Sessions
            <Badge className="bg-slate-200 text-slate-600 ml-1 text-xs">{sessions.length}</Badge>
          </div>
        </button>
        <button
          onClick={() => setActiveTab("appeals")}
          className={`px-5 py-2 rounded-md text-sm font-medium transition-all ${activeTab === "appeals" ? "bg-white shadow-sm text-slate-900" : "text-slate-500 hover:text-slate-700"}`}
        >
          <div className="flex items-center gap-2">
            <MessageSquare className="h-4 w-4" /> Appeals
            {pendingAppeals > 0 && (
              <Badge className="bg-amber-500 text-white ml-1 text-xs">{pendingAppeals}</Badge>
            )}
          </div>
        </button>
      </div>

      {/* Content */}
      {activeTab === "sessions" ? (
        <div className="grid lg:grid-cols-2 gap-6">
          {/* Student cards */}
          <div className="space-y-3">
            {sessions.length === 0 ? (
              <div className="text-center py-16">
                <Users className="h-12 w-12 text-slate-200 mx-auto mb-3" />
                <p className="text-slate-400">No student sessions yet</p>
              </div>
            ) : (
              sessions.map((sess) => (
                <Card
                  key={sess.session_id}
                  className={`cursor-pointer transition-all hover:shadow-md border-2 ${selectedSession?.session_id === sess.session_id ? "border-indigo-400 shadow-md" : "border-transparent shadow-sm"}`}
                  onClick={() => setSelectedSession(sess.session_id === selectedSession?.session_id ? null : sess)}
                >
                  <CardContent className="p-4 space-y-3">
                    <div className="flex items-start justify-between gap-3">
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2">
                          <p className="font-semibold text-slate-900 truncate">{sess.student_name}</p>
                          {sess.has_pending_appeal && (
                            <Badge variant="outline" className="bg-amber-100 text-amber-700 border-amber-200 text-[10px] shrink-0">
                              Appeal Pending
                            </Badge>
                          )}
                        </div>
                        <p className="text-xs text-slate-400 truncate">{sess.student_email}</p>
                      </div>
                      <div className="flex items-center gap-2 shrink-0">
                        <StatusBadge status={sess.status} />
                        <ChevronRight
                          className={`h-4 w-4 text-slate-300 transition-transform ${selectedSession?.session_id === sess.session_id ? "rotate-90" : ""}`}
                        />
                      </div>
                    </div>

                    <RiskBar score={sess.risk_score} />

                    <div className="flex items-center gap-4 text-xs text-slate-500">
                      <span className="flex items-center gap-1">
                        <ShieldAlert className="h-3 w-3 text-rose-400" /> {sess.violation_count} violations
                      </span>
                      {sess.last_heartbeat && (
                        <span className="flex items-center gap-1">
                          <Activity className="h-3 w-3 text-emerald-400" />
                          Last seen {new Date(sess.last_heartbeat).toLocaleTimeString()}
                        </span>
                      )}
                      {sess.time_extension_seconds > 0 && (
                        <span className="flex items-center gap-1">
                          <Timer className="h-3 w-3 text-indigo-400" />
                          +{Math.round(sess.time_extension_seconds / 60)}m ext
                        </span>
                      )}
                    </div>
                  </CardContent>
                </Card>
              ))
            )}
          </div>

          {/* Live Monitor panel */}
          <div>
            {selectedSession ? (
              <div>
                <div className="flex items-center justify-between mb-4">
                  <div>
                    <h2 className="text-lg font-semibold text-slate-900 flex items-center gap-2">
                      <Eye className="h-5 w-5 text-indigo-500" /> {selectedSession.student_name}
                    </h2>
                    <p className="text-sm text-slate-400">{selectedSession.student_email}</p>
                  </div>
                  <StatusBadge status={selectedSession.status} />
                </div>
                <LiveMonitorPanel
                  session={selectedSession}
                  examId={examId}
                  onScoreUpdate={handleScoreUpdate}
                  onSessionTerminated={() => { fetchSessions(); setSelectedSession(null); }}
                />
              </div>
            ) : (
              <div className="flex flex-col items-center justify-center h-64 border-2 border-dashed border-slate-200 rounded-xl">
                <Eye className="h-10 w-10 text-slate-200 mb-3" />
                <p className="text-slate-400 text-sm">Select a student to open the live monitor</p>
              </div>
            )}
          </div>
        </div>
      ) : (
        <AppealsPanel examId={examId} onUpdate={fetchSessions} />
      )}
    </div>
  );
}
