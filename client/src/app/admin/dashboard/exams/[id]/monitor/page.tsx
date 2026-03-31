"use client";

import { useEffect, useState, useCallback, useRef } from "react";
import { useParams, useRouter, useSearchParams } from "next/navigation";
import {
  ArrowLeft, Loader2, RefreshCw, Users, Activity,
  ShieldAlert, Clock, CheckCircle2, XCircle, AlertTriangle,
  Eye, Timer, MessageSquare, ChevronRight, Bot, Ban, Search
} from "lucide-react";
import { Textarea } from "@/components/ui/textarea";
import { toast } from "sonner";
import api from "@/lib/axios";
import { fmtTimeIST } from "@/lib/fmt-date";

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
  last_heartbeat: string | null;
  terminated_reason: string | null;
  terminated_by: string | null;
  time_extension_seconds: number;
  has_pending_appeal: boolean;
  proctor_engine_url?: string | null;
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
  termination_type: "DISCONNECT" | "SYSTEM" | "ADMIN" | "LATE_JOIN";
  suggested_extension_minutes: number | null;
  time_since_disconnect_seconds: number | null;
}

// ──────────────────────────────────────────────
// Status helpers
// ──────────────────────────────────────────────

const STATUS_CONFIG: Record<string, { label: string; bg: string; color: string; border: string }> = {
  ACTIVE:       { label: "Active",       bg: '#ECFDF5', color: '#15803D', border: '#BBF7D0' },
  DISCONNECTED: { label: "Disconnected", bg: '#FFFBEB', color: '#B45309', border: '#FDE68A' },
  TERMINATED:   { label: "Terminated",   bg: '#FFF1F2', color: '#BE123C', border: '#FECDD3' },
  ENDED:        { label: "Submitted",    bg: '#EFF6FF', color: '#1D4ED8', border: '#BFDBFE' },
  CREATED:      { label: "Pending",      bg: '#F8FAFC', color: '#475569', border: '#E2E8F0' },
};

function StatusBadge({ status }: { status: string }) {
  const cfg = STATUS_CONFIG[status] ?? { label: status, bg: '#F8FAFC', color: '#475569', border: '#E2E8F0' };
  return (
    <span className="inline-flex items-center px-2 py-0.5 rounded-md text-xs font-semibold border"
      style={{ background: cfg.bg, color: cfg.color, borderColor: cfg.border }}>
      {cfg.label}
    </span>
  );
}

function RiskBar({ score }: { score: number }) {
  const color = score >= 70 ? "#ef4444" : score >= 40 ? "#f59e0b" : "#22c55e";
  return (
    <div className="flex items-center gap-2">
      <div className="flex-1 h-2 rounded-full overflow-hidden" style={{ background: '#F1F5F9' }}>
        <div className="h-full rounded-full transition-all" style={{ width: `${Math.min(score, 100)}%`, background: color }} />
      </div>
      <span className="text-xs font-mono font-bold w-8 text-right" style={{ color: '#475569' }}>{score}</span>
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
  NORMAL:       '#22c55e',
  WARNING:      '#f59e0b',
  HIGH_RISK:    '#ef4444',
  ADMIN_REVIEW: '#dc2626',
  TERMINATED:   '#7f1d1d',
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

function ExpandableAlertRow({ entry, index, engineUrl }: { entry: AlertEntry; index: number; engineUrl?: string | null }) {
  const [expanded, setExpanded] = useState(false);
  const [proofObjectUrl, setProofObjectUrl] = useState<string | null>(null);

  useEffect(() => {
    let active = true;
    const loadProof = async () => {
      if (!expanded || !entry.proof_url || !engineUrl) return;
      const rawPath = entry.proof_url.startsWith('http')
        ? new URL(entry.proof_url).pathname
        : entry.proof_url;
      const base = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';
      const proxyUrl = `${base}/admin/proxy-proof?engine_url=${encodeURIComponent(engineUrl)}&path=${encodeURIComponent(rawPath)}`;
      try {
        const res = await api.get(proxyUrl, { responseType: 'blob' });
        if (!active) return;
        const url = URL.createObjectURL(res.data);
        setProofObjectUrl((prev) => { if (prev) URL.revokeObjectURL(prev); return url; });
      } catch {
        if (active) { setProofObjectUrl(null); toast.error('Failed to load proof'); }
      }
    };
    void loadProof();
    return () => {
      active = false;
      setProofObjectUrl((prev) => { if (prev) URL.revokeObjectURL(prev); return null; });
    };
  }, [expanded, entry.proof_url, engineUrl]);

  return (
    <div className="rounded-lg overflow-hidden border" style={{ borderColor: '#FECDD3', background: 'rgba(254,242,242,0.5)' }}>
      <button className="w-full px-3 py-2.5 flex items-start gap-2 text-left" onClick={() => setExpanded(e => !e)}>
        <span className="text-xs font-mono mt-0.5 shrink-0" style={{ color: '#64748B' }}>{String(index + 1).padStart(2, '0')}</span>
        <div className="flex-1 min-w-0">
          <p className="text-sm font-medium leading-snug" style={{ color: '#BE123C' }}>{entry.message}</p>
          {entry.score_added !== undefined && entry.score_added > 0 && (
            <p className="text-xs mt-0.5" style={{ color: '#FDA4AF' }}>+{entry.score_added.toFixed(1)} pts · {fmtTimeIST(new Date(entry.ts).toISOString())}</p>
          )}
        </div>
        {entry.proof_url && (
          <span className="text-xs shrink-0" style={{ color: '#64748B' }}>{expanded ? '▲' : '▼'}</span>
        )}
      </button>
      {expanded && entry.proof_url && (
        <div className="px-3 pb-3">
          {!proofObjectUrl ? (
            <div className="flex items-center gap-2 py-3 text-xs" style={{ color: '#64748B' }}>
              <Loader2 className="h-4 w-4 animate-spin" /> Loading proof...
            </div>
          ) : entry.proof_type === 'audio' ? (
            <audio controls className="w-full h-8 mt-1">
              <source src={proofObjectUrl} type="audio/wav" />
            </audio>
          ) : (
            // eslint-disable-next-line @next/next/no-img-element
            <img src={proofObjectUrl} alt="Proof" className="w-full rounded-lg object-contain mt-1" style={{ maxHeight: 320, background: '#0F172A' }} />
          )}
        </div>
      )}
    </div>
  );
}

function LiveMonitorPanel({ session, examId, examMode, onScoreUpdate, onSessionTerminated }: {
  session: SessionCard;
  examId: string;
  examMode: string;
  onScoreUpdate: (sessionId: string, score: number) => void;
  onSessionTerminated: () => void;
}) {
  const [extMinutes, setExtMinutes] = useState("");
  const [extending, setExtending] = useState(false);
  const [terminating, setTerminating] = useState(false);
  const [frameUrl, setFrameUrl] = useState<string | null>(null);
  const [alerts, setAlerts] = useState<AlertEntry[]>([]);
  const [warnings, setWarnings] = useState<WarningEntry[]>([]);
  const [historyLoaded, setHistoryLoaded] = useState(false);
  const [liveRisk, setLiveRisk] = useState<RiskInfo>(() => {
    const s = session.risk_score;
    const state = s >= 70 ? 'HIGH_RISK' : s >= 40 ? 'WARNING' : 'NORMAL';
    return { score: s, fixed: s, state };
  });
  const [alertTab, setAlertTab] = useState<'alerts' | 'warnings'>('alerts');
  const [debugMode, setDebugMode] = useState(false);
  const [togglingDebug, setTogglingDebug] = useState(false);
  const sseCloseRef = useRef<(() => void) | null>(null);
  const frameTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const frameAbortRef = useRef<AbortController | null>(null);
  const prevFrameUrl = useRef<string | null>(null);
  const frameFetchingRef = useRef(false);

  const fetchFrame = useCallback(async () => {
    if (frameFetchingRef.current) return;
    frameFetchingRef.current = true;
    frameAbortRef.current = new AbortController();
    const token = localStorage.getItem('access_token') || '';
    const base = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';
    try {
      const res = await fetch(
        `${base}/admin/exams/${examId}/sessions/${session.session_id}/live-frame`,
        { headers: { Authorization: `Bearer ${token}` }, signal: frameAbortRef.current.signal }
      );
      if (res.status === 204 || !res.ok) return;
      const blob = await res.blob();
      if (!blob.size) return;
      const url = URL.createObjectURL(blob);
      const old = prevFrameUrl.current;
      prevFrameUrl.current = url;
      setFrameUrl(url);
      if (old) URL.revokeObjectURL(old);
    } catch {}
    finally { frameFetchingRef.current = false; }
  }, [examId, session.session_id]);

  useEffect(() => {
    api.get(`/admin/exams/${examId}/sessions/${session.session_id}/alert-history`)
      .then((res) => {
        const data = res.data;
        const now = Date.now();
        if (data.alerts?.length) {
          const histAlerts: AlertEntry[] = data.alerts.map((e: any) => ({
            message: e.message, proof_url: e.proof_url ?? undefined,
            proof_type: e.proof_type ?? 'image', score_added: e.score_added ?? 0,
            ts: now - (e.elapsed_s ?? 0) * 1000,
          }));
          setAlerts(histAlerts);
        }
        if (data.warnings?.length) {
          const histWarnings: WarningEntry[] = data.warnings.map((e: any) => ({
            message: e.message, ts: now - (e.elapsed_s ?? 0) * 1000,
          }));
          setWarnings(histWarnings);
        }
      })
      .catch(() => {})
      .finally(() => setHistoryLoaded(true));
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [examId, session.session_id]);

  useEffect(() => {
    if (session.status !== 'ACTIVE') return;

    let stopped = false;
    const loop = async () => {
      while (!stopped) {
        await fetchFrame();
        await new Promise(r => { frameTimerRef.current = setTimeout(r, 800); });
      }
    };
    loop();

    const token = localStorage.getItem('access_token') || '';
    const base = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';
    sseCloseRef.current = openSSE(
      `${base}/admin/exams/${examId}/sessions/${session.session_id}/live-stream`,
      token,
      {
        message: (d: any) => {
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
              message: d.message || d.key || 'Alert', key: d.key,
              score_added: d.score_added, proof_url: d.proof_url,
              proof_type: d.proof_type, ts: Date.now(),
            }, ...prev].slice(0, 100));
          } else if (d?.type === 'warning') {
            setWarnings(prev => [{ message: d.message || 'Warning', ts: Date.now() }, ...prev].slice(0, 100));
          } else if (d?.type === 'session_end') {
            onSessionTerminated();
          }
        },
      }
    );
    return () => {
      stopped = true;
      if (frameTimerRef.current) clearTimeout(frameTimerRef.current);
      frameAbortRef.current?.abort();
      sseCloseRef.current?.();
      if (prevFrameUrl.current) { URL.revokeObjectURL(prevFrameUrl.current); prevFrameUrl.current = null; }
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
    } finally { setExtending(false); }
  };

  const handleDebugToggle = async () => {
    setTogglingDebug(true);
    try {
      await api.post(`/admin/exams/${examId}/sessions/${session.session_id}/debug-mode`, { enabled: !debugMode });
      setDebugMode(d => !d);
      toast.success(`Debug overlay ${!debugMode ? 'enabled' : 'disabled'}`);
    } catch { toast.error('Failed to toggle debug mode'); }
    finally { setTogglingDebug(false); }
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
    } finally { setTerminating(false); }
  };

  return (
    <div className="space-y-4">
      {/* Live Camera Feed */}
      <div className="rounded-xl overflow-hidden" style={{ background: '#0F172A', border: '1px solid #1E293B' }}>
        <div className="flex items-center justify-between px-4 py-3" style={{ borderBottom: '1px solid #1E293B' }}>
          <div className="flex items-center gap-2">
            <Bot className="h-4 w-4" style={{ color: '#818CF8' }} />
            <span className="text-sm font-medium" style={{ color: '#475569' }}>AI Proctoring Feed</span>
            {session.status === 'ACTIVE' && (
              <span className="flex items-center gap-1 text-xs font-semibold px-1.5 py-0.5 rounded"
                style={{ background: 'rgba(34,197,94,0.15)', color: '#22c55e' }}>
                <span className="h-1.5 w-1.5 rounded-full bg-green-400 animate-pulse inline-block" /> LIVE
              </span>
            )}
          </div>
          {session.status === 'ACTIVE' && (
            <button
              onClick={handleDebugToggle}
              disabled={togglingDebug}
              className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-xs font-medium transition-all duration-150"
              style={debugMode
                ? { background: 'rgba(99,102,241,0.2)', color: '#A5B4FC', border: '1px solid rgba(99,102,241,0.3)' }
                : { background: 'rgba(255,255,255,0.06)', color: '#64748B', border: '1px solid rgba(255,255,255,0.1)' }
              }
            >
              {togglingDebug ? <Loader2 className="h-3 w-3 animate-spin" /> : debugMode ? 'Debug: ON' : 'Debug: OFF'}
            </button>
          )}
        </div>
        <div className="p-3">
          {frameUrl ? (
            // eslint-disable-next-line @next/next/no-img-element
            <img src={frameUrl} alt="Live proctoring frame"
              className="w-full rounded-lg object-contain"
              style={{ background: '#1E293B', maxHeight: '360px' }} />
          ) : (
            <div className="aspect-video rounded-lg flex flex-col items-center justify-center gap-3"
              style={{ background: '#1E293B', border: '1px solid #334155' }}>
              <Bot className="h-12 w-12" style={{ color: '#334155' }} />
              <p className="text-sm text-center max-w-xs" style={{ color: '#475569' }}>
                {session.status === 'ACTIVE' ? 'Waiting for engine frame…' : 'Session not active'}
              </p>
            </div>
          )}
        </div>
      </div>

      {/* Risk Score */}
      <div className="bg-white rounded-xl border overflow-hidden"
        style={{ borderColor: '#E2E8F0', boxShadow: '0 1px 3px rgba(15,23,42,0.04)' }}>
        <div className="flex items-center justify-between px-4 py-3" style={{ borderBottom: '1px solid #F1F5F9' }}>
          <div className="flex items-center gap-2">
            <Activity className="h-4 w-4" style={{ color: '#22577A' }} />
            <span className="text-sm font-semibold" style={{ color: '#0F172A' }}>Risk Assessment</span>
          </div>
          <RiskBadge state={liveRisk.state} />
        </div>
        <div className="p-4 space-y-3">
          <div className="flex items-end gap-3">
            <p className="text-5xl font-bold tabular-nums transition-all"
              style={{ color: RISK_COLORS[liveRisk.state] ?? '#22c55e', letterSpacing: '-0.03em' }}>
              {Math.round(liveRisk.score)}
            </p>
            <span className="text-xs mb-1.5" style={{ color: '#64748B' }}>/ 100</span>
          </div>
          <div className="h-2 rounded-full overflow-hidden" style={{ background: '#F1F5F9' }}>
            <div className="h-2 rounded-full transition-all duration-700"
              style={{ width: `${Math.min(liveRisk.score, 100)}%`, background: RISK_COLORS[liveRisk.state] ?? '#22c55e' }} />
          </div>
          <div className="flex gap-4 text-xs" style={{ color: '#64748B' }}>
            <span>Fixed <span className="font-semibold" style={{ color: '#475569' }}>{Math.round(liveRisk.fixed)}</span></span>
            {liveRisk.decaying !== undefined && (
              <span>Decaying <span className="font-semibold" style={{ color: '#475569' }}>{Math.round(liveRisk.decaying)}</span></span>
            )}
          </div>
          {liveRisk.terminated && (
            <div className="text-xs font-bold text-center py-2 rounded-lg"
              style={{ background: '#FFF1F2', color: '#BE123C', border: '1px solid #FECDD3' }}>
              EXAM TERMINATED BY ENGINE
            </div>
          )}
          <div className="grid grid-cols-3 gap-3 pt-2" style={{ borderTop: '1px solid #F1F5F9' }}>
            <div className="text-center">
              <p className="text-lg font-bold" style={{ color: '#EF4444' }}>{alerts.length}</p>
              <p className="text-xs" style={{ color: '#64748B' }}>Alerts</p>
            </div>
            <div className="text-center">
              <p className="text-lg font-bold" style={{ color: '#F59E0B' }}>{warnings.length}</p>
              <p className="text-xs" style={{ color: '#64748B' }}>Warnings</p>
            </div>
            <div className="text-center">
              <p className="text-lg font-bold" style={{ color: '#475569' }}>
                {session.time_extension_seconds > 0 ? `+${Math.round(session.time_extension_seconds / 60)}m` : '–'}
              </p>
              <p className="text-xs" style={{ color: '#64748B' }}>Time Ext.</p>
            </div>
          </div>
        </div>
      </div>

      {/* Alert / Warning log */}
      <div className="bg-white rounded-xl border overflow-hidden"
        style={{ borderColor: '#E2E8F0', boxShadow: '0 1px 3px rgba(15,23,42,0.04)' }}>
        <div className="flex gap-1 px-1 pt-1" style={{ borderBottom: '1px solid #F1F5F9' }}>
          <button
            onClick={() => setAlertTab('alerts')}
            className={`px-4 py-2.5 text-sm font-semibold border-b-2 transition-colors -mb-px`}
            style={alertTab === 'alerts'
              ? { borderBottomColor: '#EF4444', color: '#BE123C' }
              : { borderBottomColor: 'transparent', color: '#64748B' }
            }
          >
            Alerts
            {alerts.length > 0 && (
              <span className="ml-1.5 text-xs px-1.5 py-0.5 rounded-full"
                style={{ background: '#FFF1F2', color: '#BE123C' }}>{alerts.length}</span>
            )}
          </button>
          <button
            onClick={() => setAlertTab('warnings')}
            className={`px-4 py-2.5 text-sm font-semibold border-b-2 transition-colors -mb-px`}
            style={alertTab === 'warnings'
              ? { borderBottomColor: '#F59E0B', color: '#B45309' }
              : { borderBottomColor: 'transparent', color: '#64748B' }
            }
          >
            Warnings
            {warnings.length > 0 && (
              <span className="ml-1.5 text-xs px-1.5 py-0.5 rounded-full"
                style={{ background: '#FFFBEB', color: '#B45309' }}>{warnings.length}</span>
            )}
          </button>
        </div>
        <div className="p-3">
          <div className="space-y-2 max-h-56 overflow-y-auto">
            {!historyLoaded ? (
              <div className="flex items-center justify-center gap-2 py-6 text-sm" style={{ color: '#64748B' }}>
                <Loader2 className="h-4 w-4 animate-spin" /> Loading history…
              </div>
            ) : alertTab === 'alerts' ? (
              alerts.length === 0
                ? <p className="text-sm text-center py-6" style={{ color: '#64748B' }}>No alerts yet</p>
                : alerts.map((a, i) => (
                  <ExpandableAlertRow key={i} entry={a} index={alerts.length - 1 - i} engineUrl={session.proctor_engine_url} />
                ))
            ) : (
              warnings.length === 0
                ? <p className="text-sm text-center py-6" style={{ color: '#64748B' }}>No warnings yet</p>
                : warnings.map((w, i) => (
                  <div key={i} className="flex items-start gap-2 px-3 py-2 rounded-lg border text-xs"
                    style={{ background: 'rgba(255,251,235,0.5)', borderColor: '#FDE68A' }}>
                    <AlertTriangle className="h-3.5 w-3.5 shrink-0 mt-0.5" style={{ color: '#F59E0B' }} />
                    <div>
                      <p style={{ color: '#B45309' }}>{w.message}</p>
                      <p className="mt-0.5" style={{ color: '#FDE68A' }}>{fmtTimeIST(new Date(w.ts).toISOString())}</p>
                    </div>
                  </div>
                ))
            )}
          </div>
        </div>
      </div>

      {/* Manual time extension */}
      {session.status === "ACTIVE" && (
        <div className="bg-white rounded-xl border overflow-hidden"
          style={{ borderColor: '#E2E8F0', boxShadow: '0 1px 3px rgba(15,23,42,0.04)' }}>
          <div className="flex items-center gap-2 px-4 py-3" style={{ borderBottom: '1px solid #F1F5F9' }}>
            <Timer className="h-4 w-4" style={{ color: examMode === 'FIXED' ? '#94A3B8' : '#15803D' }} />
            <span className="text-sm font-semibold" style={{ color: '#0F172A' }}>Grant Extra Time</span>
            {examMode === 'FIXED' && (
              <span className="text-xs px-2 py-0.5 rounded-full ml-auto"
                style={{ background: '#F1F5F9', color: '#64748B', border: '1px solid #E2E8F0' }}>
                Disabled — FIXED mode
              </span>
            )}
          </div>
          {examMode !== 'FIXED' ? (
            <div className="p-4 flex gap-3">
              <input
                type="number" min={1} placeholder="Minutes"
                value={extMinutes} onChange={(e) => setExtMinutes(e.target.value)}
                className="w-32 px-3 py-2 text-sm rounded-lg border outline-none transition-all"
                style={{ borderColor: '#E2E8F0', color: '#0F172A' }}
                onFocus={e => { (e.target as HTMLElement).style.borderColor = '#38A3A5'; (e.target as HTMLElement).style.boxShadow = '0 0 0 3px rgba(56,163,165,0.12)'; }}
                onBlur={e => { (e.target as HTMLElement).style.borderColor = '#E2E8F0'; (e.target as HTMLElement).style.boxShadow = 'none'; }}
              />
              <button
                onClick={handleExtend} disabled={extending}
                className="flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-semibold text-white transition-all duration-150"
                style={{ background: extending ? '#94A3B8' : '#15803D', cursor: extending ? 'not-allowed' : 'pointer' }}
              >
                {extending ? <Loader2 className="h-4 w-4 animate-spin" /> : null}
                Grant Extension
              </button>
            </div>
          ) : (
            <div className="p-4">
              <p className="text-sm" style={{ color: '#64748B' }}>
                Time extensions are not allowed in FIXED mode. All students share the same absolute deadline.
              </p>
            </div>
          )}
        </div>
      )}

      {/* Admin termination */}
      {session.status === "ACTIVE" && (
        <div className="rounded-xl border-2 overflow-hidden transition-all duration-300"
          style={liveRisk.score >= 100
            ? { borderColor: '#FCA5A5', background: 'rgba(254,242,242,0.3)' }
            : { borderColor: '#E2E8F0', background: '#fff' }
          }>
          <div className="flex items-center justify-between px-4 py-3" style={{ borderBottom: '1px solid #FEE2E2' }}>
            <div className="flex items-center gap-2">
              <Ban className="h-4 w-4" style={{ color: '#BE123C' }} />
              <span className="text-sm font-semibold" style={{ color: '#BE123C' }}>Terminate Session</span>
            </div>
            {liveRisk.score < 100 && (
              <span className="text-xs" style={{ color: '#64748B' }}>Available at risk ≥ 100</span>
            )}
          </div>
          <div className="p-4 space-y-3">
            {liveRisk.score >= 100 ? (
              <>
                <p className="text-sm" style={{ color: '#BE123C' }}>
                  Risk score has reached <strong>{Math.round(liveRisk.score)}</strong>. You may terminate
                  this student's session. They will be notified and can submit an appeal.
                </p>
                <button
                  onClick={handleTerminate} disabled={terminating}
                  className="w-full flex items-center justify-center gap-2 py-2.5 rounded-lg text-sm font-bold text-white transition-all duration-150"
                  style={{ background: terminating ? '#94A3B8' : '#EF4444', cursor: terminating ? 'not-allowed' : 'pointer' }}
                >
                  {terminating
                    ? <Loader2 className="h-4 w-4 animate-spin" />
                    : <Ban className="h-4 w-4" />}
                  Terminate {session.student_name}'s Session
                </button>
              </>
            ) : (
              <p className="text-sm" style={{ color: '#64748B' }}>
                The terminate button unlocks when the student's risk score reaches 100.
                Current score: <strong>{Math.round(liveRisk.score)}</strong>.
              </p>
            )}
          </div>
        </div>
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
      setExtMins((prev) => {
        const next = { ...prev };
        for (const rr of data) {
          if (rr.status === "PENDING" && rr.termination_type === "DISCONNECT" && rr.suggested_extension_minutes && !(rr.id in prev)) {
            next[rr.id] = String(rr.suggested_extension_minutes);
          }
        }
        return next;
      });
    } catch { toast.error("Failed to load appeals"); }
    finally { setLoading(false); }
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
    } finally { setReviewing(null); }
  };

  const pending = appeals.filter((a) => a.status === "PENDING");
  const reviewed = appeals.filter((a) => a.status !== "PENDING");

  if (loading) {
    return (
      <div className="flex items-center justify-center p-12">
        <Loader2 className="h-6 w-6 animate-spin" style={{ color: '#CBD5E1' }} />
      </div>
    );
  }

  return (
    <div className="space-y-5">
      {pending.length === 0 && (
        <div className="text-center py-12">
          <div className="h-14 w-14 rounded-full flex items-center justify-center mx-auto mb-3"
            style={{ background: '#ECFDF5' }}>
            <CheckCircle2 className="h-7 w-7" style={{ color: '#15803D' }} />
          </div>
          <p className="text-sm font-medium" style={{ color: '#475569' }}>No pending appeals</p>
        </div>
      )}

      {pending.map((rr) => {
        const isDisconnect = rr.termination_type === "DISCONNECT";
        const typeStyle = isDisconnect
          ? { bg: '#EFF6FF', color: '#1D4ED8', border: '#BFDBFE', label: 'Disconnect' }
          : rr.termination_type === "ADMIN"
          ? { bg: '#FFF1F2', color: '#BE123C', border: '#FECDD3', label: 'Admin Terminated' }
          : { bg: '#F5F3FF', color: '#7C3AED', border: '#DDD6FE', label: 'System Flag' };

        return (
          <div key={rr.id} className="rounded-xl border overflow-hidden"
            style={{ borderColor: '#FDE68A', background: 'rgba(255,251,235,0.3)' }}>
            <div className="flex items-start justify-between px-5 py-4" style={{ borderBottom: '1px solid #FDE68A' }}>
              <div>
                <p className="font-semibold" style={{ color: '#0F172A' }}>{rr.student_name}</p>
                <p className="text-xs mt-0.5" style={{ color: '#64748B' }}>{rr.student_email}</p>
              </div>
              <div className="flex items-center gap-2">
                <span className="inline-flex items-center px-2 py-0.5 rounded-md text-xs font-semibold border"
                  style={{ background: typeStyle.bg, color: typeStyle.color, borderColor: typeStyle.border }}>
                  {typeStyle.label}
                </span>
                <span className="inline-flex items-center px-2 py-0.5 rounded-md text-xs font-semibold border"
                  style={{ background: '#FFFBEB', color: '#B45309', borderColor: '#FDE68A' }}>
                  Pending Review
                </span>
              </div>
            </div>
            <div className="p-5 space-y-4">
              <div className="p-3 rounded-lg border" style={{ background: '#fff', borderColor: '#E2E8F0' }}>
                <p className="text-[10px] font-semibold uppercase tracking-wider mb-1" style={{ color: '#64748B' }}>Student's Reason</p>
                <p className="text-sm leading-relaxed" style={{ color: '#475569' }}>"{rr.reason}"</p>
              </div>

              {isDisconnect && rr.time_since_disconnect_seconds != null && (
                <div className="flex items-center gap-2 p-2.5 rounded-lg border text-xs"
                  style={{ background: '#EFF6FF', borderColor: '#BFDBFE', color: '#1D4ED8' }}>
                  <Clock className="h-3.5 w-3.5 shrink-0" />
                  Appeal filed <strong className="ml-1">
                    {rr.time_since_disconnect_seconds < 60
                      ? `${rr.time_since_disconnect_seconds}s`
                      : `${Math.floor(rr.time_since_disconnect_seconds / 60)}m ${rr.time_since_disconnect_seconds % 60}s`}
                  </strong>&nbsp;after disconnection
                </div>
              )}

              {!isDisconnect && (
                <div className="flex items-start gap-2 p-2.5 rounded-lg border"
                  style={{ background: '#F8FAFC', borderColor: '#E2E8F0' }}>
                  <AlertTriangle className="h-4 w-4 mt-0.5 shrink-0" style={{ color: '#64748B' }} />
                  <p className="text-xs" style={{ color: '#64748B' }}>
                    Timer continued running during this appeal. No extra time is typically granted for {rr.termination_type === "ADMIN" ? "admin-terminated" : "system-flagged"} sessions, but you may still add minutes if appropriate.
                  </p>
                </div>
              )}

              <div className="grid sm:grid-cols-2 gap-3">
                <div>
                  <label className="text-xs font-semibold block mb-1.5" style={{ color: '#64748B' }}>Review Note (optional)</label>
                  <Textarea
                    placeholder="Add a note for the student…"
                    rows={2}
                    value={notes[rr.id] ?? ""}
                    onChange={(e) => setNotes((n) => ({ ...n, [rr.id]: e.target.value }))}
                    className="text-sm"
                  />
                </div>
                <div>
                  <label className="text-xs font-semibold block mb-1.5" style={{ color: '#64748B' }}>
                    {isDisconnect ? "Extra Minutes if Approved" : "Extra Minutes (optional)"}
                  </label>
                  <input
                    type="number" min={1} placeholder="e.g. 10"
                    value={extMins[rr.id] ?? ""}
                    onChange={(e) => setExtMins((m) => ({ ...m, [rr.id]: e.target.value }))}
                    className="w-full px-3 py-2.5 text-sm rounded-lg border outline-none transition-all"
                    style={{ borderColor: '#E2E8F0', color: '#0F172A' }}
                    onFocus={e => { (e.target as HTMLElement).style.borderColor = '#38A3A5'; (e.target as HTMLElement).style.boxShadow = '0 0 0 3px rgba(56,163,165,0.12)'; }}
                    onBlur={e => { (e.target as HTMLElement).style.borderColor = '#E2E8F0'; (e.target as HTMLElement).style.boxShadow = 'none'; }}
                  />
                  {isDisconnect && rr.suggested_extension_minutes && (
                    <p className="text-xs mt-1" style={{ color: '#64748B' }}>
                      Suggested: {rr.suggested_extension_minutes} min
                    </p>
                  )}
                </div>
              </div>

              <div className="flex gap-3 pt-1">
                <button
                  onClick={() => handleReview(rr.id, "APPROVED")}
                  disabled={reviewing === rr.id}
                  className="flex-1 flex items-center justify-center gap-2 py-2.5 rounded-lg text-sm font-semibold text-white transition-all duration-150"
                  style={{ background: reviewing === rr.id ? '#94A3B8' : '#15803D', cursor: reviewing === rr.id ? 'not-allowed' : 'pointer' }}
                >
                  {reviewing === rr.id ? <Loader2 className="h-4 w-4 animate-spin" /> : <CheckCircle2 className="h-4 w-4" />}
                  Approve
                </button>
                <button
                  onClick={() => handleReview(rr.id, "DENIED")}
                  disabled={reviewing === rr.id}
                  className="flex-1 flex items-center justify-center gap-2 py-2.5 rounded-lg text-sm font-semibold border transition-all duration-150"
                  style={{ borderColor: '#FECDD3', color: '#BE123C', background: '#fff', cursor: reviewing === rr.id ? 'not-allowed' : 'pointer' }}
                  onMouseEnter={e => { if (reviewing !== rr.id) (e.currentTarget as HTMLElement).style.background = '#FFF1F2'; }}
                  onMouseLeave={e => { (e.currentTarget as HTMLElement).style.background = '#fff'; }}
                >
                  <XCircle className="h-4 w-4" /> Deny
                </button>
              </div>
            </div>
          </div>
        );
      })}

      {reviewed.length > 0 && (
        <div>
          <p className="text-xs font-semibold uppercase tracking-wider mb-3" style={{ color: '#64748B' }}>Reviewed</p>
          <div className="space-y-2">
            {reviewed.slice(0, 10).map((rr) => (
              <div key={rr.id} className="flex items-center justify-between p-3 rounded-xl border"
                style={{ background: '#fff', borderColor: '#E2E8F0' }}>
                <div>
                  <p className="text-sm font-medium" style={{ color: '#0F172A' }}>{rr.student_name}</p>
                  <p className="text-xs truncate mt-0.5" style={{ color: '#64748B' }}>"{rr.reason}"</p>
                </div>
                <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-xs font-semibold border ml-3 shrink-0"
                  style={rr.status === "APPROVED"
                    ? { background: '#ECFDF5', color: '#15803D', borderColor: '#BBF7D0' }
                    : { background: '#FFF1F2', color: '#BE123C', borderColor: '#FECDD3' }
                  }>
                  {rr.status === "APPROVED"
                    ? <><CheckCircle2 className="h-3 w-3" /> APPROVED</>
                    : <><XCircle className="h-3 w-3" /> DENIED</>
                  }
                </span>
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
  const searchParams = useSearchParams();
  const examId = params.id as string;

  const [sessions, setSessions] = useState<SessionCard[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedSession, setSelectedSession] = useState<SessionCard | null>(null);
  const [activeTab, setActiveTab] = useState<"sessions" | "appeals">("sessions");
  const [bulkMinutes, setBulkMinutes] = useState("");
  const [bulkExtending, setBulkExtending] = useState(false);
  const [search, setSearch] = useState('');
  const [examMode, setExamMode] = useState<string>('FLEXIBLE');

  useEffect(() => {
    setActiveTab(searchParams.get('tab') === 'appeals' ? 'appeals' : 'sessions');
  }, [searchParams]);

  useEffect(() => {
    if (!selectedSession) return;
    const latest = sessions.find(s => s.session_id === selectedSession.session_id);
    if (latest) setSelectedSession(latest);
  }, [sessions]);

  const handleScoreUpdate = useCallback((sessionId: string, score: number) => {
    setSessions(prev => prev.map(s => s.session_id === sessionId ? { ...s, risk_score: score } : s));
  }, []);

  useEffect(() => {
    api.get(`/admin/exams/${examId}`).then(res => setExamMode(res.data.exam_mode ?? 'FLEXIBLE')).catch(() => {});
  }, [examId]);

  const fetchSessions = useCallback(async () => {
    try {
      const res = await api.get(`/admin/exams/${examId}/sessions`);
      setSessions(res.data);
    } catch { }
    finally { setLoading(false); }
  }, [examId]);

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
    } finally { setBulkExtending(false); }
  };

  const activeSessions = sessions.filter((s) => s.status === "ACTIVE");
  const pendingAppeals = sessions.filter((s) => s.has_pending_appeal).length;
  const filteredSessions = search.trim()
    ? sessions.filter(s =>
        s.student_name.toLowerCase().includes(search.toLowerCase()) ||
        s.student_email.toLowerCase().includes(search.toLowerCase())
      )
    : sessions;

  if (loading) {
    return (
      <div className="flex items-center justify-center p-24">
        <Loader2 className="h-7 w-7 animate-spin" style={{ color: '#CBD5E1' }} />
      </div>
    );
  }

  const statCards = [
    { value: activeSessions.length,                               label: 'Active Students',  icon: Users,      iconBg: '#ECFDF5', iconColor: '#15803D', alert: false },
    { value: sessions.filter(s => s.status === "ENDED").length,  label: 'Submitted',         icon: CheckCircle2, iconBg: '#EFF6FF', iconColor: '#1D4ED8', alert: false },
    { value: pendingAppeals,                                      label: 'Pending Appeals',   icon: MessageSquare, iconBg: pendingAppeals > 0 ? '#FFFBEB' : '#F8FAFC', iconColor: pendingAppeals > 0 ? '#B45309' : '#94A3B8', alert: pendingAppeals > 0 },
    { value: sessions.filter(s => s.status === "TERMINATED").length, label: 'Terminated',   icon: ShieldAlert, iconBg: '#FFF1F2', iconColor: '#BE123C', alert: false },
  ];

  return (
    <div className="space-y-6 pb-12">
      {/* Header */}
      <div className="flex items-center gap-4">
        <button
          onClick={() => router.back()}
          className="h-9 w-9 flex items-center justify-center rounded-lg border shrink-0 transition-all duration-150"
          style={{ borderColor: '#E2E8F0', color: '#475569', background: '#fff' }}
          onMouseEnter={e => (e.currentTarget as HTMLElement).style.background = '#F8FAFC'}
          onMouseLeave={e => (e.currentTarget as HTMLElement).style.background = '#fff'}
        >
          <ArrowLeft className="h-4 w-4" />
        </button>
        <div className="flex-1">
          <h1 className="text-2xl font-bold" style={{ color: '#0F172A', letterSpacing: '-0.025em' }}>Live Monitoring</h1>
          <p className="text-sm mt-0.5" style={{ color: '#64748B' }}>Real-time session overview and appeal management</p>
        </div>
        <button
          onClick={fetchSessions}
          className="flex items-center gap-2 px-3 py-2 rounded-lg text-sm font-medium border transition-all duration-150"
          style={{ borderColor: '#E2E8F0', color: '#475569', background: '#fff' }}
          onMouseEnter={e => (e.currentTarget as HTMLElement).style.background = '#F8FAFC'}
          onMouseLeave={e => (e.currentTarget as HTMLElement).style.background = '#fff'}
        >
          <RefreshCw className="h-3.5 w-3.5" /> Refresh
        </button>
      </div>

      {/* Stats row */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        {statCards.map(({ value, label, icon: Icon, iconBg, iconColor, alert }) => (
          <div key={label} className="bg-white rounded-xl border p-5 relative"
            style={{
              borderColor: alert ? '#FDE68A' : '#E2E8F0',
              boxShadow: alert ? '0 0 0 3px rgba(245,158,11,0.08), 0 1px 3px rgba(15,23,42,0.04)' : '0 1px 3px rgba(15,23,42,0.04)',
            }}>
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg shrink-0" style={{ background: iconBg }}>
                <Icon className="h-5 w-5" style={{ color: iconColor }} />
              </div>
              <div>
                <p className="text-2xl font-bold" style={{ color: '#0F172A', letterSpacing: '-0.03em' }}>{value}</p>
                <p className="text-xs" style={{ color: '#64748B' }}>{label}</p>
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* Bulk time extension */}
      {activeSessions.length > 0 && examMode !== 'FIXED' && (
        <div className="rounded-xl border p-4 flex flex-wrap items-center gap-4"
          style={{ background: '#ECFDF5', borderColor: '#BBF7D0' }}>
          <div className="flex items-center gap-2 text-sm font-semibold" style={{ color: '#15803D' }}>
            <Timer className="h-4 w-4" /> Bulk Time Extension for All Active Students
          </div>
          <div className="flex items-center gap-2 ml-auto">
            <input
              type="number" min={1} placeholder="Minutes"
              value={bulkMinutes} onChange={(e) => setBulkMinutes(e.target.value)}
              className="w-28 px-3 py-1.5 text-sm rounded-lg border outline-none transition-all"
              style={{ borderColor: '#BBF7D0', color: '#0F172A', background: '#fff' }}
              onFocus={e => { (e.target as HTMLElement).style.borderColor = '#38A3A5'; (e.target as HTMLElement).style.boxShadow = '0 0 0 3px rgba(56,163,165,0.12)'; }}
              onBlur={e => { (e.target as HTMLElement).style.borderColor = '#BBF7D0'; (e.target as HTMLElement).style.boxShadow = 'none'; }}
            />
            <button
              onClick={handleBulkExtend} disabled={bulkExtending}
              className="flex items-center gap-2 px-4 py-1.5 rounded-lg text-sm font-semibold text-white transition-all duration-150"
              style={{ background: bulkExtending ? '#94A3B8' : '#15803D', cursor: bulkExtending ? 'not-allowed' : 'pointer' }}
            >
              {bulkExtending ? <Loader2 className="h-4 w-4 animate-spin" /> : null}
              Grant to All
            </button>
          </div>
        </div>
      )}

      {/* Tab nav */}
      <div className="flex gap-1 p-1 rounded-lg w-fit" style={{ background: '#F1F5F9' }}>
        <button
          onClick={() => setActiveTab("sessions")}
          className="px-5 py-2 rounded-md text-sm font-medium transition-all"
          style={activeTab === "sessions"
            ? { background: '#fff', color: '#0F172A', boxShadow: '0 1px 3px rgba(15,23,42,0.08)' }
            : { background: 'transparent', color: '#64748B' }
          }
        >
          <div className="flex items-center gap-2">
            <Users className="h-4 w-4" /> Sessions
            <span className="text-xs px-1.5 py-0.5 rounded-full font-semibold"
              style={{ background: '#E2E8F0', color: '#475569' }}>{sessions.length}</span>
          </div>
        </button>
        <button
          onClick={() => setActiveTab("appeals")}
          className="px-5 py-2 rounded-md text-sm font-medium transition-all"
          style={activeTab === "appeals"
            ? { background: '#fff', color: '#0F172A', boxShadow: '0 1px 3px rgba(15,23,42,0.08)' }
            : { background: 'transparent', color: '#64748B' }
          }
        >
          <div className="flex items-center gap-2">
            <MessageSquare className="h-4 w-4" /> Appeals
            {pendingAppeals > 0 && (
              <span className="text-xs px-1.5 py-0.5 rounded-full font-semibold text-white"
                style={{ background: '#F59E0B' }}>{pendingAppeals}</span>
            )}
          </div>
        </button>
      </div>

      {/* Content */}
      {activeTab === "sessions" ? (
        <div className="grid lg:grid-cols-2 gap-6">
          {/* Student cards */}
          <div className="space-y-3">
            {sessions.length > 0 && (
              <div className="relative">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4" style={{ color: '#CBD5E1' }} />
                <input
                  type="text" placeholder="Search by name or email…"
                  value={search} onChange={e => setSearch(e.target.value)}
                  className="w-full py-2 text-sm rounded-lg border outline-none transition-all"
                  style={{ borderColor: '#E2E8F0', color: '#0F172A', paddingLeft: '2.25rem', paddingRight: '0.75rem' }}
                  onFocus={e => { (e.target as HTMLElement).style.borderColor = '#38A3A5'; (e.target as HTMLElement).style.boxShadow = '0 0 0 3px rgba(56,163,165,0.12)'; }}
                  onBlur={e => { (e.target as HTMLElement).style.borderColor = '#E2E8F0'; (e.target as HTMLElement).style.boxShadow = 'none'; }}
                />
              </div>
            )}
            {filteredSessions.length === 0 ? (
              <div className="text-center py-16">
                <Users className="h-12 w-12 mx-auto mb-3" style={{ color: '#E2E8F0' }} />
                <p className="text-sm" style={{ color: '#64748B' }}>
                  {sessions.length === 0 ? 'No student sessions yet' : 'No students match your search'}
                </p>
              </div>
            ) : (
              filteredSessions.map((sess) => {
                const isSelected = selectedSession?.session_id === sess.session_id;
                return (
                  <div
                    key={sess.session_id}
                    className="bg-white rounded-xl border-2 cursor-pointer transition-all duration-150 overflow-hidden"
                    style={{
                      borderColor: isSelected ? '#22577A' : '#E2E8F0',
                      boxShadow: isSelected ? '0 0 0 3px rgba(34,87,122,0.1), 0 4px 12px rgba(15,23,42,0.08)' : '0 1px 3px rgba(15,23,42,0.04)',
                    }}
                    onClick={() => setSelectedSession(sess.session_id === selectedSession?.session_id ? null : sess)}
                  >
                    {isSelected && <div className="h-1" style={{ background: '#22577A' }} />}
                    <div className="p-4 space-y-3">
                      <div className="flex items-start justify-between gap-3">
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2 flex-wrap">
                            <p className="font-semibold text-sm truncate" style={{ color: '#0F172A' }}>{sess.student_name}</p>
                            {sess.has_pending_appeal && (
                              <span className="inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-semibold border shrink-0"
                                style={{ background: '#FFFBEB', color: '#B45309', borderColor: '#FDE68A' }}>
                                Appeal Pending
                              </span>
                            )}
                          </div>
                          <p className="text-xs truncate mt-0.5" style={{ color: '#64748B' }}>{sess.student_email}</p>
                        </div>
                        <div className="flex items-center gap-2 shrink-0">
                          <StatusBadge status={sess.status} />
                          <ChevronRight className={`h-4 w-4 transition-transform ${isSelected ? 'rotate-90' : ''}`} style={{ color: '#CBD5E1' }} />
                        </div>
                      </div>

                      <RiskBar score={sess.risk_score} />

                      <div className="flex items-center gap-4 text-xs flex-wrap" style={{ color: '#64748B' }}>
                        {sess.last_heartbeat && (
                          <span className="flex items-center gap-1">
                            <Activity className="h-3 w-3" style={{ color: '#86EFAC' }} />
                            Last seen {fmtTimeIST(sess.last_heartbeat)}
                          </span>
                        )}
                        {sess.time_extension_seconds > 0 && (
                          <span className="flex items-center gap-1">
                            <Timer className="h-3 w-3" style={{ color: '#A5B4FC' }} />
                            +{Math.round(sess.time_extension_seconds / 60)}m ext
                          </span>
                        )}
                      </div>
                    </div>
                  </div>
                );
              })
            )}
          </div>

          {/* Live Monitor panel */}
          <div>
            {selectedSession ? (
              <div>
                <div className="flex items-center justify-between mb-4">
                  <div>
                    <h2 className="text-lg font-semibold flex items-center gap-2" style={{ color: '#0F172A' }}>
                      <Eye className="h-5 w-5" style={{ color: '#22577A' }} /> {selectedSession.student_name}
                    </h2>
                    <p className="text-sm mt-0.5" style={{ color: '#64748B' }}>{selectedSession.student_email}</p>
                  </div>
                  <StatusBadge status={selectedSession.status} />
                </div>
                <LiveMonitorPanel
                  key={selectedSession.session_id}
                  session={selectedSession}
                  examId={examId}
                  examMode={examMode}
                  onScoreUpdate={handleScoreUpdate}
                  onSessionTerminated={() => { fetchSessions(); setSelectedSession(null); }}
                />
              </div>
            ) : (
              <div className="flex flex-col items-center justify-center h-64 rounded-xl border-2 border-dashed"
                style={{ borderColor: '#E2E8F0' }}>
                <Eye className="h-10 w-10 mb-3" style={{ color: '#E2E8F0' }} />
                <p className="text-sm" style={{ color: '#64748B' }}>Select a student to open the live monitor</p>
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
