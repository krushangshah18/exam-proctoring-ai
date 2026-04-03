'use client';

import { useEffect, useState, useCallback, useRef } from 'react';
import {
  RefreshCw, Users, ShieldAlert, Activity, Loader2,
  AlertTriangle, Eye, Bot, CheckCircle2, XCircle, Server, Search,
} from 'lucide-react';
import { toast } from 'sonner';
import api from '@/lib/axios';

// ── Types ─────────────────────────────────────────────────────────────────────

interface LiveSession {
  session_id: string;
  exam_id: string;
  exam_title: string;
  student_name: string;
  student_email: string;
  status: string;
  start_time: string | null;
  risk_score: number;
  last_heartbeat: string | null;
  proctor_connected: boolean;
  proctor_engine_url: string | null;
  terminated_reason: string | null;
}

interface AlertEntry {
  message: string;
  key?: string;
  score_added?: number;
  proof_url?: string;
  proof_type?: string;
  ts: number;
}
interface WarningEntry { message: string; ts: number; }
interface RiskInfo { score: number; fixed: number; decaying?: number; state: string; }
interface HistoryLogEntry {
  message?: string;
  key?: string;
  score_added?: number;
  proof_url?: string;
  proof_type?: string;
  elapsed_s?: number;
  time?: string;
}
interface AlertHistoryResponse {
  alerts: HistoryLogEntry[];
  warnings: HistoryLogEntry[];
}
interface LiveStreamEvent {
  type?: string;
  message?: string;
  key?: string;
  score_added?: number;
  proof_url?: string;
  proof_type?: string;
  risk?: {
    score?: number;
    fixed?: number;
    decaying?: number;
    state?: string;
  };
}

// ── Persistence helpers ───────────────────────────────────────────────────────

const SS_ALERTS   = (id: string) => `live_alerts_${id}`;
const SS_WARNINGS = (id: string) => `live_warnings_${id}`;

function loadAlerts(id: string): AlertEntry[] {
  try { return JSON.parse(sessionStorage.getItem(SS_ALERTS(id)) ?? '[]'); } catch { return []; }
}
function loadWarnings(id: string): WarningEntry[] {
  try { return JSON.parse(sessionStorage.getItem(SS_WARNINGS(id)) ?? '[]'); } catch { return []; }
}
function saveAlerts(id: string, a: AlertEntry[]) {
  try { sessionStorage.setItem(SS_ALERTS(id), JSON.stringify(a.slice(0, 200))); } catch {}
}
function saveWarnings(id: string, w: WarningEntry[]) {
  try { sessionStorage.setItem(SS_WARNINGS(id), JSON.stringify(w.slice(0, 200))); } catch {}
}

// ── Helpers ───────────────────────────────────────────────────────────────────

const RISK_COLORS: Record<string, string> = {
  NORMAL: '#22c55e', WARNING: '#f59e0b', HIGH_RISK: '#ef4444',
  ADMIN_REVIEW: '#dc2626', TERMINATED: '#7f1d1d',
};

function RiskBadge({ state }: { state: string }) {
  const color = RISK_COLORS[state] ?? '#22c55e';
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

function RiskBar({ score }: { score: number }) {
  const color = score >= 70 ? '#ef4444' : score >= 40 ? '#f59e0b' : '#22c55e';
  return (
    <div className="flex items-center gap-2">
      <div className="flex-1 h-1.5 rounded-full overflow-hidden" style={{ background: '#F1F5F9' }}>
        <div className="h-full rounded-full transition-all duration-500" style={{ width: `${Math.min(score, 100)}%`, background: color }} />
      </div>
      <span className="text-xs font-mono font-bold w-7 text-right" style={{ color }}>{score}</span>
    </div>
  );
}

function openSSE(url: string, token: string, handlers: Record<string, (d: unknown) => void>): () => void {
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

function buildProofUrl(engineUrl: string | null, rawPath?: string): string | null {
  if (!engineUrl || !rawPath) return null;
  const base = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';
  let path = rawPath;
  try {
    path = rawPath.startsWith('http') ? new URL(rawPath).pathname : rawPath;
  } catch {
    path = rawPath;
  }
  return `${base}/admin/proxy-proof?engine_url=${encodeURIComponent(engineUrl)}&path=${encodeURIComponent(path)}`;
}

// ── Session detail panel ──────────────────────────────────────────────────────

function SessionDetailPanel({ session, onScoreUpdate }: {
  session: LiveSession;
  onScoreUpdate: (id: string, score: number) => void;
}) {
  const [frameUrl, setFrameUrl]   = useState<string | null>(null);
  const [alerts, setAlerts]       = useState<AlertEntry[]>(() => loadAlerts(session.session_id));
  const [warnings, setWarnings]   = useState<WarningEntry[]>(() => loadWarnings(session.session_id));
  const [liveRisk, setLiveRisk]   = useState<RiskInfo>({ score: session.risk_score, fixed: 0, state: 'NORMAL' });
  const [alertTab, setAlertTab]   = useState<'alerts' | 'warnings'>('alerts');
  const [historyLoaded, setHistoryLoaded] = useState(false);
  const [debugMode, setDebugMode] = useState(false);
  const [togglingDebug, setTogglingDebug] = useState(false);
  const sseRef   = useRef<(() => void) | null>(null);
  const frameRef = useRef<NodeJS.Timeout | null>(null);
  const prevFrameUrl = useRef<string | null>(null);
  const alertsRef    = useRef(alerts);
  const warningsRef  = useRef(warnings);
  const frameFetchingRef = useRef(false);
  const frameFailureCountRef = useRef(0);

  useEffect(() => { alertsRef.current = alerts;   saveAlerts(session.session_id, alerts);   }, [alerts, session.session_id]);
  useEffect(() => { warningsRef.current = warnings; saveWarnings(session.session_id, warnings); }, [warnings, session.session_id]);

  useEffect(() => {
    let cancelled = false;

    api.get<AlertHistoryResponse>(`/admin/sessions/${session.session_id}/alert-history`)
      .then((res) => {
        if (cancelled) return;
        const now = Date.now();
        const histAlerts: AlertEntry[] = (res.data?.alerts ?? []).map((e) => ({
          message: e.message || 'Alert',
          key: e.key,
          score_added: e.score_added,
          proof_url: e.proof_url,
          proof_type: e.proof_type ?? 'image',
          ts: now - (e.elapsed_s ?? 0) * 1000,
        }));
        const histWarnings: WarningEntry[] = (res.data?.warnings ?? []).map((e) => ({
          message: e.message || 'Warning',
          ts: now - (e.elapsed_s ?? 0) * 1000,
        }));
        setAlerts(histAlerts);
        setWarnings(histWarnings);
      })
      .catch(() => {
        if (!cancelled) {
          setAlerts(loadAlerts(session.session_id));
          setWarnings(loadWarnings(session.session_id));
        }
      })
      .finally(() => {
        if (!cancelled) setHistoryLoaded(true);
      });

    return () => { cancelled = true; };
  }, [session.session_id]);

  const fetchFrame = useCallback(async () => {
    if (frameFetchingRef.current || document.hidden) return 'skipped';
    frameFetchingRef.current = true;
    const token = localStorage.getItem('access_token') || '';
    const base = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';
    try {
      const res = await fetch(
        `${base}/admin/sessions/${session.session_id}/live-frame`,
        { headers: { Authorization: `Bearer ${token}` } }
      );
      if (res.status === 204) return 'empty';
      if (!res.ok) return 'error';
      const blob = await res.blob();
      if (!blob.size) return 'empty';
      const url = URL.createObjectURL(blob);
      const old = prevFrameUrl.current;
      prevFrameUrl.current = url;
      setFrameUrl(url);
      if (old) setTimeout(() => URL.revokeObjectURL(old), 500);
      frameFailureCountRef.current = 0;
      return 'success';
    } catch {
      return 'error';
    } finally {
      frameFetchingRef.current = false;
    }
  }, [session.session_id]);

  useEffect(() => {
    if (session.status !== 'ACTIVE') return;

    let stopped = false;
    const initialFrameTimer = setTimeout(() => {
      const loop = async () => {
        while (!stopped) {
          const result = await fetchFrame();
          if (result === 'empty' || result === 'error') {
            frameFailureCountRef.current += 1;
          }
          const delay = document.hidden
            ? 5000
            : result === 'success'
              ? 500
              : Math.min(500 * (2 ** Math.min(frameFailureCountRef.current, 4)), 10000);
          await new Promise((resolve) => {
            frameRef.current = setTimeout(resolve, delay);
          });
        }
      };
      void loop();
    }, 0);

    const token = localStorage.getItem('access_token') || '';
    const base = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';
    sseRef.current = openSSE(
      `${base}/admin/sessions/${session.session_id}/live-stream`,
      token,
      {
        message: (payload: unknown) => {
          const d = payload as LiveStreamEvent;
          if (d?.risk) {
            const risk: RiskInfo = {
              score: d.risk.score ?? 0,
              fixed: d.risk.fixed ?? 0,
              decaying: d.risk.decaying,
              state: d.risk.state ?? 'NORMAL',
            };
            setLiveRisk(risk);
            onScoreUpdate(session.session_id, Math.round(risk.score));
          }
          if (d?.type === 'alert') {
            setAlerts(prev => {
              const next = [{ message: d.message || d.key || 'Alert', key: d.key, score_added: d.score_added, proof_url: d.proof_url, proof_type: d.proof_type, ts: Date.now() }, ...prev].slice(0, 200);
              return next;
            });
          } else if (d?.type === 'warning') {
            setWarnings(prev => [{ message: d.message || 'Warning', ts: Date.now() }, ...prev].slice(0, 200));
          }
        },
      }
    );

    return () => {
      stopped = true;
      clearTimeout(initialFrameTimer);
      if (frameRef.current) clearTimeout(frameRef.current);
      sseRef.current?.();
      if (prevFrameUrl.current) URL.revokeObjectURL(prevFrameUrl.current);
    };
  }, [session.session_id, session.status]);

  const scoreColor = RISK_COLORS[liveRisk.state] ?? '#22c55e';

  const handleDebugToggle = async () => {
    setTogglingDebug(true);
    try {
      await api.post(`/admin/sessions/${session.session_id}/debug-mode`, { enabled: !debugMode });
      setDebugMode((value) => !value);
      toast.success(`Debug overlay ${!debugMode ? 'enabled' : 'disabled'}`);
    } catch {
      toast.error('Failed to toggle debug mode');
    } finally {
      setTogglingDebug(false);
    }
  };

  return (
    <div className="space-y-4">
      {/* Live camera — dark panel */}
      <div className="rounded-xl overflow-hidden border" style={{ background: '#0F172A', borderColor: '#1E293B' }}>
        <div className="flex items-center gap-2 px-4 py-3" style={{ borderBottom: '1px solid #1E293B' }}>
          <Bot className="h-4 w-4" style={{ color: '#38A3A5' }} />
          <p className="text-sm font-semibold" style={{ color: '#94A3B8' }}>
            AI Feed — {session.student_name}
          </p>
          <span className="ml-auto flex items-center gap-2">
            <span className="h-1.5 w-1.5 rounded-full animate-pulse" style={{ background: '#22c55e' }} />
            <span className="text-xs" style={{ color: '#64748B' }}>LIVE</span>
            {session.status === 'ACTIVE' && (
              <button
                onClick={handleDebugToggle}
                disabled={togglingDebug}
                className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-xs font-medium transition-all duration-150 disabled:opacity-60"
                style={debugMode
                  ? { background: 'rgba(56,163,165,0.2)', color: '#7BDFF2', border: '1px solid rgba(56,163,165,0.35)' }
                  : { background: 'rgba(255,255,255,0.06)', color: '#94A3B8', border: '1px solid rgba(255,255,255,0.1)' }
                }
              >
                {togglingDebug ? <Loader2 className="h-3 w-3 animate-spin" /> : debugMode ? 'Debug: ON' : 'Debug: OFF'}
              </button>
            )}
          </span>
        </div>
        <div className="p-4">
          {frameUrl ? (
            // eslint-disable-next-line @next/next/no-img-element
            <img
              src={frameUrl}
              alt="Live feed"
              className="w-full aspect-video rounded-lg object-cover"
              style={{ background: '#1E293B' }}
              decoding="async"
            />
          ) : (
            <div className="aspect-video rounded-lg flex items-center justify-center border"
              style={{ background: '#1E293B', borderColor: '#334155' }}>
              <p className="text-sm" style={{ color: '#475569' }}>
                {session.status === 'ACTIVE' && session.proctor_connected ? 'Loading feed…' : 'Engine not connected'}
              </p>
            </div>
          )}
        </div>
      </div>

      {/* Risk assessment */}
      <div className="bg-white rounded-xl border overflow-hidden"
        style={{ borderColor: '#E2E8F0', boxShadow: '0 1px 3px rgba(15,23,42,0.04)' }}>
        <div className="flex items-center justify-between px-4 py-3" style={{ borderBottom: '1px solid #F1F5F9' }}>
          <div className="flex items-center gap-2">
            <Activity className="h-4 w-4" style={{ color: '#22577A' }} />
            <p className="text-sm font-semibold" style={{ color: '#0F172A' }}>Risk Assessment</p>
          </div>
          <RiskBadge state={liveRisk.state} />
        </div>
        <div className="p-4 space-y-3">
          <div className="flex items-end gap-2">
            <p className="text-5xl font-bold tabular-nums transition-all" style={{ color: scoreColor, letterSpacing: '-0.03em' }}>
              {Math.round(liveRisk.score)}
            </p>
            <span className="text-xs mb-1.5 font-medium" style={{ color: '#64748B' }}>/ 100</span>
          </div>
          <div className="h-2 rounded-full overflow-hidden" style={{ background: '#F1F5F9' }}>
            <div className="h-2 rounded-full transition-all duration-700"
              style={{ width: `${Math.min(liveRisk.score, 100)}%`, background: scoreColor }} />
          </div>
          <div className="flex gap-4 text-xs font-medium" style={{ color: '#64748B' }}>
            <span>Fixed <span className="font-semibold" style={{ color: '#0F172A' }}>{Math.round(liveRisk.fixed)}</span></span>
            {liveRisk.decaying !== undefined && (
              <span>Decaying <span className="font-semibold" style={{ color: '#0F172A' }}>{Math.round(liveRisk.decaying)}</span></span>
            )}
          </div>
          <div className="grid grid-cols-2 gap-2 pt-3 text-center" style={{ borderTop: '1px solid #F1F5F9' }}>
            <div className="rounded-lg py-2" style={{ background: '#FFF1F2' }}>
              <p className="text-lg font-bold" style={{ color: '#BE123C' }}>{alerts.length}</p>
              <p className="text-xs font-medium" style={{ color: '#64748B' }}>Alerts</p>
            </div>
            <div className="rounded-lg py-2" style={{ background: '#FFFBEB' }}>
              <p className="text-lg font-bold" style={{ color: '#B45309' }}>{warnings.length}</p>
              <p className="text-xs font-medium" style={{ color: '#64748B' }}>Warnings</p>
            </div>
          </div>
        </div>
      </div>

      {/* Alert / Warning log */}
      <div className="bg-white rounded-xl border overflow-hidden"
        style={{ borderColor: '#E2E8F0', boxShadow: '0 1px 3px rgba(15,23,42,0.04)' }}>
        <div className="flex" style={{ borderBottom: '1px solid #F1F5F9' }}>
          {(['alerts', 'warnings'] as const).map(tab => (
            <button key={tab} onClick={() => setAlertTab(tab)}
              className="px-4 py-3 text-sm font-semibold transition-colors capitalize relative"
              style={{
                color: alertTab === tab
                  ? (tab === 'alerts' ? '#BE123C' : '#B45309')
                  : '#64748B',
                borderBottom: alertTab === tab
                  ? `2px solid ${tab === 'alerts' ? '#BE123C' : '#B45309'}`
                  : '2px solid transparent',
              }}>
              {tab}
              {(tab === 'alerts' ? alerts : warnings).length > 0 && (
                <span className="ml-1.5 text-xs px-1.5 py-0.5 rounded-full font-medium"
                  style={{
                    background: tab === 'alerts' ? '#FFF1F2' : '#FFFBEB',
                    color: tab === 'alerts' ? '#BE123C' : '#B45309',
                  }}>
                  {(tab === 'alerts' ? alerts : warnings).length}
                </span>
              )}
            </button>
          ))}
        </div>
        <div className="p-4">
          <div className="space-y-2 max-h-56 overflow-y-auto">
            {!historyLoaded ? (
              <div className="flex items-center justify-center gap-2 py-6 text-sm font-medium" style={{ color: '#64748B' }}>
                <Loader2 className="h-4 w-4 animate-spin" /> Loading history…
              </div>
            ) : alertTab === 'alerts' ? (alerts.length === 0
              ? <p className="text-sm text-center py-6 font-medium" style={{ color: '#64748B' }}>No alerts yet</p>
              : alerts.map((a, i) => (
                <div key={i} className="flex items-start gap-2 px-3 py-2 rounded-lg border text-xs"
                  style={{ background: '#FFF1F2', borderColor: '#FECDD3' }}>
                  <AlertTriangle className="h-3.5 w-3.5 shrink-0 mt-0.5" style={{ color: '#BE123C' }} />
                  <div className="flex-1 min-w-0">
                    <p className="font-medium" style={{ color: '#BE123C' }}>{a.message}</p>
                    <div className="flex items-center gap-3 mt-0.5" style={{ color: '#FDA4AF' }}>
                      {a.score_added !== undefined && a.score_added > 0 && <span>+{a.score_added.toFixed(1)} pts</span>}
                      <span>{new Date(a.ts).toLocaleTimeString()}</span>
                      {buildProofUrl(session.proctor_engine_url, a.proof_url) && (
                        <button
                          type="button"
                          onClick={async (e) => {
                            e.preventDefault();
                            try {
                              const res = await api.get(buildProofUrl(session.proctor_engine_url, a.proof_url)!, { responseType: 'blob' });
                              const url = URL.createObjectURL(res.data);
                              window.open(url, '_blank');
                            } catch {
                              toast.error('Failed to load proof image');
                            }
                          }}
                          className="underline"
                          style={{ color: '#22577A' }}
                        >
                          proof
                        </button>
                      )}
                    </div>
                  </div>
                </div>
              ))
            ) : (warnings.length === 0
              ? <p className="text-sm text-center py-6 font-medium" style={{ color: '#64748B' }}>No warnings yet</p>
              : warnings.map((w, i) => (
                <div key={i} className="flex items-start gap-2 px-3 py-2 rounded-lg border text-xs"
                  style={{ background: '#FFFBEB', borderColor: '#FDE68A' }}>
                  <AlertTriangle className="h-3.5 w-3.5 shrink-0 mt-0.5" style={{ color: '#B45309' }} />
                  <div>
                    <p style={{ color: '#B45309' }}>{w.message}</p>
                    <p className="mt-0.5" style={{ color: '#D97706' }}>{new Date(w.ts).toLocaleTimeString()}</p>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function SessionsMonitorPage() {
  const [sessions, setSessions]   = useState<LiveSession[]>([]);
  const [loading, setLoading]     = useState(true);
  const [selected, setSelected]   = useState<LiveSession | null>(null);
  const [search, setSearch]       = useState('');

  const fetchSessions = useCallback(async (silent = false) => {
    try {
      const res = await api.get('/admin/sessions');
      setSessions(res.data);
      return true;
    } catch {
      if (!silent) toast.error('Failed to load sessions');
    } finally {
      setLoading(false);
    }
    return false;
  }, []);

  useEffect(() => {
    let stopped = false;
    let failureCount = 0;

    const loop = async () => {
      while (!stopped) {
        const ok = document.hidden ? true : await fetchSessions(failureCount > 0);
        failureCount = ok ? 0 : failureCount + 1;
        const delay = document.hidden
          ? 30000
          : ok
            ? 10000
            : Math.min(10000 * (2 ** Math.min(failureCount, 3)), 60000);
        await new Promise((resolve) => setTimeout(resolve, delay));
      }
    };

    void loop();
    return () => { stopped = true; };
  }, [fetchSessions]);

  useEffect(() => {
    if (!selected) return;
    const latest = sessions.find(s => s.session_id === selected.session_id);
    if (latest) setSelected(latest);
  }, [sessions]);

  const handleScoreUpdate = useCallback((id: string, score: number) => {
    setSessions(prev => prev.map(s => s.session_id === id ? { ...s, risk_score: score } : s));
  }, []);

  const active       = sessions.filter(s => s.status === 'ACTIVE');
  const disconnected = sessions.filter(s => s.status === 'DISCONNECTED');

  const q = search.trim().toLowerCase();
  const filtered = q
    ? sessions.filter(s =>
        s.student_name.toLowerCase().includes(q) ||
        s.student_email.toLowerCase().includes(q) ||
        s.exam_title.toLowerCase().includes(q)
      )
    : sessions;

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-[60vh]">
        <Loader2 className="h-7 w-7 animate-spin" style={{ color: '#94A3B8' }} />
      </div>
    );
  }

  return (
    <div className="space-y-6 pb-12">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold" style={{ color: '#0F172A', letterSpacing: '-0.025em' }}>Live Sessions</h1>
          <p className="text-sm mt-1 font-medium" style={{ color: '#64748B' }}>All active exam sessions across every exam</p>
        </div>
        <button
          onClick={() => fetchSessions()}
          className="flex items-center gap-2 px-3 py-2 rounded-lg text-sm font-medium border transition-all duration-150"
          style={{ borderColor: '#E2E8F0', color: '#475569', background: '#fff' }}
        >
          <RefreshCw className="h-3.5 w-3.5" /> Refresh
        </button>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-3 gap-4">
        {[
          { label: 'Active',       value: active.length,                                    iconBg: '#ECFDF5', iconColor: '#15803D', Icon: Users      },
          { label: 'Disconnected', value: disconnected.length,                               iconBg: '#FFFBEB', iconColor: '#B45309', Icon: Activity   },
          { label: 'High Risk',    value: sessions.filter(s => s.risk_score >= 70).length,  iconBg: '#FFF1F2', iconColor: '#BE123C', Icon: ShieldAlert },
        ].map(({ label, value, iconBg, iconColor, Icon }) => (
          <div key={label} className="bg-white rounded-xl border p-5 flex items-center gap-3"
            style={{ borderColor: '#E2E8F0', boxShadow: '0 1px 3px rgba(15,23,42,0.04)' }}>
            <div className="p-2 rounded-lg shrink-0" style={{ background: iconBg }}>
              <Icon className="h-5 w-5" style={{ color: iconColor }} />
            </div>
            <div>
              <p className="text-2xl font-bold" style={{ color: '#0F172A', letterSpacing: '-0.02em' }}>{value}</p>
              <p className="text-xs font-medium" style={{ color: '#64748B' }}>{label}</p>
            </div>
          </div>
        ))}
      </div>

      {/* Search */}
      {sessions.length > 0 && (
        <div className="relative">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4" style={{ color: '#94A3B8' }} />
          <input
            type="text"
            placeholder="Search by student name, email, or exam…"
            value={search}
            onChange={e => setSearch(e.target.value)}
            className="w-full pl-9 pr-4 py-2.5 text-sm rounded-lg border outline-none transition-all"
            style={{ borderColor: '#E2E8F0', color: '#0F172A', background: '#fff' }}
            onFocus={e => { (e.target as HTMLElement).style.borderColor = '#38A3A5'; (e.target as HTMLElement).style.boxShadow = '0 0 0 3px rgba(56,163,165,0.12)'; }}
            onBlur={e => { (e.target as HTMLElement).style.borderColor = '#E2E8F0'; (e.target as HTMLElement).style.boxShadow = 'none'; }}
          />
        </div>
      )}

      {/* Empty state */}
      {sessions.length === 0 ? (
        <div className="bg-white rounded-xl border py-20 text-center"
          style={{ borderColor: '#E2E8F0', boxShadow: '0 1px 3px rgba(15,23,42,0.04)' }}>
          <Users className="h-12 w-12 mx-auto mb-3" style={{ color: '#E2E8F0' }} />
          <p className="text-sm font-medium" style={{ color: '#475569' }}>No active sessions</p>
          <p className="text-xs mt-1 font-medium" style={{ color: '#64748B' }}>Sessions appear here when students are taking exams</p>
        </div>
      ) : (
        <div className="grid lg:grid-cols-2 gap-6">
          {/* Session cards */}
          <div className="space-y-2">
            {filtered.length === 0 ? (
              <p className="text-sm text-center py-6 font-medium" style={{ color: '#64748B' }}>No sessions match your search</p>
            ) : (
              filtered.map(sess => {
                const isSelected = selected?.session_id === sess.session_id;
                return (
                  <div
                    key={sess.session_id}
                    onClick={() => setSelected(s => s?.session_id === sess.session_id ? null : sess)}
                    className="bg-white rounded-xl border cursor-pointer transition-all duration-150 overflow-hidden"
                    style={{
                      borderColor: isSelected ? '#22577A' : '#E2E8F0',
                      boxShadow: isSelected
                        ? '0 0 0 3px rgba(34,87,122,0.12), 0 1px 3px rgba(15,23,42,0.04)'
                        : '0 1px 3px rgba(15,23,42,0.04)',
                      borderLeft: isSelected ? '3px solid #22577A' : '3px solid transparent',
                    }}
                  >
                    <div className="p-4 space-y-3">
                      <div className="flex items-start justify-between gap-2">
                        <div className="flex-1 min-w-0">
                          <p className="font-semibold text-sm truncate" style={{ color: '#0F172A' }}>{sess.student_name}</p>
                          <p className="text-xs truncate mt-0.5 font-medium" style={{ color: '#64748B' }}>{sess.student_email}</p>
                          <p className="text-xs font-medium mt-0.5 truncate" style={{ color: '#22577A' }}>{sess.exam_title}</p>
                        </div>
                        <div className="flex flex-col items-end gap-1.5 shrink-0">
                          <span className="inline-flex items-center px-2 py-0.5 rounded-md text-xs font-semibold border"
                            style={sess.status === 'ACTIVE'
                              ? { background: '#ECFDF5', color: '#15803D', borderColor: '#BBF7D0' }
                              : { background: '#FFFBEB', color: '#B45309', borderColor: '#FDE68A' }}>
                            {sess.status}
                          </span>
                          <div className="flex items-center gap-1 text-xs font-medium" style={{ color: '#64748B' }}>
                            {sess.proctor_connected
                              ? <CheckCircle2 className="h-3 w-3" style={{ color: '#22c55e' }} />
                              : <XCircle className="h-3 w-3" style={{ color: '#94A3B8' }} />}
                            <Server className="h-3 w-3" />
                            <span className="font-mono">{sess.proctor_engine_url?.replace(/https?:\/\//, '').split(':')[1] ?? '—'}</span>
                          </div>
                        </div>
                      </div>

                      <RiskBar score={sess.risk_score} />

                      <div className="flex items-center gap-4 text-xs font-medium" style={{ color: '#64748B' }}>
                        {sess.last_heartbeat && (
                          <span className="flex items-center gap-1">
                            <Activity className="h-3 w-3" style={{ color: '#86EFAC' }} />
                            {new Date(sess.last_heartbeat + 'Z').toLocaleTimeString()}
                          </span>
                        )}
                      </div>
                    </div>
                  </div>
                );
              })
            )}
          </div>

          {/* Detail panel */}
          <div>
            {selected ? (
              <div>
                <div className="flex items-center justify-between mb-4">
                  <h2 className="text-sm font-semibold flex items-center gap-2" style={{ color: '#0F172A' }}>
                    <Eye className="h-4 w-4" style={{ color: '#22577A' }} />
                    {selected.student_name}
                  </h2>
                  <button
                    onClick={() => setSelected(null)}
                    className="text-xs px-2 py-1 rounded-md border transition-colors"
                    style={{ color: '#64748B', borderColor: '#E2E8F0' }}
                  >
                    Close
                  </button>
                </div>
                <SessionDetailPanel
                  key={selected.session_id}
                  session={selected}
                  onScoreUpdate={handleScoreUpdate}
                />
              </div>
            ) : (
              <div className="flex flex-col items-center justify-center h-64 rounded-xl border-2 border-dashed"
                style={{ borderColor: '#E2E8F0' }}>
                <Eye className="h-10 w-10 mb-3" style={{ color: '#E2E8F0' }} />
                <p className="text-sm font-medium" style={{ color: '#64748B' }}>Select a session to monitor</p>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
