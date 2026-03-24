'use client';

import { useEffect, useState, useCallback, useRef } from 'react';
import {
  RefreshCw, Users, ShieldAlert, Activity, Loader2,
  AlertTriangle, Eye, Bot, CheckCircle2, XCircle, Server,
} from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
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
  violation_count: number;
  last_heartbeat: string | null;
  proctor_connected: boolean;
  proctor_engine_url: string | null;
  terminated_reason: string | null;
}

interface AlertEntry { message: string; key?: string; score_added?: number; proof_url?: string; proof_type?: string; ts: number; }
interface WarningEntry { message: string; ts: number; }
interface RiskInfo { score: number; fixed: number; decaying?: number; state: string; terminated?: boolean; }

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
    <span className="text-xs font-bold px-2 py-0.5 rounded border"
      style={{ background: `${color}22`, color, borderColor: `${color}44` }}>
      {labels[state] ?? state}
    </span>
  );
}

function RiskBar({ score }: { score: number }) {
  const color = score >= 70 ? '#ef4444' : score >= 40 ? '#f59e0b' : '#22c55e';
  return (
    <div className="flex items-center gap-2">
      <div className="flex-1 h-1.5 bg-slate-100 rounded-full overflow-hidden">
        <div className="h-full rounded-full transition-all" style={{ width: `${Math.min(score, 100)}%`, background: color }} />
      </div>
      <span className="text-xs font-mono font-bold w-7 text-right" style={{ color }}>{score}</span>
    </div>
  );
}

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

// ── Live session detail panel ─────────────────────────────────────────────────

function SessionDetailPanel({ session, onScoreUpdate }: {
  session: LiveSession;
  onScoreUpdate: (id: string, score: number) => void;
}) {
  const [frameUrl, setFrameUrl] = useState<string | null>(null);
  const [alerts, setAlerts] = useState<AlertEntry[]>([]);
  const [warnings, setWarnings] = useState<WarningEntry[]>([]);
  const [liveRisk, setLiveRisk] = useState<RiskInfo>({ score: session.risk_score, fixed: 0, state: 'NORMAL' });
  const [alertTab, setAlertTab] = useState<'alerts' | 'warnings'>('alerts');
  const sseRef = useRef<(() => void) | null>(null);
  const frameRef = useRef<NodeJS.Timeout | null>(null);
  const prevFrame = useRef<string | null>(null);

  const fetchFrame = useCallback(async () => {
    const token = localStorage.getItem('access_token') || '';
    const base = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';
    try {
      const res = await fetch(`${base}/admin/sessions/${session.session_id}/live-frame`,
        { headers: { Authorization: `Bearer ${token}` } });
      if (res.status === 204 || !res.ok) return;
      const blob = await res.blob();
      if (!blob.size) return;
      const url = URL.createObjectURL(blob);
      if (prevFrame.current) URL.revokeObjectURL(prevFrame.current);
      prevFrame.current = url;
      setFrameUrl(url);
    } catch {}
  }, [session.session_id]);

  useEffect(() => {
    setAlerts([]);
    setWarnings([]);
    setFrameUrl(null);
    setLiveRisk({ score: session.risk_score, fixed: 0, state: 'NORMAL' });

    if (session.status !== 'ACTIVE') return;

    fetchFrame();
    frameRef.current = setInterval(fetchFrame, 2000);

    const token = localStorage.getItem('access_token') || '';
    const base = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';
    sseRef.current = openSSE(
      `${base}/admin/sessions/${session.session_id}/live-stream`,
      token,
      {
        message: (d: any) => {
          if (d?.risk) {
            const risk: RiskInfo = { score: d.risk.score ?? 0, fixed: d.risk.fixed ?? 0, decaying: d.risk.decaying, state: d.risk.state ?? 'NORMAL', terminated: d.risk.terminated };
            setLiveRisk(risk);
            onScoreUpdate(session.session_id, Math.round(risk.score));
          }
          if (d?.type === 'alert') {
            setAlerts(prev => [{ message: d.message || d.key || 'Alert', key: d.key, score_added: d.score_added, proof_url: d.proof_url, proof_type: d.proof_type, ts: Date.now() }, ...prev].slice(0, 100));
          } else if (d?.type === 'warning') {
            setWarnings(prev => [{ message: d.message || 'Warning', ts: Date.now() }, ...prev].slice(0, 100));
          }
        },
      }
    );

    return () => {
      if (frameRef.current) clearInterval(frameRef.current);
      sseRef.current?.();
      if (prevFrame.current) URL.revokeObjectURL(prevFrame.current);
    };
  }, [session.session_id, session.status]);

  const scoreColor = RISK_COLORS[liveRisk.state] ?? '#22c55e';

  return (
    <div className="space-y-4">
      {/* Live camera */}
      <Card className="bg-slate-900 border-slate-800">
        <CardHeader className="pb-2">
          <CardTitle className="text-sm text-slate-300 flex items-center gap-2">
            <Bot className="h-4 w-4 text-indigo-400" /> AI Feed — {session.student_name}
          </CardTitle>
        </CardHeader>
        <CardContent>
          {frameUrl ? (
            // eslint-disable-next-line @next/next/no-img-element
            <img src={frameUrl} alt="Live feed" className="w-full aspect-video rounded-lg object-cover bg-slate-800" />
          ) : (
            <div className="aspect-video bg-slate-800 rounded-lg flex items-center justify-center border border-slate-700">
              <p className="text-slate-500 text-sm">{session.status === 'ACTIVE' && session.proctor_connected ? 'Loading feed…' : 'Engine not connected'}</p>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Risk card */}
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
          <div className="flex items-end gap-2">
            <p className="text-5xl font-bold tabular-nums transition-all" style={{ color: scoreColor }}>
              {Math.round(liveRisk.score)}
            </p>
            <span className="text-xs text-slate-400 mb-1.5">/ 100</span>
          </div>
          <div className="h-2 rounded-full overflow-hidden bg-slate-100">
            <div className="h-2 rounded-full transition-all duration-700"
              style={{ width: `${Math.min(liveRisk.score, 100)}%`, background: scoreColor }} />
          </div>
          <div className="flex gap-4 text-xs text-slate-500">
            <span>Fixed <span className="font-semibold text-slate-700">{Math.round(liveRisk.fixed)}</span></span>
            {liveRisk.decaying !== undefined && (
              <span>Decaying <span className="font-semibold text-slate-700">{Math.round(liveRisk.decaying)}</span></span>
            )}
          </div>
          <div className="grid grid-cols-3 gap-2 pt-1 border-t border-slate-100 text-center">
            <div><p className="text-lg font-bold text-rose-500">{alerts.length}</p><p className="text-xs text-slate-400">Alerts</p></div>
            <div><p className="text-lg font-bold text-amber-500">{warnings.length}</p><p className="text-xs text-slate-400">Warnings</p></div>
            <div><p className="text-lg font-bold text-slate-700">{session.violation_count}</p><p className="text-xs text-slate-400">Violations</p></div>
          </div>
        </CardContent>
      </Card>

      {/* Alert / Warning log */}
      <Card>
        <CardHeader className="pb-0 border-b border-slate-100">
          <div className="flex gap-1">
            {(['alerts', 'warnings'] as const).map(tab => (
              <button key={tab} onClick={() => setAlertTab(tab)}
                className={`px-4 py-2.5 text-sm font-semibold border-b-2 -mb-px transition-colors capitalize
                  ${alertTab === tab
                    ? (tab === 'alerts' ? 'border-rose-500 text-rose-600' : 'border-amber-500 text-amber-600')
                    : 'border-transparent text-slate-400 hover:text-slate-600'}`}>
                {tab}
                {(tab === 'alerts' ? alerts : warnings).length > 0 && (
                  <span className={`ml-1.5 text-xs px-1.5 py-0.5 rounded-full ${tab === 'alerts' ? 'bg-rose-100 text-rose-600' : 'bg-amber-100 text-amber-600'}`}>
                    {(tab === 'alerts' ? alerts : warnings).length}
                  </span>
                )}
              </button>
            ))}
          </div>
        </CardHeader>
        <CardContent className="pt-3">
          <div className="space-y-2 max-h-56 overflow-y-auto">
            {alertTab === 'alerts' && (alerts.length === 0
              ? <p className="text-sm text-slate-400 text-center py-6">No alerts yet</p>
              : alerts.map((a, i) => (
                <div key={i} className="flex items-start gap-2 px-3 py-2 bg-rose-50/50 rounded-lg border border-rose-100 text-xs">
                  <AlertTriangle className="h-3.5 w-3.5 text-rose-500 shrink-0 mt-0.5" />
                  <div>
                    <p className="font-medium text-rose-700">{a.message}</p>
                    {a.score_added !== undefined && a.score_added > 0 && (
                      <p className="text-rose-400 mt-0.5">+{a.score_added.toFixed(1)} pts · {new Date(a.ts).toLocaleTimeString()}</p>
                    )}
                  </div>
                </div>
              ))
            )}
            {alertTab === 'warnings' && (warnings.length === 0
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
    </div>
  );
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function SessionsMonitorPage() {
  const [sessions, setSessions] = useState<LiveSession[]>([]);
  const [loading, setLoading] = useState(true);
  const [selected, setSelected] = useState<LiveSession | null>(null);
  const intervalRef = useRef<NodeJS.Timeout | null>(null);

  const fetchSessions = useCallback(async (silent = false) => {
    try {
      const res = await api.get('/admin/sessions');
      setSessions(res.data);
    } catch {
      if (!silent) toast.error('Failed to load sessions');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchSessions();
    intervalRef.current = setInterval(() => fetchSessions(true), 15000);
    return () => { if (intervalRef.current) clearInterval(intervalRef.current); };
  }, [fetchSessions]);

  // Sync selected with latest data
  useEffect(() => {
    if (!selected) return;
    const latest = sessions.find(s => s.session_id === selected.session_id);
    if (latest) setSelected(latest);
  }, [sessions]);

  const handleScoreUpdate = useCallback((id: string, score: number) => {
    setSessions(prev => prev.map(s => s.session_id === id ? { ...s, risk_score: score } : s));
  }, []);

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-[60vh]">
        <Loader2 className="h-8 w-8 animate-spin text-slate-400" />
      </div>
    );
  }

  const active = sessions.filter(s => s.status === 'ACTIVE');
  const disconnected = sessions.filter(s => s.status === 'DISCONNECTED');

  return (
    <div className="space-y-6 pb-12">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-slate-900">Live Sessions</h1>
          <p className="text-sm text-slate-500 mt-0.5">All active exam sessions across every exam</p>
        </div>
        <Button variant="outline" size="sm" onClick={() => fetchSessions()} className="gap-2">
          <RefreshCw className="h-4 w-4" /> Refresh
        </Button>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-3 gap-4">
        <Card className="shadow-none border-slate-200">
          <CardContent className="pt-5 pb-4 flex items-center gap-3">
            <div className="bg-emerald-100 p-2 rounded-lg"><Users className="h-5 w-5 text-emerald-600" /></div>
            <div><p className="text-2xl font-bold">{active.length}</p><p className="text-xs text-slate-500">Active</p></div>
          </CardContent>
        </Card>
        <Card className="shadow-none border-slate-200">
          <CardContent className="pt-5 pb-4 flex items-center gap-3">
            <div className="bg-amber-100 p-2 rounded-lg"><Activity className="h-5 w-5 text-amber-600" /></div>
            <div><p className="text-2xl font-bold">{disconnected.length}</p><p className="text-xs text-slate-500">Disconnected</p></div>
          </CardContent>
        </Card>
        <Card className="shadow-none border-slate-200">
          <CardContent className="pt-5 pb-4 flex items-center gap-3">
            <div className="bg-rose-100 p-2 rounded-lg"><ShieldAlert className="h-5 w-5 text-rose-600" /></div>
            <div>
              <p className="text-2xl font-bold">{sessions.filter(s => s.risk_score >= 70).length}</p>
              <p className="text-xs text-slate-500">High Risk</p>
            </div>
          </CardContent>
        </Card>
      </div>

      {sessions.length === 0 ? (
        <Card className="border-slate-200">
          <CardContent className="py-20 text-center text-slate-400">
            <Users className="h-12 w-12 mx-auto mb-3 text-slate-200" />
            <p className="font-medium">No active sessions</p>
            <p className="text-sm mt-1">Sessions appear here when students are taking exams</p>
          </CardContent>
        </Card>
      ) : (
        <div className="grid lg:grid-cols-2 gap-6">
          {/* Session cards */}
          <div className="space-y-3">
            {sessions.map(sess => (
              <Card key={sess.session_id}
                className={`cursor-pointer transition-all hover:shadow-md border-2 ${selected?.session_id === sess.session_id ? 'border-indigo-400 shadow-md' : 'border-transparent shadow-sm'}`}
                onClick={() => setSelected(s => s?.session_id === sess.session_id ? null : sess)}>
                <CardContent className="p-4 space-y-3">
                  <div className="flex items-start justify-between gap-2">
                    <div className="flex-1 min-w-0">
                      <p className="font-semibold text-slate-900 truncate">{sess.student_name}</p>
                      <p className="text-xs text-slate-400 truncate">{sess.student_email}</p>
                      <p className="text-xs text-indigo-600 font-medium mt-0.5 truncate">{sess.exam_title}</p>
                    </div>
                    <div className="flex flex-col items-end gap-1.5 shrink-0">
                      <Badge variant="outline" className={`text-xs ${sess.status === 'ACTIVE' ? 'bg-emerald-50 text-emerald-700 border-emerald-200' : 'bg-amber-50 text-amber-700 border-amber-200'}`}>
                        {sess.status}
                      </Badge>
                      <div className="flex items-center gap-1 text-xs text-slate-400">
                        {sess.proctor_connected
                          ? <CheckCircle2 className="h-3 w-3 text-emerald-500" />
                          : <XCircle className="h-3 w-3 text-slate-300" />}
                        <Server className="h-3 w-3" />
                        {sess.proctor_engine_url?.replace(/https?:\/\//, '').split(':')[1] ?? '—'}
                      </div>
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
                        {new Date(sess.last_heartbeat + 'Z').toLocaleTimeString()}
                      </span>
                    )}
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>

          {/* Detail panel */}
          <div>
            {selected ? (
              <div>
                <div className="flex items-center justify-between mb-4">
                  <h2 className="text-lg font-semibold text-slate-900 flex items-center gap-2">
                    <Eye className="h-5 w-5 text-indigo-500" /> {selected.student_name}
                  </h2>
                  <button onClick={() => setSelected(null)} className="text-xs text-slate-400 hover:text-slate-600">Close ×</button>
                </div>
                <SessionDetailPanel session={selected} onScoreUpdate={handleScoreUpdate} />
              </div>
            ) : (
              <div className="flex flex-col items-center justify-center h-64 border-2 border-dashed border-slate-200 rounded-xl">
                <Eye className="h-10 w-10 text-slate-200 mb-3" />
                <p className="text-slate-400 text-sm">Select a session to monitor</p>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
