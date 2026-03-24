'use client';

import { useEffect, useState, useCallback, useRef } from 'react';
import {
  Cpu, MemoryStick, Activity, Zap, Server, RefreshCw,
  AlertTriangle, CheckCircle2, XCircle, Loader2, ChevronDown, ChevronUp,
} from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { toast } from 'sonner';
import api from '@/lib/axios';

// ── Helpers ──────────────────────────────────────────────────────────────────

function fmt(n: number | undefined | null, dec = 1): string {
  if (n == null) return '—';
  return n.toFixed(dec);
}

function GaugeBar({ value, max, color }: { value: number; max: number; color: string }) {
  const pct = max ? Math.min(100, (value / max) * 100) : 0;
  return (
    <div className="h-2 rounded-full overflow-hidden bg-slate-100">
      <div className="h-2 rounded-full transition-all duration-700" style={{ width: `${pct}%`, background: color }} />
    </div>
  );
}

function StatCell({ label, value, sub, color }: { label: string; value: React.ReactNode; sub?: string; color?: string }) {
  return (
    <div className="bg-slate-50 rounded-lg p-3 border border-slate-100">
      <p className="text-xs text-slate-400 uppercase tracking-wider font-semibold mb-1">{label}</p>
      <p className="text-xl font-bold tabular-nums" style={{ color: color || '#0f172a' }}>{value}</p>
      {sub && <p className="text-xs text-slate-400 mt-0.5">{sub}</p>}
    </div>
  );
}

// ── Container card ────────────────────────────────────────────────────────────

interface ContainerInfo {
  id: string;
  url: string;
  max_sessions: number;
  is_active: boolean;
  active_sessions: number;
}

interface MetricsResult {
  url: string;
  ok: boolean;
  error?: string;
  metrics?: any;
}

function ContainerCard({ container, metricsResult }: { container: ContainerInfo; metricsResult?: MetricsResult }) {
  const [expanded, setExpanded] = useState(true);
  const m = metricsResult?.ok ? metricsResult.metrics : null;
  const sys = m?.system;

  const slotPct = container.max_sessions ? (container.active_sessions / container.max_sessions) * 100 : 0;
  const slotColor = slotPct >= 90 ? '#ef4444' : slotPct >= 60 ? '#f59e0b' : '#22c55e';

  return (
    <Card className="border-slate-200">
      <CardHeader className="pb-3 border-b border-slate-100">
        <div className="flex items-center justify-between gap-3">
          <div className="flex items-center gap-2 min-w-0">
            <Server className="h-4 w-4 text-indigo-500 shrink-0" />
            <span className="font-mono text-sm font-semibold text-slate-800 truncate">{container.url}</span>
          </div>
          <div className="flex items-center gap-2 shrink-0">
            {container.is_active
              ? <Badge className="bg-emerald-100 text-emerald-700 border-emerald-200 text-xs">Active</Badge>
              : <Badge className="bg-slate-100 text-slate-500 border-slate-200 text-xs">Inactive</Badge>}
            {!metricsResult ? (
              <Badge className="bg-slate-100 text-slate-400 text-xs">Fetching…</Badge>
            ) : metricsResult.ok ? (
              <Badge className="bg-emerald-100 text-emerald-700 border-emerald-200 text-xs flex items-center gap-1">
                <CheckCircle2 className="h-3 w-3" /> Reachable
              </Badge>
            ) : (
              <Badge className="bg-rose-100 text-rose-700 border-rose-200 text-xs flex items-center gap-1">
                <XCircle className="h-3 w-3" /> Unreachable
              </Badge>
            )}
            <button onClick={() => setExpanded(e => !e)} className="text-slate-400 hover:text-slate-600">
              {expanded ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
            </button>
          </div>
        </div>

        {/* Slot usage bar */}
        <div className="mt-3 space-y-1">
          <div className="flex justify-between text-xs text-slate-500">
            <span>Session Slots</span>
            <span className="font-semibold" style={{ color: slotColor }}>
              {container.active_sessions} / {container.max_sessions}
            </span>
          </div>
          <GaugeBar value={container.active_sessions} max={container.max_sessions} color={slotColor} />
        </div>
      </CardHeader>

      {expanded && (
        <CardContent className="pt-4 space-y-4">
          {!metricsResult && (
            <div className="flex items-center justify-center py-6 text-slate-400">
              <Loader2 className="h-5 w-5 animate-spin mr-2" /> Fetching metrics…
            </div>
          )}

          {metricsResult && !metricsResult.ok && (
            <div className="flex items-center gap-2 p-3 bg-rose-50 rounded-lg border border-rose-100 text-sm text-rose-700">
              <AlertTriangle className="h-4 w-4 shrink-0" />
              <span>Engine unreachable: {metricsResult.error}</span>
            </div>
          )}

          {m && sys && (
            <>
              {/* System resources */}
              <div>
                <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">System Resources</p>
                <div className="grid grid-cols-2 gap-3">
                  <div className="space-y-1">
                    <div className="flex justify-between text-xs text-slate-500">
                      <span className="flex items-center gap-1"><Cpu className="h-3 w-3" /> CPU</span>
                      <span className="font-semibold" style={{ color: sys.cpu_percent > 80 ? '#ef4444' : '#0f172a' }}>
                        {fmt(sys.cpu_percent)}%
                      </span>
                    </div>
                    <GaugeBar value={sys.cpu_percent} max={100} color={sys.cpu_percent > 80 ? '#ef4444' : '#6366f1'} />
                  </div>
                  <div className="space-y-1">
                    <div className="flex justify-between text-xs text-slate-500">
                      <span className="flex items-center gap-1"><MemoryStick className="h-3 w-3" /> RAM (RSS)</span>
                      <span className="font-semibold">{fmt(sys.mem_rss_mb, 0)} MB</span>
                    </div>
                    <GaugeBar value={sys.mem_rss_mb} max={Math.max(sys.mem_rss_mb * 1.5, 512)} color="#06b6d4" />
                  </div>
                  {sys.gpu_mem_total_mb > 0 && (
                    <>
                      <div className="space-y-1">
                        <div className="flex justify-between text-xs text-slate-500">
                          <span className="flex items-center gap-1"><Zap className="h-3 w-3" /> GPU Util</span>
                          <span className="font-semibold">{fmt(sys.gpu_util_pct)}%</span>
                        </div>
                        <GaugeBar value={sys.gpu_util_pct} max={100} color="#a855f7" />
                      </div>
                      <div className="space-y-1">
                        <div className="flex justify-between text-xs text-slate-500">
                          <span>GPU VRAM</span>
                          <span className="font-semibold">{fmt(sys.gpu_mem_used_mb, 0)} / {fmt(sys.gpu_mem_total_mb, 0)} MB</span>
                        </div>
                        <GaugeBar value={sys.gpu_mem_used_mb} max={sys.gpu_mem_total_mb} color="#ec4899" />
                      </div>
                    </>
                  )}
                </div>
              </div>

              {/* Inference perf */}
              <div>
                <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">Inference Performance</p>
                <div className="grid grid-cols-3 sm:grid-cols-6 gap-2">
                  <StatCell label="YOLO avg" value={`${fmt(m.yolo?.lat_avg_ms)} ms`} />
                  <StatCell label="YOLO p95" value={`${fmt(m.yolo?.lat_p95_ms)} ms`}
                    color={(m.yolo?.lat_p95_ms ?? 0) > 200 ? '#f59e0b' : undefined} />
                  <StatCell label="YOLO p99" value={`${fmt(m.yolo?.lat_p99_ms)} ms`}
                    color={(m.yolo?.lat_p99_ms ?? 0) > 500 ? '#ef4444' : undefined} />
                  <StatCell label="Tick avg" value={`${fmt(m.coordinator?.tick_avg_ms)} ms`} />
                  <StatCell label="Tick p95" value={`${fmt(m.coordinator?.tick_p95_ms)} ms`}
                    color={(m.coordinator?.tick_p95_ms ?? 0) > 150 ? '#f59e0b' : undefined} />
                  <StatCell label="Sessions" value={`${m.coordinator?.active_sessions ?? m.sessions?.active ?? 0} / ${m.coordinator?.max_sessions ?? container.max_sessions}`} />
                </div>
              </div>

              {/* Overview stats */}
              <div>
                <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">Session Stats</p>
                <div className="grid grid-cols-4 gap-2">
                  <StatCell label="Uptime" value={m.uptime ?? '—'} />
                  <StatCell label="Requests" value={(m.requests?.total ?? 0).toLocaleString()} />
                  <StatCell label="Total Alerts" value={m.events?.alerts_total ?? 0}
                    color={(m.events?.alerts_total ?? 0) > 0 ? '#ef4444' : undefined} />
                  <StatCell label="Total Warnings" value={m.events?.warnings_total ?? 0}
                    color={(m.events?.warnings_total ?? 0) > 0 ? '#f59e0b' : undefined} />
                </div>
              </div>

              {/* Active sessions on this engine */}
              {Array.isArray(m.coordinator?.active_session_details) && m.coordinator.active_session_details.length > 0 && (
                <div>
                  <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">Active Engine Sessions</p>
                  <div className="rounded-lg overflow-hidden border border-slate-100">
                    <table className="w-full text-xs">
                      <thead>
                        <tr className="bg-slate-50 border-b border-slate-100">
                          {['Label', 'State', 'FPS', 'Risk', 'Risk State', 'Alerts', 'Warnings'].map(h => (
                            <th key={h} className="px-3 py-2 text-left font-semibold text-slate-400 uppercase tracking-wider">{h}</th>
                          ))}
                        </tr>
                      </thead>
                      <tbody>
                        {m.coordinator.active_session_details.map((s: any, i: number) => (
                          <tr key={i} className={i > 0 ? 'border-t border-slate-50' : ''}>
                            <td className="px-3 py-2 font-medium">{s.label || s.pc_id?.slice(0, 8)}</td>
                            <td className="px-3 py-2 text-slate-500">{s.state}</td>
                            <td className="px-3 py-2 tabular-nums">{s.fps ?? '—'}</td>
                            <td className="px-3 py-2 tabular-nums font-bold"
                              style={{ color: s.risk_score >= 70 ? '#ef4444' : s.risk_score >= 40 ? '#f59e0b' : '#22c55e' }}>
                              {Math.round(s.risk_score ?? 0)}
                            </td>
                            <td className="px-3 py-2">{s.risk_state}</td>
                            <td className="px-3 py-2 tabular-nums" style={{ color: s.alerts > 0 ? '#ef4444' : '#94a3b8' }}>{s.alerts ?? 0}</td>
                            <td className="px-3 py-2 tabular-nums" style={{ color: s.warnings > 0 ? '#f59e0b' : '#94a3b8' }}>{s.warnings ?? 0}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}
            </>
          )}
        </CardContent>
      )}
    </Card>
  );
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function EngineMonitorPage() {
  const [containers, setContainers] = useState<ContainerInfo[]>([]);
  const [metrics, setMetrics] = useState<MetricsResult[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const intervalRef = useRef<NodeJS.Timeout | null>(null);

  const fetchAll = useCallback(async (silent = false) => {
    if (!silent) setRefreshing(true);
    try {
      const [containersRes, metricsRes] = await Promise.all([
        api.get('/admin/engine/containers'),
        api.get('/admin/engine/metrics'),
      ]);
      setContainers(containersRes.data);
      setMetrics(metricsRes.data);
    } catch {
      if (!silent) toast.error('Failed to fetch engine data');
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, []);

  useEffect(() => {
    fetchAll();
    intervalRef.current = setInterval(() => fetchAll(true), 10000);
    return () => { if (intervalRef.current) clearInterval(intervalRef.current); };
  }, [fetchAll]);

  const totalSlots = containers.reduce((s, c) => s + c.max_sessions, 0);
  const usedSlots = containers.reduce((s, c) => s + c.active_sessions, 0);
  const reachable = metrics.filter(m => m.ok).length;

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-[60vh]">
        <Loader2 className="h-8 w-8 animate-spin text-slate-400" />
      </div>
    );
  }

  return (
    <div className="space-y-6 pb-12">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-slate-900">Engine Monitor</h1>
          <p className="text-sm text-slate-500 mt-0.5">Real-time proctoring engine health and resource usage</p>
        </div>
        <Button variant="outline" size="sm" onClick={() => fetchAll()} disabled={refreshing} className="gap-2">
          <RefreshCw className={`h-4 w-4 ${refreshing ? 'animate-spin' : ''}`} />
          Refresh
        </Button>
      </div>

      {/* Summary row */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        <Card className="shadow-none border-slate-200">
          <CardContent className="pt-5 pb-4">
            <p className="text-2xl font-bold text-slate-900">{containers.filter(c => c.is_active).length}</p>
            <p className="text-xs text-slate-500 mt-0.5">Active Containers</p>
          </CardContent>
        </Card>
        <Card className="shadow-none border-slate-200">
          <CardContent className="pt-5 pb-4">
            <p className="text-2xl font-bold text-slate-900">{usedSlots} / {totalSlots}</p>
            <p className="text-xs text-slate-500 mt-0.5">Session Slots Used</p>
          </CardContent>
        </Card>
        <Card className="shadow-none border-slate-200">
          <CardContent className="pt-5 pb-4">
            <p className={`text-2xl font-bold ${reachable === metrics.length ? 'text-emerald-600' : 'text-rose-600'}`}>
              {reachable} / {metrics.length}
            </p>
            <p className="text-xs text-slate-500 mt-0.5">Containers Reachable</p>
          </CardContent>
        </Card>
        <Card className="shadow-none border-slate-200">
          <CardContent className="pt-5 pb-4">
            <p className={`text-2xl font-bold ${reachable === metrics.length ? 'text-emerald-600' : 'text-amber-600'}`}>
              {reachable === metrics.length ? 'Healthy' : 'Degraded'}
            </p>
            <p className="text-xs text-slate-500 mt-0.5">Overall Status</p>
          </CardContent>
        </Card>
      </div>

      {/* Per-container cards */}
      {containers.length === 0 ? (
        <Card className="border-slate-200">
          <CardContent className="py-16 text-center text-slate-400">
            <Server className="h-10 w-10 mx-auto mb-3 text-slate-200" />
            <p>No engine containers configured.</p>
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-4">
          {containers.map(c => (
            <ContainerCard
              key={c.id}
              container={c}
              metricsResult={metrics.find(m => m.url === c.url)}
            />
          ))}
        </div>
      )}
    </div>
  );
}
