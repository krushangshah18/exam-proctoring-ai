'use client';

import { useEffect, useState, useCallback, useRef } from 'react';
import {
  Cpu, MemoryStick, Activity, Zap, Server, RefreshCw,
  AlertTriangle, CheckCircle2, XCircle, Loader2, ChevronDown, ChevronUp,
} from 'lucide-react';
import { toast } from 'sonner';
import api from '@/lib/axios';

// ── Helpers ───────────────────────────────────────────────────────────────────
function fmt(n: number | undefined | null, dec = 1): string {
  if (n == null) return '—';
  return n.toFixed(dec);
}

function GaugeBar({ value, max, color }: { value: number; max: number; color: string }) {
  const pct = max ? Math.min(100, (value / max) * 100) : 0;
  return (
    <div className="h-1.5 rounded-full overflow-hidden" style={{ background: '#F1F5F9' }}>
      <div className="h-full rounded-full transition-all duration-700" style={{ width: `${pct}%`, background: color }} />
    </div>
  );
}

function MetricCell({ label, value, sub, color }: { label: string; value: React.ReactNode; sub?: string; color?: string }) {
  return (
    <div className="rounded-lg p-3 border" style={{ background: '#F8FAFC', borderColor: '#E2E8F0' }}>
      <p className="text-[10px] font-semibold uppercase tracking-wider mb-1" style={{ color: '#64748B' }}>{label}</p>
      <p className="text-lg font-bold tabular-nums" style={{ color: color || '#0F172A' }}>{value}</p>
      {sub && <p className="text-xs mt-0.5 font-medium" style={{ color: '#64748B' }}>{sub}</p>}
    </div>
  );
}

// ── Container card ─────────────────────────────────────────────────────────────
interface ContainerInfo {
  id: string; url: string; max_sessions: number;
  is_active: boolean; active_sessions: number;
}
interface MetricsResult {
  url: string; ok: boolean; error?: string; metrics?: any;
}

function ContainerCard({ container, metricsResult }: { container: ContainerInfo; metricsResult?: MetricsResult }) {
  const [expanded, setExpanded] = useState(true);
  const m   = metricsResult?.ok ? metricsResult.metrics : null;
  const sys = m?.system;
  const slotPct   = container.max_sessions ? (container.active_sessions / container.max_sessions) * 100 : 0;
  const slotColor = slotPct >= 90 ? '#EF4444' : slotPct >= 60 ? '#F59E0B' : '#22C55E';

  return (
    <div className="bg-white rounded-xl border overflow-hidden"
      style={{ borderColor: '#E2E8F0', boxShadow: '0 1px 3px rgba(15,23,42,0.04)' }}>
      {/* Header */}
      <div className="p-5" style={{ borderBottom: '1px solid #F1F5F9' }}>
        <div className="flex items-center justify-between gap-3 mb-4">
          <div className="flex items-center gap-2.5 min-w-0">
            <div className="h-8 w-8 rounded-lg flex items-center justify-center shrink-0"
              style={{ background: '#EFF6FF' }}>
              <Server className="h-4 w-4" style={{ color: '#22577A' }} />
            </div>
            <span className="font-mono text-sm font-semibold truncate" style={{ color: '#0F172A' }}>{container.url}</span>
          </div>
          <div className="flex items-center gap-2 shrink-0">
            <span className="px-2 py-0.5 rounded-md text-xs font-semibold border"
              style={container.is_active
                ? { background: '#ECFDF5', color: '#15803D', borderColor: '#BBF7D0' }
                : { background: '#F8FAFC', color: '#64748B', borderColor: '#E2E8F0' }}>
              {container.is_active ? 'Active' : 'Inactive'}
            </span>
            {!metricsResult ? (
              <span className="px-2 py-0.5 rounded-md text-xs font-semibold border"
                style={{ background: '#F8FAFC', color: '#64748B', borderColor: '#E2E8F0' }}>
                Fetching…
              </span>
            ) : metricsResult.ok ? (
              <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-xs font-semibold border"
                style={{ background: '#ECFDF5', color: '#15803D', borderColor: '#BBF7D0' }}>
                <CheckCircle2 className="h-3 w-3" /> Reachable
              </span>
            ) : (
              <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-xs font-semibold border"
                style={{ background: '#FFF1F2', color: '#BE123C', borderColor: '#FECDD3' }}>
                <XCircle className="h-3 w-3" /> Unreachable
              </span>
            )}
            <button onClick={() => setExpanded(e => !e)}
              className="p-1 rounded-lg transition-colors"
              style={{ color: '#64748B' }}>
              {expanded ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
            </button>
          </div>
        </div>

        {/* Slot bar */}
        <div className="space-y-1.5">
          <div className="flex justify-between text-xs">
            <span className="font-medium" style={{ color: '#64748B' }}>Session Slots</span>
            <span className="font-semibold tabular-nums" style={{ color: slotColor }}>
              {container.active_sessions} / {container.max_sessions}
            </span>
          </div>
          <GaugeBar value={container.active_sessions} max={container.max_sessions} color={slotColor} />
        </div>
      </div>

      {/* Body */}
      {expanded && (
        <div className="p-5 space-y-5">
          {!metricsResult && (
            <div className="flex items-center justify-center py-8 gap-2 font-medium" style={{ color: '#64748B' }}>
              <Loader2 className="h-5 w-5 animate-spin" /> Fetching metrics…
            </div>
          )}
          {metricsResult && !metricsResult.ok && (
            <div className="flex items-center gap-2.5 p-3.5 rounded-lg border text-sm"
              style={{ background: '#FFF1F2', borderColor: '#FECDD3', color: '#BE123C' }}>
              <AlertTriangle className="h-4 w-4 shrink-0" />
              Engine unreachable: {metricsResult.error}
            </div>
          )}

          {m && sys && (
            <>
              {/* System resources */}
              <div>
                <p className="text-[10px] font-semibold uppercase tracking-wider mb-3" style={{ color: '#64748B' }}>System Resources</p>
                <div className="grid grid-cols-2 gap-4">
                  {[
                    { icon: Cpu, label: 'CPU', value: `${fmt(sys.cpu_percent)}%`, pct: sys.cpu_percent, max: 100, color: sys.cpu_percent > 80 ? '#EF4444' : '#22577A' },
                    { icon: MemoryStick, label: 'RAM (RSS)', value: `${fmt(sys.mem_rss_mb, 0)} MB`, pct: sys.mem_rss_mb, max: Math.max(sys.mem_rss_mb * 1.5, 512), color: '#38A3A5' },
                  ].map(({ icon: Icon, label, value, pct, max, color }) => (
                    <div key={label} className="space-y-1.5">
                      <div className="flex justify-between text-xs">
                        <span className="flex items-center gap-1 font-medium" style={{ color: '#64748B' }}>
                          <Icon className="h-3.5 w-3.5" /> {label}
                        </span>
                        <span className="font-semibold tabular-nums" style={{ color }}>{value}</span>
                      </div>
                      <GaugeBar value={pct} max={max} color={color} />
                    </div>
                  ))}
                  {sys.gpu_mem_total_mb > 0 && (
                    <>
                      <div className="space-y-1.5">
                        <div className="flex justify-between text-xs">
                          <span className="flex items-center gap-1 font-medium" style={{ color: '#64748B' }}><Zap className="h-3.5 w-3.5" /> GPU Util</span>
                          <span className="font-semibold tabular-nums" style={{ color: '#7C3AED' }}>{fmt(sys.gpu_util_pct)}%</span>
                        </div>
                        <GaugeBar value={sys.gpu_util_pct} max={100} color="#7C3AED" />
                      </div>
                      <div className="space-y-1.5">
                        <div className="flex justify-between text-xs">
                          <span className="font-medium" style={{ color: '#64748B' }}>GPU VRAM</span>
                          <span className="font-semibold tabular-nums" style={{ color: '#DB2777' }}>{fmt(sys.gpu_mem_used_mb, 0)} / {fmt(sys.gpu_mem_total_mb, 0)} MB</span>
                        </div>
                        <GaugeBar value={sys.gpu_mem_used_mb} max={sys.gpu_mem_total_mb} color="#DB2777" />
                      </div>
                    </>
                  )}
                </div>
              </div>

              {/* Inference */}
              <div>
                <p className="text-[10px] font-semibold uppercase tracking-wider mb-3" style={{ color: '#64748B' }}>Inference Performance</p>
                <div className="grid grid-cols-3 sm:grid-cols-6 gap-2">
                  <MetricCell label="YOLO avg" value={`${fmt(m.yolo?.lat_avg_ms)} ms`} />
                  <MetricCell label="YOLO p95" value={`${fmt(m.yolo?.lat_p95_ms)} ms`} color={(m.yolo?.lat_p95_ms ?? 0) > 200 ? '#F59E0B' : undefined} />
                  <MetricCell label="YOLO p99" value={`${fmt(m.yolo?.lat_p99_ms)} ms`} color={(m.yolo?.lat_p99_ms ?? 0) > 500 ? '#EF4444' : undefined} />
                  <MetricCell label="Tick avg" value={`${fmt(m.coordinator?.tick_avg_ms)} ms`} />
                  <MetricCell label="Tick p95" value={`${fmt(m.coordinator?.tick_p95_ms)} ms`} color={(m.coordinator?.tick_p95_ms ?? 0) > 150 ? '#F59E0B' : undefined} />
                  <MetricCell label="Sessions" value={`${m.coordinator?.active_sessions ?? 0} / ${m.coordinator?.max_sessions ?? container.max_sessions}`} />
                </div>
              </div>

              {/* Overview */}
              <div>
                <p className="text-[10px] font-semibold uppercase tracking-wider mb-3" style={{ color: '#64748B' }}>Session Stats</p>
                <div className="grid grid-cols-4 gap-2">
                  <MetricCell label="Uptime" value={m.uptime ?? '—'} />
                  <MetricCell label="Requests" value={(m.requests?.total ?? 0).toLocaleString()} />
                  <MetricCell label="Total Alerts" value={m.events?.alerts_total ?? 0} color={(m.events?.alerts_total ?? 0) > 0 ? '#EF4444' : undefined} />
                  <MetricCell label="Warnings" value={m.events?.warnings_total ?? 0} color={(m.events?.warnings_total ?? 0) > 0 ? '#F59E0B' : undefined} />
                </div>
              </div>

              {/* Active session details */}
              {Array.isArray(m.coordinator?.active_session_details) && m.coordinator.active_session_details.length > 0 && (
                <div>
                  <p className="text-[10px] font-semibold uppercase tracking-wider mb-3" style={{ color: '#64748B' }}>Active Engine Sessions</p>
                  <div className="rounded-lg overflow-hidden border" style={{ borderColor: '#E2E8F0' }}>
                    <table className="w-full text-xs">
                      <thead>
                        <tr style={{ background: '#F8FAFC', borderBottom: '1px solid #F1F5F9' }}>
                          {['Label', 'State', 'FPS', 'Risk', 'Risk State', 'Alerts', 'Warnings'].map(h => (
                            <th key={h} className="px-3 py-2.5 text-left font-semibold uppercase tracking-wider"
                              style={{ color: '#64748B' }}>{h}</th>
                          ))}
                        </tr>
                      </thead>
                      <tbody>
                        {m.coordinator.active_session_details.map((s: any, i: number) => (
                          <tr key={i} style={{ borderTop: i > 0 ? '1px solid #F8FAFC' : 'none' }}>
                            <td className="px-3 py-2.5 font-medium" style={{ color: '#0F172A' }}>{s.label || s.pc_id?.slice(0, 8)}</td>
                            <td className="px-3 py-2.5" style={{ color: '#475569' }}>{s.state}</td>
                            <td className="px-3 py-2.5 tabular-nums" style={{ color: '#475569' }}>{s.fps ?? '—'}</td>
                            <td className="px-3 py-2.5 tabular-nums font-bold"
                              style={{ color: s.risk_score >= 70 ? '#EF4444' : s.risk_score >= 40 ? '#F59E0B' : '#22C55E' }}>
                              {Math.round(s.risk_score ?? 0)}
                            </td>
                            <td className="px-3 py-2.5" style={{ color: '#475569' }}>{s.risk_state}</td>
                            <td className="px-3 py-2.5 tabular-nums font-semibold" style={{ color: s.alerts > 0 ? '#EF4444' : '#64748B' }}>{s.alerts ?? 0}</td>
                            <td className="px-3 py-2.5 tabular-nums font-semibold" style={{ color: s.warnings > 0 ? '#F59E0B' : '#64748B' }}>{s.warnings ?? 0}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}
            </>
          )}
        </div>
      )}
    </div>
  );
}

// ── Main page ─────────────────────────────────────────────────────────────────
export default function EngineMonitorPage() {
  const [containers, setContainers] = useState<ContainerInfo[]>([]);
  const [metrics, setMetrics]       = useState<MetricsResult[]>([]);
  const [loading, setLoading]       = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const intervalRef = useRef<NodeJS.Timeout | null>(null);

  const fetchAll = useCallback(async (silent = false) => {
    if (!silent) setRefreshing(true);
    try {
      const [cr, mr] = await Promise.all([
        api.get('/admin/engine/containers'),
        api.get('/admin/engine/metrics'),
      ]);
      setContainers(cr.data);
      setMetrics(mr.data);
    } catch { if (!silent) toast.error('Failed to fetch engine data'); }
    finally { setLoading(false); setRefreshing(false); }
  }, []);

  useEffect(() => {
    fetchAll();
    intervalRef.current = setInterval(() => fetchAll(true), 10000);
    return () => { if (intervalRef.current) clearInterval(intervalRef.current); };
  }, [fetchAll]);

  const totalSlots = containers.reduce((s, c) => s + c.max_sessions, 0);
  const usedSlots  = containers.reduce((s, c) => s + c.active_sessions, 0);
  const reachable  = metrics.filter(m => m.ok).length;
  const healthy    = reachable === metrics.length;

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-[60vh]">
        <Loader2 className="h-7 w-7 animate-spin" style={{ color: '#94A3B8' }} />
      </div>
    );
  }

  return (
    <div className="space-y-6 max-w-6xl pb-12">
      {/* Header */}
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold" style={{ color: '#0F172A', letterSpacing: '-0.025em' }}>Engine Monitor</h1>
          <p className="text-sm mt-1 font-medium" style={{ color: '#64748B' }}>Real-time proctoring engine health and resource usage</p>
        </div>
        <button
          onClick={() => fetchAll()} disabled={refreshing}
          className="flex items-center gap-2 px-3 py-2 rounded-lg text-sm font-medium border transition-all duration-150"
          style={{ borderColor: '#E2E8F0', color: '#475569', background: '#fff' }}
        >
          <RefreshCw className={`h-3.5 w-3.5 ${refreshing ? 'animate-spin' : ''}`} /> Refresh
        </button>
      </div>

      {/* Summary */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        {[
          { label: 'Active Containers',    value: containers.filter(c => c.is_active).length, color: '#0F172A' },
          { label: 'Session Slots Used',   value: `${usedSlots} / ${totalSlots}`,              color: '#0F172A' },
          { label: 'Containers Reachable', value: `${reachable} / ${metrics.length}`,          color: healthy ? '#15803D' : '#BE123C' },
          { label: 'Overall Status',       value: healthy ? 'Healthy' : 'Degraded',            color: healthy ? '#15803D' : '#D97706' },
        ].map(({ label, value, color }) => (
          <div key={label} className="bg-white rounded-xl border p-5"
            style={{ borderColor: '#E2E8F0', boxShadow: '0 1px 3px rgba(15,23,42,0.04)' }}>
            <p className="text-2xl font-bold tabular-nums" style={{ color }}>{value}</p>
            <p className="text-xs mt-0.5 font-medium" style={{ color: '#64748B' }}>{label}</p>
          </div>
        ))}
      </div>

      {/* Containers */}
      {containers.length === 0 ? (
        <div className="bg-white rounded-xl border p-16 text-center"
          style={{ borderColor: '#E2E8F0' }}>
          <Server className="h-10 w-10 mx-auto mb-3" style={{ color: '#E2E8F0' }} />
          <p className="font-medium" style={{ color: '#64748B' }}>No engine containers configured.</p>
        </div>
      ) : (
        <div className="space-y-4">
          {containers.map(c => (
            <ContainerCard key={c.id} container={c} metricsResult={metrics.find(m => m.url === c.url)} />
          ))}
        </div>
      )}
    </div>
  );
}
