"use client";

import { useEffect, useState, useCallback, useRef } from "react";
import {
  Cpu,
  MemoryStick,
  Zap,
  Server,
  RefreshCw,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  Loader2,
  ChevronDown,
  ChevronUp,
  Play,
  Square,
  Activity,
  Power,
  Edit2,
  X,
  Check,
  CloudLightning,
} from "lucide-react";
import { toast } from "sonner";
import api from "@/lib/axios";

// ── Helpers ───────────────────────────────────────────────────────────────────
function fmt(n: number | undefined | null, dec = 1): string {
  if (n == null) return "—";
  return n.toFixed(dec);
}

function GaugeBar({
  value,
  max,
  color,
}: {
  value: number;
  max: number;
  color: string;
}) {
  const pct = max ? Math.min(100, (value / max) * 100) : 0;
  return (
    <div
      className="h-1.5 rounded-full overflow-hidden"
      style={{ background: "#F1F5F9" }}
    >
      <div
        className="h-full rounded-full transition-all duration-700"
        style={{ width: `${pct}%`, background: color }}
      />
    </div>
  );
}

function MetricCell({
  label,
  value,
  sub,
  color,
}: {
  label: string;
  value: React.ReactNode;
  sub?: string;
  color?: string;
}) {
  return (
    <div
      className="rounded-lg p-3 border"
      style={{ background: "#F8FAFC", borderColor: "#E2E8F0" }}
    >
      <p
        className="text-[10px] font-semibold uppercase tracking-wider mb-1"
        style={{ color: "#64748B" }}
      >
        {label}
      </p>
      <p
        className="text-lg font-bold tabular-nums"
        style={{ color: color || "#0F172A" }}
      >
        {value}
      </p>
      {sub && (
        <p className="text-xs mt-0.5 font-medium" style={{ color: "#64748B" }}>
          {sub}
        </p>
      )}
    </div>
  );
}

// ── Types ─────────────────────────────────────────────────────────────────────
interface ContainerInfo {
  id: string;
  url: string;
  max_sessions: number;
  is_active: boolean;
  active_sessions: number;
  ec2_instance_id?: string | null;
  ec2_region?: string | null;
  container_name?: string | null;
  container_port?: number | null;
}
interface MetricsResult {
  url: string;
  ok: boolean;
  error?: string;
  metrics?: any;
}

// ── EC2 Configure Dialog (per container — name + port only) ──────────────────
function EC2ConfigDialog({
  containerId,
  current,
  onClose,
  onSaved,
}: {
  containerId: string;
  current: {
    container_name?: string | null;
    container_port?: number | null;
    ec2_instance_id?: string | null;
    ec2_region?: string | null;
  };
  onClose: () => void;
  onSaved: () => void;
}) {
  const [form, setForm] = useState({
    ec2_instance_id: current.ec2_instance_id || "",
    ec2_region: current.ec2_region || "ap-south-1",
    container_name: current.container_name || "",
    container_port: current.container_port || 8000,
  });
  const [saving, setSaving] = useState(false);

  const handleSave = async () => {
    if (!form.container_name.trim()) {
      toast.error("Container name is required");
      return;
    }
    setSaving(true);
    try {
      await api.patch(`/admin/engine/containers/${containerId}/meta`, form);
      toast.success("Container metadata saved");
      onSaved();
      onClose();
    } catch (e: any) {
      toast.error(e?.response?.data?.detail || "Failed to save");
    } finally {
      setSaving(false);
    }
  };

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center"
      style={{ background: "rgba(0,0,0,0.5)" }}
    >
      <div
        className="bg-white rounded-xl border shadow-xl w-full max-w-md p-6"
        style={{ borderColor: "#E2E8F0" }}
      >
        <div className="flex items-center justify-between mb-5">
          <h3 className="text-base font-bold" style={{ color: "#0F172A" }}>
            Configure Container
          </h3>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg hover:bg-slate-100 transition-colors"
          >
            <X className="h-4 w-4" style={{ color: "#64748B" }} />
          </button>
        </div>
        <div className="space-y-4">
          <div>
            <label
              className="block text-xs font-semibold uppercase tracking-wider mb-1.5"
              style={{ color: "#64748B" }}
            >
              EC2 Instance ID
            </label>
            <input
              type="text"
              placeholder="i-0abc123def456789"
              value={form.ec2_instance_id}
              onChange={(e) =>
                setForm((f) => ({ ...f, ec2_instance_id: e.target.value }))
              }
              className="w-full px-3 py-2 rounded-lg border text-sm font-mono focus:outline-none focus:ring-2 focus:ring-blue-500"
              style={{ borderColor: "#E2E8F0", color: "#0F172A" }}
            />
          </div>
          <div>
            <label
              className="block text-xs font-semibold uppercase tracking-wider mb-1.5"
              style={{ color: "#64748B" }}
            >
              AWS Region
            </label>
            <input
              type="text"
              placeholder="ap-south-1"
              value={form.ec2_region}
              onChange={(e) =>
                setForm((f) => ({ ...f, ec2_region: e.target.value }))
              }
              className="w-full px-3 py-2 rounded-lg border text-sm font-mono focus:outline-none focus:ring-2 focus:ring-blue-500"
              style={{ borderColor: "#E2E8F0", color: "#0F172A" }}
            />
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label
                className="block text-xs font-semibold uppercase tracking-wider mb-1.5"
                style={{ color: "#64748B" }}
              >
                Container Name
              </label>
              <input
                type="text"
                placeholder="proctor1"
                value={form.container_name}
                onChange={(e) =>
                  setForm((f) => ({ ...f, container_name: e.target.value }))
                }
                className="w-full px-3 py-2 rounded-lg border text-sm font-mono focus:outline-none focus:ring-2 focus:ring-blue-500"
                style={{ borderColor: "#E2E8F0", color: "#0F172A" }}
              />
            </div>
            <div>
              <label
                className="block text-xs font-semibold uppercase tracking-wider mb-1.5"
                style={{ color: "#64748B" }}
              >
                Port
              </label>
              <input
                type="number"
                placeholder="8000"
                value={form.container_port}
                onChange={(e) =>
                  setForm((f) => ({
                    ...f,
                    container_port: parseInt(e.target.value) || 8000,
                  }))
                }
                className="w-full px-3 py-2 rounded-lg border text-sm font-mono focus:outline-none focus:ring-2 focus:ring-blue-500"
                style={{ borderColor: "#E2E8F0", color: "#0F172A" }}
              />
            </div>
          </div>
        </div>
        <div className="flex items-center justify-end gap-2 mt-6">
          <button
            onClick={onClose}
            className="px-4 py-2 rounded-lg border text-sm font-medium"
            style={{ borderColor: "#E2E8F0", color: "#64748B" }}
          >
            Cancel
          </button>
          <button
            onClick={handleSave}
            disabled={saving}
            className="flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-semibold text-white disabled:opacity-60"
            style={{ background: "#22577A" }}
          >
            {saving ? (
              <Loader2 className="h-3.5 w-3.5 animate-spin" />
            ) : (
              <Check className="h-3.5 w-3.5" />
            )}
            Save
          </button>
        </div>
      </div>
    </div>
  );
}

// ── Per-container start/stop controls ────────────────────────────────────────
function ContainerControls({ container }: { container: ContainerInfo }) {
  const [loading, setLoading] = useState<"start" | "stop" | null>(null);

  const act = async (action: "start" | "stop") => {
    setLoading(action);
    try {
      const r = await api.post(
        `/admin/engine/containers/${container.id}/${action}`,
      );
      toast.success(
        r.data.message ||
          `${action === "start" ? "Starting" : "Stopping"} ${container.container_name}…`,
      );
    } catch (e: any) {
      toast.error(e?.response?.data?.detail || `Failed to ${action} container`);
    } finally {
      setLoading(null);
    }
  };

  return (
    <div
      className="flex items-center justify-between gap-3 px-3 py-2.5 rounded-lg border"
      style={{ background: "#fff", borderColor: "#E2E8F0" }}
    >
      <div className="text-xs">
        <span className="font-mono font-semibold" style={{ color: "#0F172A" }}>
          {container.container_name}
        </span>
        <span className="ml-2 font-medium" style={{ color: "#64748B" }}>
          :{container.container_port}
        </span>
      </div>
      <div className="flex items-center gap-1.5">
        <button
          onClick={() => act("start")}
          disabled={!!loading}
          className="inline-flex items-center gap-1 px-2.5 py-1 rounded-md border text-[11px] font-semibold transition-colors disabled:opacity-50"
          style={{
            borderColor: "#BBF7D0",
            color: "#15803D",
            background: "#ECFDF5",
          }}
        >
          {loading === "start" ? (
            <Loader2 className="h-3 w-3 animate-spin" />
          ) : (
            <Play className="h-3 w-3" />
          )}
          Start
        </button>
        <button
          onClick={() => act("stop")}
          disabled={!!loading}
          className="inline-flex items-center gap-1 px-2.5 py-1 rounded-md border text-[11px] font-semibold transition-colors disabled:opacity-50"
          style={{
            borderColor: "#FECDD3",
            color: "#BE123C",
            background: "#FFF1F2",
          }}
        >
          {loading === "stop" ? (
            <Loader2 className="h-3 w-3 animate-spin" />
          ) : (
            <Square className="h-3 w-3" />
          )}
          Stop
        </button>
      </div>
    </div>
  );
}

// ── EC2 Instance Card (top-level, shared) ─────────────────────────────────────
function EC2InstanceCard({
  containers,
  onRefresh,
}: {
  containers: ContainerInfo[];
  onRefresh: () => void;
}) {
  const ec2Container = containers.find((c) => c.ec2_instance_id);
  const instanceId = ec2Container?.ec2_instance_id;
  const region = ec2Container?.ec2_region || "ap-south-1";
  const fallbackHost = (() => {
    const firstUrl = containers[0]?.url;
    if (!firstUrl) return null;
    try {
      return new URL(firstUrl).hostname;
    } catch {
      return null;
    }
  })();
  const displayId = instanceId || fallbackHost;
  const hasEc2Controls = !!instanceId;

  const [ec2State, setEc2State] = useState<{
    state: string;
    public_ip?: string;
  } | null>(null);
  const [statusLoading, setStatusLoading] = useState(false);
  const [actionLoading, setActionLoading] = useState<
    "start" | "stop" | "apply" | null
  >(null);
  const [applyResults, setApplyResults] = useState<any[] | null>(null);

  const fetchStatus = async () => {
    if (!instanceId) return;
    setStatusLoading(true);
    try {
      const r = await api.post("/admin/engine/ec2/status", {
        instance_id: instanceId,
        region,
      });
      setEc2State(r.data);
    } catch (e: any) {
      toast.error(e?.response?.data?.detail || "Failed to get EC2 status");
    } finally {
      setStatusLoading(false);
    }
  };

  const handleStart = async () => {
    if (!instanceId) return;
    setActionLoading("start");
    try {
      await api.post("/admin/engine/ec2/start", {
        instance_id: instanceId,
        region,
      });
      toast.success("EC2 instance starting… check status in ~60s");
      setTimeout(fetchStatus, 10000);
    } catch (e: any) {
      toast.error(e?.response?.data?.detail || "Failed to start EC2");
    } finally {
      setActionLoading(null);
    }
  };

  const handleStop = async () => {
    if (!instanceId) return;
    setActionLoading("stop");
    try {
      await api.post("/admin/engine/ec2/stop", {
        instance_id: instanceId,
        region,
      });
      toast.success("EC2 instance stopping…");
      setTimeout(fetchStatus, 5000);
    } catch (e: any) {
      toast.error(e?.response?.data?.detail || "Failed to stop EC2");
    } finally {
      setActionLoading(null);
    }
  };

  const handleApply = async () => {
    setActionLoading("apply");
    setApplyResults(null);
    try {
      const r = await api.post("/admin/engine/apply-settings");
      setApplyResults(r.data.results || []);
      toast.success(
        r.data.message || "Settings applied. Containers restarting…",
      );
      setTimeout(() => {
        fetchStatus();
        onRefresh();
      }, 5000);
    } catch (e: any) {
      toast.error(e?.response?.data?.detail || "Failed to apply settings");
    } finally {
      setActionLoading(null);
    }
  };

  const stateColor =
    ec2State?.state === "running"
      ? "#15803D"
      : ec2State?.state === "stopped"
        ? "#BE123C"
        : ec2State?.state === "pending" || ec2State?.state === "stopping"
          ? "#D97706"
          : "#64748B";

  const stateBg =
    ec2State?.state === "running"
      ? { background: "#ECFDF5", color: "#15803D", borderColor: "#BBF7D0" }
      : ec2State?.state === "stopped"
        ? { background: "#FFF1F2", color: "#BE123C", borderColor: "#FECDD3" }
        : ec2State?.state
          ? { background: "#FFFBEB", color: "#D97706", borderColor: "#FDE68A" }
          : { background: "#F8FAFC", color: "#64748B", borderColor: "#E2E8F0" };

  return (
    <div
      className="bg-white rounded-xl border p-5 space-y-4"
      style={{
        borderColor: "#E2E8F0",
        boxShadow: "0 1px 3px rgba(15,23,42,0.04)",
      }}
    >
      {/* Title row */}
      <div className="flex items-center justify-between gap-3">
        <div className="flex items-center gap-2.5">
          <div
            className="h-9 w-9 rounded-lg flex items-center justify-center shrink-0"
            style={{ background: "#EFF6FF" }}
          >
            <CloudLightning className="h-4 w-4" style={{ color: "#22577A" }} />
          </div>
          <div>
            <p className="text-sm font-bold" style={{ color: "#0F172A" }}>
              EC2 Instance
            </p>
            <p
              className="text-xs font-mono mt-0.5"
              style={{ color: "#64748B" }}
            >
              {displayId ||
                "Not configured — use Configure on a container card"}
            </p>
            {!instanceId && fallbackHost && (
              <p className="text-[11px] mt-1" style={{ color: "#64748B" }}>
                Using container URL host as a stable Elastic IP display. AWS
                start/stop/status still require the EC2 instance ID.
              </p>
            )}
          </div>
        </div>
        {ec2State && (
          <span
            className="px-2.5 py-1 rounded-lg border text-xs font-semibold"
            style={stateBg}
          >
            {ec2State.state.charAt(0).toUpperCase() + ec2State.state.slice(1)}
          </span>
        )}
      </div>

      {/* Info row */}
      {displayId && (
        <div className="grid grid-cols-3 gap-3 text-xs">
          <div
            className="rounded-lg border p-3"
            style={{ background: "#F8FAFC", borderColor: "#E2E8F0" }}
          >
            <p className="font-medium mb-0.5" style={{ color: "#64748B" }}>
              Region
            </p>
            <p className="font-mono font-semibold" style={{ color: "#0F172A" }}>
              {region}
            </p>
          </div>
          <div
            className="rounded-lg border p-3"
            style={{ background: "#F8FAFC", borderColor: "#E2E8F0" }}
          >
            <p className="font-medium mb-0.5" style={{ color: "#64748B" }}>
              Public IP
            </p>
            <p className="font-mono font-semibold" style={{ color: "#0F172A" }}>
              {ec2State?.public_ip || fallbackHost || "—"}
            </p>
          </div>
          <div
            className="rounded-lg border p-3"
            style={{ background: "#F8FAFC", borderColor: "#E2E8F0" }}
          >
            <p className="font-medium mb-0.5" style={{ color: "#64748B" }}>
              Containers
            </p>
            <p className="font-semibold" style={{ color: "#0F172A" }}>
              {containers
                .filter((c) => c.container_name)
                .map((c) => c.container_name)
                .join(", ") || "—"}
            </p>
          </div>
        </div>
      )}

      {/* Per-container controls */}
      {containers.filter((c) => c.container_name).length > 0 && (
        <div className="space-y-2">
          <p
            className="text-[10px] font-semibold uppercase tracking-wider"
            style={{ color: "#64748B" }}
          >
            Docker Containers
          </p>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
            {containers
              .filter((c) => c.container_name)
              .map((c) => (
                <ContainerControls key={c.id} container={c} />
              ))}
          </div>
        </div>
      )}

      {/* Action buttons */}
      <div className="flex items-center gap-2 flex-wrap">
        <button
          onClick={fetchStatus}
          disabled={!hasEc2Controls || statusLoading}
          className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border text-xs font-semibold transition-colors disabled:opacity-50"
          style={{
            borderColor: "#E2E8F0",
            color: "#475569",
            background: "#F8FAFC",
          }}
        >
          {statusLoading ? (
            <Loader2 className="h-3.5 w-3.5 animate-spin" />
          ) : (
            <Activity className="h-3.5 w-3.5" />
          )}
          Check Status
        </button>
        <button
          onClick={handleStart}
          disabled={!hasEc2Controls || !!actionLoading}
          className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border text-xs font-semibold transition-colors disabled:opacity-50"
          style={{
            borderColor: "#BBF7D0",
            color: "#15803D",
            background: "#ECFDF5",
          }}
        >
          {actionLoading === "start" ? (
            <Loader2 className="h-3.5 w-3.5 animate-spin" />
          ) : (
            <Play className="h-3.5 w-3.5" />
          )}
          Start Instance
        </button>
        <button
          onClick={handleStop}
          disabled={!hasEc2Controls || !!actionLoading}
          className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border text-xs font-semibold transition-colors disabled:opacity-50"
          style={{
            borderColor: "#FECDD3",
            color: "#BE123C",
            background: "#FFF1F2",
          }}
        >
          {actionLoading === "stop" ? (
            <Loader2 className="h-3.5 w-3.5 animate-spin" />
          ) : (
            <Square className="h-3.5 w-3.5" />
          )}
          Stop Instance
        </button>

        {/* Divider */}
        <div className="h-5 w-px mx-1" style={{ background: "#E2E8F0" }} />

        <button
          onClick={handleApply}
          disabled={!!actionLoading}
          className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border text-xs font-semibold text-white transition-colors disabled:opacity-50"
          style={{ background: "#EA580C", borderColor: "#EA580C" }}
        >
          {actionLoading === "apply" ? (
            <Loader2 className="h-3.5 w-3.5 animate-spin" />
          ) : (
            <Power className="h-3.5 w-3.5" />
          )}
          {actionLoading === "apply" ? "Applying…" : "Apply Settings & Restart"}
        </button>
      </div>

      {/* Apply results */}
      {applyResults && applyResults.length > 0 && (
        <div className="space-y-1.5">
          {applyResults.map((r, i) => (
            <div
              key={i}
              className="flex items-center gap-3 px-3 py-2 rounded-lg border text-xs"
              style={{
                background: r.status === "sent" ? "#F0FDF4" : "#FFF1F2",
                borderColor: r.status === "sent" ? "#BBF7D0" : "#FECDD3",
                color: r.status === "sent" ? "#15803D" : "#BE123C",
              }}
            >
              {r.status === "sent" ? (
                <CheckCircle2 className="h-3.5 w-3.5 shrink-0" />
              ) : (
                <XCircle className="h-3.5 w-3.5 shrink-0" />
              )}
              <span className="font-mono font-semibold">{r.container}</span>
              {r.status === "sent" && r.command_id && (
                <span className="ml-auto text-[10px] font-mono opacity-60">
                  {r.command_id}
                </span>
              )}
              {r.error && <span className="ml-auto">{r.error}</span>}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ── Container card ─────────────────────────────────────────────────────────────
function ContainerCard({
  container,
  metricsResult,
  onRefresh,
}: {
  container: ContainerInfo;
  metricsResult?: MetricsResult;
  onRefresh: () => void;
}) {
  const [expanded, setExpanded] = useState(true);
  const [configOpen, setConfigOpen] = useState(false);

  const m = metricsResult?.ok ? metricsResult.metrics : null;
  const sys = m?.system;
  const slotPct = container.max_sessions
    ? (container.active_sessions / container.max_sessions) * 100
    : 0;
  const slotColor =
    slotPct >= 90 ? "#EF4444" : slotPct >= 60 ? "#F59E0B" : "#22C55E";

  return (
    <div
      className="bg-white rounded-xl border overflow-hidden"
      style={{
        borderColor: "#E2E8F0",
        boxShadow: "0 1px 3px rgba(15,23,42,0.04)",
      }}
    >
      {/* Header */}
      <div className="p-5" style={{ borderBottom: "1px solid #F1F5F9" }}>
        <div className="flex items-center justify-between gap-3 mb-4">
          <div className="flex items-center gap-2.5 min-w-0">
            <div
              className="h-8 w-8 rounded-lg flex items-center justify-center shrink-0"
              style={{ background: "#EFF6FF" }}
            >
              <Server className="h-4 w-4" style={{ color: "#22577A" }} />
            </div>
            <div className="min-w-0">
              <p
                className="font-mono text-sm font-semibold truncate"
                style={{ color: "#0F172A" }}
              >
                {container.url}
              </p>
              {container.container_name && (
                <p
                  className="text-xs font-medium mt-0.5"
                  style={{ color: "#64748B" }}
                >
                  {container.container_name} · port {container.container_port}
                </p>
              )}
            </div>
          </div>
          <div className="flex items-center gap-2 shrink-0">
            <span
              className="px-2 py-0.5 rounded-md text-xs font-semibold border"
              style={
                container.is_active
                  ? {
                      background: "#ECFDF5",
                      color: "#15803D",
                      borderColor: "#BBF7D0",
                    }
                  : {
                      background: "#F8FAFC",
                      color: "#64748B",
                      borderColor: "#E2E8F0",
                    }
              }
            >
              {container.is_active ? "Active" : "Inactive"}
            </span>
            {!metricsResult ? (
              <span
                className="px-2 py-0.5 rounded-md text-xs font-semibold border"
                style={{
                  background: "#F8FAFC",
                  color: "#64748B",
                  borderColor: "#E2E8F0",
                }}
              >
                Fetching…
              </span>
            ) : metricsResult.ok ? (
              <span
                className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-xs font-semibold border"
                style={{
                  background: "#ECFDF5",
                  color: "#15803D",
                  borderColor: "#BBF7D0",
                }}
              >
                <CheckCircle2 className="h-3 w-3" /> Reachable
              </span>
            ) : (
              <span
                className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-xs font-semibold border"
                style={{
                  background: "#FFF1F2",
                  color: "#BE123C",
                  borderColor: "#FECDD3",
                }}
              >
                <XCircle className="h-3 w-3" /> Unreachable
              </span>
            )}
            <button
              onClick={() => setConfigOpen(true)}
              className="p-1.5 rounded-lg border transition-colors hover:bg-slate-50"
              title="Configure container"
              style={{ borderColor: "#E2E8F0", color: "#64748B" }}
            >
              <Edit2 className="h-3.5 w-3.5" />
            </button>
            <button
              onClick={() => setExpanded((e) => !e)}
              className="p-1 rounded-lg transition-colors"
              style={{ color: "#64748B" }}
            >
              {expanded ? (
                <ChevronUp className="h-4 w-4" />
              ) : (
                <ChevronDown className="h-4 w-4" />
              )}
            </button>
          </div>
        </div>

        {/* Slot bar */}
        <div className="space-y-1.5">
          <div className="flex justify-between text-xs">
            <span className="font-medium" style={{ color: "#64748B" }}>
              Session Slots
            </span>
            <span
              className="font-semibold tabular-nums"
              style={{ color: slotColor }}
            >
              {container.active_sessions} / {container.max_sessions}
            </span>
          </div>
          <GaugeBar
            value={container.active_sessions}
            max={container.max_sessions}
            color={slotColor}
          />
        </div>
      </div>

      {/* Body */}
      {expanded && (
        <div className="p-5 space-y-5">
          {!metricsResult && (
            <div
              className="flex items-center justify-center py-8 gap-2 font-medium"
              style={{ color: "#64748B" }}
            >
              <Loader2 className="h-5 w-5 animate-spin" /> Fetching metrics…
            </div>
          )}
          {metricsResult && !metricsResult.ok && (
            <div
              className="flex items-center gap-2.5 p-3.5 rounded-lg border text-sm"
              style={{
                background: "#FFF1F2",
                borderColor: "#FECDD3",
                color: "#BE123C",
              }}
            >
              <AlertTriangle className="h-4 w-4 shrink-0" />
              Engine unreachable: {metricsResult.error}
            </div>
          )}

          {m && sys && (
            <>
              {/* System resources */}
              <div>
                <p
                  className="text-[10px] font-semibold uppercase tracking-wider mb-3"
                  style={{ color: "#64748B" }}
                >
                  System Resources
                </p>
                <div className="grid grid-cols-2 gap-4">
                  {[
                    {
                      icon: Cpu,
                      label: "CPU",
                      value: `${fmt(sys.cpu_percent)}%`,
                      pct: sys.cpu_percent,
                      max: 100,
                      color: sys.cpu_percent > 80 ? "#EF4444" : "#22577A",
                    },
                    {
                      icon: MemoryStick,
                      label: "RAM (RSS)",
                      value: `${fmt(sys.mem_rss_mb, 0)} MB`,
                      pct: sys.mem_rss_mb,
                      max: Math.max(sys.mem_rss_mb * 1.5, 512),
                      color: "#38A3A5",
                    },
                  ].map(({ icon: Icon, label, value, pct, max, color }) => (
                    <div key={label} className="space-y-1.5">
                      <div className="flex justify-between text-xs">
                        <span
                          className="flex items-center gap-1 font-medium"
                          style={{ color: "#64748B" }}
                        >
                          <Icon className="h-3.5 w-3.5" /> {label}
                        </span>
                        <span
                          className="font-semibold tabular-nums"
                          style={{ color }}
                        >
                          {value}
                        </span>
                      </div>
                      <GaugeBar value={pct} max={max} color={color} />
                    </div>
                  ))}
                  {sys.gpu_mem_total_mb > 0 && (
                    <>
                      <div className="space-y-1.5">
                        <div className="flex justify-between text-xs">
                          <span
                            className="flex items-center gap-1 font-medium"
                            style={{ color: "#64748B" }}
                          >
                            <Zap className="h-3.5 w-3.5" /> GPU Util
                          </span>
                          <span
                            className="font-semibold tabular-nums"
                            style={{ color: "#7C3AED" }}
                          >
                            {fmt(sys.gpu_util_pct)}%
                          </span>
                        </div>
                        <GaugeBar
                          value={sys.gpu_util_pct}
                          max={100}
                          color="#7C3AED"
                        />
                      </div>
                      <div className="space-y-1.5">
                        <div className="flex justify-between text-xs">
                          <span
                            className="font-medium"
                            style={{ color: "#64748B" }}
                          >
                            GPU VRAM
                          </span>
                          <span
                            className="font-semibold tabular-nums"
                            style={{ color: "#DB2777" }}
                          >
                            {fmt(sys.gpu_mem_used_mb, 0)} /{" "}
                            {fmt(sys.gpu_mem_total_mb, 0)} MB
                          </span>
                        </div>
                        <GaugeBar
                          value={sys.gpu_mem_used_mb}
                          max={sys.gpu_mem_total_mb}
                          color="#DB2777"
                        />
                      </div>
                    </>
                  )}
                </div>
              </div>

              {/* Inference */}
              <div>
                <p
                  className="text-[10px] font-semibold uppercase tracking-wider mb-3"
                  style={{ color: "#64748B" }}
                >
                  Inference Performance
                </p>
                <div className="grid grid-cols-3 sm:grid-cols-6 gap-2">
                  <MetricCell
                    label="YOLO avg"
                    value={`${fmt(m.yolo?.lat_avg_ms)} ms`}
                  />
                  <MetricCell
                    label="YOLO p95"
                    value={`${fmt(m.yolo?.lat_p95_ms)} ms`}
                    color={
                      (m.yolo?.lat_p95_ms ?? 0) > 200 ? "#F59E0B" : undefined
                    }
                  />
                  <MetricCell
                    label="YOLO p99"
                    value={`${fmt(m.yolo?.lat_p99_ms)} ms`}
                    color={
                      (m.yolo?.lat_p99_ms ?? 0) > 500 ? "#EF4444" : undefined
                    }
                  />
                  <MetricCell
                    label="Tick avg"
                    value={`${fmt(m.coordinator?.tick_avg_ms)} ms`}
                  />
                  <MetricCell
                    label="Tick p95"
                    value={`${fmt(m.coordinator?.tick_p95_ms)} ms`}
                    color={
                      (m.coordinator?.tick_p95_ms ?? 0) > 150
                        ? "#F59E0B"
                        : undefined
                    }
                  />
                  <MetricCell
                    label="Sessions"
                    value={`${m.coordinator?.active_sessions ?? 0} / ${m.coordinator?.max_sessions ?? container.max_sessions}`}
                  />
                </div>
              </div>

              {/* Session stats */}
              <div>
                <p
                  className="text-[10px] font-semibold uppercase tracking-wider mb-3"
                  style={{ color: "#64748B" }}
                >
                  Session Stats
                </p>
                <div className="grid grid-cols-4 gap-2">
                  <MetricCell label="Uptime" value={m.uptime ?? "—"} />
                  <MetricCell
                    label="Requests"
                    value={(m.requests?.total ?? 0).toLocaleString()}
                  />
                  <MetricCell
                    label="Total Alerts"
                    value={m.events?.alerts_total ?? 0}
                    color={
                      (m.events?.alerts_total ?? 0) > 0 ? "#EF4444" : undefined
                    }
                  />
                  <MetricCell
                    label="Warnings"
                    value={m.events?.warnings_total ?? 0}
                    color={
                      (m.events?.warnings_total ?? 0) > 0
                        ? "#F59E0B"
                        : undefined
                    }
                  />
                </div>
              </div>

              {/* Active sessions table */}
              {Array.isArray(m.coordinator?.active_session_details) &&
                m.coordinator.active_session_details.length > 0 && (
                  <div>
                    <p
                      className="text-[10px] font-semibold uppercase tracking-wider mb-3"
                      style={{ color: "#64748B" }}
                    >
                      Active Engine Sessions
                    </p>
                    <div
                      className="rounded-lg overflow-hidden border"
                      style={{ borderColor: "#E2E8F0" }}
                    >
                      <table className="w-full text-xs">
                        <thead>
                          <tr
                            style={{
                              background: "#F8FAFC",
                              borderBottom: "1px solid #F1F5F9",
                            }}
                          >
                            {[
                              "Label",
                              "State",
                              "FPS",
                              "Risk",
                              "Risk State",
                              "Alerts",
                              "Warnings",
                            ].map((h) => (
                              <th
                                key={h}
                                className="px-3 py-2.5 text-left font-semibold uppercase tracking-wider"
                                style={{ color: "#64748B" }}
                              >
                                {h}
                              </th>
                            ))}
                          </tr>
                        </thead>
                        <tbody>
                          {m.coordinator.active_session_details.map(
                            (s: any, i: number) => (
                              <tr
                                key={i}
                                style={{
                                  borderTop:
                                    i > 0 ? "1px solid #F8FAFC" : "none",
                                }}
                              >
                                <td
                                  className="px-3 py-2.5 font-medium"
                                  style={{ color: "#0F172A" }}
                                >
                                  {s.label || s.pc_id?.slice(0, 8)}
                                </td>
                                <td
                                  className="px-3 py-2.5"
                                  style={{ color: "#475569" }}
                                >
                                  {s.state}
                                </td>
                                <td
                                  className="px-3 py-2.5 tabular-nums"
                                  style={{ color: "#475569" }}
                                >
                                  {s.fps ?? "—"}
                                </td>
                                <td
                                  className="px-3 py-2.5 tabular-nums font-bold"
                                  style={{
                                    color:
                                      s.risk_score >= 70
                                        ? "#EF4444"
                                        : s.risk_score >= 40
                                          ? "#F59E0B"
                                          : "#22C55E",
                                  }}
                                >
                                  {Math.round(s.risk_score ?? 0)}
                                </td>
                                <td
                                  className="px-3 py-2.5"
                                  style={{ color: "#475569" }}
                                >
                                  {s.risk_state}
                                </td>
                                <td
                                  className="px-3 py-2.5 tabular-nums font-semibold"
                                  style={{
                                    color: s.alerts > 0 ? "#EF4444" : "#64748B",
                                  }}
                                >
                                  {s.alerts ?? 0}
                                </td>
                                <td
                                  className="px-3 py-2.5 tabular-nums font-semibold"
                                  style={{
                                    color:
                                      s.warnings > 0 ? "#F59E0B" : "#64748B",
                                  }}
                                >
                                  {s.warnings ?? 0}
                                </td>
                              </tr>
                            ),
                          )}
                        </tbody>
                      </table>
                    </div>
                  </div>
                )}
            </>
          )}
        </div>
      )}

      {configOpen && (
        <EC2ConfigDialog
          containerId={container.id}
          current={container}
          onClose={() => setConfigOpen(false)}
          onSaved={onRefresh}
        />
      )}
    </div>
  );
}

// ── Main page ─────────────────────────────────────────────────────────────────
export default function EngineMonitorPage() {
  const [containers, setContainers] = useState<ContainerInfo[]>([]);
  const [metrics, setMetrics] = useState<MetricsResult[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);

  const fetchAll = useCallback(async (silent = false) => {
    if (!silent) setRefreshing(true);
    try {
      const [cr, mr] = await Promise.all([
        api.get("/admin/engine/containers"),
        api.get("/admin/engine/metrics"),
      ]);
      setContainers(cr.data);
      setMetrics(mr.data);
      return true;
    } catch {
      if (!silent) toast.error("Failed to fetch engine data");
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
    return false;
  }, []);

  useEffect(() => {
    let stopped = false;
    let failureCount = 0;

    const loop = async () => {
      while (!stopped) {
        const ok = document.hidden ? true : await fetchAll(failureCount > 0);
        failureCount = ok ? 0 : failureCount + 1;
        const delay = document.hidden
          ? 30000
          : ok
            ? 10000
            : Math.min(10000 * 2 ** Math.min(failureCount, 3), 60000);
        await new Promise((resolve) => setTimeout(resolve, delay));
      }
    };

    void loop();
    return () => {
      stopped = true;
    };
  }, [fetchAll]);

  const totalSlots = containers.reduce((s, c) => s + c.max_sessions, 0);
  const usedSlots = containers.reduce((s, c) => s + c.active_sessions, 0);
  const reachable = metrics.filter((m) => m.ok).length;
  const healthy = reachable === metrics.length && metrics.length > 0;

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-[60vh]">
        <Loader2
          className="h-7 w-7 animate-spin"
          style={{ color: "#64748B" }}
        />
      </div>
    );
  }

  return (
    <div className="space-y-6 max-w-6xl pb-12">
      {/* Header */}
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1
            className="text-2xl font-bold"
            style={{ color: "#0F172A", letterSpacing: "-0.025em" }}
          >
            Engine Monitor
          </h1>
          <p className="text-sm mt-1 font-medium" style={{ color: "#64748B" }}>
            Real-time proctoring engine health, resource usage, and EC2
            management
          </p>
        </div>
        <button
          onClick={() => fetchAll()}
          disabled={refreshing}
          className="flex items-center gap-2 px-3 py-2 rounded-lg text-sm font-medium border transition-all duration-150"
          style={{
            borderColor: "#E2E8F0",
            color: "#475569",
            background: "#fff",
          }}
        >
          <RefreshCw
            className={`h-3.5 w-3.5 ${refreshing ? "animate-spin" : ""}`}
          />{" "}
          Refresh
        </button>
      </div>

      {/* Summary stats */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        {[
          {
            label: "Active Containers",
            value: containers.filter((c) => c.is_active).length,
            color: "#0F172A",
          },
          {
            label: "Session Slots Used",
            value: `${usedSlots} / ${totalSlots}`,
            color: "#0F172A",
          },
          {
            label: "Containers Reachable",
            value: `${reachable} / ${metrics.length}`,
            color: healthy ? "#15803D" : "#BE123C",
          },
          {
            label: "Overall Status",
            value: healthy ? "Healthy" : "Degraded",
            color: healthy ? "#15803D" : "#D97706",
          },
        ].map(({ label, value, color }) => (
          <div
            key={label}
            className="bg-white rounded-xl border p-5"
            style={{
              borderColor: "#E2E8F0",
              boxShadow: "0 1px 3px rgba(15,23,42,0.04)",
            }}
          >
            <p className="text-2xl font-bold tabular-nums" style={{ color }}>
              {value}
            </p>
            <p
              className="text-xs mt-0.5 font-medium"
              style={{ color: "#64748B" }}
            >
              {label}
            </p>
          </div>
        ))}
      </div>

      {/* EC2 Instance Card */}
      <EC2InstanceCard
        containers={containers}
        onRefresh={() => fetchAll(true)}
      />

      {/* Container cards */}
      {containers.length === 0 ? (
        <div
          className="bg-white rounded-xl border p-16 text-center"
          style={{ borderColor: "#E2E8F0" }}
        >
          <Server
            className="h-10 w-10 mx-auto mb-3"
            style={{ color: "#E2E8F0" }}
          />
          <p className="font-medium" style={{ color: "#64748B" }}>
            No engine containers configured.
          </p>
        </div>
      ) : (
        <div className="space-y-4">
          {containers.map((c) => (
            <ContainerCard
              key={c.id}
              container={c}
              metricsResult={metrics.find((m) => m.url === c.url)}
              onRefresh={() => fetchAll(true)}
            />
          ))}
        </div>
      )}
    </div>
  );
}
