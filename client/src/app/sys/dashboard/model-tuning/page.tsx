"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import {
  Activity,
  Camera,
  Cpu,
  Loader2,
  PauseCircle,
  PlayCircle,
  RefreshCw,
  Save,
  SlidersHorizontal,
  Sparkles,
  ToggleLeft,
  ToggleRight,
  RotateCcw,
} from "lucide-react";
import { toast } from "sonner";
import api from "@/lib/axios";

type TuningKey =
  | "looking_away_threshold"
  | "gaze_threshold"
  | "partial_face_duration_gate"
  | "face_hidden_dur_1"
  | "face_hidden_dur_2"
  | "face_hidden_recency_s"
  | "no_person_dur_1"
  | "no_person_dur_2"
  | "no_person_terminate_s"
  | "multi_people_terminate_s"
  | "fake_presence_dur_1"
  | "fake_presence_dur_2"
  | "speaker_occ1_warn_s"
  | "speaker_occ2_warn_s"
  | "speaker_repeat_interval"
  | "detect_looking_away"
  | "detect_looking_down"
  | "detect_looking_up"
  | "detect_looking_side"
  | "detect_partial_face"
  | "detect_face_hidden"
  | "detect_fake_presence"
  | "detect_multiple_people"
  | "detect_phone"
  | "detect_book"
  | "detect_headphone"
  | "detect_earbud";

type DraftConfig = Record<TuningKey, number | boolean>;

type ContainerInfo = {
  id: string;
  url: string;
  container_name: string;
  container_port: number;
  is_active: boolean;
};

type CalibrationSessionResponse = {
  session_id: string;
  tick_rate_hz: number;
  object_window_frames: number;
  object_vote_targets: Record<string, number>;
  engine: {
    container_id: string;
    container_name: string;
    url: string;
  };
};

type SignalTelemetry = {
  key: string;
  label: string;
  category: string;
  enabled: boolean;
  condition_active: boolean;
  active: boolean;
  duration_s: number;
  risk_added: number;
  thresholds: Record<string, number>;
  risk_debug: {
    occurrence_count: number;
    score_cooldown_remaining_s: number;
    active_duration_s: number;
    decay_interval_s: number;
    quiet_for_s: number;
  };
  alert_debug: {
    warn_cooldown_remaining_s: number;
    api_cooldown_remaining_s: number;
    warn_cooldown_s: number;
    api_cooldown_s: number;
  };
  stage: string;
  details: Record<string, unknown>;
};

type TuningTelemetry = {
  image_base64?: string;
  processing_ms?: number;
  risk: {
    score: number;
    fixed: number;
    decaying: number;
    state: string;
    terminated: boolean;
    decay_interval_s: number;
    quiet_for_s: number;
  };
  summary: {
    people_count: number;
    landmarks_active: boolean;
    speech_active: boolean;
    lip_speaking: boolean;
    lip_mar: number;
    face_detected: boolean;
    pose: {
      yaw: number;
      pitch: number;
      gaze: number;
      ear: number;
      blinked: boolean;
      total_blinks: number;
    };
    active_warnings: string[];
    active_alerts: string[];
  };
  signals: SignalTelemetry[];
  tick_rate_hz: number;
};

type FocusKey =
  | "looking_away"
  | "looking_down"
  | "looking_up"
  | "looking_side"
  | "partial_face"
  | "face_hidden"
  | "fake_presence"
  | "multiple_people"
  | "no_person"
  | "speaker_audio"
  | "phone"
  | "book"
  | "headphone"
  | "earbud";

const NUM_FIELDS: Array<{
  key: TuningKey;
  label: string;
  step: number;
  min: number;
  max: number;
  unit?: string;
}> = [
  {
    key: "looking_away_threshold",
    label: "Head Hold",
    step: 0.5,
    min: 0.5,
    max: 12,
    unit: "s",
  },
  {
    key: "gaze_threshold",
    label: "Side Gaze Hold",
    step: 0.5,
    min: 0.5,
    max: 12,
    unit: "s",
  },
  {
    key: "partial_face_duration_gate",
    label: "Partial Face Score Gate",
    step: 0.5,
    min: 1,
    max: 20,
    unit: "s",
  },
  {
    key: "face_hidden_recency_s",
    label: "Face Hidden Recency",
    step: 0.5,
    min: 1,
    max: 15,
    unit: "s",
  },
  {
    key: "face_hidden_dur_1",
    label: "Face Hidden Tier 1",
    step: 0.5,
    min: 1,
    max: 30,
    unit: "s",
  },
  {
    key: "face_hidden_dur_2",
    label: "Face Hidden Tier 2",
    step: 1,
    min: 2,
    max: 60,
    unit: "s",
  },
  {
    key: "no_person_dur_1",
    label: "No Person Tier 1",
    step: 0.5,
    min: 1,
    max: 30,
    unit: "s",
  },
  {
    key: "no_person_dur_2",
    label: "No Person Tier 2",
    step: 1,
    min: 2,
    max: 60,
    unit: "s",
  },
  {
    key: "no_person_terminate_s",
    label: "No Person Terminate",
    step: 1,
    min: 5,
    max: 120,
    unit: "s",
  },
  {
    key: "multi_people_terminate_s",
    label: "Multi Person Terminate",
    step: 1,
    min: 5,
    max: 120,
    unit: "s",
  },
  {
    key: "fake_presence_dur_1",
    label: "Fake Presence Tier 1",
    step: 1,
    min: 3,
    max: 60,
    unit: "s",
  },
  {
    key: "fake_presence_dur_2",
    label: "Fake Presence Tier 2",
    step: 1,
    min: 5,
    max: 120,
    unit: "s",
  },
  {
    key: "speaker_occ1_warn_s",
    label: "Speaker Episode 1 Warn",
    step: 0.5,
    min: 1,
    max: 20,
    unit: "s",
  },
  {
    key: "speaker_occ2_warn_s",
    label: "Speaker Episode 2 Warn",
    step: 0.5,
    min: 1,
    max: 20,
    unit: "s",
  },
  {
    key: "speaker_repeat_interval",
    label: "Speaker Repeat Interval",
    step: 1,
    min: 3,
    max: 30,
    unit: "s",
  },
];

const TOGGLE_FIELDS: Array<{ key: TuningKey; label: string }> = [
  { key: "detect_looking_away", label: "Looking Away" },
  { key: "detect_looking_down", label: "Looking Down" },
  { key: "detect_looking_up", label: "Looking Up" },
  { key: "detect_looking_side", label: "Looking Side" },
  { key: "detect_partial_face", label: "Partial Face" },
  { key: "detect_face_hidden", label: "Face Hidden" },
  { key: "detect_fake_presence", label: "Fake Presence" },
  { key: "detect_multiple_people", label: "Multiple People" },
  { key: "detect_phone", label: "Phone" },
  { key: "detect_book", label: "Book" },
  { key: "detect_headphone", label: "Headphone" },
  { key: "detect_earbud", label: "Earbud" },
];

const FOCUS_OPTIONS: Array<{
  key: FocusKey;
  label: string;
  fields: TuningKey[];
  toggle?: TuningKey;
}> = [
  {
    key: "looking_away",
    label: "Looking Away",
    fields: ["looking_away_threshold"],
    toggle: "detect_looking_away",
  },
  {
    key: "looking_down",
    label: "Looking Down",
    fields: ["looking_away_threshold"],
    toggle: "detect_looking_down",
  },
  {
    key: "looking_up",
    label: "Looking Up",
    fields: ["looking_away_threshold"],
    toggle: "detect_looking_up",
  },
  {
    key: "looking_side",
    label: "Looking Side",
    fields: ["gaze_threshold"],
    toggle: "detect_looking_side",
  },
  {
    key: "partial_face",
    label: "Partial Face",
    fields: ["partial_face_duration_gate"],
    toggle: "detect_partial_face",
  },
  {
    key: "face_hidden",
    label: "Face Hidden",
    fields: ["face_hidden_recency_s", "face_hidden_dur_1", "face_hidden_dur_2"],
    toggle: "detect_face_hidden",
  },
  {
    key: "fake_presence",
    label: "Fake Presence",
    fields: ["fake_presence_dur_1", "fake_presence_dur_2"],
    toggle: "detect_fake_presence",
  },
  {
    key: "multiple_people",
    label: "Multiple People",
    fields: ["multi_people_terminate_s"],
    toggle: "detect_multiple_people",
  },
  {
    key: "no_person",
    label: "No Person",
    fields: ["no_person_dur_1", "no_person_dur_2", "no_person_terminate_s"],
  },
  {
    key: "speaker_audio",
    label: "Speaker Audio",
    fields: [
      "speaker_occ1_warn_s",
      "speaker_occ2_warn_s",
      "speaker_repeat_interval",
    ],
  },
  { key: "phone", label: "Phone", fields: [], toggle: "detect_phone" },
  { key: "book", label: "Book", fields: [], toggle: "detect_book" },
  {
    key: "headphone",
    label: "Headphone",
    fields: [],
    toggle: "detect_headphone",
  },
  { key: "earbud", label: "Earbud", fields: [], toggle: "detect_earbud" },
];

const STAGE_COLORS: Record<string, { bg: string; fg: string; border: string }> =
  {
    idle: { bg: "#F8FAFC", fg: "#475569", border: "#E2E8F0" },
    accumulating: { bg: "#EFF6FF", fg: "#1D4ED8", border: "#BFDBFE" },
    warning: { bg: "#FFFBEB", fg: "#B45309", border: "#FDE68A" },
    "grace-warning": { bg: "#FFF7ED", fg: "#C2410C", border: "#FDBA74" },
    "score-ready": { bg: "#FEF3C7", fg: "#92400E", border: "#FCD34D" },
    "score-window": { bg: "#FEF3C7", fg: "#92400E", border: "#FCD34D" },
    "score-cooldown": { bg: "#F5F3FF", fg: "#6D28D9", border: "#DDD6FE" },
    scored: { bg: "#FFF1F2", fg: "#BE123C", border: "#FECDD3" },
    "tier-1": { bg: "#FFF7ED", fg: "#C2410C", border: "#FDBA74" },
    "tier-2": { bg: "#FFE4E6", fg: "#BE123C", border: "#FDA4AF" },
    "terminate-ready": { bg: "#7F1D1D", fg: "#FFFFFF", border: "#991B1B" },
    disabled: { bg: "#F1F5F9", fg: "#64748B", border: "#E2E8F0" },
  };

function fmtSeconds(value: number | undefined | null) {
  if (value === undefined || value === null || Number.isNaN(value)) return "—";
  return `${value.toFixed(value >= 10 ? 0 : 1)}s`;
}

function fmtThresholds(thresholds: Record<string, number>) {
  const pairs = Object.entries(thresholds);
  if (pairs.length === 0) return "—";
  return pairs
    .map(([key, value]) => `${key.replaceAll("_", " ")}: ${fmtSeconds(value)}`)
    .join(" • ");
}

function stageStyle(stage: string) {
  return STAGE_COLORS[stage] ?? STAGE_COLORS.idle;
}

export default function ModelTuningPage() {
  const [containers, setContainers] = useState<ContainerInfo[]>([]);
  const [selectedContainerId, setSelectedContainerId] = useState("");
  const [draft, setDraft] = useState<DraftConfig | null>(null);
  const [savedDraft, setSavedDraft] = useState<DraftConfig | null>(null);
  const [sessionMeta, setSessionMeta] =
    useState<CalibrationSessionResponse | null>(null);
  const [telemetry, setTelemetry] = useState<TuningTelemetry | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [resetting, setResetting] = useState(false);
  const [connecting, setConnecting] = useState(false);
  const [cameraReady, setCameraReady] = useState(false);
  const [processedSrc, setProcessedSrc] = useState<string | null>(null);
  const [isStreaming, setIsStreaming] = useState(false);
  const [focusedDetection, setFocusedDetection] =
    useState<FocusKey>("looking_away");

  const videoRef = useRef<HTMLVideoElement | null>(null);
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const streamRef = useRef<MediaStream | null>(null);
  const sessionIdRef = useRef<string | null>(null);
  const captureRunningRef = useRef(false);
  const draftRef = useRef<DraftConfig | null>(null);
  const frameFailureCountRef = useRef(0);
  const frameErrorShownRef = useRef(false);

  const buildDraftPayload = useCallback(() => {
    if (!draft) return {};
    return draft;
  }, [draft]);

  useEffect(() => {
    draftRef.current = draft;
  }, [draft]);

  const closeCalibrationSession = useCallback(async () => {
    const current = sessionIdRef.current;
    sessionIdRef.current = null;
    if (!current) return;
    try {
      await api.delete(`/admin/model-tuning/sessions/${current}`);
    } catch {}
  }, []);

  const loadInitialData = useCallback(async () => {
    setLoading(true);
    try {
      const [settingsRes, containersRes] = await Promise.all([
        api.get("/admin/system-settings"),
        api.get("/admin/engine/containers"),
      ]);
      const nextDraft = settingsRes.data as DraftConfig;
      const activeContainers = (containersRes.data as ContainerInfo[]).filter(
        (container) => container.is_active,
      );
      setDraft(nextDraft);
      setSavedDraft(nextDraft);
      setContainers(activeContainers);
      setSelectedContainerId(
        (previous) => previous || activeContainers[0]?.id || "",
      );
    } catch {
      toast.error("Failed to load tuning settings");
    } finally {
      setLoading(false);
    }
  }, []);

  const createCalibrationSession = useCallback(async () => {
    const currentDraft = draftRef.current;
    if (!selectedContainerId || !currentDraft) return;
    setConnecting(true);
    await closeCalibrationSession();
    try {
      const res = await api.post<CalibrationSessionResponse>(
        "/admin/model-tuning/sessions",
        {
          container_id: selectedContainerId,
          overrides: currentDraft,
        },
      );
      sessionIdRef.current = res.data.session_id;
      setSessionMeta(res.data);
      setTelemetry(null);
      setProcessedSrc(null);
    } catch (error: unknown) {
      const detail =
        typeof error === "object" && error && "response" in error
          ? (error as { response?: { data?: { detail?: string } } }).response
              ?.data?.detail
          : undefined;
      toast.error(detail || "Failed to start calibration session");
    } finally {
      setConnecting(false);
    }
  }, [closeCalibrationSession, selectedContainerId]);

  useEffect(() => {
    void loadInitialData();
  }, [loadInitialData]);

  useEffect(() => {
    let cancelled = false;
    const startCamera = async () => {
      try {
        const stream = await navigator.mediaDevices.getUserMedia({
          video: { width: 960, height: 540, facingMode: "user" },
          audio: false,
        });
        if (cancelled) {
          stream.getTracks().forEach((track) => track.stop());
          return;
        }
        streamRef.current = stream;
        if (videoRef.current) {
          videoRef.current.srcObject = stream;
          await videoRef.current.play();
        }
        setCameraReady(true);
      } catch {
        toast.error("Camera access is required for model tuning");
      }
    };
    void startCamera();
    return () => {
      cancelled = true;
      setCameraReady(false);
      streamRef.current?.getTracks().forEach((track) => track.stop());
      streamRef.current = null;
    };
  }, []);

  // Calibration session is created on-demand when "Start Stream" is clicked.
  // Clean up any open session when the page unmounts or container changes.
  useEffect(() => {
    return () => {
      void closeCalibrationSession();
    };
  }, [closeCalibrationSession, selectedContainerId]);

  useEffect(() => {
    let stopped = false;
    const loop = async () => {
      while (!stopped) {
        const sessionId = sessionIdRef.current;
        const video = videoRef.current;
        const canvas = canvasRef.current;
        if (
          !isStreaming ||
          !sessionId ||
          !video ||
          !canvas ||
          !cameraReady ||
          draft === null ||
          video.readyState < 2
        ) {
          await new Promise((resolve) => setTimeout(resolve, 250));
          continue;
        }
        if (captureRunningRef.current) {
          await new Promise((resolve) => setTimeout(resolve, 50));
          continue;
        }

        captureRunningRef.current = true;
        const started = performance.now();
        let nextDelay = 100;
        try {
          canvas.width = video.videoWidth || 960;
          canvas.height = video.videoHeight || 540;
          const ctx = canvas.getContext("2d");
          if (!ctx) throw new Error("Canvas unavailable");
          ctx.drawImage(video, 0, 0, canvas.width, canvas.height);
          const blob = await new Promise<Blob | null>((resolve) =>
            canvas.toBlob(resolve, "image/jpeg", 0.8),
          );
          if (!blob) throw new Error("Failed to capture frame");

          const formData = new FormData();
          formData.append("frame", blob, "frame.jpg");
          formData.append("config_json", JSON.stringify(buildDraftPayload()));

          const res = await api.post(
            `/admin/model-tuning/sessions/${sessionId}/frame`,
            formData,
            {
              headers: { "Content-Type": "multipart/form-data" },
            },
          );

          const nextTelemetry = res.data.telemetry as TuningTelemetry;
          setTelemetry(nextTelemetry);
          setProcessedSrc(`data:image/jpeg;base64,${res.data.image_base64}`);
          frameFailureCountRef.current = 0;
          frameErrorShownRef.current = false;
        } catch (error: unknown) {
          const detail =
            typeof error === "object" && error && "response" in error
              ? (error as { response?: { data?: { detail?: string } } })
                  .response?.data?.detail
              : undefined;
          frameFailureCountRef.current += 1;
          nextDelay = Math.min(
            1000 * 2 ** Math.min(frameFailureCountRef.current - 1, 4),
            15000,
          );
          if (!frameErrorShownRef.current) {
            toast.error(detail || "Calibration frame failed");
            frameErrorShownRef.current = true;
          }
        } finally {
          captureRunningRef.current = false;
          const elapsed = performance.now() - started;
          const delay = Math.max(0, nextDelay - elapsed);
          await new Promise((resolve) => setTimeout(resolve, delay));
        }
      }
    };
    void loop();
    return () => {
      stopped = true;
    };
  }, [buildDraftPayload, cameraReady, draft, isStreaming]);

  const handleSave = async () => {
    if (!draft) return;
    setSaving(true);
    try {
      await api.post("/admin/system-settings", draft);
      setSavedDraft(draft);
      toast.success("Tuning values saved to system settings");
    } catch {
      toast.error("Failed to save tuning values");
    } finally {
      setSaving(false);
    }
  };

  const handleReset = async () => {
    if (!savedDraft) return;
    setResetting(true);
    setDraft(savedDraft);
    setResetting(false);
  };

  const handleNumericChange = (key: TuningKey, value: string) => {
    setDraft((current) =>
      current ? { ...current, [key]: Number(value) } : current,
    );
  };

  const handleToggle = (key: TuningKey) => {
    setDraft((current) =>
      current ? { ...current, [key]: !(current[key] as boolean) } : current,
    );
  };

  if (loading || draft === null) {
    return (
      <div className="min-h-[60vh] flex items-center justify-center">
        <div
          className="flex items-center gap-3 text-sm font-medium"
          style={{ color: "#64748B" }}
        >
          <Loader2 className="h-4 w-4 animate-spin" />
          Loading model tuning workspace…
        </div>
      </div>
    );
  }

  const tickRate = sessionMeta?.tick_rate_hz ?? 10;
  const objectVoteTargets = sessionMeta?.object_vote_targets ?? {};
  const objectTiming = ["phone", "book", "headphone", "earbud"].map((key) => ({
    key,
    votes: objectVoteTargets[key] ?? 0,
    seconds: tickRate > 0 ? (objectVoteTargets[key] ?? 0) / tickRate : 0,
  }));
  const focusConfig =
    FOCUS_OPTIONS.find((option) => option.key === focusedDetection) ??
    FOCUS_OPTIONS[0];
  const focusedSignals =
    telemetry?.signals.filter((signal) => signal.key === focusedDetection) ??
    [];
  const visibleFields = NUM_FIELDS.filter((field) =>
    focusConfig.fields.includes(field.key),
  );
  const visibleToggle = focusConfig.toggle
    ? (TOGGLE_FIELDS.find((field) => field.key === focusConfig.toggle) ?? null)
    : null;
  const focusedObjectTiming =
    objectTiming.find((item) => item.key === focusedDetection) ?? null;
  const poseSummary = telemetry?.summary.pose;

  return (
    <div className="space-y-6">
      <canvas ref={canvasRef} className="hidden" />

      <section
        className="rounded-3xl border p-5 lg:p-5"
        style={{
          background: "linear-gradient(135deg, #0F172A 0%, #134E4A 100%)",
          borderColor: "rgba(255,255,255,0.08)",
        }}
      >
        <div className="flex flex-col gap-4 xl:flex-row xl:items-start xl:justify-between">
          <div className="space-y-2 max-w-2xl">
            <div
              className="inline-flex items-center gap-2 rounded-full px-3 py-1 text-[11px] font-semibold"
              style={{ background: "rgba(255,255,255,0.08)", color: "#A7F3D0" }}
            >
              <Sparkles className="h-3.5 w-3.5" />
              Sysadmin Calibration Lab
            </div>
            <div>
              <h1 className="text-2xl font-bold tracking-tight text-white lg:text-[2rem]">
                Model Tuning
              </h1>
              <p
                className="mt-1.5 text-sm leading-6"
                style={{ color: "rgba(255,255,255,0.72)" }}
              >
                Raw webcam on the left, engine debug view on the right, and
                exact persistence/cooldown numbers underneath. Draft values
                apply immediately to the calibration session at 10 fps. Save
                only when the behavior feels right.
              </p>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-2.5 xl:max-w-[48rem] xl:justify-end">
            <select
              value={selectedContainerId}
              onChange={(event) => setSelectedContainerId(event.target.value)}
              className="rounded-xl border px-3 py-2 text-sm font-medium min-w-[9rem]"
              style={{
                background: "rgba(255,255,255,0.08)",
                color: "#FFFFFF",
                borderColor: "rgba(255,255,255,0.12)",
              }}
            >
              {containers.map((container) => (
                <option
                  key={container.id}
                  value={container.id}
                  style={{ color: "#0F172A" }}
                >
                  {container.container_name || "engine"} :{" "}
                  {container.container_port}
                </option>
              ))}
            </select>
            <select
              value={focusedDetection}
              onChange={(event) =>
                setFocusedDetection(event.target.value as FocusKey)
              }
              className="rounded-xl border px-3 py-2 text-sm font-medium min-w-[10rem]"
              style={{
                background: "rgba(255,255,255,0.08)",
                color: "#FFFFFF",
                borderColor: "rgba(255,255,255,0.12)",
              }}
            >
              {FOCUS_OPTIONS.map((option) => (
                <option
                  key={option.key}
                  value={option.key}
                  style={{ color: "#0F172A" }}
                >
                  {option.label}
                </option>
              ))}
            </select>
            <button
              disabled={connecting}
              onClick={async () => {
                if (isStreaming) {
                  setIsStreaming(false);
                  await closeCalibrationSession();
                } else {
                  await createCalibrationSession();
                  setIsStreaming(true);
                }
              }}
              className="inline-flex items-center gap-2 rounded-xl border px-4 py-2 text-sm font-semibold disabled:opacity-60"
              style={{
                borderColor: isStreaming ? "rgba(255,255,255,0.12)" : "#A7F3D0",
                background: isStreaming
                  ? "rgba(255,255,255,0.08)"
                  : "rgba(16,185,129,0.16)",
                color: "#FFFFFF",
              }}
            >
              {connecting ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : isStreaming ? (
                <PauseCircle className="h-4 w-4" />
              ) : (
                <PlayCircle className="h-4 w-4" />
              )}
              {connecting
                ? "Connecting…"
                : isStreaming
                  ? "Stop Stream"
                  : "Start Stream"}
            </button>
            <button
              onClick={async () => {
                await createCalibrationSession();
                setIsStreaming(true);
              }}
              disabled={connecting || !isStreaming}
              className="inline-flex items-center gap-2 rounded-xl px-4 py-2 text-sm font-semibold text-white disabled:opacity-60"
              style={{ background: "#0EA5E9" }}
            >
              {connecting ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : (
                <RefreshCw className="h-4 w-4" />
              )}
              Reconnect
            </button>
            <button
              onClick={handleReset}
              disabled={resetting}
              className="inline-flex items-center gap-2 rounded-xl border px-4 py-2 text-sm font-semibold disabled:opacity-60"
              style={{
                borderColor: "rgba(255,255,255,0.18)",
                color: "#E2E8F0",
              }}
            >
              {resetting ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : (
                <RotateCcw className="h-4 w-4" />
              )}
              Reset Draft
            </button>
            <button
              onClick={handleSave}
              disabled={saving}
              className="inline-flex items-center gap-2 rounded-xl px-4 py-2 text-sm font-semibold text-white disabled:opacity-60"
              style={{ background: "#F97316" }}
            >
              {saving ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : (
                <Save className="h-4 w-4" />
              )}
              Save Settings
            </button>
          </div>
        </div>

        <div className="mt-4 grid gap-3 sm:grid-cols-2 xl:grid-cols-5">
          <div
            className="rounded-2xl border p-3.5"
            style={{
              background: "rgba(255,255,255,0.08)",
              borderColor: "rgba(255,255,255,0.08)",
            }}
          >
            <p
              className="text-xs font-semibold uppercase tracking-[0.18em]"
              style={{ color: "rgba(255,255,255,0.5)" }}
            >
              Tick Rate
            </p>
            <p className="mt-1.5 text-xl font-bold text-white">
              {tickRate} fps
            </p>
            <p
              className="mt-1 text-xs"
              style={{ color: "rgba(255,255,255,0.6)" }}
            >
              100 ms request loop
            </p>
          </div>
          <div
            className="rounded-2xl border p-3.5"
            style={{
              background: "rgba(255,255,255,0.08)",
              borderColor: "rgba(255,255,255,0.08)",
            }}
          >
            <p
              className="text-xs font-semibold uppercase tracking-[0.18em]"
              style={{ color: "rgba(255,255,255,0.5)" }}
            >
              Engine
            </p>
            <p className="mt-1.5 text-base font-bold text-white">
              {sessionMeta?.engine.container_name || "—"}
            </p>
            <p
              className="mt-1 text-xs font-mono"
              style={{ color: "rgba(255,255,255,0.6)" }}
            >
              {sessionMeta?.engine.url || "No engine selected"}
            </p>
          </div>
          <div
            className="rounded-2xl border p-3.5"
            style={{
              background: "rgba(255,255,255,0.08)",
              borderColor: "rgba(255,255,255,0.08)",
            }}
          >
            <p
              className="text-xs font-semibold uppercase tracking-[0.18em]"
              style={{ color: "rgba(255,255,255,0.5)" }}
            >
              Focused Detection
            </p>
            <p className="mt-1.5 text-lg font-bold text-white">
              {focusConfig.label}
            </p>
            <p
              className="mt-1 text-xs"
              style={{ color: "rgba(255,255,255,0.6)" }}
            >
              {visibleFields.length > 0
                ? `${visibleFields.length} timing control${visibleFields.length > 1 ? "s" : ""}`
                : "No numeric duration control"}
              {visibleToggle ? " • toggle available" : ""}
            </p>
          </div>
          <div
            className="rounded-2xl border p-3.5"
            style={{
              background: "rgba(255,255,255,0.08)",
              borderColor: "rgba(255,255,255,0.08)",
            }}
          >
            <p
              className="text-xs font-semibold uppercase tracking-[0.18em]"
              style={{ color: "rgba(255,255,255,0.5)" }}
            >
              Processing
            </p>
            <p className="mt-1.5 text-xl font-bold text-white">
              {telemetry?.processing_ms?.toFixed(1) ?? "—"} ms
            </p>
            <p
              className="mt-1 text-xs"
              style={{ color: "rgba(255,255,255,0.6)" }}
            >
              Inference + telemetry roundtrip
            </p>
          </div>
          <div
            className="rounded-2xl border p-3.5"
            style={{
              background: "rgba(255,255,255,0.08)",
              borderColor: "rgba(255,255,255,0.08)",
            }}
          >
            <p
              className="text-xs font-semibold uppercase tracking-[0.18em]"
              style={{ color: "rgba(255,255,255,0.5)" }}
            >
              Risk State
            </p>
            <p className="mt-1.5 text-xl font-bold text-white">
              {telemetry?.risk.state || "NORMAL"}
            </p>
            <p
              className="mt-1 text-xs"
              style={{ color: "rgba(255,255,255,0.6)" }}
            >
              Score {telemetry?.risk.score ?? 0} • Quiet{" "}
              {fmtSeconds(telemetry?.risk.quiet_for_s)}
            </p>
          </div>
        </div>
      </section>

      <section className="space-y-6">
        <div className="grid gap-6 xl:grid-cols-2">
          <div
            className="rounded-3xl border bg-white p-4 lg:p-5"
            style={{ borderColor: "#E2E8F0" }}
          >
            <div className="mb-3 flex items-center gap-2">
              <Camera className="h-4 w-4" style={{ color: "#0EA5E9" }} />
              <h2
                className="text-sm font-semibold"
                style={{ color: "#0F172A" }}
              >
                Raw Webcam
              </h2>
            </div>
            <div
              className="overflow-hidden rounded-2xl border"
              style={{ borderColor: "#E2E8F0", background: "#020617" }}
            >
              <video
                ref={videoRef}
                autoPlay
                muted
                playsInline
                className="aspect-[16/10] w-full object-cover lg:aspect-[16/9]"
              />
            </div>
            <p className="mt-3 text-xs leading-5" style={{ color: "#64748B" }}>
              This is the direct browser feed before the engine applies
              detection, gating, or overlays.
            </p>
          </div>

          <div
            className="rounded-3xl border bg-white p-4 lg:p-5"
            style={{ borderColor: "#E2E8F0" }}
          >
            <div className="mb-3 flex items-center gap-2">
              <Cpu className="h-4 w-4" style={{ color: "#F97316" }} />
              <h2
                className="text-sm font-semibold"
                style={{ color: "#0F172A" }}
              >
                Model Debug View
              </h2>
            </div>
            <div
              className="overflow-hidden rounded-2xl border"
              style={{ borderColor: "#E2E8F0", background: "#020617" }}
            >
              {processedSrc ? (
                // eslint-disable-next-line @next/next/no-img-element
                <img
                  src={processedSrc}
                  alt="Model debug"
                  className="aspect-[16/10] w-full object-cover lg:aspect-[16/9]"
                />
              ) : (
                <div
                  className="aspect-[16/10] flex items-center justify-center text-sm lg:aspect-[16/9]"
                  style={{ color: "#64748B" }}
                >
                  {isStreaming
                    ? "Waiting for processed frames…"
                    : "Streaming paused"}
                </div>
              )}
            </div>
            <p className="mt-3 text-xs leading-5" style={{ color: "#64748B" }}>
              Forced debug overlay from the engine. Use this to judge what the
              model actually sees and why a timer is or is not progressing.
            </p>
          </div>
        </div>

        <div className="grid gap-6 xl:grid-cols-[1.2fr_0.8fr]">
          <div className="space-y-6">
            <div
              className="rounded-3xl border bg-white p-5"
              style={{ borderColor: "#E2E8F0" }}
            >
              <div className="flex items-center gap-2">
                <Activity className="h-4 w-4" style={{ color: "#22577A" }} />
                <h2
                  className="text-sm font-semibold"
                  style={{ color: "#0F172A" }}
                >
                  {focusConfig.label} Telemetry
                </h2>
              </div>
              <p
                className="mt-2 text-xs leading-5"
                style={{ color: "#64748B" }}
              >
                This view is narrowed to the selected detection so you can read
                the actual thresholds, occurrences, and cooldowns without
                scanning unrelated signals.
              </p>

              <div className="mt-5 space-y-3">
                {focusedSignals.length === 0 && (
                  <div
                    className="rounded-2xl border p-4 text-sm"
                    style={{
                      borderColor: "#E2E8F0",
                      background: "#FCFDFE",
                      color: "#64748B",
                    }}
                  >
                    No live telemetry is available yet for{" "}
                    {focusConfig.label.toLowerCase()}.
                  </div>
                )}
                {focusedSignals.map((signal) => {
                  const stage = stageStyle(signal.stage);
                  return (
                    <div
                      key={signal.key}
                      className="rounded-2xl border p-4"
                      style={{ borderColor: "#E2E8F0", background: "#FCFDFE" }}
                    >
                      <div className="flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between">
                        <div className="space-y-2">
                          <div className="flex items-center gap-2">
                            <span
                              className="text-sm font-semibold"
                              style={{ color: "#0F172A" }}
                            >
                              {signal.label}
                            </span>
                            <span
                              className="rounded-full border px-2 py-0.5 text-[11px] font-semibold capitalize"
                              style={{
                                background: stage.bg,
                                color: stage.fg,
                                borderColor: stage.border,
                              }}
                            >
                              {signal.stage.replaceAll("-", " ")}
                            </span>
                          </div>
                          <p
                            className="text-xs leading-5"
                            style={{ color: "#64748B" }}
                          >
                            {fmtThresholds(signal.thresholds)}
                          </p>
                        </div>
                        <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
                          <div>
                            <p
                              className="text-[11px] font-semibold uppercase tracking-wide"
                              style={{ color: "#64748B" }}
                            >
                              Duration
                            </p>
                            <p
                              className="mt-1 text-sm font-semibold"
                              style={{ color: "#0F172A" }}
                            >
                              {fmtSeconds(signal.duration_s)}
                            </p>
                          </div>
                          <div>
                            <p
                              className="text-[11px] font-semibold uppercase tracking-wide"
                              style={{ color: "#64748B" }}
                            >
                              Occurrences
                            </p>
                            <p
                              className="mt-1 text-sm font-semibold"
                              style={{ color: "#0F172A" }}
                            >
                              {signal.risk_debug.occurrence_count}
                            </p>
                          </div>
                          <div>
                            <p
                              className="text-[11px] font-semibold uppercase tracking-wide"
                              style={{ color: "#64748B" }}
                            >
                              Score CD
                            </p>
                            <p
                              className="mt-1 text-sm font-semibold"
                              style={{ color: "#0F172A" }}
                            >
                              {fmtSeconds(
                                signal.risk_debug.score_cooldown_remaining_s,
                              )}
                            </p>
                          </div>
                          <div>
                            <p
                              className="text-[11px] font-semibold uppercase tracking-wide"
                              style={{ color: "#64748B" }}
                            >
                              Warn CD
                            </p>
                            <p
                              className="mt-1 text-sm font-semibold"
                              style={{ color: "#0F172A" }}
                            >
                              {fmtSeconds(
                                signal.alert_debug.warn_cooldown_remaining_s,
                              )}
                            </p>
                          </div>
                        </div>
                      </div>

                      <div
                        className="mt-3 grid gap-2 sm:grid-cols-2 xl:grid-cols-3 text-xs"
                        style={{ color: "#64748B" }}
                      >
                        <div>
                          Condition:{" "}
                          <span
                            className="font-semibold"
                            style={{ color: "#0F172A" }}
                          >
                            {signal.condition_active ? "true" : "false"}
                          </span>
                        </div>
                        <div>
                          Active:{" "}
                          <span
                            className="font-semibold"
                            style={{ color: "#0F172A" }}
                          >
                            {signal.active ? "true" : "false"}
                          </span>
                        </div>
                        <div>
                          Risk Added:{" "}
                          <span
                            className="font-semibold"
                            style={{ color: "#0F172A" }}
                          >
                            {signal.risk_added}
                          </span>
                        </div>
                        {"tracker" in signal.details && (
                          <div>
                            Votes:{" "}
                            <span
                              className="font-semibold"
                              style={{ color: "#0F172A" }}
                            >
                              {String(
                                (
                                  signal.details.tracker as Record<
                                    string,
                                    unknown
                                  >
                                ).votes,
                              )}
                              /
                              {String(
                                (
                                  signal.details.tracker as Record<
                                    string,
                                    unknown
                                  >
                                ).min_votes,
                              )}
                            </span>
                          </div>
                        )}
                        {"confidence" in signal.details && (
                          <div>
                            Confidence:{" "}
                            <span
                              className="font-semibold"
                              style={{ color: "#0F172A" }}
                            >
                              {String(signal.details.confidence)}
                            </span>
                          </div>
                        )}
                        {"people_count" in signal.details && (
                          <div>
                            People Count:{" "}
                            <span
                              className="font-semibold"
                              style={{ color: "#0F172A" }}
                            >
                              {String(signal.details.people_count)}
                            </span>
                          </div>
                        )}
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>

            <div
              className="rounded-3xl border bg-white p-5"
              style={{ borderColor: "#E2E8F0" }}
            >
              <div className="flex items-center gap-2">
                <Cpu className="h-4 w-4" style={{ color: "#7C3AED" }} />
                <h2
                  className="text-sm font-semibold"
                  style={{ color: "#0F172A" }}
                >
                  Readable Pose Metrics
                </h2>
              </div>
              <p
                className="mt-2 text-xs leading-5"
                style={{ color: "#64748B" }}
              >
                These are the exact live values behind the tiny debug labels,
                shown larger so you can tune head and liveness thresholds
                without squinting.
              </p>

              <div className="mt-4 grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
                {[
                  {
                    label: "Yaw",
                    value: poseSummary ? poseSummary.yaw.toFixed(2) : "—",
                    hint: "Head turn angle",
                  },
                  {
                    label: "Pitch",
                    value: poseSummary ? poseSummary.pitch.toFixed(2) : "—",
                    hint: "Up/down tilt",
                  },
                  {
                    label: "Gaze",
                    value: poseSummary ? poseSummary.gaze.toFixed(2) : "—",
                    hint: "Eye direction score",
                  },
                  {
                    label: "EAR",
                    value: poseSummary ? poseSummary.ear.toFixed(3) : "—",
                    hint: "Eye aspect ratio",
                  },
                  {
                    label: "Lip MAR",
                    value:
                      telemetry?.summary.lip_mar !== undefined
                        ? telemetry.summary.lip_mar.toFixed(3)
                        : "—",
                    hint: "Mouth aspect ratio",
                  },
                  {
                    label: "Blinks",
                    value: poseSummary ? String(poseSummary.total_blinks) : "—",
                    hint: poseSummary?.blinked
                      ? "Blink detected this tick"
                      : "No blink on this tick",
                  },
                ].map((item) => (
                  <div
                    key={item.label}
                    className="rounded-2xl border p-4"
                    style={{ borderColor: "#E2E8F0", background: "#FCFDFE" }}
                  >
                    <p
                      className="text-[11px] font-semibold uppercase tracking-[0.18em]"
                      style={{ color: "#64748B" }}
                    >
                      {item.label}
                    </p>
                    <p
                      className="mt-2 text-3xl font-bold tabular-nums"
                      style={{ color: "#0F172A" }}
                    >
                      {item.value}
                    </p>
                    <p className="mt-1 text-xs" style={{ color: "#64748B" }}>
                      {item.hint}
                    </p>
                  </div>
                ))}
              </div>
            </div>
          </div>

          <div className="space-y-6">
            <div
              className="rounded-3xl border bg-white p-5"
              style={{ borderColor: "#E2E8F0" }}
            >
              <div className="flex items-center gap-2">
                <SlidersHorizontal
                  className="h-4 w-4"
                  style={{ color: "#F97316" }}
                />
                <h2
                  className="text-sm font-semibold"
                  style={{ color: "#0F172A" }}
                >
                  {focusConfig.label} Controls
                </h2>
              </div>
              <p
                className="mt-2 text-xs leading-5"
                style={{ color: "#64748B" }}
              >
                Only the timing settings that affect{" "}
                {focusConfig.label.toLowerCase()} are shown here. Draft values
                are sent to the calibration engine on every frame.
              </p>

              <div className="mt-4 space-y-3">
                {visibleFields.length === 0 && (
                  <div
                    className="rounded-2xl border p-4 text-sm"
                    style={{
                      borderColor: "#E2E8F0",
                      background: "#FCFDFE",
                      color: "#64748B",
                    }}
                  >
                    {focusConfig.label} does not expose a seconds-based slider
                    here. Use the toggle below or the object persistence card if
                    relevant.
                  </div>
                )}
                {visibleFields.map((field) => (
                  <label
                    key={field.key}
                    className="block rounded-2xl border p-3"
                    style={{ borderColor: "#E2E8F0", background: "#FCFDFE" }}
                  >
                    <div className="flex items-center justify-between gap-3">
                      <span
                        className="text-sm font-medium"
                        style={{ color: "#0F172A" }}
                      >
                        {field.label}
                      </span>
                      <span
                        className="text-xs font-semibold"
                        style={{ color: "#64748B" }}
                      >
                        {String(draft[field.key])}
                        {field.unit ? ` ${field.unit}` : ""}
                      </span>
                    </div>
                    <input
                      type="range"
                      min={field.min}
                      max={field.max}
                      step={field.step}
                      value={Number(draft[field.key])}
                      onChange={(event) =>
                        handleNumericChange(field.key, event.target.value)
                      }
                      className="mt-3 w-full accent-orange-500"
                    />
                  </label>
                ))}
              </div>
            </div>

            <div
              className="rounded-3xl border bg-white p-5"
              style={{ borderColor: "#E2E8F0" }}
            >
              <h2
                className="text-sm font-semibold"
                style={{ color: "#0F172A" }}
              >
                {focusConfig.label} Toggle
              </h2>
              <div className="mt-4 space-y-2">
                {!visibleToggle && (
                  <div
                    className="rounded-2xl border px-3 py-3 text-sm"
                    style={{
                      borderColor: "#E2E8F0",
                      background: "#F8FAFC",
                      color: "#64748B",
                    }}
                  >
                    No dedicated enable or disable toggle is available for this
                    focused detection.
                  </div>
                )}
                {visibleToggle &&
                  (() => {
                    const field = visibleToggle;
                    const enabled = Boolean(draft[field.key]);
                    return (
                      <button
                        key={field.key}
                        onClick={() => handleToggle(field.key)}
                        className="flex w-full items-center justify-between rounded-2xl border px-3 py-2.5 text-sm font-medium"
                        style={{
                          borderColor: enabled ? "#BBF7D0" : "#E2E8F0",
                          background: enabled ? "#ECFDF5" : "#F8FAFC",
                          color: "#0F172A",
                        }}
                      >
                        <span>{field.label}</span>
                        {enabled ? (
                          <ToggleRight
                            className="h-4 w-4"
                            style={{ color: "#16A34A" }}
                          />
                        ) : (
                          <ToggleLeft
                            className="h-4 w-4"
                            style={{ color: "#64748B" }}
                          />
                        )}
                      </button>
                    );
                  })()}
              </div>
            </div>

            <div
              className="rounded-3xl border bg-white p-5"
              style={{ borderColor: "#E2E8F0" }}
            >
              <h2
                className="text-sm font-semibold"
                style={{ color: "#0F172A" }}
              >
                Object Persistence At {tickRate} fps
              </h2>
              <p
                className="mt-2 text-xs leading-5"
                style={{ color: "#64748B" }}
              >
                Object detections use vote windows, not plain seconds. These are
                the effective stable times with the current engine
                configuration.
              </p>
              <div className="mt-4 space-y-2">
                {focusedObjectTiming ? (
                  <div
                    className="flex items-center justify-between rounded-2xl border px-3 py-2.5 text-sm"
                    style={{ borderColor: "#E2E8F0", background: "#FCFDFE" }}
                  >
                    <span
                      className="font-medium capitalize"
                      style={{ color: "#0F172A" }}
                    >
                      {focusedObjectTiming.key}
                    </span>
                    <span style={{ color: "#64748B" }}>
                      {focusedObjectTiming.votes} votes ≈{" "}
                      {fmtSeconds(focusedObjectTiming.seconds)}
                    </span>
                  </div>
                ) : (
                  <div
                    className="rounded-2xl border px-3 py-3 text-sm"
                    style={{
                      borderColor: "#E2E8F0",
                      background: "#F8FAFC",
                      color: "#64748B",
                    }}
                  >
                    Focused detection is not using object-vote persistence.
                  </div>
                )}
              </div>
            </div>

            <div
              className="rounded-3xl border bg-white p-5"
              style={{ borderColor: "#E2E8F0" }}
            >
              <h2
                className="text-sm font-semibold"
                style={{ color: "#0F172A" }}
              >
                Session Summary
              </h2>
              <div className="mt-4 grid gap-3 sm:grid-cols-2">
                <div
                  className="rounded-2xl border p-3"
                  style={{ borderColor: "#E2E8F0", background: "#FCFDFE" }}
                >
                  <p
                    className="text-[11px] font-semibold uppercase tracking-wide"
                    style={{ color: "#64748B" }}
                  >
                    Warnings
                  </p>
                  <p
                    className="mt-2 text-sm font-medium"
                    style={{ color: "#0F172A" }}
                  >
                    {telemetry?.summary.active_warnings.join(", ") || "None"}
                  </p>
                </div>
                <div
                  className="rounded-2xl border p-3"
                  style={{ borderColor: "#E2E8F0", background: "#FCFDFE" }}
                >
                  <p
                    className="text-[11px] font-semibold uppercase tracking-wide"
                    style={{ color: "#64748B" }}
                  >
                    Alerts
                  </p>
                  <p
                    className="mt-2 text-sm font-medium"
                    style={{ color: "#0F172A" }}
                  >
                    {telemetry?.summary.active_alerts.join(", ") || "None"}
                  </p>
                </div>
                <div
                  className="rounded-2xl border p-3"
                  style={{ borderColor: "#E2E8F0", background: "#FCFDFE" }}
                >
                  <p
                    className="text-[11px] font-semibold uppercase tracking-wide"
                    style={{ color: "#64748B" }}
                  >
                    People / Face
                  </p>
                  <p
                    className="mt-2 text-sm font-medium"
                    style={{ color: "#0F172A" }}
                  >
                    {telemetry?.summary.people_count ?? 0} people • face{" "}
                    {telemetry?.summary.face_detected ? "detected" : "missing"}
                  </p>
                </div>
                <div
                  className="rounded-2xl border p-3"
                  style={{ borderColor: "#E2E8F0", background: "#FCFDFE" }}
                >
                  <p
                    className="text-[11px] font-semibold uppercase tracking-wide"
                    style={{ color: "#64748B" }}
                  >
                    Landmarks / Audio
                  </p>
                  <p
                    className="mt-2 text-sm font-medium"
                    style={{ color: "#0F172A" }}
                  >
                    landmarks{" "}
                    {telemetry?.summary.landmarks_active ? "on" : "off"} •
                    speech {telemetry?.summary.speech_active ? "on" : "off"}
                  </p>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>
    </div>
  );
}
