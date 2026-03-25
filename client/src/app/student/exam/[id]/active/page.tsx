'use client';

import { useEffect, useState, useRef, useCallback } from 'react';
import { useRouter, useParams } from 'next/navigation';
import {
  Loader2, AlertOctagon, CheckCircle2, ShieldAlert,
  Maximize2, AlertTriangle, Clock
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';
import { toast } from 'sonner';
import api from '@/lib/axios';
import { ConfirmDialog } from '@/components/common/ConfirmDialog';

// ──────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────

function parseUTCDate(iso: string): Date {
  if (!iso) return new Date(NaN);
  // Already has timezone info (Z or +00:00 style) — parse directly
  if (iso.endsWith('Z') || /[+-]\d{2}:\d{2}$/.test(iso)) return new Date(iso);
  // Naive datetime from server — treat as UTC
  return new Date(iso + 'Z');
}

function computeRemaining(
  startTimeISO: string,
  durationMinutes: number,
  extensionSeconds: number,
  serverNowISO: string,
): number {
  const start = parseUTCDate(startTimeISO).getTime();
  const totalMs = (durationMinutes * 60 + extensionSeconds) * 1000;
  const deadline = start + totalMs;
  const localNow = Date.now();
  // Compute clock skew from server_now
  const serverNow = parseUTCDate(serverNowISO).getTime();
  const skew = serverNow - localNow;
  const remaining = Math.max(0, Math.floor((deadline - (localNow + skew)) / 1000));
  return remaining;
}

// SSE client using fetch + ReadableStream (supports Authorization header)
function openSSE(
  url: string,
  token: string,
  handlers: Record<string, (data: any) => void>,
): () => void {
  let cancelled = false;
  const controller = new AbortController();

  (async () => {
    try {
      const res = await fetch(url, {
        headers: { Authorization: `Bearer ${token}` },
        signal: controller.signal,
      });
      if (!res.body) return;
      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      let buf = '';
      while (!cancelled) {
        const { done, value } = await reader.read();
        if (done) break;
        buf += decoder.decode(value, { stream: true });
        const lines = buf.split('\n');
        buf = lines.pop() ?? '';
        let eventType = 'message';
        for (const line of lines) {
          if (line.startsWith('event: ')) {
            eventType = line.slice(7).trim();
          } else if (line.startsWith('data: ')) {
            try {
              const payload = JSON.parse(line.slice(6));
              handlers[eventType]?.(payload);
            } catch {}
            eventType = 'message';
          }
        }
      }
    } catch {
      // Connection closed / cancelled — normal
    }
  })();

  return () => {
    cancelled = true;
    controller.abort();
  };
}

export default function ActiveExamPage() {
  const router = useRouter();
  const params = useParams();
  const examId = params.id as string;

  const videoRef = useRef<HTMLVideoElement>(null);
  const streamRef = useRef<MediaStream | null>(null);
  const timerRef = useRef<NodeJS.Timeout | null>(null);
  const sseCloseRef = useRef<(() => void) | null>(null);
  const pcRef = useRef<RTCPeerConnection | null>(null);
  const proctorPcIdRef = useRef<string | null>(null);
  const proctorSseCloseRef = useRef<(() => void) | null>(null);

  const [exam, setExam] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [timeLeft, setTimeLeft] = useState(0);

  // Termination (overlay removed — redirects to /terminated page)
  const [terminated, setTerminated] = useState(false);

  // UI states
  const [isConfirmOpen, setIsConfirmOpen] = useState(false);
  const [fullscreenExited, setFullscreenExited] = useState(false);
  const [tabSwitchCount, setTabSwitchCount] = useState(0);
  const tabThreshold = exam?.config?.tab_switching ? (exam?.flag_threshold || 3) : Infinity;

  // ── Helpers ──

  const startTimer = useCallback((remaining: number) => {
    if (timerRef.current) clearInterval(timerRef.current);
    setTimeLeft(remaining);
    timerRef.current = setInterval(() => {
      setTimeLeft((prev) => {
        if (prev <= 1) {
          clearInterval(timerRef.current!);
          handleAutoSubmit();
          return 0;
        }
        return prev - 1;
      });
    }, 1000);
  }, []);

  const handleAutoSubmit = useCallback(async () => {
    setSubmitting(true);
    toast.error('Time is up! Auto-submitting…');
    await executeSubmit(true);
  }, []);

  const executeSubmit = useCallback(async (isAuto = false) => {
    setSubmitting(true);
    try {
      await api.post('/exam/submit');
      await api.post('/exam/end');
      if (document.fullscreenElement) await document.exitFullscreen().catch(() => {});
      sseCloseRef.current?.();
      proctorSseCloseRef.current?.();
      pcRef.current?.close();
      if (streamRef.current) streamRef.current.getTracks().forEach((t) => t.stop());
      router.push(`/student/exam/${examId}/completion`);
    } catch (err: any) {
      toast.error(err?.response?.data?.detail || 'Submit failed. Please retry.');
      if (!isAuto) setSubmitting(false);
    }
  }, [examId, router]);

  // ── SSE setup ──

  const setupSSE = useCallback((sessionId: string) => {
    const token = localStorage.getItem('access_token') || '';
    const baseUrl = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

    sseCloseRef.current?.();
    sseCloseRef.current = openSSE(
      `${baseUrl}/exam/${examId}/events`,
      token,
      {
        TIME_EXTENDED: (data) => {
          toast.success(`Time extended by ${data.added_minutes} minute(s)!`);
          setTimeLeft((prev) => prev + data.added_minutes * 60);
        },
        TERMINATED: () => {
          if (document.fullscreenElement) document.exitFullscreen().catch(() => {});
          router.replace(`/student/exam/${examId}/terminated`);
        },
      }
    );
  }, [examId, exam]);

  // ── Proctor engine WebRTC setup ──

  const setupProctor = useCallback(async () => {
    if (!streamRef.current) return;
    try {
      const pc = new RTCPeerConnection({ iceServers: [] });
      pcRef.current = pc;

      streamRef.current.getTracks().forEach(t => pc.addTrack(t, streamRef.current!));

      // Trickle ICE proxy
      pc.onicecandidate = async (e) => {
        if (e.candidate && proctorPcIdRef.current) {
          try {
            await api.post(`/exam/${examId}/proctor-ice`, {
              candidate: e.candidate.candidate,
              sdpMid: e.candidate.sdpMid,
              sdpMLineIndex: e.candidate.sdpMLineIndex,
            });
          } catch {}
        }
      };

      const offer = await pc.createOffer();
      await pc.setLocalDescription(offer);

      // Wait for ICE gathering (max 3s)
      await new Promise<void>(resolve => {
        if (pc.iceGatheringState === 'complete') { resolve(); return; }
        const check = () => { if (pc.iceGatheringState === 'complete') resolve(); };
        pc.addEventListener('icegatheringstatechange', check);
        setTimeout(resolve, 3000);
      });

      const res = await api.post(`/exam/${examId}/proctor-connect`, {
        sdp: pc.localDescription!.sdp,
        type: pc.localDescription!.type,
      });

      proctorPcIdRef.current = res.data.pc_id ?? res.data.device_id;
      await pc.setRemoteDescription(
        new RTCSessionDescription({ sdp: res.data.sdp, type: res.data.type })
      );

      // Open proctor events SSE
      // Engine sends all events as: data: {"type":"alert",...}  (no event: line)
      // so the openSSE helper dispatches them all under 'message'.
      const token = localStorage.getItem('access_token') || '';
      const baseUrl = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';
      proctorSseCloseRef.current = openSSE(
        `${baseUrl}/exam/${examId}/proctor-events`,
        token,
        {
          message: (data: any) => {
            const t = data?.type;
            if (t === 'alert' || t === 'warning') {
              toast.warning(data.message || data.alert_type || 'Proctoring alert', {
                duration: 6000,
                icon: <ShieldAlert className="h-5 w-5 text-amber-500" />,
              });
            } else if (t === 'risk_update') {
              if (data.state === 'HIGH_RISK' || data.state === 'ADMIN_REVIEW') {
                toast.error(`Risk Level: ${data.state} (score: ${Math.round(data.risk_score ?? 0)})`, { duration: 6000 });
              }
            }
          },
        }
      );
    } catch (err: any) {
      const detail = err?.response?.data?.detail;
      if (detail) toast.error(`Proctor engine: ${detail}`);
      // Non-fatal — session continues; backend already logged it
    }
  }, [examId]);

  // ── Init ──

  useEffect(() => {
    let cancelled = false;

    const init = async () => {
      try {
        const [sessionRes] = await Promise.all([api.get(`/exam/${examId}/session-active`)]);
        if (cancelled) return;

        const sessionData = sessionRes.data;
        setExam(sessionData);

        const remaining = computeRemaining(
          sessionData.start_time,
          sessionData.duration_minutes,
          sessionData.time_extension_seconds || 0,
          sessionData.server_now,
        );

        // Resume camera
        const camId = localStorage.getItem(`exam_cam_${examId}`);
        const micId = localStorage.getItem(`exam_mic_${examId}`);
        const s = await navigator.mediaDevices.getUserMedia({
          video: { deviceId: camId ? { exact: camId } : undefined },
          audio: { deviceId: micId ? { exact: micId } : undefined },
        });
        if (cancelled) { s.getTracks().forEach((t) => t.stop()); return; }
        streamRef.current = s;

        setLoading(false);
        startTimer(remaining);
        setupSSE(sessionData.session_id);
        setupProctor();

        if (sessionData.status === 'TERMINATED') {
          // Navigate to dedicated terminated page — do not show overlay
          if (document.fullscreenElement) document.exitFullscreen().catch(() => {});
          router.replace(`/student/exam/${examId}/terminated`);
          return;
        } else if (sessionData.status === 'DISCONNECTED') {
          // Session went stale — go back through full preExam flow
          toast.error('Your session was disconnected. Please reconnect.');
          router.replace(`/student/exam/${examId}/device`);
          return;
        } else if (sessionData.status !== 'ACTIVE') {
          // CREATED or unknown — exam wasn't properly started
          toast.error('Exam session is not active. Please start your exam.');
          router.replace(`/student/exam/${examId}/info`);
          return;
        }
      } catch {
        toast.error('Failed to load exam. Redirecting…');
        router.replace('/student/dashboard');
      }
    };

    init();
    return () => {
      cancelled = true;
      if (timerRef.current) clearInterval(timerRef.current);
      sseCloseRef.current?.();
      proctorSseCloseRef.current?.();
      pcRef.current?.close();
      streamRef.current?.getTracks().forEach((t) => t.stop());
    };
  }, [examId]);

  // Bind video once loaded
  useEffect(() => {
    if (!loading && streamRef.current && videoRef.current) {
      videoRef.current.srcObject = streamRef.current;
    }
  }, [loading]);

  // Heartbeat (fallback for SSE gaps)
  useEffect(() => {
    if (loading || terminated) return;
    const id = setInterval(async () => {
      try {
        const res = await api.post('/exam/heartbeat');
        if (res.data.status === 'terminated') {
          if (document.fullscreenElement) document.exitFullscreen().catch(() => {});
          router.replace(`/student/exam/${examId}/terminated`);
        }
      } catch (err: any) {
        if (err?.response?.status === 403) {
          // 403 can mean TERMINATED, ENDED, DISCONNECTED, or expired — check actual status
          try {
            const sr = await api.get(`/exam/${examId}/session-active`);
            const s = sr.data.status;
            if (s === 'TERMINATED') {
              if (document.fullscreenElement) document.exitFullscreen().catch(() => {});
              router.replace(`/student/exam/${examId}/terminated`);
            } else if (s === 'ENDED') {
              router.replace(`/student/exam/${examId}/completion`);
            } else {
              // DISCONNECTED or unexpected — send through full preExam reconnect
              toast.error('Session disconnected. Please reconnect.');
              router.replace(`/student/exam/${examId}/device`);
            }
          } catch {
            router.replace('/student/dashboard');
          }
        }
      }
    }, 15000);
    return () => clearInterval(id);
  }, [loading, terminated]);

  // Fullscreen exit detection
  useEffect(() => {
    if (loading) return;
    const onFsChange = async () => {
      if (!document.fullscreenElement && !terminated && !submitting) {
        setFullscreenExited(true);
        // Report fullscreen exit violation to engine (same channel as tab switch)
        try {
          const res = await api.post(`/exam/${examId}/proctor-violation`, { reason: 'fullscreen_exit' });
          const risk = res.data?.risk;
          if (risk?.terminated) {
            router.replace(`/student/exam/${examId}/terminated`);
          }
        } catch {
          // Engine unreachable — show overlay anyway, continue exam
        }
      } else {
        setFullscreenExited(false);
      }
    };
    document.addEventListener('fullscreenchange', onFsChange);
    return () => document.removeEventListener('fullscreenchange', onFsChange);
  }, [loading, terminated, submitting, examId]);

  // Tab switch monitoring
  useEffect(() => {
    if (loading || !exam?.config?.tab_switching) return;
    const onVisibility = async () => {
      if (!document.hidden) return;

      const next = tabSwitchCount + 1;
      setTabSwitchCount(next);
      toast.error(`Tab switch detected (${next}/${exam?.flag_threshold || 3} warnings)`, {
        duration: 5000,
        icon: <AlertOctagon className="h-5 w-5 text-rose-500" />,
      });

      // Report to engine via backend and act on the response
      try {
        const res = await api.post(`/exam/${examId}/proctor-violation`, { reason: 'tab_switch' });
        const risk = res.data?.risk;
        if (risk?.terminated) {
          // Engine auto-terminated — redirect to terminated page
          if (document.fullscreenElement) document.exitFullscreen().catch(() => {});
          router.replace(`/student/exam/${examId}/terminated`);
        }
      } catch {
        // Engine unreachable — violation already logged locally, continue
      }
    };
    document.addEventListener('visibilitychange', onVisibility);
    return () => document.removeEventListener('visibilitychange', onVisibility);
  }, [loading, exam, tabSwitchCount]);

  // Unload beacon
  useEffect(() => {
    if (loading || submitting || terminated) return;
    const onUnload = () => {
      const token = localStorage.getItem('access_token');
      if (!token) return;
      const base = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';
      fetch(`${base}/exam/heartbeat`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${token}` },
        keepalive: true,
      });
    };
    window.addEventListener('unload', onUnload);
    return () => window.removeEventListener('unload', onUnload);
  }, [loading, submitting, terminated]);

  const formatTime = (secs: number) => {
    const h = Math.floor(secs / 3600);
    const m = Math.floor((secs % 3600) / 60);
    const s = secs % 60;
    if (h > 0) return `${h}:${m.toString().padStart(2, '0')}:${s.toString().padStart(2, '0')}`;
    return `${m.toString().padStart(2, '0')}:${s.toString().padStart(2, '0')}`;
  };

  if (loading) {
    return (
      <div className="flex-1 flex flex-col items-center justify-center bg-slate-900 text-white min-h-screen">
        <Loader2 className="h-10 w-10 animate-spin text-indigo-500 mb-4" />
        <p className="text-xl font-bold animate-pulse">Initializing Secure Environment…</p>
      </div>
    );
  }

  return (
    <div className="flex flex-col h-screen overflow-hidden bg-slate-100 relative">

      {/* FULLSCREEN EXIT OVERLAY — non-dismissible */}
      {fullscreenExited && !terminated && (
        <div className="absolute inset-0 z-[200] bg-black/90 backdrop-blur-md flex items-center justify-center">
          <Card className="max-w-sm w-full p-8 bg-slate-900 border-amber-700 text-white text-center shadow-2xl">
            <Maximize2 className="h-12 w-12 text-amber-400 mx-auto mb-4" />
            <h2 className="text-2xl font-bold text-amber-300 mb-2">Fullscreen Required</h2>
            <p className="text-slate-400 mb-6">
              You exited fullscreen mode. The exam must be in fullscreen at all times.
            </p>
            <Button
              onClick={() => {
                document.documentElement.requestFullscreen().catch(() => {});
                setFullscreenExited(false);
              }}
              className="w-full bg-amber-500 hover:bg-amber-600 text-black font-bold"
            >
              <Maximize2 className="h-4 w-4 mr-2" /> Return to Fullscreen
            </Button>
          </Card>
        </div>
      )}

      {/* EXAM HUD HEADER */}
      <header className="bg-slate-900 text-white px-6 py-3 flex items-center justify-between shadow-md z-50">
        <div className="flex items-center gap-3">
          <div className="flex h-3 w-3 relative">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-rose-400 opacity-75" />
            <span className="relative inline-flex rounded-full h-3 w-3 bg-rose-500" />
          </div>
          <h1 className="text-lg font-bold tracking-tight">{exam?.title || 'Exam in Progress'}</h1>
        </div>

        <div className="flex items-center gap-4">
          {/* Tab switch warning counter */}
          {exam?.config?.tab_switching && tabSwitchCount > 0 && (
            <div className={`flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-bold ${tabSwitchCount >= tabThreshold ? 'bg-rose-600 text-white' : 'bg-amber-500/20 text-amber-400'}`}>
              <AlertTriangle className="h-3.5 w-3.5" />
              {tabSwitchCount}/{tabThreshold} Warnings
            </div>
          )}

          {/* Timer */}
          <div
            className={`px-4 py-1.5 rounded-md font-mono text-xl font-bold tracking-wider flex items-center gap-1.5 ${
              timeLeft < 300 ? 'bg-rose-600 text-white animate-pulse' : 'bg-slate-800 text-emerald-400'
            }`}
          >
            <Clock className="h-4 w-4" />
            {formatTime(timeLeft)}
          </div>

          <Button
            onClick={() => setIsConfirmOpen(true)}
            disabled={submitting}
            variant="destructive"
            size="sm"
            className="font-bold tracking-wide"
          >
            {submitting ? (
              <Loader2 className="h-4 w-4 mr-2 animate-spin" />
            ) : (
              <CheckCircle2 className="h-4 w-4 mr-2" />
            )}
            {submitting ? 'Submitting…' : 'Submit Exam'}
          </Button>
        </div>
      </header>

      {/* MAIN CONTENT */}
      <div className="flex-1 flex relative">
        <div className="flex-1 p-8 overflow-y-auto w-full">
          <Card className="max-w-4xl mx-auto p-12 text-center bg-white shadow-sm border-slate-200 min-h-[60vh] flex flex-col items-center justify-center">
            <ShieldAlert className="h-16 w-16 text-slate-300 mx-auto mb-4" />
            <h2 className="text-2xl font-bold text-slate-800 mb-2">Exam in Progress</h2>
            <p className="text-slate-500 max-w-lg mx-auto">
              You are securely connected. Do not close this tab, minimize the window, or switch to other applications.
              <br /><br />
              <em className="text-slate-400 text-sm">(Exam question content renders here in the full implementation)</em>
            </p>
          </Card>
        </div>

        {/* PiP Camera */}
        <div className="absolute bottom-6 right-6 w-64 aspect-video bg-black rounded-xl overflow-hidden shadow-2xl border-4 border-slate-800 pointer-events-none">
          <video
            ref={videoRef}
            autoPlay
            playsInline
            muted
            className="w-full h-full object-cover"
            style={{ transform: 'scaleX(-1)' }}
          />
          <div className="absolute top-2 left-2 bg-black/60 px-2 py-0.5 rounded text-[10px] font-bold text-emerald-400 uppercase tracking-wider backdrop-blur-sm">
            Monitoring Active
          </div>
        </div>
      </div>

      <ConfirmDialog
        isOpen={isConfirmOpen}
        onOpenChange={setIsConfirmOpen}
        title="Submit Exam?"
        description="Are you sure you want to finalize your exam attempt? This action cannot be reversed."
        onConfirm={() => executeSubmit(false)}
        confirmLabel="Yes, Submit Exam"
        variant="destructive"
      />
    </div>
  );
}
