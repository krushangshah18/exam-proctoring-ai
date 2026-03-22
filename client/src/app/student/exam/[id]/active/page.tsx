'use client';

import { useEffect, useState, useRef, useCallback } from 'react';
import { useRouter, useParams } from 'next/navigation';
import {
  Loader2, AlertOctagon, CheckCircle2, ShieldAlert, Ban,
  Maximize2, AlertTriangle, Clock
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';
import { Textarea } from '@/components/ui/textarea';
import { toast } from 'sonner';
import api from '@/lib/axios';
import { ConfirmDialog } from '@/components/common/ConfirmDialog';

// ──────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────

function parseUTCDate(iso: string): Date {
  return new Date(iso.endsWith('Z') ? iso : iso + 'Z');
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

// ──────────────────────────────────────────────

type TerminationCause = 'violation' | 'admin' | 'disconnection' | 'timeout' | 'generic';

function getTerminationMessage(cause: TerminationCause, reason?: string) {
  switch (cause) {
    case 'violation':
      return {
        title: 'Exam Terminated — Integrity Violation',
        body: reason || 'Your session was ended because the system detected a violation of exam rules.',
      };
    case 'admin':
      return {
        title: 'Exam Terminated by Proctor',
        body: reason || 'The exam proctor has ended your session. Contact your instructor for details.',
      };
    case 'disconnection':
      return {
        title: 'Session Disconnected',
        body: 'Your session was disconnected due to prolonged inactivity or network interruption. Submit an appeal if this was unintentional.',
      };
    case 'timeout':
      return {
        title: 'Time Expired',
        body: 'Your exam time has run out and your answers have been auto-submitted.',
      };
    default:
      return {
        title: 'Exam Terminated',
        body: reason || 'Your session was terminated. You may submit an appeal.',
      };
  }
}

function detectCause(terminatedBy: string, reason: string): TerminationCause {
  if (!terminatedBy && !reason) return 'generic';
  if (terminatedBy === 'ADMIN') return 'admin';
  if (reason?.toLowerCase().includes('disconnect')) return 'disconnection';
  if (reason?.toLowerCase().includes('violation') || reason?.toLowerCase().includes('flag')) return 'violation';
  return 'generic';
}

export default function ActiveExamPage() {
  const router = useRouter();
  const params = useParams();
  const examId = params.id as string;

  const videoRef = useRef<HTMLVideoElement>(null);
  const streamRef = useRef<MediaStream | null>(null);
  const timerRef = useRef<NodeJS.Timeout | null>(null);
  const sseCloseRef = useRef<(() => void) | null>(null);

  const [exam, setExam] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [timeLeft, setTimeLeft] = useState(0);

  // Termination
  const [terminated, setTerminated] = useState(false);
  const [termCause, setTermCause] = useState<TerminationCause>('generic');
  const [termReason, setTermReason] = useState('');
  const [termBy, setTermBy] = useState('');

  // Appeal
  const [appealReason, setAppealReason] = useState('');
  const [submittingAppeal, setSubmittingAppeal] = useState(false);
  const [appealData, setAppealData] = useState<any>(null);

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
        RESUME_APPROVED: (data) => {
          toast.success('Appeal approved! You may resume.');
          setTerminated(false);
          setAppealData(null);
          if (data.time_extension_seconds) {
            setTimeLeft((prev) => prev + (data.time_extension_seconds - (exam?.extensionApplied || 0)));
          }
          if (document.documentElement.requestFullscreen) {
            document.documentElement.requestFullscreen().catch(() => {});
          }
        },
        RESUME_DENIED: (data) => {
          setAppealData((prev: any) => ({
            ...prev,
            status: 'DENIED',
            review_note: data.review_note,
          }));
          toast.error('Your appeal was denied.');
        },
        TIME_EXTENDED: (data) => {
          toast.success(`Time extended by ${data.added_minutes} minute(s)!`);
          setTimeLeft((prev) => prev + data.added_minutes * 60);
        },
        TERMINATED: (data) => {
          const cause = detectCause(data.terminated_by, data.terminated_reason);
          setTermCause(cause);
          setTermReason(data.terminated_reason || '');
          setTermBy(data.terminated_by || '');
          setTerminated(true);
          if (document.fullscreenElement) document.exitFullscreen().catch(() => {});
        },
      }
    );
  }, [examId, exam]);

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

        if (sessionData.status === 'TERMINATED') {
          const cause = detectCause(sessionData.terminated_by, sessionData.terminated_reason);
          setTermCause(cause);
          setTermReason(sessionData.terminated_reason || '');
          setTermBy(sessionData.terminated_by || '');
          setTerminated(true);
          if (sessionData.active_resume_request) setAppealData(sessionData.active_resume_request);
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
          const cause = detectCause(res.data.terminated_by || '', res.data.terminated_reason || '');
          setTermCause(cause);
          setTermReason(res.data.terminated_reason || '');
          setTermBy(res.data.terminated_by || '');
          setTerminated(true);
          if (document.fullscreenElement) document.exitFullscreen().catch(() => {});
        }
      } catch {}
    }, 15000);
    return () => clearInterval(id);
  }, [loading, terminated]);

  // Fullscreen exit detection
  useEffect(() => {
    if (loading) return;
    const onFsChange = () => {
      if (!document.fullscreenElement && !terminated && !submitting) {
        setFullscreenExited(true);
      } else {
        setFullscreenExited(false);
      }
    };
    document.addEventListener('fullscreenchange', onFsChange);
    return () => document.removeEventListener('fullscreenchange', onFsChange);
  }, [loading, terminated, submitting]);

  // Tab switch monitoring
  useEffect(() => {
    if (loading || !exam?.config?.tab_switching) return;
    const onVisibility = () => {
      if (document.hidden) {
        setTabSwitchCount((c) => {
          const next = c + 1;
          toast.error(`Tab switch detected (${next}/${exam?.flag_threshold || 3} warnings)`, {
            duration: 5000,
            icon: <AlertOctagon className="h-5 w-5 text-rose-500" />,
          });
          return next;
        });
      }
    };
    document.addEventListener('visibilitychange', onVisibility);
    return () => document.removeEventListener('visibilitychange', onVisibility);
  }, [loading, exam]);

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

  // Appeal handlers
  const handleAppealSubmit = async () => {
    if (!appealReason.trim()) return toast.error('Please enter a reason.');
    setSubmittingAppeal(true);
    try {
      await api.post(`/exam/${examId}/appeal`, { reason: appealReason });
      toast.success('Appeal submitted.');
      const res = await api.get(`/exam/${examId}/session-active`);
      setAppealData(res.data.active_resume_request);
    } catch (err: any) {
      toast.error(err.response?.data?.detail || 'Failed to submit appeal.');
    } finally {
      setSubmittingAppeal(false);
    }
  };

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

  const termMsg = getTerminationMessage(termCause, termReason);

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

      {/* TERMINATION OVERLAY */}
      {terminated && (
        <div className="absolute inset-0 z-[100] bg-slate-900/95 backdrop-blur-md flex items-center justify-center p-6 text-white">
          <Card className="max-w-md w-full p-8 border-rose-900 bg-slate-900 text-white shadow-2xl">
            <Ban className="h-16 w-16 text-rose-500 mx-auto mb-4 animate-in zoom-in" />
            <h2 className="text-2xl font-bold text-rose-100 mb-2">{termMsg.title}</h2>
            <p className="text-slate-400 mb-6 text-sm leading-relaxed">{termMsg.body}</p>

            {termCause === 'timeout' ? (
              <Button
                onClick={() => router.push(`/student/exam/${examId}/completion`)}
                className="w-full bg-slate-700 hover:bg-slate-600"
              >
                View Results
              </Button>
            ) : !appealData ? (
              <div className="space-y-4 text-left">
                <p className="text-sm font-semibold text-slate-300">
                  Submit an appeal to request session resumption:
                </p>
                <Textarea
                  placeholder="Clearly explain what happened…"
                  value={appealReason}
                  onChange={(e) => setAppealReason(e.target.value)}
                  className="bg-slate-800 border-slate-700 text-slate-200"
                />
                <Button
                  onClick={handleAppealSubmit}
                  disabled={submittingAppeal}
                  className="w-full bg-rose-600 hover:bg-rose-700"
                >
                  {submittingAppeal && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}
                  Submit Appeal
                </Button>
              </div>
            ) : appealData.status === 'PENDING' ? (
              <div className="bg-slate-800/50 p-4 rounded-lg flex flex-col items-center gap-3">
                <Loader2 className="h-8 w-8 text-amber-500 animate-spin" />
                <p className="font-semibold text-amber-400">Appeal Pending Review</p>
                <p className="text-sm text-slate-400 text-center">
                  The proctor is reviewing your request. Please keep this window open.
                </p>
              </div>
            ) : appealData.status === 'DENIED' ? (
              <div className="bg-rose-950/30 border border-rose-900 p-4 rounded-lg space-y-3">
                <p className="font-bold text-rose-400">Appeal Denied</p>
                {appealData.review_note && (
                  <p className="text-sm text-rose-300">Note: {appealData.review_note}</p>
                )}
                <Button
                  onClick={() => router.push('/student/dashboard')}
                  variant="outline"
                  className="w-full border-slate-700 text-slate-300"
                >
                  Return to Dashboard
                </Button>
              </div>
            ) : null}
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
