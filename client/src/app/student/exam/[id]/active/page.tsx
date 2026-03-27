'use client';

import { useEffect, useState, useRef, useCallback } from 'react';
import { useRouter, useParams } from 'next/navigation';
import {
  Loader2, CheckCircle2, ShieldAlert,
  Maximize2, Clock, Eye, BookOpen,
} from 'lucide-react';
import { toast } from 'sonner';
import api from '@/lib/axios';
import { ConfirmDialog } from '@/components/common/ConfirmDialog';

/* ── helpers ──────────────────────────────────────────────────────────────── */
function parseUTCDate(iso: string): Date {
  if (!iso) return new Date(NaN);
  if (iso.endsWith('Z') || /[+-]\d{2}:\d{2}$/.test(iso)) return new Date(iso);
  return new Date(iso + 'Z');
}

function computeRemaining(startTimeISO: string, durationMinutes: number, extensionSeconds: number, serverNowISO: string): number {
  const start = parseUTCDate(startTimeISO).getTime();
  const totalMs = (durationMinutes * 60 + extensionSeconds) * 1000;
  const deadline = start + totalMs;
  const localNow = Date.now();
  const serverNow = parseUTCDate(serverNowISO).getTime();
  const skew = serverNow - localNow;
  return Math.max(0, Math.floor((deadline - (localNow + skew)) / 1000));
}

function openSSE(url: string, token: string, handlers: Record<string, (data: any) => void>): () => void {
  let cancelled = false;
  const controller = new AbortController();
  (async () => {
    try {
      const res = await fetch(url, { headers: { Authorization: `Bearer ${token}` }, signal: controller.signal });
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
          if (line.startsWith('event: ')) eventType = line.slice(7).trim();
          else if (line.startsWith('data: ')) {
            try { handlers[eventType]?.(JSON.parse(line.slice(6))); } catch {}
            eventType = 'message';
          }
        }
      }
    } catch {}
  })();
  return () => { cancelled = true; controller.abort(); };
}

type AlertKind = 'warning' | 'critical' | 'info' | 'success';

/* ── main component ──────────────────────────────────────────────────────── */
export default function ActiveExamPage() {
  const router   = useRouter();
  const params   = useParams();
  const examId   = params.id as string;

  const videoRef           = useRef<HTMLVideoElement>(null);
  const streamRef          = useRef<MediaStream | null>(null);
  const timerRef           = useRef<NodeJS.Timeout | null>(null);
  const sseCloseRef        = useRef<(() => void) | null>(null);
  const pcRef              = useRef<RTCPeerConnection | null>(null);
  const proctorPcIdRef     = useRef<string | null>(null);
  const proctorSseCloseRef = useRef<(() => void) | null>(null);

  const [exam, setExam]                   = useState<any>(null);
  const [loading, setLoading]             = useState(true);
  const [submitting, setSubmitting]       = useState(false);
  const [timeLeft, setTimeLeft]           = useState(0);
  const [terminated, setTerminated]       = useState(false);
  const [isConfirmOpen, setIsConfirmOpen] = useState(false);
  const [fullscreenExited, setFullscreenExited] = useState(false);
  const [tabSwitchCount, setTabSwitchCount]     = useState(0);

  const tabThreshold = exam?.config?.tab_switching ? (exam?.flag_threshold || 3) : Infinity;

  /* push alert — toast only, auto-dismisses */
  const pushAlert = useCallback((kind: AlertKind, message: string) => {
    if (kind === 'critical') toast.error(message,   { duration: 6000 });
    else if (kind === 'warning')  toast.warning(message, { duration: 6000 });
    else if (kind === 'success')  toast.success(message, { duration: 5000 });
    else                          toast.info(message,    { duration: 5000 });
  }, []);

  /* timer */
  const startTimer = useCallback((remaining: number) => {
    if (timerRef.current) clearInterval(timerRef.current);
    setTimeLeft(remaining);
    timerRef.current = setInterval(() => {
      setTimeLeft(prev => {
        if (prev <= 1) { clearInterval(timerRef.current!); handleAutoSubmit(); return 0; }
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
      if (streamRef.current) streamRef.current.getTracks().forEach(t => t.stop());
      router.push(`/student/exam/${examId}/completion`);
    } catch (err: any) {
      toast.error(err?.response?.data?.detail || 'Submit failed. Please retry.');
      if (!isAuto) setSubmitting(false);
    }
  }, [examId, router]);

  const setupSSE = useCallback((sessionId: string) => {
    const token   = localStorage.getItem('access_token') || '';
    const baseUrl = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';
    sseCloseRef.current?.();
    sseCloseRef.current = openSSE(`${baseUrl}/exam/${examId}/events`, token, {
      TIME_EXTENDED: (data) => {
        pushAlert('success', `Time extended by ${data.added_minutes} minute(s)!`);
        setTimeLeft(prev => prev + data.added_minutes * 60);
      },
      TERMINATED: () => {
        if (document.fullscreenElement) document.exitFullscreen().catch(() => {});
        router.replace(`/student/exam/${examId}/terminated`);
      },
    });
  }, [examId, pushAlert]);

  const setupProctor = useCallback(async () => {
    if (!streamRef.current) return;
    try {
      const pc = new RTCPeerConnection({ iceServers: [] });
      pcRef.current = pc;
      streamRef.current.getTracks().forEach(t => pc.addTrack(t, streamRef.current!));
      pc.onicecandidate = async (e) => {
        if (e.candidate && proctorPcIdRef.current) {
          try {
            await api.post(`/exam/${examId}/proctor-ice`, { candidate: e.candidate.candidate, sdpMid: e.candidate.sdpMid, sdpMLineIndex: e.candidate.sdpMLineIndex });
          } catch {}
        }
      };
      const offer = await pc.createOffer();
      await pc.setLocalDescription(offer);
      await new Promise<void>(resolve => {
        if (pc.iceGatheringState === 'complete') { resolve(); return; }
        const check = () => { if (pc.iceGatheringState === 'complete') resolve(); };
        pc.addEventListener('icegatheringstatechange', check);
        setTimeout(resolve, 3000);
      });
      const res = await api.post(`/exam/${examId}/proctor-connect`, { sdp: pc.localDescription!.sdp, type: pc.localDescription!.type });
      proctorPcIdRef.current = res.data.pc_id ?? res.data.device_id;
      await pc.setRemoteDescription(new RTCSessionDescription({ sdp: res.data.sdp, type: res.data.type }));
      const token   = localStorage.getItem('access_token') || '';
      const baseUrl = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';
      proctorSseCloseRef.current = openSSE(`${baseUrl}/exam/${examId}/proctor-events`, token, {
        message: (data: any) => {
          const t = data?.type;
          if (t === 'alert' || t === 'warning') {
            pushAlert('warning', data.message || data.alert_type || 'Proctoring alert');
          } else if (t === 'risk_update') {
            if (data.state === 'HIGH_RISK' || data.state === 'ADMIN_REVIEW') {
              pushAlert('critical', `Risk Level: ${data.state} (score: ${Math.round(data.risk_score ?? 0)})`);
            }
          }
        },
      });
    } catch (err: any) {
      const detail = err?.response?.data?.detail;
      if (detail) pushAlert('critical', `Proctor engine: ${detail}`);
    }
  }, [examId, pushAlert]);

  /* init */
  useEffect(() => {
    let cancelled = false;
    const init = async () => {
      try {
        const [sessionRes] = await Promise.all([api.get(`/exam/${examId}/session-active`)]);
        if (cancelled) return;
        const sessionData = sessionRes.data;
        setExam(sessionData);
        const remaining = computeRemaining(sessionData.start_time, sessionData.duration_minutes, sessionData.time_extension_seconds || 0, sessionData.server_now);
        const camId = localStorage.getItem(`exam_cam_${examId}`);
        const micId = localStorage.getItem(`exam_mic_${examId}`);
        const s = await navigator.mediaDevices.getUserMedia({
          video: { deviceId: camId ? { exact: camId } : undefined },
          audio: { deviceId: micId ? { exact: micId } : undefined },
        });
        if (cancelled) { s.getTracks().forEach(t => t.stop()); return; }
        streamRef.current = s;
        setLoading(false);
        startTimer(remaining);
        setupSSE(sessionData.session_id);
        setupProctor();
        if (sessionData.status === 'TERMINATED') {
          if (document.fullscreenElement) document.exitFullscreen().catch(() => {});
          router.replace(`/student/exam/${examId}/terminated`);
        } else if (sessionData.status === 'DISCONNECTED') {
          toast.error('Your session was disconnected. Please reconnect.');
          router.replace(`/student/exam/${examId}/device`);
        } else if (sessionData.status !== 'ACTIVE') {
          toast.error('Exam session is not active. Please start your exam.');
          router.replace(`/student/exam/${examId}/info`);
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
      streamRef.current?.getTracks().forEach(t => t.stop());
    };
  }, [examId]);

  useEffect(() => {
    if (!loading && streamRef.current && videoRef.current) videoRef.current.srcObject = streamRef.current;
  }, [loading]);

  /* heartbeat */
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
          try {
            const sr = await api.get(`/exam/${examId}/session-active`);
            const s = sr.data.status;
            if (s === 'TERMINATED') { if (document.fullscreenElement) document.exitFullscreen().catch(() => {}); router.replace(`/student/exam/${examId}/terminated`); }
            else if (s === 'ENDED') { router.replace(`/student/exam/${examId}/completion`); }
            else { toast.error('Session disconnected. Please reconnect.'); router.replace(`/student/exam/${examId}/device`); }
          } catch { router.replace('/student/dashboard'); }
        }
      }
    }, 15000);
    return () => clearInterval(id);
  }, [loading, terminated]);

  /* fullscreen guard */
  useEffect(() => {
    if (loading) return;
    const onFsChange = async () => {
      if (!document.fullscreenElement && !terminated && !submitting) {
        setFullscreenExited(true);
        try {
          const res = await api.post(`/exam/${examId}/proctor-violation`, { reason: 'fullscreen_exit' });
          if (res.data?.risk?.terminated) router.replace(`/student/exam/${examId}/terminated`);
        } catch {}
      } else { setFullscreenExited(false); }
    };
    document.addEventListener('fullscreenchange', onFsChange);
    return () => document.removeEventListener('fullscreenchange', onFsChange);
  }, [loading, terminated, submitting, examId]);

  /* tab switch guard */
  useEffect(() => {
    if (loading || !exam?.config?.tab_switching) return;
    const onVisibility = async () => {
      if (!document.hidden) return;
      const next = tabSwitchCount + 1;
      setTabSwitchCount(next);
      pushAlert('critical', `Tab switch detected (${next}/${exam?.flag_threshold || 3} warnings)`);
      try {
        const res = await api.post(`/exam/${examId}/proctor-violation`, { reason: 'tab_switch' });
        if (res.data?.risk?.terminated) { if (document.fullscreenElement) document.exitFullscreen().catch(() => {}); router.replace(`/student/exam/${examId}/terminated`); }
      } catch {}
    };
    document.addEventListener('visibilitychange', onVisibility);
    return () => document.removeEventListener('visibilitychange', onVisibility);
  }, [loading, exam, tabSwitchCount, pushAlert]);

  /* unload beacon */
  useEffect(() => {
    if (loading || submitting || terminated) return;
    const onUnload = () => {
      const token = localStorage.getItem('access_token');
      if (!token) return;
      const base = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';
      fetch(`${base}/exam/heartbeat`, { method: 'POST', headers: { Authorization: `Bearer ${token}` }, keepalive: true });
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

  /* ── loading screen ─────────────────────────────────────────────────────── */
  if (loading) {
    return (
      <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', height: '100vh', background: '#F8FAFC' }}>
        <style>{`@import url('https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&display=swap'); @keyframes spin{to{transform:rotate(360deg)}}`}</style>
        <div style={{ width: '52px', height: '52px', borderRadius: '14px', background: '#22577A', display: 'flex', alignItems: 'center', justifyContent: 'center', marginBottom: '20px' }}>
          <Shield style={{ width: '24px', height: '24px', color: '#57CC99' }} />
        </div>
        <Loader2 style={{ width: '28px', height: '28px', color: '#22577A', animation: 'spin 1s linear infinite', marginBottom: '12px' }} />
        <p style={{ fontSize: '15px', fontWeight: 700, color: '#22577A', fontFamily: "'Plus Jakarta Sans', sans-serif" }}>Initializing Secure Environment…</p>
      </div>
    );
  }

  const isLowTime = timeLeft < 300;
  const isWarningTime = timeLeft < 600 && timeLeft >= 300;

  /* ── main render ─────────────────────────────────────────────────────────── */
  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100vh', overflow: 'hidden', background: '#F1F5F9', fontFamily: "'Plus Jakarta Sans', sans-serif", position: 'relative' }}>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&display=swap');
        @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@600;800&display=swap');
        @keyframes spin { to { transform: rotate(360deg); } }
        @keyframes ping  { 75%,100% { transform: scale(2); opacity: 0; } }
        @keyframes pulse-timer { 0%,100% { opacity: 1; } 50% { opacity: 0.65; } }
        @keyframes slide-in { from { opacity: 0; transform: translateY(6px); } to { opacity: 1; transform: translateY(0); } }
      `}</style>

      {/* ── FULLSCREEN EXIT OVERLAY ────────────────────────────────────────── */}
      {fullscreenExited && !terminated && (
        <div style={{ position: 'absolute', inset: 0, zIndex: 300, background: 'rgba(15,23,42,0.85)', backdropFilter: 'blur(12px)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
          <div style={{
            background: '#fff', border: '2px solid #F59E0B', borderRadius: '20px',
            padding: '40px', maxWidth: '400px', width: '100%', textAlign: 'center',
            boxShadow: '0 32px 80px rgba(15,23,42,0.3)',
          }}>
            <div style={{ width: '64px', height: '64px', borderRadius: '16px', background: 'rgba(245,158,11,0.1)', border: '2px solid rgba(245,158,11,0.25)', display: 'flex', alignItems: 'center', justifyContent: 'center', margin: '0 auto 18px' }}>
              <Maximize2 style={{ width: '28px', height: '28px', color: '#F59E0B' }} />
            </div>
            <h2 style={{ fontSize: '20px', fontWeight: 800, color: '#0F172A', marginBottom: '8px', letterSpacing: '-0.02em' }}>Fullscreen Required</h2>
            <p style={{ fontSize: '13.5px', color: '#64748B', marginBottom: '24px', lineHeight: 1.65, fontWeight: 500 }}>
              You exited fullscreen mode. The exam must be in fullscreen at all times. This will be recorded as a critical event.
            </p>
            <button
              onClick={() => { document.documentElement.requestFullscreen().catch(() => {}); setFullscreenExited(false); }}
              style={{
                width: '100%', padding: '13px', borderRadius: '10px', border: 'none', cursor: 'pointer',
                background: '#F59E0B', color: '#fff', fontSize: '14px', fontWeight: 800,
                display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '8px',
                fontFamily: "'Plus Jakarta Sans', sans-serif", letterSpacing: '-0.01em',
              }}
            >
              <Maximize2 style={{ width: '16px', height: '16px' }} /> Return to Fullscreen
            </button>
          </div>
        </div>
      )}

      {/* ── HEADER ────────────────────────────────────────────────────────── */}
      <header style={{
        background: '#22577A',
        height: '54px', flexShrink: 0,
        display: 'flex', alignItems: 'center', justifyContent: 'space-between',
        padding: '0 20px', zIndex: 50,
        boxShadow: '0 2px 12px rgba(34,87,122,0.3)',
      }}>
        {/* Left — exam title */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <div style={{ position: 'relative', width: '10px', height: '10px', flexShrink: 0 }}>
            <span style={{ position: 'absolute', inset: 0, borderRadius: '50%', background: '#EF4444', opacity: 0.5, animation: 'ping 1.5s cubic-bezier(0,0,.2,1) infinite' }} />
            <span style={{ borderRadius: '50%', background: '#EF4444', width: '10px', height: '10px', position: 'relative', display: 'block' }} />
          </div>
          <span style={{ fontSize: '14.5px', fontWeight: 700, color: '#fff', letterSpacing: '-0.01em' }}>
            {exam?.title || 'Exam in Progress'}
          </span>
          <span style={{ fontSize: '10px', fontWeight: 700, color: 'rgba(255,255,255,0.4)', textTransform: 'uppercase', letterSpacing: '0.1em', marginLeft: '2px' }}>
            · LIVE
          </span>
        </div>

        {/* Right — timer + submit */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          {/* Timer */}
          <div style={{
            display: 'flex', alignItems: 'center', gap: '7px',
            padding: '6px 14px', borderRadius: '8px',
            background: isLowTime
              ? 'rgba(239,68,68,0.2)'
              : isWarningTime
              ? 'rgba(245,158,11,0.15)'
              : 'rgba(255,255,255,0.08)',
            border: `1px solid ${isLowTime ? 'rgba(239,68,68,0.45)' : isWarningTime ? 'rgba(245,158,11,0.35)' : 'rgba(255,255,255,0.12)'}`,
            animation: isLowTime ? 'pulse-timer 1s ease-in-out infinite' : 'none',
          }}>
            <Clock style={{ width: '13px', height: '13px', color: isLowTime ? '#EF4444' : isWarningTime ? '#F59E0B' : '#57CC99', flexShrink: 0 }} />
            <span style={{
              fontFamily: "'JetBrains Mono', monospace",
              fontSize: '17px', fontWeight: 800, letterSpacing: '0.05em',
              color: isLowTime ? '#EF4444' : isWarningTime ? '#F59E0B' : '#57CC99',
            }}>
              {formatTime(timeLeft)}
            </span>
          </div>

          {/* Submit */}
          <button
            onClick={() => setIsConfirmOpen(true)}
            disabled={submitting}
            style={{
              display: 'flex', alignItems: 'center', gap: '6px',
              padding: '7px 16px', borderRadius: '8px', cursor: submitting ? 'not-allowed' : 'pointer',
              background: submitting ? 'rgba(255,255,255,0.15)' : '#fff',
              border: 'none',
              color: submitting ? 'rgba(255,255,255,0.5)' : '#22577A',
              fontSize: '13px', fontWeight: 800,
              fontFamily: "'Plus Jakarta Sans', sans-serif",
              transition: 'all 150ms',
              letterSpacing: '-0.01em',
            }}
            onMouseEnter={e => { if (!submitting) { (e.currentTarget as HTMLElement).style.background = '#F1F5F9'; } }}
            onMouseLeave={e => { if (!submitting) { (e.currentTarget as HTMLElement).style.background = '#fff'; } }}
          >
            {submitting
              ? <><Loader2 style={{ width: '13px', height: '13px', animation: 'spin 1s linear infinite' }} /> Submitting…</>
              : <><CheckCircle2 style={{ width: '13px', height: '13px' }} /> Submit Exam</>
            }
          </button>
        </div>
      </header>

      {/* ── BODY ──────────────────────────────────────────────────────────── */}
      <div
        style={{ flex: 1, display: 'flex', overflow: 'hidden' }}
        onCopy={e => { e.preventDefault(); pushAlert('warning', 'Copying is not allowed during the exam.'); }}
        onPaste={e => { e.preventDefault(); pushAlert('warning', 'Pasting is not allowed during the exam.'); }}
        onCut={e => { e.preventDefault(); pushAlert('warning', 'Cutting text is not allowed during the exam.'); }}
      >

        {/* Question canvas */}
        <div style={{ flex: 1, overflowY: 'auto', padding: '20px' }}>
          <div style={{
            maxWidth: '860px', margin: '0 auto',
            background: '#fff',
            border: '1.5px solid #E2E8F0',
            borderRadius: '16px',
            minHeight: 'calc(100vh - 94px)',
            display: 'flex', flexDirection: 'column',
            boxShadow: '0 1px 4px rgba(15,23,42,0.05)',
            overflow: 'hidden',
          }}>
            {/* Question panel header */}
            <div style={{
              padding: '14px 22px',
              borderBottom: '1.5px solid #F1F5F9',
              display: 'flex', alignItems: 'center', justifyContent: 'space-between',
              background: '#FAFCFF',
              flexShrink: 0,
            }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <BookOpen style={{ width: '15px', height: '15px', color: '#22577A' }} />
                <span style={{ fontSize: '12px', fontWeight: 700, color: '#22577A', textTransform: 'uppercase', letterSpacing: '0.07em' }}>Question Area</span>
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '5px' }}>
                <span style={{ width: '7px', height: '7px', borderRadius: '50%', background: '#57CC99', display: 'inline-block' }} />
                <span style={{ fontSize: '11px', fontWeight: 600, color: '#38A3A5' }}>Secure Session Active</span>
              </div>
            </div>

            {/* Placeholder body */}
            <div style={{ flex: 1, padding: '32px 36px', display: 'flex', flexDirection: 'column', gap: '28px' }}>

              {/* Sample question block */}
              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '14px' }}>
                  <span style={{ width: '24px', height: '24px', borderRadius: '6px', background: '#22577A', display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}>
                    <span style={{ fontSize: '11px', fontWeight: 800, color: '#fff' }}>1</span>
                  </span>
                  <p style={{ fontSize: '15px', fontWeight: 700, color: '#0F172A', lineHeight: 1.6 }}>
                    Exam question content renders here in the full implementation. This is a sample question to demonstrate the exam interface and copy-paste restrictions.
                  </p>
                </div>

                {/* Copy-paste restricted textarea */}
                <div style={{ position: 'relative' }}>
                  <div style={{
                    display: 'flex', alignItems: 'center', gap: '6px',
                    marginBottom: '8px',
                  }}>
                    <ShieldAlert style={{ width: '13px', height: '13px', color: '#22577A' }} />
                    <span style={{ fontSize: '12px', fontWeight: 600, color: '#22577A' }}>Your Answer</span>
                    <span style={{
                      fontSize: '10px', fontWeight: 700, color: '#DC2626',
                      background: 'rgba(239,68,68,0.07)', border: '1px solid rgba(239,68,68,0.18)',
                      padding: '1px 7px', borderRadius: '20px', marginLeft: '4px',
                    }}>Copy & Paste Disabled</span>
                  </div>
                  <textarea
                    placeholder="Type your answer here…"
                    onCopy={e => { e.preventDefault(); pushAlert('warning', 'Copying is not allowed during the exam.'); }}
                    onPaste={e => { e.preventDefault(); pushAlert('warning', 'Pasting is not allowed during the exam.'); }}
                    onCut={e => { e.preventDefault(); pushAlert('warning', 'Cutting text is not allowed during the exam.'); }}
                    style={{
                      width: '100%',
                      minHeight: '160px',
                      padding: '14px 16px',
                      borderRadius: '10px',
                      border: '1.5px solid #E2E8F0',
                      background: '#FAFCFF',
                      fontSize: '14px',
                      fontWeight: 500,
                      color: '#0F172A',
                      lineHeight: 1.7,
                      resize: 'vertical',
                      fontFamily: "'Plus Jakarta Sans', sans-serif",
                      outline: 'none',
                      boxSizing: 'border-box',
                      transition: 'border-color 150ms',
                      userSelect: 'none',
                    }}
                    onFocus={e => { e.currentTarget.style.borderColor = '#38A3A5'; }}
                    onBlur={e => { e.currentTarget.style.borderColor = '#E2E8F0'; }}
                  />
                  {/* Subtle no-copy overlay hint */}
                  <p style={{ fontSize: '11px', color: '#94A3B8', marginTop: '6px', fontWeight: 500 }}>
                    Keyboard shortcuts Ctrl+C, Ctrl+V, and Ctrl+X are blocked. Any attempt is logged.
                  </p>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* ── RIGHT SIDEBAR ──────────────────────────────────────────────── */}
        <div style={{
          width: '252px', flexShrink: 0,
          borderLeft: '1.5px solid #E2E8F0',
          background: '#fff',
          display: 'flex', flexDirection: 'column',
          overflow: 'hidden',
        }}>

          {/* Camera */}
          <div style={{ flexShrink: 0, borderBottom: '1.5px solid #F1F5F9' }}>
            <div style={{ background: '#0F172A', position: 'relative' }}>
              <div style={{ aspectRatio: '4/3', position: 'relative' }}>
                <video
                  ref={videoRef}
                  autoPlay playsInline muted
                  style={{ position: 'absolute', inset: 0, width: '100%', height: '100%', objectFit: 'cover', display: 'block', transform: 'scaleX(-1)' }}
                />
              </div>
            </div>
            <div style={{ padding: '8px 12px', background: '#F8FAFC', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                <span style={{ width: '7px', height: '7px', borderRadius: '50%', background: '#22C55E', display: 'inline-block' }} />
                <span style={{ fontSize: '10px', fontWeight: 700, color: '#16A34A', textTransform: 'uppercase', letterSpacing: '0.08em' }}>Monitoring</span>
              </div>
              <Eye style={{ width: '12px', height: '12px', color: '#94A3B8' }} />
            </div>
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
