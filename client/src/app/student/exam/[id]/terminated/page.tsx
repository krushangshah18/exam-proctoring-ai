'use client';

import { useEffect, useRef, useState, useCallback } from 'react';
import { useRouter, useParams } from 'next/navigation';
import {
  Ban, Loader2, MessageSquare, ArrowLeft,
  XCircle, AlertTriangle
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';
import { Textarea } from '@/components/ui/textarea';
import { Badge } from '@/components/ui/badge';
import { toast } from 'sonner';
import api from '@/lib/axios';

// ─────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────

type ResumeState = 'CAN_APPLY' | 'PENDING' | 'APPROVED' | 'DENIED' | 'NOT_APPLIED' | 'AGAIN' | null;

// ─────────────────────────────────────────────────────────
// SSE helper (same pattern as active page)
// ─────────────────────────────────────────────────────────

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
      // Connection closed / cancelled
    }
  })();

  return () => {
    cancelled = true;
    controller.abort();
  };
}

// ─────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────

function getTerminationLabel(terminatedBy: string | null): { label: string; color: string } {
  if (terminatedBy === 'ADMIN') return { label: 'Terminated by Proctor', color: 'rose' };
  if (terminatedBy === 'SYSTEM_DISCONNECT') return { label: 'Disconnection Timeout', color: 'amber' };
  if (terminatedBy?.startsWith('SYSTEM')) return { label: 'Violation Detected', color: 'rose' };
  return { label: 'Session Terminated', color: 'rose' };
}

// ─────────────────────────────────────────────────────────
// Page
// ─────────────────────────────────────────────────────────

export default function TerminatedPage() {
  const router = useRouter();
  const params = useParams();
  const examId = params.id as string;

  // Session data
  const [examTitle, setExamTitle] = useState('');
  const [terminatedBy, setTerminatedBy] = useState<string | null>(null);
  const [terminatedReason, setTerminatedReason] = useState('');
  const [resumeState, setResumeState] = useState<ResumeState>(null);
  const [resumeRequest, setResumeRequest] = useState<any>(null);
  const [loading, setLoading] = useState(true);

  // Appeal form
  const [showAppealForm, setShowAppealForm] = useState(false);
  const [appealReason, setAppealReason] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [dismissing, setDismissing] = useState(false);

  // Camera PiP
  const videoRef = useRef<HTMLVideoElement>(null);
  const streamRef = useRef<MediaStream | null>(null);
  const [cameraActive, setCameraActive] = useState(false);

  // SSE
  const sseCloseRef = useRef<(() => void) | null>(null);

  // ── Fetch status ──────────────────────────────────────

  const fetchStatus = useCallback(async () => {
    try {
      const res = await api.get(`/exam/${examId}/status`);
      const data = res.data;

      setExamTitle(data.title || '');
      setTerminatedBy(data.session_terminated_by || null);
      setTerminatedReason(data.session_terminated_reason || '');
      setResumeState(data.resume_state);
      setResumeRequest(data.active_resume_request || null);

      // If approved — session is CREATED, redirect to full preExam flow
      if (data.resume_state === 'APPROVED' || data.session_status === 'CREATED') {
        router.replace(`/student/exam/${examId}/device`);
        return;
      }
    } catch {
      // Stay on page — don't redirect on fetch failure
    } finally {
      setLoading(false);
    }
  }, [examId, router]);

  // ── Camera PiP — re-acquire using stored device IDs ──

  useEffect(() => {
    const camId = localStorage.getItem(`exam_cam_${examId}`);
    const micId = localStorage.getItem(`exam_mic_${examId}`);

    if (!camId && !micId) return;

    navigator.mediaDevices
      .getUserMedia({
        video: camId ? { deviceId: { exact: camId } } : true,
        audio: micId ? { deviceId: { exact: micId } } : false,
      })
      .then((s) => {
        streamRef.current = s;
        if (videoRef.current) videoRef.current.srcObject = s;
        setCameraActive(true);
      })
      .catch(() => {
        // Camera unavailable — PiP just won't show
      });

    return () => {
      streamRef.current?.getTracks().forEach((t) => t.stop());
    };
  }, [examId]);

  // ── SSE for approval/denial events ───────────────────

  useEffect(() => {
    const token = localStorage.getItem('access_token') || '';
    const baseUrl = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

    sseCloseRef.current = openSSE(
      `${baseUrl}/exam/${examId}/events`,
      token,
      {
        RESUME_APPROVED: () => {
          toast.success('Appeal approved! Proceeding to setup…');
          router.replace(`/student/exam/${examId}/device`);
        },
        RESUME_DENIED: (data) => {
          setResumeState('DENIED');
          setResumeRequest((prev: any) => ({ ...prev, status: 'DENIED', review_note: data.review_note }));
          toast.error('Your appeal was denied.');
        },
      }
    );

    return () => sseCloseRef.current?.();
  }, [examId, router]);

  // ── Poll every 10s ────────────────────────────────────

  useEffect(() => {
    fetchStatus();
    const id = setInterval(fetchStatus, 10000);
    return () => clearInterval(id);
  }, [fetchStatus]);

  // ── Dismiss beacon on tab close ───────────────────────

  useEffect(() => {
    const onUnload = () => {
      if (resumeState !== 'CAN_APPLY') return;
      const token = localStorage.getItem('access_token');
      if (!token) return;
      const base = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';
      fetch(`${base}/exam/${examId}/dismiss-appeal`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${token}` },
        keepalive: true,
      });
    };
    window.addEventListener('unload', onUnload);
    return () => window.removeEventListener('unload', onUnload);
  }, [examId, resumeState]);

  // ── Handlers ──────────────────────────────────────────

  const handleAppealSubmit = async () => {
    if (!appealReason.trim()) return toast.error('Please enter a reason.');
    setSubmitting(true);
    try {
      await api.post(`/exam/${examId}/appeal`, { reason: appealReason });
      toast.success('Appeal submitted. Awaiting admin review…');
      setResumeState('PENDING');
      setResumeRequest({ status: 'PENDING', reason: appealReason });
      setShowAppealForm(false);
    } catch (err: any) {
      toast.error(err?.response?.data?.detail || 'Failed to submit appeal.');
    } finally {
      setSubmitting(false);
    }
  };

  const handleDismiss = async () => {
    setDismissing(true);
    try {
      await api.post(`/exam/${examId}/dismiss-appeal`);
    } catch {
      // Best-effort
    }
    router.replace('/student/dashboard');
  };

  // ─────────────────────────────────────────────────────
  // Render helpers
  // ─────────────────────────────────────────────────────

  if (loading) {
    return (
      <div className="flex-1 flex items-center justify-center bg-slate-900 min-h-screen">
        <Loader2 className="h-10 w-10 animate-spin text-indigo-400" />
      </div>
    );
  }

  const { label: terminationLabel } = getTerminationLabel(terminatedBy);
  const isDisconnect = terminatedBy === 'SYSTEM_DISCONNECT';

  const renderContent = () => {
    // AGAIN — second termination, no more appeals
    if (resumeState === 'AGAIN') {
      return (
        <div className="space-y-4">
          <div className="p-4 bg-slate-800 border border-rose-800 rounded-lg">
            <p className="text-rose-400 font-bold flex items-center gap-2">
              <XCircle className="h-5 w-5" /> No Further Appeals Allowed
            </p>
            <p className="text-slate-400 text-sm mt-2 leading-relaxed">
              Your session was terminated a second time after a previous appeal was approved.
              No further appeals are permitted.
            </p>
          </div>
          <Button
            onClick={handleDismiss}
            className="w-full bg-slate-700 hover:bg-slate-600 text-white"
          >
            <ArrowLeft className="h-4 w-4 mr-2" /> Return to Dashboard
          </Button>
        </div>
      );
    }

    // DENIED
    if (resumeState === 'DENIED') {
      return (
        <div className="space-y-4">
          <div className="p-4 bg-slate-800 border border-rose-800 rounded-lg">
            <p className="text-rose-400 font-bold flex items-center gap-2">
              <XCircle className="h-5 w-5" /> Appeal Denied
            </p>
            <p className="text-slate-400 text-sm mt-2 leading-relaxed">
              Your appeal was reviewed and denied. Your exam session has been permanently closed.
            </p>
            {resumeRequest?.review_note && (
              <p className="text-slate-300 text-sm mt-2 bg-slate-700/50 p-3 rounded">
                <span className="text-slate-400">Admin note: </span>{resumeRequest.review_note}
              </p>
            )}
          </div>
          <Button
            onClick={handleDismiss}
            className="w-full bg-slate-700 hover:bg-slate-600 text-white"
          >
            <ArrowLeft className="h-4 w-4 mr-2" /> Return to Dashboard
          </Button>
        </div>
      );
    }

    // NOT_APPLIED — already dismissed
    if (resumeState === 'NOT_APPLIED') {
      return (
        <div className="space-y-4">
          <div className="p-4 bg-slate-800 border border-slate-700 rounded-lg">
            <p className="text-slate-400 text-sm leading-relaxed">
              You chose not to appeal your session termination. Your exam attempt has been closed.
            </p>
          </div>
          <Button
            onClick={() => router.replace('/student/dashboard')}
            className="w-full bg-slate-700 hover:bg-slate-600 text-white"
          >
            <ArrowLeft className="h-4 w-4 mr-2" /> Return to Dashboard
          </Button>
        </div>
      );
    }

    // PENDING — waiting for admin
    if (resumeState === 'PENDING') {
      return (
        <div className="space-y-4">
          <div className="p-4 bg-amber-900/30 border border-amber-700 rounded-lg">
            <p className="text-amber-400 font-semibold flex items-center gap-2">
              <Loader2 className="h-4 w-4 animate-spin" /> Appeal Under Review
            </p>
            <p className="text-slate-400 text-sm mt-2">
              Your request is being reviewed by the exam proctor. Keep this page open.
            </p>
            {resumeRequest?.reason && (
              <p className="text-slate-500 text-sm italic mt-2">"{resumeRequest.reason}"</p>
            )}
            <p className="text-xs text-slate-600 mt-2">Checking for updates every 10 seconds…</p>
          </div>
          <p className="text-xs text-slate-500 text-center">
            {isDisconnect
              ? 'If approved, you will receive extra time to compensate for what was lost.'
              : 'If approved, your timer will continue from where it stopped. No extra time will be added.'}
          </p>
        </div>
      );
    }

    // CAN_APPLY — show appeal option
    return (
      <div className="space-y-4">
        <p className="text-slate-400 text-sm leading-relaxed">
          {isDisconnect
            ? 'Your session was closed due to a disconnection. If this was unintentional, you can appeal for reinstatement with extra time.'
            : 'If you believe this termination was in error, you can appeal once. The proctor will review your case.'}
        </p>
        <p className="text-xs text-amber-400 font-semibold uppercase tracking-wide flex items-center gap-1.5">
          <AlertTriangle className="h-3.5 w-3.5" />
          You have one appeal opportunity. Use it carefully.
        </p>

        {showAppealForm ? (
          <div className="space-y-3">
            <Textarea
              placeholder={
                isDisconnect
                  ? 'My browser/tab closed unexpectedly during the exam. This was due to a network issue or accidental closure, not intentional.'
                  : 'Clearly explain why you believe this termination was incorrect…'
              }
              value={appealReason}
              onChange={(e) => setAppealReason(e.target.value)}
              className="bg-slate-800 border-slate-700 text-slate-200 placeholder:text-slate-600"
              rows={4}
            />
            <div className="flex gap-3">
              <Button
                onClick={handleAppealSubmit}
                disabled={submitting}
                className="flex-1 bg-indigo-600 hover:bg-indigo-700"
              >
                {submitting && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}
                Submit Appeal
              </Button>
              <Button
                onClick={() => setShowAppealForm(false)}
                variant="outline"
                className="border-slate-700 text-slate-300 hover:bg-slate-800"
              >
                Cancel
              </Button>
            </div>
          </div>
        ) : (
          <div className="flex flex-col gap-3">
            <Button
              onClick={() => setShowAppealForm(true)}
              className="w-full bg-indigo-600 hover:bg-indigo-700 gap-2"
            >
              <MessageSquare className="h-4 w-4" /> Appeal This Decision
            </Button>
            <Button
              onClick={handleDismiss}
              disabled={dismissing}
              variant="outline"
              className="w-full border-slate-700 text-slate-400 hover:bg-slate-800 hover:text-slate-200"
            >
              {dismissing && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}
              <ArrowLeft className="h-4 w-4 mr-2" /> Back to Dashboard (No Appeal)
            </Button>
          </div>
        )}
      </div>
    );
  };

  return (
    <div className="flex flex-col min-h-screen bg-slate-900 text-white">
      <div className="flex-1 flex items-center justify-center p-6">
        <Card className="w-full max-w-md bg-slate-900 border-rose-900 text-white shadow-2xl p-8">

          {/* Icon + Title */}
          <div className="text-center mb-6">
            <Ban className="h-16 w-16 text-rose-500 mx-auto mb-4" />
            <Badge
              className={`mb-3 text-xs font-semibold ${
                isDisconnect
                  ? 'bg-amber-900/60 text-amber-300 border-amber-700'
                  : 'bg-rose-900/60 text-rose-300 border-rose-700'
              }`}
              variant="outline"
            >
              {terminationLabel}
            </Badge>
            <h1 className="text-2xl font-bold text-white">Session Terminated</h1>
            {examTitle && (
              <p className="text-slate-400 text-sm mt-1">{examTitle}</p>
            )}
          </div>

          {/* Termination reason */}
          {terminatedReason && (
            <div className="mb-5 p-3 bg-slate-800 rounded-lg border border-slate-700">
              <p className="text-xs text-slate-500 uppercase tracking-wider mb-1">Reason</p>
              <p className="text-slate-300 text-sm">{terminatedReason}</p>
            </div>
          )}

          {/* State-based content */}
          {renderContent()}

        </Card>
      </div>

      {/* Camera PiP — always visible if available */}
      {cameraActive && (
        <div className="fixed bottom-6 right-6 w-56 aspect-video bg-black rounded-xl overflow-hidden shadow-2xl border-2 border-slate-700 pointer-events-none">
          <video
            ref={videoRef}
            autoPlay
            playsInline
            muted
            className="w-full h-full object-cover"
            style={{ transform: 'scaleX(-1)' }}
          />
          <div className="absolute top-1.5 left-1.5 bg-black/70 px-2 py-0.5 rounded text-[9px] font-bold text-amber-400 uppercase tracking-wider">
            Session Ended
          </div>
        </div>
      )}
    </div>
  );
}
