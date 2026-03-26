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
      <div className="flex-1 flex items-center justify-center bg-gray-50 min-h-screen">
        <Loader2 className="h-10 w-10 animate-spin text-blue-600" />
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
          <div className="p-4 bg-gray-50 border border-gray-200 rounded-lg">
            <p className="text-gray-900 font-semibold flex items-center gap-2">
              <XCircle className="h-5 w-5 text-gray-500" /> No Further Appeals Allowed
            </p>
            <p className="text-gray-600 text-sm mt-1 leading-relaxed">
              Your session was terminated a second time after a previous appeal was approved.
              No further appeals are permitted.
            </p>
          </div>
          <Button
            onClick={handleDismiss}
            variant="outline"
            className="w-full bg-white border-gray-300 text-gray-700 hover:bg-gray-50"
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
          <div className="p-4 bg-gray-50 border border-gray-200 rounded-lg">
            <p className="text-gray-900 font-semibold flex items-center gap-2">
              <XCircle className="h-5 w-5 text-rose-500" /> Appeal Denied
            </p>
            <p className="text-gray-600 text-sm mt-1 leading-relaxed">
              Your appeal was reviewed and denied. Your exam session has been permanently closed.
            </p>
            {resumeRequest?.review_note && (
              <div className="mt-3 p-3 bg-white border border-gray-200 rounded text-sm">
                <span className="font-medium text-gray-900">Admin note: </span>
                <span className="text-gray-700">{resumeRequest.review_note}</span>
              </div>
            )}
          </div>
          <Button
            onClick={handleDismiss}
            variant="outline"
            className="w-full bg-white border-gray-300 text-gray-700 hover:bg-gray-50"
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
          <div className="p-4 bg-gray-50 border border-gray-200 rounded-lg">
            <p className="text-gray-600 text-sm leading-relaxed">
              You chose not to appeal your session termination. Your exam attempt has been closed.
            </p>
          </div>
          <Button
            onClick={() => router.replace('/student/dashboard')}
            variant="outline"
            className="w-full bg-white border-gray-300 text-gray-700 hover:bg-gray-50"
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
          <div className="p-4 bg-blue-50 border border-blue-100 rounded-lg">
            <div className="flex items-center gap-3">
              <Loader2 className="h-5 w-5 text-blue-600 animate-spin" />
              <div>
                <p className="text-blue-900 font-medium">Appeal Under Review</p>
                <p className="text-blue-700 text-sm mt-0.5">
                  Your request is being reviewed by the exam proctor. Please keep this page open.
                </p>
              </div>
            </div>
            {resumeRequest?.reason && (
              <div className="mt-3 bg-white/60 p-3 rounded border border-blue-100">
                <p className="text-gray-700 text-sm italic">"{resumeRequest.reason}"</p>
              </div>
            )}
            <p className="text-xs text-blue-600 mt-3 font-medium">Auto-checking for updates every 10s...</p>
          </div>
          <p className="text-xs text-gray-500 text-center">
            {isDisconnect
              ? 'If approved, you may receive extra time to compensate for the disconnection.'
              : 'If approved, your session will resume where it stopped.'}
          </p>
        </div>
      );
    }

    // CAN_APPLY — show appeal option
    return (
      <div className="space-y-5">
        <div className="bg-gray-50 p-4 rounded-lg border border-gray-200">
          <p className="text-gray-700 text-sm leading-relaxed">
            {isDisconnect
              ? 'Your session ended due to a disconnection summary. If this was an accident (e.g., network drop), you can appeal to resume the exam.'
              : 'If you believe this termination was a system error, you may submit an appeal. A proctor will review your request.'}
          </p>
          <div className="mt-3 flex items-start gap-2 text-amber-700 bg-amber-50 p-2.5 rounded border border-amber-200">
            <AlertTriangle className="h-4 w-4 shrink-0 mt-0.5" />
            <p className="text-xs font-medium">
              You only have one opportunity to appeal. Please explain the situation clearly.
            </p>
          </div>
        </div>

        {showAppealForm ? (
          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-900 mb-1.5">Appeal Reason</label>
              <Textarea
                placeholder={
                  isDisconnect
                    ? 'My browser/tab closed unexpectedly due to a system crash/network issue...'
                    : 'Please explain why this termination should be reversed...'
                }
                value={appealReason}
                onChange={(e) => setAppealReason(e.target.value)}
                className="bg-white border-gray-300 text-gray-900 focus:ring-blue-500 focus:border-blue-500 min-h-[100px]"
              />
            </div>
            <div className="flex gap-3">
              <Button
                onClick={handleAppealSubmit}
                disabled={submitting}
                className="flex-1 bg-blue-600 hover:bg-blue-700 text-white font-medium shadow-sm"
              >
                {submitting && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}
                Submit Appeal
              </Button>
              <Button
                onClick={() => setShowAppealForm(false)}
                variant="outline"
                className="bg-white border-gray-300 text-gray-700 hover:bg-gray-50"
              >
                Cancel
              </Button>
            </div>
          </div>
        ) : (
          <div className="flex flex-col gap-3">
            <Button
              onClick={() => setShowAppealForm(true)}
              className="w-full bg-blue-600 hover:bg-blue-700 text-white font-medium shadow-sm gap-2"
            >
              <MessageSquare className="h-4 w-4" /> Request to Resume
            </Button>
            <Button
              onClick={handleDismiss}
              disabled={dismissing}
              variant="outline"
              className="w-full bg-white border-gray-300 text-gray-600 hover:bg-gray-50 hover:text-gray-900"
            >
              {dismissing && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}
              Return to Dashboard (No Appeal)
            </Button>
          </div>
        )}
      </div>
    );
  };

  return (
    <div className="flex flex-col min-h-screen bg-gray-50 text-gray-900 font-sans">
      <div className="flex-1 flex items-center justify-center p-6">
        <Card className="w-full max-w-md bg-white border border-gray-200 shadow-xl rounded-xl p-8">

          {/* Icon + Title */}
          <div className="text-center mb-8">
            <div className="inline-flex items-center justify-center p-4 bg-rose-50 rounded-full mb-4">
              <Ban className="h-10 w-10 text-rose-600" />
            </div>
            <div>
              <Badge
                className={`mb-3 text-xs font-semibold uppercase tracking-wider ${
                  isDisconnect
                    ? 'bg-amber-100 text-amber-800 border-amber-200'
                    : 'bg-rose-100 text-rose-800 border-rose-200'
                }`}
                variant="outline"
              >
                {terminationLabel}
              </Badge>
            </div>
            <h1 className="text-2xl font-bold text-gray-900 tracking-tight">Session Terminated</h1>
            {examTitle && (
              <p className="text-gray-500 text-sm mt-1.5">{examTitle}</p>
            )}
          </div>

          {/* Termination reason */}
          {terminatedReason && (
            <div className="mb-6 p-4 bg-gray-50 rounded-lg border border-gray-200">
              <p className="text-xs text-gray-500 font-semibold uppercase tracking-wider mb-1">Reason for Termination</p>
              <p className="text-gray-900 text-sm font-medium">{terminatedReason}</p>
            </div>
          )}

          {/* State-based content */}
          {renderContent()}

        </Card>
      </div>

      {/* Camera PiP — always visible if available */}
      {cameraActive && (
        <div className="fixed bottom-6 right-6 w-48 aspect-video bg-black rounded-lg overflow-hidden shadow-lg border border-gray-300 pointer-events-none">
          <video
            ref={videoRef}
            autoPlay
            playsInline
            muted
            className="w-full h-full object-cover"
            style={{ transform: 'scaleX(-1)' }}
          />
          <div className="absolute top-2 left-2 bg-black/60 px-2 py-1 rounded text-[10px] font-semibold text-white backdrop-blur-sm">
            Camera Active
          </div>
        </div>
      )}
    </div>
  );
}
