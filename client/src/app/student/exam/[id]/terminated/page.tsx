'use client';

import { useEffect, useRef, useState, useCallback } from 'react';
import { useRouter, useParams } from 'next/navigation';
import { Ban, Loader2, MessageSquare, ArrowLeft, XCircle, AlertTriangle } from 'lucide-react';
import { toast } from 'sonner';
import api from '@/lib/axios';

type ResumeState = 'CAN_APPLY' | 'PENDING' | 'APPROVED' | 'DENIED' | 'NOT_APPLIED' | 'AGAIN' | null;

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

function getTerminationLabel(terminatedBy: string | null): { label: string; isDisconnect: boolean } {
  if (terminatedBy === 'SYSTEM_DISCONNECT') return { label: 'Disconnection Timeout', isDisconnect: true };
  if (terminatedBy === 'ADMIN') return { label: 'Terminated by Proctor', isDisconnect: false };
  if (terminatedBy?.startsWith('SYSTEM')) return { label: 'System Flag Triggered', isDisconnect: false };
  return { label: 'Session Terminated', isDisconnect: false };
}

export default function TerminatedPage() {
  const router = useRouter();
  const params = useParams();
  const examId = params.id as string;

  const [examTitle, setExamTitle] = useState('');
  const [terminatedBy, setTerminatedBy] = useState<string | null>(null);
  const [terminatedReason, setTerminatedReason] = useState('');
  const [resumeState, setResumeState] = useState<ResumeState>(null);
  const [resumeRequest, setResumeRequest] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [showAppealForm, setShowAppealForm] = useState(false);
  const [appealReason, setAppealReason] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [dismissing, setDismissing] = useState(false);
  const videoRef = useRef<HTMLVideoElement>(null);
  const streamRef = useRef<MediaStream | null>(null);
  const [cameraActive, setCameraActive] = useState(false);
  const sseCloseRef = useRef<(() => void) | null>(null);

  const fetchStatus = useCallback(async () => {
    try {
      const res = await api.get(`/exam/${examId}/status`);
      const data = res.data;
      setExamTitle(data.title || '');
      setTerminatedBy(data.session_terminated_by || null);
      setTerminatedReason(data.session_terminated_reason || '');
      setResumeState(data.resume_state);
      setResumeRequest(data.active_resume_request || null);
      if (data.resume_state === 'APPROVED' || data.session_status === 'CREATED') {
        router.replace(`/student/exam/${examId}/device`);
        return;
      }
    } catch {}
    finally { setLoading(false); }
  }, [examId, router]);

  useEffect(() => {
    const camId = localStorage.getItem(`exam_cam_${examId}`);
    const micId = localStorage.getItem(`exam_mic_${examId}`);
    if (!camId && !micId) return;
    navigator.mediaDevices.getUserMedia({
      video: camId ? { deviceId: { exact: camId } } : true,
      audio: micId ? { deviceId: { exact: micId } } : false,
    }).then(s => {
      streamRef.current = s;
      if (videoRef.current) videoRef.current.srcObject = s;
      setCameraActive(true);
    }).catch(() => {});
    return () => { streamRef.current?.getTracks().forEach(t => t.stop()); };
  }, [examId]);

  useEffect(() => {
    const token = localStorage.getItem('access_token') || '';
    const baseUrl = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';
    sseCloseRef.current = openSSE(`${baseUrl}/exam/${examId}/events`, token, {
      RESUME_APPROVED: () => { toast.success('Appeal approved! Proceeding to setup…'); router.replace(`/student/exam/${examId}/device`); },
      RESUME_DENIED: (data) => { setResumeState('DENIED'); setResumeRequest((prev: any) => ({ ...prev, status: 'DENIED', review_note: data.review_note })); toast.error('Your appeal was denied.'); },
    });
    return () => sseCloseRef.current?.();
  }, [examId, router]);

  useEffect(() => {
    fetchStatus();
    const id = setInterval(fetchStatus, 10000);
    return () => clearInterval(id);
  }, [fetchStatus]);

  useEffect(() => {
    const onUnload = () => {
      if (resumeState !== 'CAN_APPLY') return;
      const token = localStorage.getItem('access_token');
      if (!token) return;
      const base = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';
      fetch(`${base}/exam/${examId}/dismiss-appeal`, { method: 'POST', headers: { Authorization: `Bearer ${token}` }, keepalive: true });
    };
    window.addEventListener('unload', onUnload);
    return () => window.removeEventListener('unload', onUnload);
  }, [examId, resumeState]);

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
    } finally { setSubmitting(false); }
  };

  const handleDismiss = async () => {
    setDismissing(true);
    try { await api.post(`/exam/${examId}/dismiss-appeal`); } catch {}
    router.replace('/student/dashboard');
  };

  if (loading) {
    return (
      <div style={{ minHeight: '100vh', background: '#F8FAFC', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
        <Loader2 style={{ width: '28px', height: '28px', color: '#22577A', animation: 'spin 1s linear infinite' }} />
        <style>{`@keyframes spin{to{transform:rotate(360deg)}}`}</style>
      </div>
    );
  }

  const { label: terminationLabel, isDisconnect } = getTerminationLabel(terminatedBy);

  const renderContent = () => {
    if (resumeState === 'AGAIN') {
      return (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
          <div style={{ padding: '14px 16px', background: '#F8FAFC', border: '1.5px solid #E2E8F0', borderRadius: '10px' }}>
            <p style={{ fontSize: '14px', fontWeight: 700, color: '#475569', display: 'flex', alignItems: 'center', gap: '8px' }}>
              <XCircle style={{ width: '16px', height: '16px', color: '#64748B' }} /> No Further Appeals Allowed
            </p>
            <p style={{ fontSize: '13px', color: '#64748B', marginTop: '6px', lineHeight: 1.55 }}>
              Your session was terminated a second time after a previous appeal was approved. No further appeals are permitted.
            </p>
          </div>
          <button onClick={handleDismiss} className="st-btn-ghost" style={{ width: '100%', justifyContent: 'center' }}>
            <ArrowLeft style={{ width: '14px', height: '14px' }} /> Return to Dashboard
          </button>
        </div>
      );
    }

    if (resumeState === 'DENIED') {
      return (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
          <div style={{ padding: '14px 16px', background: '#F8FAFC', border: '1.5px solid #E2E8F0', borderRadius: '10px' }}>
            <p style={{ fontSize: '14px', fontWeight: 700, color: '#DC2626', display: 'flex', alignItems: 'center', gap: '8px' }}>
              <XCircle style={{ width: '16px', height: '16px' }} /> Appeal Denied
            </p>
            <p style={{ fontSize: '13px', color: '#64748B', marginTop: '6px', lineHeight: 1.55 }}>
              Your appeal was reviewed and denied. Your exam session has been permanently closed.
            </p>
            {resumeRequest?.review_note && (
              <div style={{ marginTop: '10px', padding: '10px 12px', background: '#fff', border: '1px solid #E2E8F0', borderRadius: '8px', fontSize: '13px' }}>
                <span style={{ fontWeight: 700, color: '#475569' }}>Admin note: </span>
                <span style={{ color: '#64748B' }}>{resumeRequest.review_note}</span>
              </div>
            )}
          </div>
          <button onClick={handleDismiss} className="st-btn-ghost" style={{ width: '100%', justifyContent: 'center' }}>
            <ArrowLeft style={{ width: '14px', height: '14px' }} /> Return to Dashboard
          </button>
        </div>
      );
    }

    if (resumeState === 'NOT_APPLIED') {
      return (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
          <div style={{ padding: '14px 16px', background: '#F8FAFC', border: '1.5px solid #E2E8F0', borderRadius: '10px' }}>
            <p style={{ fontSize: '13.5px', color: '#64748B', lineHeight: 1.55 }}>
              You chose not to appeal your session termination. Your exam attempt has been closed.
            </p>
          </div>
          <button onClick={() => router.replace('/student/dashboard')} className="st-btn-ghost" style={{ width: '100%', justifyContent: 'center' }}>
            <ArrowLeft style={{ width: '14px', height: '14px' }} /> Return to Dashboard
          </button>
        </div>
      );
    }

    if (resumeState === 'PENDING') {
      return (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
          <div style={{ padding: '16px', background: 'rgba(34,87,122,0.05)', border: '1.5px solid rgba(34,87,122,0.15)', borderRadius: '10px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '10px' }}>
              <Loader2 style={{ width: '16px', height: '16px', color: '#22577A', animation: 'spin 1s linear infinite' }} />
              <div>
                <p style={{ fontSize: '14px', fontWeight: 700, color: '#22577A' }}>Appeal Under Review</p>
                <p style={{ fontSize: '12.5px', color: '#38A3A5', marginTop: '2px' }}>Your request is being reviewed by the exam proctor. Please keep this page open.</p>
              </div>
            </div>
            {resumeRequest?.reason && (
              <div style={{ padding: '10px 12px', background: 'rgba(255,255,255,0.7)', borderRadius: '8px', border: '1px solid rgba(34,87,122,0.1)' }}>
                <p style={{ fontSize: '13px', color: '#475569', fontStyle: 'italic' }}>"{resumeRequest.reason}"</p>
              </div>
            )}
            <p style={{ fontSize: '11.5px', color: '#38A3A5', marginTop: '10px', fontWeight: 600 }}>Auto-checking for updates every 10 seconds…</p>
          </div>
          <p style={{ fontSize: '12px', color: '#64748B', textAlign: 'center' }}>
            {isDisconnect
              ? 'If approved, you may receive extra time to compensate for the disconnection.'
              : 'If approved, your session will resume where it stopped.'}
          </p>
        </div>
      );
    }

    // CAN_APPLY
    return (
      <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
        <div style={{ padding: '14px 16px', background: '#F8FAFC', border: '1.5px solid #E2E8F0', borderRadius: '10px' }}>
          <p style={{ fontSize: '13.5px', color: '#64748B', lineHeight: 1.6 }}>
            {isDisconnect
              ? 'Your session ended due to a disconnection. If this was an accident (e.g., network drop), you can appeal to resume the exam.'
              : 'If you believe this termination was a system error, you may submit an appeal. A proctor will review your request.'}
          </p>
          <div style={{ marginTop: '10px', display: 'flex', alignItems: 'flex-start', gap: '8px', padding: '10px 12px', background: 'rgba(245,158,11,0.06)', borderRadius: '8px', border: '1px solid rgba(245,158,11,0.2)' }}>
            <AlertTriangle style={{ width: '14px', height: '14px', color: '#F59E0B', flexShrink: 0, marginTop: '1px' }} />
            <p style={{ fontSize: '12px', fontWeight: 600, color: '#B45309' }}>
              You only have one opportunity to appeal. Please explain the situation clearly.
            </p>
          </div>
        </div>

        {showAppealForm ? (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
            <div>
              <label style={{ display: 'block', fontSize: '13px', fontWeight: 600, color: '#475569', marginBottom: '6px' }}>Appeal Reason</label>
              <textarea
                placeholder={isDisconnect ? 'My browser/tab closed unexpectedly due to a system crash/network issue...' : 'Please explain why this termination should be reversed...'}
                value={appealReason}
                onChange={e => setAppealReason(e.target.value)}
                className="st-textarea"
              />
            </div>
            <div style={{ display: 'flex', gap: '10px' }}>
              <button
                onClick={handleAppealSubmit}
                disabled={submitting}
                className="st-btn"
                style={{ flex: 1 }}
              >
                {submitting && <Loader2 style={{ width: '14px', height: '14px', animation: 'spin 1s linear infinite' }} />}
                Submit Appeal
              </button>
              <button onClick={() => setShowAppealForm(false)} className="st-btn-ghost">Cancel</button>
            </div>
          </div>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
            <button onClick={() => setShowAppealForm(true)} className="st-btn" style={{ width: '100%' }}>
              <MessageSquare style={{ width: '14px', height: '14px' }} /> Request to Resume
            </button>
            <button onClick={handleDismiss} disabled={dismissing} className="st-btn-ghost" style={{ width: '100%', justifyContent: 'center' }}>
              {dismissing && <Loader2 style={{ width: '14px', height: '14px', animation: 'spin 1s linear infinite' }} />}
              Return to Dashboard (No Appeal)
            </button>
          </div>
        )}
      </div>
    );
  };

  return (
    <div style={{ minHeight: '100vh', background: '#F8FAFC', fontFamily: "'Plus Jakarta Sans', sans-serif", display: 'flex', alignItems: 'center', justifyContent: 'center', padding: '24px' }}>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&display=swap');
        @keyframes spin{to{transform:rotate(360deg)}}
        .st-btn{display:flex;align-items:center;justify-content:center;gap:7px;padding:10px 18px;border-radius:8px;border:none;font-size:13.5px;font-weight:700;cursor:pointer;font-family:'Plus Jakarta Sans',sans-serif;background:#22577A;color:#fff;transition:background 150ms;width:100%;}
        .st-btn:hover:not(:disabled){background:#2C6A91}
        .st-btn:disabled{background:#94A3B8!important;cursor:not-allowed}
        .st-btn-ghost{display:flex;align-items:center;gap:6px;padding:9px 14px;border-radius:8px;border:1.5px solid #E2E8F0;background:#fff;font-size:13px;font-family:'Plus Jakarta Sans',sans-serif;font-weight:600;cursor:pointer;color:#475569;transition:background 150ms,border-color 150ms;}
        .st-btn-ghost:hover{background:#F8FAFC;border-color:#CBD5E1}
        .st-btn-ghost:disabled{opacity:0.5;cursor:not-allowed}
        .st-textarea{display:block;width:100%;padding:9px 13px;border:1.5px solid #E2E8F0;border-radius:8px;font-size:14px;font-family:'Plus Jakarta Sans',sans-serif;color:#0F172A;background:#fff;line-height:1.6;resize:vertical;min-height:100px;transition:border-color 150ms,box-shadow 150ms;outline:none;}
        .st-textarea::placeholder{color:#94A3B8;opacity:1}
        .st-textarea:focus{border-color:#38A3A5;box-shadow:0 0 0 3px rgba(56,163,165,0.12)}
      `}</style>

      <div style={{ width: '100%', maxWidth: '460px' }}>
        <div style={{ background: '#fff', border: '1.5px solid #E2E8F0', borderRadius: '16px', overflow: 'hidden', boxShadow: '0 8px 32px rgba(0,0,0,0.07)' }}>
          {/* Red/amber top bar */}
          <div style={{ height: '4px', background: isDisconnect ? 'linear-gradient(90deg, #F59E0B, #FCD34D)' : 'linear-gradient(90deg, #EF4444, #F87171)' }} />

          <div style={{ padding: '28px 28px 24px', textAlign: 'center', borderBottom: '1px solid #F1F5F9' }}>
            <div style={{
              width: '60px', height: '60px', borderRadius: '50%',
              background: isDisconnect ? 'rgba(245,158,11,0.1)' : 'rgba(239,68,68,0.08)',
              display: 'flex', alignItems: 'center', justifyContent: 'center', margin: '0 auto 12px',
            }}>
              <Ban style={{ width: '28px', height: '28px', color: isDisconnect ? '#F59E0B' : '#EF4444' }} />
            </div>

            <span style={{
              display: 'inline-block', marginBottom: '10px',
              padding: '4px 12px', borderRadius: '20px', fontSize: '11px', fontWeight: 700,
              letterSpacing: '0.05em', textTransform: 'uppercase',
              background: isDisconnect ? 'rgba(245,158,11,0.1)' : 'rgba(239,68,68,0.08)',
              color: isDisconnect ? '#D97706' : '#DC2626',
              border: `1px solid ${isDisconnect ? 'rgba(245,158,11,0.25)' : 'rgba(239,68,68,0.2)'}`,
            }}>
              {terminationLabel}
            </span>

            <h1 style={{ fontSize: '22px', fontWeight: 800, color: '#0F172A', letterSpacing: '-0.02em' }}>Session Terminated</h1>
            {examTitle && <p style={{ fontSize: '13.5px', color: '#64748B', marginTop: '4px', fontWeight: 500 }}>{examTitle}</p>}
          </div>

          <div style={{ padding: '20px 28px 24px', display: 'flex', flexDirection: 'column', gap: '14px' }}>
            {terminatedReason && (
              <div style={{ padding: '12px 14px', background: '#F8FAFC', borderRadius: '10px', border: '1.5px solid #E2E8F0' }}>
                <p style={{ fontSize: '10.5px', fontWeight: 700, color: '#64748B', textTransform: 'uppercase', letterSpacing: '0.07em', marginBottom: '5px' }}>
                  Reason for Termination
                </p>
                <p style={{ fontSize: '13.5px', color: '#0F172A', fontWeight: 600 }}>{terminatedReason}</p>
              </div>
            )}

            {renderContent()}
          </div>
        </div>
      </div>

      {/* Camera PiP */}
      {cameraActive && (
        <div style={{
          position: 'fixed', bottom: '20px', right: '20px',
          width: '180px', aspectRatio: '16/9',
          background: '#000', borderRadius: '10px', overflow: 'hidden',
          border: '2px solid #E2E8F0', boxShadow: '0 4px 20px rgba(0,0,0,0.15)',
          pointerEvents: 'none',
        }}>
          <video ref={videoRef} autoPlay playsInline muted style={{ width: '100%', height: '100%', objectFit: 'cover', display: 'block', transform: 'scaleX(-1)' }} />
          <div style={{ position: 'absolute', bottom: '5px', left: '5px', background: 'rgba(0,0,0,0.65)', padding: '2px 6px', borderRadius: '3px' }}>
            <span style={{ fontSize: '9px', fontWeight: 700, color: '#fff', textTransform: 'uppercase', letterSpacing: '0.07em' }}>Camera Active</span>
          </div>
        </div>
      )}
    </div>
  );
}
