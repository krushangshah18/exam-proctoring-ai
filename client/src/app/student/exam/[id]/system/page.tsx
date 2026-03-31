'use client';

import { useEffect, useRef, useState } from 'react';
import { useRouter, useParams, useSearchParams } from 'next/navigation';
import { Loader2, ArrowRight, Monitor, LogOut, CheckCircle2, ShieldAlert, AlertTriangle, Cpu } from 'lucide-react';
import { toast } from 'sonner';
import api from '@/lib/axios';
import { parseUTC } from '@/lib/fmt-date';

type CheckStatus = 'pending' | 'checking' | 'pass' | 'fail';

function StatusIndicator({ status }: { status: CheckStatus }) {
  if (status === 'checking') return <Loader2 style={{ width: '22px', height: '22px', color: '#22577A', animation: 'spin 1s linear infinite' }} />;
  if (status === 'pass') return <CheckCircle2 style={{ width: '22px', height: '22px', color: '#22C55E' }} />;
  if (status === 'fail') return <ShieldAlert style={{ width: '22px', height: '22px', color: '#EF4444' }} />;
  return <div style={{ width: '22px', height: '22px', borderRadius: '50%', border: '2px solid #E2E8F0' }} />;
}

function CheckCard({ icon, title, subtitle, status, error }: {
  icon: React.ReactNode; title: string; subtitle: string; status: CheckStatus; error?: string;
}) {
  return (
    <div style={{
      background: '#fff',
      border: `1.5px solid ${status === 'fail' ? 'rgba(239,68,68,0.25)' : status === 'pass' ? 'rgba(34,197,94,0.2)' : '#E2E8F0'}`,
      borderRadius: '12px', overflow: 'hidden',
      transition: 'border-color 200ms',
    }}>
      <div style={{ padding: '16px 20px', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
          <div style={{
            width: '40px', height: '40px', borderRadius: '10px',
            background: 'rgba(34,87,122,0.08)', display: 'flex', alignItems: 'center', justifyContent: 'center',
          }}>
            {icon}
          </div>
          <div>
            <h3 style={{ fontSize: '14.5px', fontWeight: 700, color: '#0F172A' }}>{title}</h3>
            <p style={{ fontSize: '12.5px', color: '#64748B', marginTop: '2px' }}>{subtitle}</p>
          </div>
        </div>
        <StatusIndicator status={status} />
      </div>

      {status === 'fail' && error && (
        <div style={{
          margin: '0 16px 14px', padding: '10px 14px', borderRadius: '8px',
          background: 'rgba(239,68,68,0.05)', border: '1px solid rgba(239,68,68,0.15)',
          display: 'flex', alignItems: 'flex-start', gap: '8px',
        }}>
          <AlertTriangle style={{ width: '14px', height: '14px', color: '#EF4444', flexShrink: 0, marginTop: '2px' }} />
          <p style={{ fontSize: '13px', color: '#DC2626', lineHeight: 1.5 }}>{error}</p>
        </div>
      )}
    </div>
  );
}

export default function SystemCheckPage() {
  const router = useRouter();
  const params = useParams();
  const searchParams = useSearchParams();
  const examId = params.id as string;
  const isReconnect = searchParams.get('reconnect') === 'true';

  const [exam, setExam] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [fsStatus, setFsStatus] = useState<CheckStatus>('pending');
  const [sessionStatus, setSessionStatus] = useState<CheckStatus>('pending');
  const [sessionError, setSessionError] = useState<string>('');
  const [engineStatus, setEngineStatus] = useState<CheckStatus>('pending');
  const [engineError, setEngineError] = useState<string>('');
  const [isExamReady, setIsExamReady] = useState(false);
  const [countdown, setCountdown] = useState<number>(0);
  const countdownIntervalRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const countdownEndRef = useRef<number>(0);

  useEffect(() => {
    const initSystem = async () => {
      try {
        const res = await api.get(`/exam/${examId}/status`);
        const data = res.data;
        if (data.session_status === 'TERMINATED') { router.replace(`/student/exam/${examId}/terminated`); return; }
        setExam(data);
        setIsExamReady(data.allowed_to_start);
        if (!data.allowed_to_start && data.start_window) {
          const startMs = parseUTC(data.start_window).getTime();
          const msUntilStart = Math.max(0, startMs - Date.now());
          if (msUntilStart > 0) {
            countdownEndRef.current = startMs;
            setCountdown(Math.ceil(msUntilStart / 1000));
            countdownIntervalRef.current = setInterval(() => {
              const remaining = Math.max(0, Math.ceil((countdownEndRef.current - Date.now()) / 1000));
              setCountdown(remaining);
              if (remaining <= 0) { clearInterval(countdownIntervalRef.current!); setIsExamReady(true); }
            }, 1000);
          }
        }
        setLoading(false);
        runSystemChecks();
      } catch {
        toast.error('Failed to load exam specs');
        router.replace('/student/dashboard');
      }
    };
    initSystem();
    return () => { if (countdownIntervalRef.current) clearInterval(countdownIntervalRef.current); };
  }, [examId]);

  const runSystemChecks = async () => {
    setSessionStatus('checking'); setSessionError('');
    try {
      await api.post(`/exam/${examId}/lock-session`);
      setSessionStatus('pass');
    } catch (err: any) {
      setSessionStatus('fail');
      if (err.response?.status === 409) {
        setSessionError(err.response.data?.detail || 'This exam is already active on another device. Please use that device.');
        toast.error('Another device is already active for this exam.');
      } else {
        setSessionError('Failed to lock concurrent sessions.');
        toast.error('Failed to lock concurrent sessions.');
      }
    }

    setFsStatus('checking');
    setTimeout(() => {
      setFsStatus(document.fullscreenEnabled ? 'pass' : 'fail');
      if (!document.fullscreenEnabled) toast.error('Your browser does not support fullscreen mode. Please use Chrome or Edge.');
    }, 1200);

    setEngineStatus('checking'); setEngineError('');
    try {
      const res = await api.get(`/exam/${examId}/engine-status`);
      if (res.data.available) { setEngineStatus('pass'); }
      else { setEngineStatus('fail'); setEngineError('Please wait a few minutes — we are allocating a proctoring engine for your session.'); toast.error('Proctoring engine is being allocated. Please retry in a moment.'); }
    } catch {
      setEngineStatus('fail');
      setEngineError('Please wait a few minutes — we are allocating a proctoring engine for your session.');
      toast.error('Proctoring engine is being allocated. Please retry in a moment.');
    }
  };

  const handleStartExam = async () => {
    try {
      if (document.documentElement.requestFullscreen) await document.documentElement.requestFullscreen();
      await api.post(`/exam/start/${examId}`);
      router.push(`/student/exam/${examId}/active`);
    } catch (err: any) {
      toast.error(err?.response?.data?.detail || 'Could not launch exam. Ensure browser allows Fullscreen.');
    }
  };

  const allPassed = fsStatus === 'pass' && sessionStatus === 'pass' && engineStatus === 'pass';
  const anyChecking = fsStatus === 'checking' || sessionStatus === 'checking' || engineStatus === 'checking';
  const anyFailed = fsStatus === 'fail' || sessionStatus === 'fail' || engineStatus === 'fail';

  const formatCountdown = (secs: number) => {
    const h = Math.floor(secs / 3600);
    const m = Math.floor((secs % 3600) / 60);
    const s = secs % 60;
    if (h > 0) return `${h}:${m.toString().padStart(2, '0')}:${s.toString().padStart(2, '0')}`;
    return `${m.toString().padStart(2, '0')}:${s.toString().padStart(2, '0')}`;
  };

  if (loading) {
    return (
      <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
        <Loader2 style={{ width: '28px', height: '28px', color: '#22577A', animation: 'spin 1s linear infinite' }} />
        <style>{`@keyframes spin{to{transform:rotate(360deg)}}`}</style>
      </div>
    );
  }

  return (
    <>
      <style>{`@keyframes spin{to{transform:rotate(360deg)}}`}</style>
      <div style={{ flex: 1, overflowY: 'auto', padding: '24px', background: '#F8FAFC' }}>
        <div style={{ maxWidth: '580px', margin: '0 auto' }} className="st-fadein">

          <div style={{ textAlign: 'center', marginBottom: '28px' }}>
            <div style={{
              width: '52px', height: '52px', borderRadius: '14px',
              background: 'rgba(34,87,122,0.08)', display: 'flex', alignItems: 'center', justifyContent: 'center',
              margin: '0 auto 14px',
            }}>
              <ShieldAlert style={{ width: '24px', height: '24px', color: '#22577A' }} />
            </div>
            <h1 style={{ fontSize: '22px', fontWeight: 800, color: '#0F172A', letterSpacing: '-0.02em', marginBottom: '6px' }}>
              {isReconnect ? 'Reconnect System Check' : 'Final System Lock'}
            </h1>
            <p style={{ fontSize: '14px', color: '#64748B' }}>
              {isReconnect
                ? 'Verifying your device before reconnecting to the exam.'
                : 'Preparing the secure environment for your exam.'}
            </p>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '12px', marginBottom: '20px' }}>
            <CheckCard
              icon={<LogOut style={{ width: '18px', height: '18px', color: '#22577A' }} />}
              title="Cross-Device Lock"
              subtitle="Revoking access on all other active devices"
              status={sessionStatus}
              error={sessionError}
            />
            <CheckCard
              icon={<Monitor style={{ width: '18px', height: '18px', color: '#22577A' }} />}
              title="Fullscreen Enforcement"
              subtitle="Checking browser capability for kiosk mode"
              status={fsStatus}
            />
            <CheckCard
              icon={<Cpu style={{ width: '18px', height: '18px', color: '#22577A' }} />}
              title="Proctoring Engine"
              subtitle="Verifying AI monitoring service availability"
              status={engineStatus}
              error={engineError}
            />
          </div>

          {anyFailed && (
            <button
              onClick={runSystemChecks}
              className="st-btn-ghost"
              style={{ width: '100%', justifyContent: 'center', marginBottom: '14px' }}
            >
              <Loader2 style={{ width: '14px', height: '14px' }} /> Retry All Checks
            </button>
          )}

          {/* Launch button */}
          <div>
            {anyChecking ? (
              <button disabled className="st-btn" style={{ width: '100%', padding: '14px', fontSize: '15px', background: '#94A3B8', cursor: 'not-allowed' }}>
                <Loader2 style={{ width: '18px', height: '18px', animation: 'spin 1s linear infinite' }} /> Finalizing Environment…
              </button>
            ) : !allPassed ? (
              <button disabled className="st-btn" style={{ width: '100%', padding: '14px', fontSize: '15px', background: 'rgba(239,68,68,0.1)', color: '#DC2626', border: '1.5px solid rgba(239,68,68,0.2)', cursor: 'not-allowed' }}>
                Waiting for proctoring engine…
              </button>
            ) : !isExamReady ? (
              <button disabled className="st-btn st-btn-warning" style={{ width: '100%', padding: '14px', fontSize: '18px', fontFamily: "'Plus Jakarta Sans', sans-serif", letterSpacing: '0.04em', cursor: 'not-allowed', fontWeight: 800 }}>
                {formatCountdown(countdown)}
              </button>
            ) : (
              <button
                onClick={handleStartExam}
                className="st-btn st-btn-success st-btn-lg"
                style={{ width: '100%', padding: '14px', fontSize: '15px', boxShadow: '0 8px 24px rgba(34,197,94,0.25)' }}
              >
                {isReconnect ? 'Reconnect to Exam' : 'Enter Fullscreen & Start Exam'}
                <ArrowRight style={{ width: '18px', height: '18px' }} />
              </button>
            )}
          </div>

          <p style={{ textAlign: 'center', fontSize: '11.5px', color: '#64748B', marginTop: '14px', lineHeight: 1.6, maxWidth: '400px', margin: '14px auto 0' }}>
            {isReconnect
              ? 'Your timer resumed from where it stopped. Any time lost may have been compensated.'
              : 'By clicking "Start Exam", your browser will be locked to the exam window. Navigating away may automatically terminate your attempt.'}
          </p>
        </div>
      </div>
    </>
  );
}
