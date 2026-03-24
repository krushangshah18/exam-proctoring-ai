'use client';

import { useEffect, useRef, useState } from 'react';
import { useRouter, useParams, useSearchParams } from 'next/navigation';
import { Loader2, ArrowRight, Monitor, LogOut, CheckCircle2, ShieldAlert, AlertTriangle, Cpu } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { toast } from 'sonner';
import api from '@/lib/axios';
import { parseUTC } from '@/lib/fmt-date';

type CheckStatus = 'pending' | 'checking' | 'pass' | 'fail';

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

        // Block terminated sessions — send to the dedicated terminated page
        if (data.session_status === 'TERMINATED') {
          router.replace(`/student/exam/${examId}/terminated`);
          return;
        }

        setExam(data);
        setIsExamReady(data.allowed_to_start);

        // If exam hasn't started yet, start a countdown to the actual start_window
        if (!data.allowed_to_start && data.start_window) {
          const startMs = parseUTC(data.start_window).getTime();
          const msUntilStart = Math.max(0, startMs - Date.now());

          if (msUntilStart > 0) {
            countdownEndRef.current = startMs;
            setCountdown(Math.ceil(msUntilStart / 1000));

            countdownIntervalRef.current = setInterval(() => {
              const remaining = Math.max(0, Math.ceil((countdownEndRef.current - Date.now()) / 1000));
              setCountdown(remaining);
              if (remaining <= 0) {
                clearInterval(countdownIntervalRef.current!);
                countdownIntervalRef.current = null;
                setIsExamReady(true);
              }
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
    return () => {
      if (countdownIntervalRef.current) clearInterval(countdownIntervalRef.current);
    };
  }, [examId]);

  const runSystemChecks = async () => {
    // 1. Cross-device lock
    setSessionStatus('checking');
    setSessionError('');
    try {
      await api.post(`/exam/${examId}/lock-session`);
      setSessionStatus('pass');
    } catch (err: any) {
      setSessionStatus('fail');
      if (err.response?.status === 409) {
        setSessionError(
          err.response.data?.detail ||
            'This exam is already active on another device. Please use that device.'
        );
        toast.error('Another device is already active for this exam.');
      } else {
        setSessionError('Failed to lock concurrent sessions.');
        toast.error('Failed to lock concurrent sessions.');
      }
    }

    // 2. Fullscreen capability check
    setFsStatus('checking');
    setTimeout(() => {
      setFsStatus(document.fullscreenEnabled ? 'pass' : 'fail');
      if (!document.fullscreenEnabled) {
        toast.error('Your browser does not support fullscreen mode. Please use Chrome or Edge.');
      }
    }, 1200);

    // 3. Proctoring engine availability check
    setEngineStatus('checking');
    setEngineError('');
    try {
      const res = await api.get(`/exam/${examId}/engine-status`);
      if (res.data.available) {
        setEngineStatus('pass');
      } else {
        setEngineStatus('fail');
        setEngineError(res.data.message || 'Proctoring engine is unavailable.');
        toast.error(res.data.message || 'Proctoring engine is unavailable.');
      }
    } catch {
      setEngineStatus('fail');
      setEngineError('Could not reach the proctoring engine. Please contact your administrator.');
      toast.error('Proctoring engine check failed.');
    }
  };

  const handleStartExam = async () => {
    try {
      if (document.documentElement.requestFullscreen) {
        await document.documentElement.requestFullscreen();
      }
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

  const StatusIcon = ({ status }: { status: CheckStatus }) => {
    if (status === 'checking') return <Loader2 className="h-6 w-6 animate-spin text-indigo-500" />;
    if (status === 'pass') return <CheckCircle2 className="h-6 w-6 text-emerald-500" />;
    if (status === 'fail') return <ShieldAlert className="h-6 w-6 text-rose-500" />;
    return <div className="h-6 w-6 rounded-full border-2 border-slate-200" />;
  };

  if (loading) {
    return (
      <div className="flex-1 flex items-center justify-center p-24">
        <Loader2 className="h-8 w-8 animate-spin text-slate-400" />
      </div>
    );
  }

  return (
    <div className="flex-1 flex overflow-hidden bg-slate-50">
      <div className="flex-1 overflow-y-auto p-6 md:p-12">
        <div className="max-w-2xl mx-auto space-y-8 animate-in fade-in slide-in-from-bottom-4 duration-500">
          <div className="text-center mb-10">
            <h1 className="text-3xl font-bold text-slate-900 mb-2">
              {isReconnect ? 'Reconnect System Check' : 'Final System Lock'}
            </h1>
            <p className="text-lg text-slate-600">
              {isReconnect
                ? 'Verifying your device before reconnecting to the exam.'
                : 'Preparing the secure environment for your exam.'}
            </p>
          </div>

          <div className="space-y-4">
            {/* Cross-device lock */}
            <Card className="p-5 border-slate-200 shadow-sm overflow-hidden">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-4">
                  <div className="bg-indigo-100 p-2.5 rounded-lg">
                    <LogOut className="h-6 w-6 text-indigo-600" />
                  </div>
                  <div>
                    <h3 className="font-semibold text-slate-900 text-lg">Cross-Device Lock</h3>
                    <p className="text-sm text-slate-500">Revoking access on all other active devices</p>
                  </div>
                </div>
                <StatusIcon status={sessionStatus} />
              </div>
              {sessionStatus === 'fail' && sessionError && (
                <Alert className="mt-4 bg-rose-50 border-rose-200">
                  <AlertTriangle className="h-4 w-4 text-rose-600" />
                  <AlertDescription className="text-rose-800 text-sm">{sessionError}</AlertDescription>
                </Alert>
              )}
            </Card>

            {/* Fullscreen check */}
            <Card className="p-5 flex items-center justify-between border-slate-200 shadow-sm">
              <div className="flex items-center gap-4">
                <div className="bg-indigo-100 p-2.5 rounded-lg">
                  <Monitor className="h-6 w-6 text-indigo-600" />
                </div>
                <div>
                  <h3 className="font-semibold text-slate-900 text-lg">Fullscreen Enforcement</h3>
                  <p className="text-sm text-slate-500">Checking browser capability for Kiosk mode</p>
                </div>
              </div>
              <StatusIcon status={fsStatus} />
            </Card>

            {/* Proctoring engine check */}
            <Card className="p-5 border-slate-200 shadow-sm overflow-hidden">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-4">
                  <div className="bg-indigo-100 p-2.5 rounded-lg">
                    <Cpu className="h-6 w-6 text-indigo-600" />
                  </div>
                  <div>
                    <h3 className="font-semibold text-slate-900 text-lg">Proctoring Engine</h3>
                    <p className="text-sm text-slate-500">Verifying AI monitoring service availability</p>
                  </div>
                </div>
                <StatusIcon status={engineStatus} />
              </div>
              {engineStatus === 'fail' && engineError && (
                <Alert className="mt-4 bg-rose-50 border-rose-200">
                  <AlertTriangle className="h-4 w-4 text-rose-600" />
                  <AlertDescription className="text-rose-800 text-sm">{engineError}</AlertDescription>
                </Alert>
              )}
            </Card>
          </div>

          {anyFailed && (
            <Button
              onClick={runSystemChecks}
              variant="outline"
              className="w-full border-slate-300"
            >
              <Loader2 className="h-4 w-4 mr-2" /> Retry All Checks
            </Button>
          )}

          <div className="pt-4 transition-all">
            {anyChecking ? (
              <Button disabled className="w-full h-14 text-lg bg-slate-200 text-slate-500">
                <Loader2 className="h-5 w-5 mr-3 animate-spin" /> Finalizing Environment…
              </Button>
            ) : !allPassed ? (
              <Button disabled className="w-full h-14 text-lg bg-rose-100 text-rose-600">
                Fix the errors above to continue
              </Button>
            ) : !isExamReady ? (
              <Button disabled className="w-full h-14 text-lg bg-amber-500 text-white shadow-xl shadow-amber-500/20">
                Exam begins in {formatCountdown(countdown)}
              </Button>
            ) : (
              <Button
                onClick={handleStartExam}
                className="w-full h-14 text-lg bg-emerald-600 hover:bg-emerald-700 shadow-xl shadow-emerald-600/20 font-bold"
              >
                {isReconnect ? 'Reconnect to Exam' : 'Enter Fullscreen & Start Exam'}
                <ArrowRight className="h-5 w-5 ml-2" />
              </Button>
            )}
          </div>

          <p className="text-center text-xs text-slate-400 mt-6 max-w-sm mx-auto">
            {isReconnect
              ? 'Your timer resumed from where it stopped. Any time lost may have been compensated.'
              : 'By clicking "Start Exam", your browser will be locked to the exam window. Navigating away may automatically terminate your attempt.'}
          </p>
        </div>
      </div>
    </div>
  );
}
