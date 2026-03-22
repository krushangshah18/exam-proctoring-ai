'use client';

import { useEffect, useState, useCallback } from 'react';
import { useRouter, useParams } from 'next/navigation';
import {
  ShieldAlert, Clock, Loader2, ArrowRight, Wifi, WifiOff,
  CheckCircle2, XCircle, AlertTriangle, Info, BookOpen, MessageSquare, History
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Textarea } from "@/components/ui/textarea";
import { Badge } from "@/components/ui/badge";
import { toast } from "sonner";
import api from '@/lib/axios';

function NetworkBadge() {
  const [online, setOnline] = useState(true);

  useEffect(() => {
    const check = async () => {
      if (!navigator.onLine) { setOnline(false); return; }
      try {
        await fetch('/favicon.ico', { method: 'HEAD', cache: 'no-store' });
        setOnline(true);
      } catch {
        setOnline(false);
      }
    };
    check();
    const id = setInterval(check, 10000);
    window.addEventListener('online', () => setOnline(true));
    window.addEventListener('offline', () => setOnline(false));
    return () => {
      clearInterval(id);
      window.removeEventListener('online', () => setOnline(true));
      window.removeEventListener('offline', () => setOnline(false));
    };
  }, []);

  return (
    <Badge
      variant="outline"
      className={`gap-1.5 text-xs font-semibold ${online ? 'bg-emerald-50 text-emerald-700 border-emerald-200' : 'bg-rose-50 text-rose-700 border-rose-200'}`}
    >
      {online ? <Wifi className="h-3 w-3" /> : <WifiOff className="h-3 w-3" />}
      {online ? 'Connected' : 'No Network'}
    </Badge>
  );
}

export default function ExamInfoPage() {
  const router = useRouter();
  const params = useParams();
  const examId = params.id as string;

  const [exam, setExam] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [appealReason, setAppealReason] = useState('');
  const [submittingAppeal, setSubmittingAppeal] = useState(false);

  const appealPending = exam?.active_resume_request?.status === 'PENDING';

  const fetchStatus = useCallback(async () => {
    try {
      const res = await api.get(`/exam/${examId}/status`);
      setExam(res.data);
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Failed to fetch exam status');
    } finally {
      setLoading(false);
    }
  }, [examId]);

  useEffect(() => {
    if (!examId) return;
    fetchStatus();
    // Fast poll when appeal is pending (5s), else 60s
    const id = setInterval(fetchStatus, appealPending ? 5000 : 60000);
    return () => clearInterval(id);
  }, [examId, fetchStatus, appealPending]);

  const handleAppealSubmit = async () => {
    if (!appealReason.trim()) return toast.error("Please enter a reason.");
    setSubmittingAppeal(true);
    try {
      await api.post(`/exam/${examId}/appeal`, { reason: appealReason });
      toast.success("Appeal submitted successfully.");
      await fetchStatus();
    } catch (err: any) {
      toast.error(err.response?.data?.detail || "Failed to submit appeal");
    } finally {
      setSubmittingAppeal(false);
    }
  };

  if (loading) {
    return (
      <div className="flex-1 flex items-center justify-center">
        <Loader2 className="h-8 w-8 animate-spin text-slate-400" />
      </div>
    );
  }

  if (error) {
    return (
      <div className="flex-1 flex items-center justify-center p-6">
        <div className="text-center max-w-md">
          <ShieldAlert className="h-12 w-12 text-rose-500 mx-auto mb-4" />
          <h2 className="text-2xl font-bold text-slate-900 mb-2">Access Denied</h2>
          <p className="text-slate-500 mb-6">{error}</p>
          <Button onClick={() => router.push('/student/dashboard')} variant="outline">
            Return to Dashboard
          </Button>
        </div>
      </div>
    );
  }

  const startTime = new Date(exam.start_window);
  const endTime = new Date(exam.end_window);
  const deadlineTime = exam.hard_join_deadline ? new Date(exam.hard_join_deadline) : null;
  const gatewayTime = new Date(startTime.getTime() - 15 * 60000);

  return (
    <div className="flex-1 flex overflow-hidden">
      <div className="flex-1 overflow-y-auto p-6 md:p-12">
        <div className="max-w-3xl mx-auto space-y-8 animate-in fade-in slide-in-from-bottom-4 duration-500">

          {/* Header */}
          <div className="flex items-start justify-between gap-4">
            <div>
              <h1 className="text-3xl font-bold text-slate-900 mb-1">{exam.title}</h1>
              <p className="text-slate-500">Review all information carefully before proceeding.</p>
            </div>
            <NetworkBadge />
          </div>

          {/* Exam Details */}
          <Card className="p-6 bg-white shadow-sm border-slate-200">
            <h3 className="font-semibold text-slate-900 mb-4 text-lg flex items-center gap-2">
              <Info className="h-5 w-5 text-indigo-500" /> Exam Details
            </h3>
            <div className="grid grid-cols-2 gap-x-8 gap-y-5">
              <div>
                <span className="text-xs font-semibold uppercase tracking-wider text-slate-400">Duration</span>
                <p className="font-semibold text-slate-900 mt-1">{exam.duration_minutes} minutes</p>
              </div>
              <div>
                <span className="text-xs font-semibold uppercase tracking-wider text-slate-400">Mode</span>
                <p className="font-semibold text-slate-900 mt-1">{exam.exam_mode}</p>
              </div>
              <div>
                <span className="text-xs font-semibold uppercase tracking-wider text-slate-400">Starts At</span>
                <p className="font-semibold text-slate-900 mt-1">{startTime.toLocaleString()}</p>
              </div>
              <div>
                <span className="text-xs font-semibold uppercase tracking-wider text-slate-400">Ends At</span>
                <p className="font-semibold text-slate-900 mt-1">{endTime.toLocaleString()}</p>
              </div>
              {deadlineTime && (
                <div>
                  <span className="text-xs font-semibold uppercase tracking-wider text-slate-400">Join Deadline</span>
                  <p className="font-semibold text-rose-600 mt-1">{deadlineTime.toLocaleString()}</p>
                </div>
              )}
              {exam.late_join_policy && (
                <div>
                  <span className="text-xs font-semibold uppercase tracking-wider text-slate-400">Late Policy</span>
                  <p className="font-semibold text-slate-900 mt-1">{exam.late_join_policy}</p>
                </div>
              )}
            </div>
          </Card>

          {/* Proctoring Rules */}
          {exam.config && Object.values(exam.config).some(Boolean) && (
            <div className="space-y-3">
              <h3 className="font-semibold text-slate-900 text-lg flex items-center gap-2">
                <ShieldAlert className="h-5 w-5 text-amber-500" /> Proctoring Active
              </h3>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                {exam.config.audio_analysis && (
                  <div className="flex items-center gap-3 bg-slate-50 p-3 rounded-lg border border-slate-200">
                    <CheckCircle2 className="h-4 w-4 text-emerald-500 shrink-0" />
                    <span className="text-sm font-medium text-slate-700">Microphone monitoring active</span>
                  </div>
                )}
                {exam.config.eye_gaze && (
                  <div className="flex items-center gap-3 bg-slate-50 p-3 rounded-lg border border-slate-200">
                    <CheckCircle2 className="h-4 w-4 text-emerald-500 shrink-0" />
                    <span className="text-sm font-medium text-slate-700">Webcam feed monitored</span>
                  </div>
                )}
                {exam.config.tab_switching && (
                  <div className="flex items-center gap-3 bg-amber-50 p-3 rounded-lg border border-amber-200">
                    <AlertTriangle className="h-4 w-4 text-amber-500 shrink-0" />
                    <span className="text-sm font-medium text-amber-800">Tab switching is monitored</span>
                  </div>
                )}
                {exam.config.multiple_person && (
                  <div className="flex items-center gap-3 bg-amber-50 p-3 rounded-lg border border-amber-200">
                    <AlertTriangle className="h-4 w-4 text-amber-500 shrink-0" />
                    <span className="text-sm font-medium text-amber-800">Multiple persons not allowed</span>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* DOS and DON'TS */}
          <Card className="p-6 bg-white border-slate-200">
            <h3 className="font-semibold text-slate-900 text-lg flex items-center gap-2 mb-4">
              <BookOpen className="h-5 w-5 text-indigo-500" /> Rules & Guidelines
            </h3>
            <div className="grid sm:grid-cols-2 gap-6">
              <div className="space-y-2">
                <p className="text-sm font-bold text-emerald-700 uppercase tracking-wider">DO</p>
                {[
                  "Ensure your face is clearly visible throughout the exam",
                  "Sit in a well-lit, quiet room with a plain background",
                  "Keep your ID document nearby if required",
                  "Stay within the exam window — do not minimize or switch tabs",
                  "Use a stable internet connection",
                  "Test your camera and microphone beforehand",
                ].map((item) => (
                  <div key={item} className="flex items-start gap-2">
                    <CheckCircle2 className="h-4 w-4 text-emerald-500 mt-0.5 shrink-0" />
                    <p className="text-sm text-slate-700">{item}</p>
                  </div>
                ))}
              </div>
              <div className="space-y-2">
                <p className="text-sm font-bold text-rose-700 uppercase tracking-wider">DON'T</p>
                {[
                  "Do not use a second monitor or device",
                  "Do not allow other people in the room",
                  "Do not cover your face with hands, headwear, or objects",
                  "Do not use headphones or earphones",
                  "Do not open other applications or browser tabs",
                  "Do not speak aloud or read questions out loud",
                ].map((item) => (
                  <div key={item} className="flex items-start gap-2">
                    <XCircle className="h-4 w-4 text-rose-500 mt-0.5 shrink-0" />
                    <p className="text-sm text-slate-700">{item}</p>
                  </div>
                ))}
              </div>
            </div>
          </Card>

          {/* Room Setup Reminder */}
          <Card className="p-5 bg-indigo-50 border-indigo-100">
            <h4 className="font-semibold text-indigo-900 mb-3 flex items-center gap-2">
              <Info className="h-4 w-4" /> Room & Environment Checklist
            </h4>
            <ul className="space-y-1.5 text-sm text-indigo-800">
              <li>• Position yourself facing the light source (window/lamp in front, not behind)</li>
              <li>• Ensure the background is a plain wall or uncluttered surface</li>
              <li>• Minimize background noise — close doors, silence phones</li>
              <li>• Do not have books, notes, or papers visible on your desk</li>
            </ul>
          </Card>

          {/* Appeals Info */}
          <Card className="p-5 bg-slate-50 border-slate-200">
            <h4 className="font-semibold text-slate-800 mb-2 flex items-center gap-2">
              <MessageSquare className="h-4 w-4 text-slate-600" /> About Appeals
            </h4>
            <p className="text-sm text-slate-600 leading-relaxed">
              If your session is unexpectedly terminated or you believe a violation was flagged in error,
              you may submit an appeal directly from the exam page. An admin will review it and can
              approve your re-entry. <strong>Do not close the exam window</strong> while your appeal is pending.
              If approved, extra time may be granted to compensate for the interruption.
            </p>
          </Card>

          {/* Late / Appeal / Gateway CTA */}
          {exam.session_status === 'ENDED' ? (
            <div className="flex items-center justify-between p-6 bg-emerald-50 border border-emerald-200 rounded-xl">
              <div className="flex items-center gap-3">
                <CheckCircle2 className="h-8 w-8 text-emerald-600 shrink-0" />
                <div>
                  <h4 className="font-semibold text-emerald-900">Exam Already Submitted</h4>
                  <p className="text-sm text-emerald-700 mt-0.5">
                    You have already completed and submitted this exam. Your attempt has been recorded.
                  </p>
                </div>
              </div>
              <Button
                variant="outline"
                onClick={() => router.push('/student/history')}
                className="shrink-0 gap-2 border-emerald-300 text-emerald-800 hover:bg-emerald-100"
              >
                <History className="h-4 w-4" /> View History
              </Button>
            </div>
          ) : exam.is_late && exam.active_resume_request?.status !== 'APPROVED' ? (
            <div className="p-6 bg-rose-50 border border-rose-200 rounded-xl space-y-4">
              <div className="flex items-center gap-3 mb-2">
                <ShieldAlert className="h-6 w-6 text-rose-600" />
                <h4 className="font-semibold text-rose-900 text-lg">Hard Deadline Passed</h4>
              </div>

              {exam.late_join_policy === 'DENY' && (
                <p className="text-rose-700">This exam strictly denies late joins. You may no longer enter.</p>
              )}

              {exam.late_join_policy === 'REVIEW' && !exam.active_resume_request && (
                <div className="space-y-4">
                  <p className="text-rose-700">You missed the join window. Submit an appeal to request late entry.</p>
                  <Textarea
                    placeholder="Explain clearly why you are late..."
                    value={appealReason}
                    onChange={(e) => setAppealReason(e.target.value)}
                    className="bg-white"
                  />
                  <Button
                    onClick={handleAppealSubmit}
                    disabled={submittingAppeal}
                    className="bg-rose-600 hover:bg-rose-700 text-white"
                  >
                    {submittingAppeal && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}
                    Submit Appeal
                  </Button>
                </div>
              )}

              {exam.late_join_policy === 'REVIEW' && exam.active_resume_request?.status === 'PENDING' && (
                <div className="p-4 bg-white/50 rounded-lg space-y-2">
                  <p className="text-rose-800 font-medium flex items-center gap-2">
                    <Loader2 className="h-4 w-4 animate-spin" />
                    Your appeal is under review — checking every 5 seconds
                  </p>
                  <p className="text-sm text-rose-600 italic">"{exam.active_resume_request.reason}"</p>
                  <p className="text-xs text-slate-500">Please keep this page open. Do not close the browser.</p>
                </div>
              )}

              {exam.late_join_policy === 'REVIEW' && exam.active_resume_request?.status === 'DENIED' && (
                <div className="p-4 bg-white/50 rounded-lg">
                  <p className="text-rose-800 font-bold">Your appeal was denied.</p>
                  {exam.active_resume_request.review_note && (
                    <p className="text-sm text-rose-700 mt-1">Note: {exam.active_resume_request.review_note}</p>
                  )}
                </div>
              )}
            </div>
          ) : !exam.allowed_to_enter ? (
            <Alert className="bg-amber-50 border-amber-200">
              <Clock className="h-5 w-5 text-amber-600" />
              <AlertTitle className="text-amber-800 font-semibold">Gateway Locked</AlertTitle>
              <AlertDescription className="text-amber-700 mt-2">
                The setup gateway opens 15 minutes before the exam starts.
                You can proceed from <strong>{gatewayTime.toLocaleTimeString()}</strong>.
                Use this time to ensure your room, lighting, and equipment are ready.
              </AlertDescription>
            </Alert>
          ) : (
            <div className="flex items-center justify-between p-6 bg-indigo-50 border border-indigo-100 rounded-xl">
              <div>
                <h4 className="font-semibold text-indigo-900">Setup Gateway Open</h4>
                <p className="text-sm text-indigo-700">Proceed with camera, microphone, and environment checks.</p>
              </div>
              <Button
                onClick={() => router.push(`/student/exam/${examId}/device`)}
                className="bg-indigo-600 hover:bg-indigo-700 shadow-md gap-2"
              >
                Start Setup <ArrowRight className="h-4 w-4" />
              </Button>
            </div>
          )}

        </div>
      </div>
    </div>
  );
}
