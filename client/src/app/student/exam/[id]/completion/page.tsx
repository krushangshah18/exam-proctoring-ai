'use client';

import { useEffect, useState } from 'react';
import { useRouter, useParams } from 'next/navigation';
import { CheckCircle2, Home, Clock, AlertTriangle, ShieldAlert, Loader2 } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';
import api from '@/lib/axios';

function formatDuration(seconds: number): string {
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const s = seconds % 60;
  if (h > 0) return `${h}h ${m}m ${s}s`;
  if (m > 0) return `${m}m ${s}s`;
  return `${s}s`;
}

export default function ExamCompletionPage() {
  const router = useRouter();
  const params = useParams();
  const examId = params.id as string;

  const [summary, setSummary] = useState<any>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    // Cleanup storage
    localStorage.removeItem(`exam_cam_${examId}`);
    localStorage.removeItem(`exam_mic_${examId}`);

    // Exit fullscreen if stuck
    if (document.fullscreenElement) {
      document.exitFullscreen().catch(() => {});
    }

    // Fetch session summary
    const fetchSummary = async () => {
      try {
        const res = await api.get(`/exam/${examId}/session-summary`);
        setSummary(res.data);
      } catch {
        // Non-critical — show page without summary
      } finally {
        setLoading(false);
      }
    };

    fetchSummary();
  }, [examId]);

  return (
    <div className="flex-1 flex overflow-hidden bg-slate-50">
      <div className="flex-1 overflow-y-auto p-6 md:p-12 flex items-center justify-center">

        <div className="max-w-xl w-full mx-auto space-y-6 animate-in fade-in slide-in-from-bottom-8 duration-700">

          {/* Success card */}
          <Card className="p-12 text-center bg-white shadow-xl shadow-slate-200/50 border-emerald-100">
            <div className="mx-auto w-24 h-24 bg-emerald-100 rounded-full flex items-center justify-center mb-8 shadow-inner shadow-emerald-200">
              <CheckCircle2 className="h-12 w-12 text-emerald-600 animate-in zoom-in duration-500 delay-300" />
            </div>

            <h1 className="text-3xl font-extrabold text-slate-900 mb-3 tracking-tight">
              Exam Submitted Successfully
            </h1>

            <p className="text-lg text-slate-500 mb-6 max-w-sm mx-auto leading-relaxed">
              Your answers, session telemetry, and proctoring feed have been securely uploaded for review.
            </p>

            {/* Session Summary */}
            {loading ? (
              <div className="flex justify-center my-6">
                <Loader2 className="h-6 w-6 animate-spin text-slate-300" />
              </div>
            ) : summary ? (
              <div className="mt-6 pt-6 border-t border-slate-100 grid grid-cols-3 gap-4 text-center">
                {summary.duration_taken_seconds != null && (
                  <div>
                    <div className="flex justify-center mb-1">
                      <Clock className="h-5 w-5 text-slate-400" />
                    </div>
                    <p className="text-lg font-bold text-slate-900">
                      {formatDuration(summary.duration_taken_seconds)}
                    </p>
                    <p className="text-xs text-slate-400 mt-0.5">Time Taken</p>
                  </div>
                )}
                <div>
                  <div className="flex justify-center mb-1">
                    <AlertTriangle className="h-5 w-5 text-amber-400" />
                  </div>
                  <p className="text-lg font-bold text-slate-900">{summary.violation_count ?? 0}</p>
                  <p className="text-xs text-slate-400 mt-0.5">Violations Flagged</p>
                </div>
                <div>
                  <div className="flex justify-center mb-1">
                    <ShieldAlert className="h-5 w-5 text-indigo-400" />
                  </div>
                  <p className="text-lg font-bold text-slate-900">{summary.risk_score ?? 0}</p>
                  <p className="text-xs text-slate-400 mt-0.5">Risk Score</p>
                </div>

                {summary.time_extension_seconds > 0 && (
                  <div className="col-span-3 mt-2 p-3 bg-emerald-50 rounded-lg">
                    <p className="text-sm text-emerald-700 font-medium">
                      +{Math.round(summary.time_extension_seconds / 60)} min extension was applied to your session
                    </p>
                  </div>
                )}
              </div>
            ) : null}

            <Button
              onClick={() => router.push('/student/dashboard')}
              size="lg"
              className="mt-8 w-full sm:w-auto h-14 px-8 bg-slate-900 hover:bg-slate-800 text-base font-semibold transition-all hover:scale-[1.02]"
            >
              <Home className="mr-2 h-5 w-5" />
              Return to Dashboard
            </Button>
          </Card>

          <p className="text-center text-xs text-slate-400">
            Results and feedback will be communicated by your instructor. You may safely close this window.
          </p>
        </div>
      </div>
    </div>
  );
}
