'use client';

import { useEffect, useState } from 'react';
import { useRouter, useParams } from 'next/navigation';
import { CheckCircle2, Home, Clock, ShieldAlert, Loader2, GraduationCap } from 'lucide-react';
import api from '@/lib/axios';

function formatDuration(seconds: number): string {
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const s = seconds % 60;
  if (h > 0) return `${h}h ${m}m ${s}s`;
  if (m > 0) return `${m}m ${s}s`;
  return `${s}s`;
}

function StatBox({ icon, value, label, color }: { icon: React.ReactNode; value: React.ReactNode; label: string; color?: string }) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '6px' }}>
      <div style={{ color: color || '#94A3B8' }}>{icon}</div>
      <p style={{ fontSize: '20px', fontWeight: 800, color: color || '#0F172A', letterSpacing: '-0.02em' }}>{value}</p>
      <p style={{ fontSize: '11.5px', fontWeight: 600, color: '#94A3B8', textTransform: 'uppercase', letterSpacing: '0.06em' }}>{label}</p>
    </div>
  );
}

export default function ExamCompletionPage() {
  const router = useRouter();
  const params = useParams();
  const examId = params.id as string;

  const [summary, setSummary] = useState<any>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    localStorage.removeItem(`exam_cam_${examId}`);
    localStorage.removeItem(`exam_mic_${examId}`);
    if (document.fullscreenElement) document.exitFullscreen().catch(() => {});

    const fetchSummary = async () => {
      try {
        const res = await api.get(`/exam/${examId}/session-summary`);
        setSummary(res.data);
      } catch {}
      finally { setLoading(false); }
    };
    fetchSummary();
  }, [examId]);

  return (
    <div style={{
      minHeight: '100vh', background: '#F8FAFC', fontFamily: "'Plus Jakarta Sans', sans-serif",
      display: 'flex', alignItems: 'center', justifyContent: 'center', padding: '24px',
    }}>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&display=swap');
        @keyframes spin{to{transform:rotate(360deg)}}
        @keyframes fadeup{from{opacity:0;transform:translateY(16px)}to{opacity:1;transform:translateY(0)}}
        @keyframes pop{0%{transform:scale(0.5);opacity:0}80%{transform:scale(1.1)}100%{transform:scale(1);opacity:1}}
      `}</style>

      <div style={{ maxWidth: '500px', width: '100%', animation: 'fadeup 0.5s ease both' }}>

        {/* Main card */}
        <div style={{
          background: '#fff', border: '1.5px solid #E2E8F0', borderRadius: '20px', overflow: 'hidden',
          boxShadow: '0 20px 60px rgba(0,0,0,0.08)',
        }}>
          {/* Green top bar */}
          <div style={{ height: '5px', background: 'linear-gradient(90deg, #22C55E 0%, #57CC99 100%)' }} />

          <div style={{ padding: '40px 36px', textAlign: 'center' }}>
            {/* Success icon */}
            <div style={{
              width: '88px', height: '88px', borderRadius: '50%', margin: '0 auto 20px',
              background: 'rgba(34,197,94,0.08)', border: '2px solid rgba(34,197,94,0.15)',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              animation: 'pop 0.5s ease 0.2s both',
            }}>
              <CheckCircle2 style={{ width: '42px', height: '42px', color: '#22C55E' }} />
            </div>

            <h1 style={{ fontSize: '24px', fontWeight: 800, color: '#0F172A', letterSpacing: '-0.025em', marginBottom: '10px' }}>
              Exam Submitted Successfully
            </h1>
            <p style={{ fontSize: '14px', color: '#64748B', lineHeight: 1.65, maxWidth: '340px', margin: '0 auto' }}>
              Your answers, session telemetry, and proctoring feed have been securely uploaded for review.
            </p>

            {/* Session stats */}
            {loading ? (
              <div style={{ display: 'flex', justifyContent: 'center', padding: '24px 0' }}>
                <Loader2 style={{ width: '22px', height: '22px', color: '#94A3B8', animation: 'spin 1s linear infinite' }} />
              </div>
            ) : summary ? (
              <div style={{
                marginTop: '24px', paddingTop: '20px', borderTop: '1.5px solid #F1F5F9',
                display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '8px',
              }}>
                {summary.duration_taken_seconds != null && (
                  <StatBox
                    icon={<Clock style={{ width: '18px', height: '18px' }} />}
                    value={formatDuration(summary.duration_taken_seconds)}
                    label="Time Taken"
                  />
                )}
                <StatBox
                  icon={<ShieldAlert style={{ width: '18px', height: '18px' }} />}
                  value={summary.risk_score ?? 0}
                  label="Risk Score"
                  color={(summary.risk_score ?? 0) >= 70 ? '#EF4444' : (summary.risk_score ?? 0) >= 40 ? '#F59E0B' : undefined}
                />

                {summary.time_extension_seconds > 0 && (
                  <div style={{
                    gridColumn: '1 / -1', marginTop: '6px',
                    padding: '10px 14px', borderRadius: '8px',
                    background: 'rgba(34,197,94,0.06)', border: '1px solid rgba(34,197,94,0.15)',
                  }}>
                    <p style={{ fontSize: '13px', color: '#16A34A', fontWeight: 600 }}>
                      +{Math.round(summary.time_extension_seconds / 60)} min extension was applied to your session
                    </p>
                  </div>
                )}
              </div>
            ) : null}

            <button
              onClick={() => router.push('/student/dashboard')}
              style={{
                marginTop: '28px', width: '100%', padding: '13px',
                background: '#22577A', color: '#fff', border: 'none', borderRadius: '10px',
                fontSize: '14.5px', fontWeight: 700, cursor: 'pointer',
                display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '8px',
                fontFamily: "'Plus Jakarta Sans', sans-serif",
                transition: 'background 150ms, transform 80ms',
              }}
              onMouseEnter={e => (e.currentTarget as HTMLElement).style.background = '#2C6A91'}
              onMouseLeave={e => (e.currentTarget as HTMLElement).style.background = '#22577A'}
            >
              <Home style={{ width: '16px', height: '16px' }} />
              Return to Dashboard
            </button>
          </div>
        </div>

        {/* Footer note */}
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '6px', marginTop: '16px' }}>
          <GraduationCap style={{ width: '14px', height: '14px', color: '#CBD5E1' }} />
          <p style={{ fontSize: '12px', color: '#94A3B8', textAlign: 'center' }}>
            Results and feedback will be communicated by your instructor.
          </p>
        </div>
      </div>
    </div>
  );
}
