'use client';

import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import {
  CheckCircle2, XCircle, Clock, AlertTriangle,
  ShieldAlert, Loader2, Ban, History
} from 'lucide-react';
import { toast } from 'sonner';
import api from '@/lib/axios';
import RoleGuard from '@/components/auth/role-guard';
import { StudentPageShell } from '@/components/student/StudentShell';
import { parseUTC, fmtDateTimeTZ, fmtTimeTZ } from '@/lib/fmt-date';

function formatDuration(seconds: number): string {
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const s = seconds % 60;
  if (h > 0) return `${h}h ${m}m`;
  if (m > 0) return `${m}m ${s}s`;
  return `${s}s`;
}

interface ExamHistoryItem {
  id: string;
  title: string;
  exam_mode: string;
  exam_status: string;
  start_window: string;
  end_window: string;
  duration_minutes: number;
  invite_used: boolean;
  session_status: string | null;
  session_start_time: string | null;
  session_end_time: string | null;
  duration_taken_seconds: number | null;
  risk_score: number;
  time_extension_seconds: number;
  terminated_reason: string | null;
}

function getSessionBadge(status: string | null): { label: string; className: string; icon: React.ReactNode } | null {
  if (!status) return null;
  const map: Record<string, { label: string; className: string; icon: React.ReactNode }> = {
    ENDED: { label: 'Submitted', className: 'st-badge st-badge-live', icon: <CheckCircle2 style={{ width: '10px', height: '10px' }} /> },
    TERMINATED: { label: 'Terminated', className: 'st-badge st-badge-terminated', icon: <Ban style={{ width: '10px', height: '10px' }} /> },
    ACTIVE: { label: 'In Progress', className: 'st-badge st-badge-active', icon: <Clock style={{ width: '10px', height: '10px' }} /> },
    DISCONNECTED: { label: 'Disconnected', className: 'st-badge st-badge-warning', icon: <AlertTriangle style={{ width: '10px', height: '10px' }} /> },
  };
  return map[status] ?? null;
}

function getExamStatusBadge(status: string): { label: string; className: string } {
  const map: Record<string, { label: string; className: string }> = {
    ENDED: { label: 'Ended', className: 'st-badge st-badge-ended' },
    CANCELLED: { label: 'Cancelled', className: 'st-badge st-badge-muted' },
    LIVE: { label: 'Live', className: 'st-badge st-badge-live' },
    SCHEDULED: { label: 'Scheduled', className: 'st-badge st-badge-scheduled' },
  };
  return map[status] ?? { label: status, className: 'st-badge st-badge-muted' };
}

function StatCell({ label, value, color }: { label: string; value: React.ReactNode; color?: string }) {
  return (
    <div>
      <p style={{ fontSize: '10.5px', fontWeight: 700, color: '#64748B', textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: '4px' }}>{label}</p>
      <p style={{ fontSize: '13.5px', fontWeight: 700, color: color || '#0F172A' }}>{value}</p>
    </div>
  );
}

export default function ExamHistoryPage() {
  const router = useRouter();
  const [exams, setExams] = useState<ExamHistoryItem[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchHistory = async () => {
      try {
        const res = await api.get('/exam/history');
        setExams(res.data);
      } catch {
        toast.error('Failed to load exam history');
      } finally {
        setLoading(false);
      }
    };
    fetchHistory();
  }, []);

  return (
    <RoleGuard allowedRoles={['STUDENT']}>
      <StudentPageShell backHref="/student/dashboard" backLabel="Back to Dashboard">

        {/* Page title */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '24px' }}>
          <div style={{
            width: '38px', height: '38px', borderRadius: '10px',
            background: 'rgba(34,87,122,0.08)', display: 'flex', alignItems: 'center', justifyContent: 'center',
          }}>
            <History style={{ width: '18px', height: '18px', color: '#22577A' }} />
          </div>
          <div>
            <h1 style={{ fontSize: '20px', fontWeight: 800, color: '#0F172A', letterSpacing: '-0.02em' }}>Exam History</h1>
            <p style={{ fontSize: '13px', color: '#64748B', marginTop: '1px' }}>
              {loading ? '' : `${exams.length} exam${exams.length !== 1 ? 's' : ''} found`}
            </p>
          </div>
        </div>

        {loading ? (
          <div style={{ display: 'flex', justifyContent: 'center', padding: '80px 0', color: '#64748B' }}>
            <Loader2 style={{ width: '28px', height: '28px', animation: 'spin 1s linear infinite' }} />
            <style>{`@keyframes spin{to{transform:rotate(360deg)}}`}</style>
          </div>
        ) : exams.length === 0 ? (
          <div style={{ textAlign: 'center', padding: '80px 0' }}>
            <History style={{ width: '52px', height: '52px', color: '#E2E8F0', margin: '0 auto 16px' }} />
            <h2 style={{ fontSize: '17px', fontWeight: 700, color: '#475569', marginBottom: '6px' }}>No exam history yet</h2>
            <p style={{ fontSize: '13.5px', color: '#64748B', marginBottom: '20px' }}>
              Completed and past exams will appear here after they have ended.
            </p>
            <button onClick={() => router.push('/student/dashboard')} className="st-btn-ghost">
              Back to Dashboard
            </button>
          </div>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }} className="st-fadein">
            {exams.map(exam => {
              const sessionBadge = getSessionBadge(exam.session_status);
              const examBadge = getExamStatusBadge(exam.exam_status);
              const submittedAt = exam.session_end_time ? parseUTC(exam.session_end_time) : null;

              return (
                <div key={exam.id} className="st-card" style={{ padding: '20px 22px' }}>
                  {/* Header row */}
                  <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: '16px', flexWrap: 'wrap', marginBottom: '14px' }}>
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap', marginBottom: '6px' }}>
                        <h3 style={{ fontSize: '15px', fontWeight: 700, color: '#0F172A', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                          {exam.title}
                        </h3>
                        <span style={{
                          fontSize: '10px', fontWeight: 700, textTransform: 'uppercase',
                          letterSpacing: '0.08em', color: '#64748B',
                          background: '#F8FAFC', padding: '2px 7px', borderRadius: '4px', border: '1px solid #E2E8F0',
                        }}>
                          {exam.exam_mode}
                        </span>
                      </div>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '6px', flexWrap: 'wrap' }}>
                        <span className={examBadge.className}>{examBadge.label}</span>
                        {sessionBadge && (
                          <span className={sessionBadge.className}>{sessionBadge.icon}{sessionBadge.label}</span>
                        )}
                        {!exam.session_status && (
                          <span className="st-badge st-badge-muted">{exam.exam_status === 'CANCELLED' ? 'Not Attempted' : 'No Session'}</span>
                        )}
                      </div>
                    </div>

                    <div style={{ textAlign: 'right', flexShrink: 0 }}>
                      <p style={{ fontSize: '10.5px', fontWeight: 700, color: '#64748B', textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: '3px' }}>Exam Date</p>
                      <p style={{ fontSize: '13.5px', fontWeight: 700, color: '#475569' }}>
                        {parseUTC(exam.start_window).toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' })}
                      </p>
                      <p style={{ fontSize: '12px', color: '#64748B' }}>{fmtTimeTZ(exam.start_window)}</p>
                    </div>
                  </div>

                  {/* Stats row */}
                  <div style={{
                    borderTop: '1px solid #F1F5F9', paddingTop: '14px',
                    display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '12px',
                  }}>
                    <StatCell
                      label="Allotted Time"
                      value={<>
                        {exam.duration_minutes} min
                        {exam.time_extension_seconds > 0 && (
                          <span style={{ color: '#16A34A', fontWeight: 600, marginLeft: '4px' }}>
                            (+{Math.round(exam.time_extension_seconds / 60)}m)
                          </span>
                        )}
                      </>}
                    />
                    <StatCell
                      label="Time Taken"
                      value={exam.duration_taken_seconds != null ? formatDuration(exam.duration_taken_seconds) : '—'}
                    />
                    <StatCell
                      label="Risk Score"
                      value={exam.risk_score}
                      color={exam.risk_score >= 70 ? '#DC2626' : exam.risk_score >= 40 ? '#D97706' : undefined}
                    />
                  </div>

                  {/* Submitted at */}
                  {submittedAt && (
                    <div style={{ marginTop: '10px', display: 'flex', alignItems: 'center', gap: '5px', fontSize: '12px', color: '#64748B' }}>
                      <Clock style={{ width: '12px', height: '12px' }} />
                      Submitted at {fmtDateTimeTZ(exam.session_end_time!)}
                    </div>
                  )}

                  {/* Termination reason */}
                  {exam.terminated_reason && (
                    <div style={{
                      marginTop: '12px', padding: '10px 12px', borderRadius: '8px',
                      background: 'rgba(239,68,68,0.04)', border: '1px solid rgba(239,68,68,0.15)',
                      display: 'flex', alignItems: 'flex-start', gap: '8px',
                    }}>
                      <ShieldAlert style={{ width: '14px', height: '14px', color: '#EF4444', flexShrink: 0, marginTop: '1px' }} />
                      <p style={{ fontSize: '12.5px', color: '#DC2626', lineHeight: 1.5 }}>{exam.terminated_reason}</p>
                    </div>
                  )}

                  {/* Cancelled notice */}
                  {exam.exam_status === 'CANCELLED' && (
                    <div style={{
                      marginTop: '12px', padding: '10px 12px', borderRadius: '8px',
                      background: '#F8FAFC', border: '1px solid #E2E8F0',
                    }}>
                      <p style={{ fontSize: '12.5px', color: '#64748B' }}>This exam was cancelled by the administrator.</p>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </StudentPageShell>
    </RoleGuard>
  );
}
