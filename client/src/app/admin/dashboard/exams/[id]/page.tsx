"use client";

import { useEffect, useState } from 'react';
import { useRouter, useParams } from 'next/navigation';
import { toast } from 'sonner';
import api from '@/lib/axios';
import { fmtDate, fmtTimeTZ } from '@/lib/fmt-date';
import {
  ArrowLeft, Calendar, Clock, Users, ShieldAlert, CheckCircle2,
  XCircle, Loader2, Trash2, Edit, Activity, Search, FileText, Info,
} from 'lucide-react';
import { ConfirmDialog } from '@/components/common/ConfirmDialog';

interface ExamInvite {
  id: string;
  student_email: string;
  token: string;
  expires_at: string;
  used: boolean;
  session_status?: string | null;
}

interface ExamDetail {
  id: string;
  title: string;
  exam_mode: string;
  status: string;
  start_window: string;
  end_window: string;
  duration_minutes: number;
  created_at: string;
  hard_join_deadline: string;
  flag_threshold: number;
  late_join_policy: string;
  allow_late_extension: boolean;
  max_late_minutes: number;
  config: Record<string, boolean>;
  detection_config: Record<string, boolean> | null;
  invites: ExamInvite[];
}

const STATUS_STYLES: Record<string, { bg: string; color: string; border: string }> = {
  LIVE:      { bg: '#ECFDF5', color: '#15803D', border: '#BBF7D0' },
  SCHEDULED: { bg: '#EFF6FF', color: '#1D4ED8', border: '#BFDBFE' },
  ENDED:     { bg: '#F8FAFC', color: '#475569', border: '#E2E8F0' },
  CANCELLED: { bg: '#FFF1F2', color: '#BE123C', border: '#FECDD3' },
  DRAFT:     { bg: '#F8FAFC', color: '#64748B', border: '#E2E8F0' },
  COMPLETED: { bg: '#EFF6FF', color: '#1D4ED8', border: '#BFDBFE' },
};

function fmtDateTime(iso: string | null | undefined): string {
  if (!iso) return '—';
  const d = new Date(iso.endsWith('Z') || /[+-]\d{2}:\d{2}$/.test(iso) ? iso : iso + 'Z');
  return d.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' });
}

export default function AdminExamDetailsPage() {
  const router = useRouter();
  const params = useParams();
  const examId = params.id as string;

  const [exam, setExam] = useState<ExamDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [isDeleteDialogOpen, setIsDeleteDialogOpen] = useState(false);
  const [rosterSearch, setRosterSearch] = useState('');

  useEffect(() => {
    if (examId) fetchExamDetails();
  }, [examId]);

  const fetchExamDetails = async () => {
    try {
      setLoading(true);
      const res = await api.get(`/admin/exams/${examId}`);
      setExam(res.data);
    } catch {
      toast.error('Failed to load exam details');
    } finally {
      setLoading(false);
    }
  };

  const handleDelete = async () => {
    try {
      await api.delete(`/admin/exams/${examId}`);
      toast.success('Exam deleted and notifications dispatched.');
      router.push('/admin/dashboard/exams');
    } catch {
      toast.error('Failed to delete exam.');
    }
  };

  if (loading || !exam) {
    return (
      <div className="flex flex-col items-center justify-center p-24">
        <Loader2 className="h-7 w-7 animate-spin mb-3" style={{ color: '#CBD5E1' }} />
        <p className="text-sm" style={{ color: '#94A3B8' }}>Loading exam data…</p>
      </div>
    );
  }

  const s = STATUS_STYLES[exam.status] ?? STATUS_STYLES.DRAFT;
  const allModules = { ...(exam.config ?? {}), ...(exam.detection_config ?? {}) };
  const activeChecksCount = Object.values(allModules).filter(Boolean).length;
  const filteredInvites = exam.invites.filter(i =>
    i.student_email.toLowerCase().includes(rosterSearch.toLowerCase())
  );

  const sectionHeader = (icon: React.ReactNode, title: string, subtitle?: string) => (
    <div className="flex items-center gap-3 px-5 py-4" style={{ borderBottom: '1px solid #F1F5F9' }}>
      {icon}
      <div>
        <p className="text-sm font-semibold" style={{ color: '#0F172A' }}>{title}</p>
        {subtitle && <p className="text-xs mt-0.5" style={{ color: '#94A3B8' }}>{subtitle}</p>}
      </div>
    </div>
  );

  return (
    <div className="space-y-6 pb-12">
      {/* Header */}
      <div className="flex flex-col md:flex-row items-start gap-4">
        <div className="flex items-start gap-3 flex-1 min-w-0">
          <button
            onClick={() => router.back()}
            className="h-9 w-9 flex items-center justify-center rounded-lg border shrink-0 mt-0.5 transition-all duration-150"
            style={{ borderColor: '#E2E8F0', color: '#475569', background: '#fff' }}
            onMouseEnter={e => (e.currentTarget as HTMLElement).style.background = '#F8FAFC'}
            onMouseLeave={e => (e.currentTarget as HTMLElement).style.background = '#fff'}
          >
            <ArrowLeft className="h-4 w-4" />
          </button>
          <div className="min-w-0">
            <div className="flex items-center gap-3 flex-wrap">
              <h1 className="text-2xl font-bold" style={{ color: '#0F172A', letterSpacing: '-0.025em' }}>{exam.title}</h1>
              <span className="inline-flex items-center px-2 py-0.5 rounded-md text-xs font-semibold border"
                style={{ background: s.bg, color: s.color, borderColor: s.border }}>
                {exam.status}
              </span>
              <span className="inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-semibold border"
                style={{ background: '#F8FAFC', color: '#64748B', borderColor: '#E2E8F0' }}>
                {exam.exam_mode}
              </span>
            </div>
            <p className="text-sm mt-1 flex items-center gap-1.5" style={{ color: '#94A3B8' }}>
              ID: <code className="text-xs px-1.5 py-0.5 rounded font-mono"
                style={{ background: '#F1F5F9', color: '#475569' }}>{exam.id}</code>
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2 flex-wrap">
          <button
            onClick={() => router.push(`/admin/dashboard/exams/${examId}/reports`)}
            className="flex items-center gap-1.5 px-3 py-2 rounded-lg text-xs font-semibold border transition-all duration-150"
            style={{ borderColor: '#E2E8F0', color: '#475569', background: '#fff' }}
            onMouseEnter={e => (e.currentTarget as HTMLElement).style.background = '#F8FAFC'}
            onMouseLeave={e => (e.currentTarget as HTMLElement).style.background = '#fff'}
          >
            <FileText className="h-3.5 w-3.5" /> Reports
          </button>
          {(exam.status === 'LIVE' || exam.status === 'ENDED') && (
            <button
              onClick={() => router.push(`/admin/dashboard/exams/${examId}/monitor`)}
              className="flex items-center gap-1.5 px-3 py-2 rounded-lg text-xs font-semibold border transition-all duration-150"
              style={{ borderColor: '#BFDBFE', color: '#1D4ED8', background: '#EFF6FF' }}
              onMouseEnter={e => (e.currentTarget as HTMLElement).style.background = '#DBEAFE'}
              onMouseLeave={e => (e.currentTarget as HTMLElement).style.background = '#EFF6FF'}
            >
              <Activity className="h-3.5 w-3.5" /> Monitor
            </button>
          )}
          <button
            onClick={() => router.push(`/admin/dashboard/exams/${examId}/edit`)}
            className="flex items-center gap-1.5 px-3 py-2 rounded-lg text-xs font-semibold border transition-all duration-150"
            style={{ borderColor: '#E2E8F0', color: '#475569', background: '#fff' }}
            onMouseEnter={e => (e.currentTarget as HTMLElement).style.background = '#F8FAFC'}
            onMouseLeave={e => (e.currentTarget as HTMLElement).style.background = '#fff'}
          >
            <Edit className="h-3.5 w-3.5" /> Edit
          </button>
          <button
            onClick={() => setIsDeleteDialogOpen(true)}
            className="flex items-center gap-1.5 px-3 py-2 rounded-lg text-xs font-semibold transition-all duration-150"
            style={{ background: '#FFF1F2', color: '#BE123C', border: '1px solid #FECDD3' }}
            onMouseEnter={e => (e.currentTarget as HTMLElement).style.background = '#FFE4E6'}
            onMouseLeave={e => (e.currentTarget as HTMLElement).style.background = '#FFF1F2'}
          >
            <Trash2 className="h-3.5 w-3.5" /> Delete
          </button>
        </div>
      </div>

      {/* Top stat cards */}
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        {[
          { label: 'Start Window',     icon: Calendar, iconBg: '#ECFDF5', iconColor: '#15803D', value: fmtDate(exam.start_window),  sub: fmtTimeTZ(exam.start_window) },
          { label: 'End Window',       icon: Calendar, iconBg: '#FFF1F2', iconColor: '#BE123C', value: fmtDate(exam.end_window),    sub: fmtTimeTZ(exam.end_window) },
          { label: 'Duration',         icon: Clock,    iconBg: '#EFF6FF', iconColor: '#1D4ED8', value: `${exam.duration_minutes}`,  sub: 'minutes · strict timer', bold: true },
          { label: 'Students Invited', icon: Users,    iconBg: '#FFFBEB', iconColor: '#B45309', value: `${exam.invites.length}`,    sub: `${exam.invites.filter(i => i.used).length} accessed`, bold: true },
        ].map(({ label, icon: Icon, iconBg, iconColor, value, sub, bold }) => (
          <div key={label} className="bg-white rounded-xl border p-5"
            style={{ borderColor: '#E2E8F0', boxShadow: '0 1px 3px rgba(15,23,42,0.04)' }}>
            <div className="flex items-center justify-between mb-3">
              <p className="text-xs font-semibold uppercase tracking-wider" style={{ color: '#94A3B8' }}>{label}</p>
              <div className="p-1.5 rounded-lg" style={{ background: iconBg }}>
                <Icon className="h-4 w-4" style={{ color: iconColor }} />
              </div>
            </div>
            {bold ? (
              <p className="text-2xl font-bold" style={{ color: '#0F172A', letterSpacing: '-0.03em' }}>
                {value}
              </p>
            ) : (
              <p className="text-lg font-semibold" style={{ color: '#0F172A' }}>{value}</p>
            )}
            <p className="text-xs mt-1" style={{ color: '#94A3B8' }}>{sub}</p>
          </div>
        ))}
      </div>

      {/* Schedule & Policy */}
      <div className="bg-white rounded-xl border overflow-hidden"
        style={{ borderColor: '#E2E8F0', boxShadow: '0 1px 3px rgba(15,23,42,0.04)' }}>
        {sectionHeader(
          <div className="h-9 w-9 rounded-lg flex items-center justify-center" style={{ background: '#EFF6FF' }}>
            <Info className="h-4 w-4" style={{ color: '#22577A' }} />
          </div>,
          'Schedule & Policy',
          'Timing and access control settings'
        )}
        <div className="p-5">
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-x-8 gap-y-5">
            {[
              { label: 'Hard Join Deadline', value: fmtDateTime(exam.hard_join_deadline) },
              { label: 'Late Join Policy', value: exam.late_join_policy.toLowerCase().replace('_', ' ') },
            ].map(({ label, value }) => (
              <div key={label}>
                <p className="text-[10px] font-semibold uppercase tracking-wider mb-1" style={{ color: '#94A3B8' }}>{label}</p>
                <p className="text-sm font-medium capitalize" style={{ color: '#0F172A' }}>{value}</p>
              </div>
            ))}
            <div>
              <p className="text-[10px] font-semibold uppercase tracking-wider mb-1" style={{ color: '#94A3B8' }}>Late Extension</p>
              <div className="flex items-center gap-1.5 mt-0.5">
                {exam.allow_late_extension
                  ? <CheckCircle2 className="h-4 w-4" style={{ color: '#15803D' }} />
                  : <XCircle className="h-4 w-4" style={{ color: '#CBD5E1' }} />}
                <span className="text-sm font-medium" style={{ color: '#0F172A' }}>
                  {exam.allow_late_extension ? `Allowed (up to ${exam.max_late_minutes} min)` : 'Not allowed'}
                </span>
              </div>
            </div>
            <div>
              <p className="text-[10px] font-semibold uppercase tracking-wider mb-1" style={{ color: '#94A3B8' }}>Created</p>
              <p className="text-sm font-medium" style={{ color: '#0F172A' }}>{fmtDateTime(exam.created_at)}</p>
            </div>
          </div>
        </div>
      </div>

      <div className="grid gap-6 md:grid-cols-2">
        {/* Proctoring Config */}
        <div className="bg-white rounded-xl border overflow-hidden"
          style={{ borderColor: '#E2E8F0', boxShadow: '0 1px 3px rgba(15,23,42,0.04)' }}>
          {sectionHeader(
            <div className="h-9 w-9 rounded-lg flex items-center justify-center" style={{ background: '#F5F3FF' }}>
              <ShieldAlert className="h-4 w-4" style={{ color: '#7C3AED' }} />
            </div>,
            'Proctoring Configuration',
            'AI behaviour and threshold rules'
          )}
          <div className="p-5 space-y-5">
            <div className="grid grid-cols-2 gap-4">
              <div className="rounded-lg border p-3" style={{ background: '#F8FAFC', borderColor: '#E2E8F0' }}>
                <p className="text-[10px] font-semibold uppercase tracking-wider mb-1" style={{ color: '#94A3B8' }}>Flag Threshold</p>
                <p className="text-lg font-bold" style={{ color: '#0F172A' }}>{exam.flag_threshold} pts</p>
              </div>
              <div className="rounded-lg border p-3" style={{ background: '#F8FAFC', borderColor: '#E2E8F0' }}>
                <p className="text-[10px] font-semibold uppercase tracking-wider mb-1" style={{ color: '#94A3B8' }}>Active Modules</p>
                <p className="text-lg font-bold" style={{ color: '#22577A' }}>
                  {activeChecksCount} / {Object.keys(allModules).length}
                </p>
              </div>
            </div>

            {(() => {
              const allConfig = { ...(exam.config ?? {}), ...(exam.detection_config ?? {}) };
              const KEY_MAP: Record<string, { group: string; label: string }> = {
                // Objects
                DETECT_PHONE:          { group: 'Objects',  label: 'phone' },
                DETECT_BOOK:           { group: 'Objects',  label: 'book' },
                DETECT_HEADPHONE:      { group: 'Objects',  label: 'headphone' },
                DETECT_EARBUD:         { group: 'Objects',  label: 'earbud' },
                phone_detected:        { group: 'Objects',  label: 'phone' },
                book_detected:         { group: 'Objects',  label: 'book' },
                earphones:             { group: 'Objects',  label: 'earbud' },
                // Looking / Gaze
                DETECT_LOOKING_AWAY:   { group: 'Looking',  label: 'away' },
                DETECT_LOOKING_DOWN:   { group: 'Looking',  label: 'down' },
                DETECT_LOOKING_UP:     { group: 'Looking',  label: 'up' },
                DETECT_LOOKING_SIDE:   { group: 'Looking',  label: 'away' },
                looking_away:          { group: 'Looking',  label: 'away' },
                eye_gaze:              { group: 'Looking',  label: 'eye gaze' },
                // Face
                DETECT_FACE_HIDDEN:    { group: 'Face',     label: 'hidden' },
                DETECT_PARTIAL_FACE:   { group: 'Face',     label: 'partial' },
                DETECT_FAKE_PRESENCE:  { group: 'Face',     label: 'fake presence' },
                static_photo:          { group: 'Face',     label: 'fake presence' },
                // Audio
                DETECT_SPEAKER_AUDIO:  { group: 'Audio',    label: 'speaker audio' },
                audio_analysis:        { group: 'Audio',    label: 'audio analysis' },
                // People
                DETECT_MULTIPLE_PEOPLE: { group: 'People', label: 'multiple people' },
                multiple_person:        { group: 'People', label: 'multiple people' },
                // Browser
                tab_switching:         { group: 'Browser',  label: 'tab switching' },
              };
              // Build a set of "group|label" pairs explicitly disabled in detection_config.
              // detection_config false values override legacy config true values that
              // share the same display label (e.g. DETECT_EARBUD:false beats earphones:true).
              const disabledKeys = new Set<string>();
              for (const [key, enabled] of Object.entries(exam.detection_config ?? {})) {
                if (!enabled) {
                  const mapped = KEY_MAP[key];
                  if (mapped) disabledKeys.add(`${mapped.group}|${mapped.label}`);
                }
              }
              const groups: Record<string, Set<string>> = {};
              for (const [key, enabled] of Object.entries(allConfig)) {
                if (!enabled) continue;
                const mapped = KEY_MAP[key];
                if (!mapped) continue;
                if (disabledKeys.has(`${mapped.group}|${mapped.label}`)) continue;
                if (!groups[mapped.group]) groups[mapped.group] = new Set();
                groups[mapped.group].add(mapped.label);
              }
              const GROUP_ORDER = ['Objects', 'Looking', 'Face', 'Audio', 'People', 'Browser'];
              const active = GROUP_ORDER.filter(g => groups[g]?.size > 0);
              if (!active.length) return null;
              return (
                <div className="space-y-2.5">
                  <p className="text-[10px] font-semibold uppercase tracking-wider" style={{ color: '#94A3B8' }}>Detection Rules</p>
                  {active.map(group => (
                    <div key={group} className="flex items-center gap-2 text-xs">
                      <span className="font-bold shrink-0" style={{ color: '#475569', minWidth: '64px' }}>{group}</span>
                      <span style={{ color: '#64748B' }}>—</span>
                      <div className="flex flex-wrap gap-1">
                        {[...groups[group]].map(label => (
                          <span key={label}
                            className="px-2 py-0.5 rounded-md border text-xs font-medium"
                            style={group === 'Browser'
                              ? { background: '#FFFBEB', color: '#B45309', borderColor: '#FDE68A' }
                              : { background: '#EFF6FF', color: '#1D4ED8', borderColor: '#BFDBFE' }
                            }>
                            {label}
                          </span>
                        ))}
                      </div>
                    </div>
                  ))}
                </div>
              );
            })()}
          </div>
        </div>

        {/* Student Roster */}
        <div className="bg-white rounded-xl border overflow-hidden flex flex-col"
          style={{ borderColor: '#E2E8F0', boxShadow: '0 1px 3px rgba(15,23,42,0.04)' }}>
          {sectionHeader(
            <div className="h-9 w-9 rounded-lg flex items-center justify-center" style={{ background: '#FFFBEB' }}>
              <Users className="h-4 w-4" style={{ color: '#B45309' }} />
            </div>,
            'Student Roster',
            `${exam.invites.filter(i => i.used).length} of ${exam.invites.length} accessed`
          )}
          {/* Search */}
          <div className="px-4 pt-3 pb-2" style={{ borderBottom: '1px solid #F1F5F9' }}>
            <div className="relative">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-3.5 w-3.5" style={{ color: '#CBD5E1' }} />
              <input
                type="text"
                placeholder="Search by email..."
                value={rosterSearch}
                onChange={e => setRosterSearch(e.target.value)}
                className="w-full py-1.5 text-sm rounded-lg border outline-none transition-all"
                style={{ borderColor: '#E2E8F0', color: '#0F172A', paddingLeft: '2rem', paddingRight: '0.75rem' }}
                onFocus={e => { (e.target as HTMLElement).style.borderColor = '#38A3A5'; (e.target as HTMLElement).style.boxShadow = '0 0 0 3px rgba(56,163,165,0.12)'; }}
                onBlur={e => { (e.target as HTMLElement).style.borderColor = '#E2E8F0'; (e.target as HTMLElement).style.boxShadow = 'none'; }}
              />
            </div>
          </div>
          <div className="overflow-auto flex-1 max-h-72">
            <table className="w-full text-sm text-left">
              <thead className="sticky top-0" style={{ background: '#F8FAFC', borderBottom: '1px solid #E2E8F0' }}>
                <tr>
                  <th className="px-4 py-2.5 text-xs font-semibold" style={{ color: '#94A3B8' }}>Email</th>
                  <th className="px-4 py-2.5 text-xs font-semibold text-center w-24" style={{ color: '#94A3B8' }}>Status</th>
                </tr>
              </thead>
              <tbody style={{ background: '#fff' }}>
                {filteredInvites.length === 0 ? (
                  <tr>
                    <td colSpan={2} className="px-4 py-8 text-center text-sm" style={{ color: '#94A3B8' }}>
                      {rosterSearch ? 'No matching students.' : 'No students invited yet.'}
                    </td>
                  </tr>
                ) : (
                  filteredInvites.map((invite) => (
                    <tr key={invite.id} style={{ borderBottom: '1px solid #F8FAFC' }}
                      onMouseEnter={e => (e.currentTarget as HTMLElement).style.background = '#F8FAFC'}
                      onMouseLeave={e => (e.currentTarget as HTMLElement).style.background = '#fff'}
                    >
                      <td className="px-4 py-2.5 text-sm font-medium" style={{ color: '#0F172A' }}>{invite.student_email}</td>
                      <td className="px-4 py-2.5 text-center">
                        {(() => {
                          const ss = invite.session_status;
                          if (ss === 'TERMINATED')
                            return <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-xs font-semibold border" style={{ background: '#FFF1F2', color: '#BE123C', borderColor: '#FECDD3' }}><ShieldAlert className="h-3 w-3" /> Terminated</span>;
                          if (ss === 'ENDED' || invite.used)
                            return <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-xs font-semibold border" style={{ background: '#ECFDF5', color: '#15803D', borderColor: '#BBF7D0' }}><CheckCircle2 className="h-3 w-3" /> Completed</span>;
                          if (ss === 'ACTIVE')
                            return <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-xs font-semibold border" style={{ background: '#EFF6FF', color: '#1D4ED8', borderColor: '#BFDBFE' }}><span className="h-1.5 w-1.5 rounded-full bg-blue-500 animate-pulse" /> In Progress</span>;
                          return <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-xs font-semibold border" style={{ background: '#F8FAFC', color: '#475569', borderColor: '#E2E8F0' }}><Clock className="h-3 w-3" /> Pending</span>;
                        })()}
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
          {rosterSearch && (
            <div className="px-4 py-2 text-xs" style={{ borderTop: '1px solid #F1F5F9', color: '#94A3B8' }}>
              {filteredInvites.length} of {exam.invites.length} shown
            </div>
          )}
        </div>
      </div>

      <ConfirmDialog
        isOpen={isDeleteDialogOpen}
        onOpenChange={setIsDeleteDialogOpen}
        title="Delete Exam"
        description="Are you sure you want to completely delete this exam? This will securely delete all corresponding data, erase all student invites, and automatically dispatch a cancellation email to everyone previously invited. This action cannot be undone."
        onConfirm={handleDelete}
        confirmLabel="Yes, Delete Exam"
        cancelLabel="Cancel"
        variant="destructive"
      />
    </div>
  );
}
