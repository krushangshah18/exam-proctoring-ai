'use client';

import { useState, useEffect, useRef } from 'react';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import * as z from 'zod';
import { useRouter } from 'next/navigation';
import { toast } from 'sonner';

import api from '@/lib/axios';
import { Form, FormControl, FormDescription, FormField, FormItem, FormLabel, FormMessage } from '@/components/ui/form';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Switch } from '@/components/ui/switch';
import { Textarea } from '@/components/ui/textarea';
import { Loader2, Users, ShieldCheck, Clock, FileText, ChevronLeft, AlertCircle, Upload, X } from 'lucide-react';
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";

// ─── Timezone helpers ────────────────────────────────────────────────────────
function toLocalInputString(date: Date): string {
  const pad = (n: number) => String(n).padStart(2, '0');
  return (
    `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}` +
    `T${pad(date.getHours())}:${pad(date.getMinutes())}`
  );
}

function formatDatePreview(localString: string): string {
  if (!localString) return '';
  const d = new Date(localString);
  if (isNaN(d.getTime())) return '';
  return d.toLocaleString('en-IN', {
    weekday: 'short', day: 'numeric', month: 'short',
    year: 'numeric', hour: '2-digit', minute: '2-digit',
    hour12: true, timeZone: 'Asia/Kolkata',
  }) + ' IST';
}
// ─────────────────────────────────────────────────────────────────────────────

const examSchema = z.object({
  title: z.string().min(3, 'Title must be at least 3 characters').max(150),
  exam_mode: z.enum(['FLEXIBLE', 'FIXED']),
  start_window: z.string().min(1, 'Start window is required'),
  end_window: z.string().min(1, 'End window is required'),
  duration_minutes: z.coerce.number().min(1, 'Duration must be at least 1 minute'),
  hard_join_deadline: z.string().min(1, 'Hard join deadline is required'),
  late_join_policy: z.enum(['ALLOW', 'REVIEW', 'DENY']),
  allow_late_extension: z.boolean().default(false),
  max_late_minutes: z.coerce.number().min(0).default(0),
  flag_threshold: z.coerce.number().min(0).default(100),
  preset: z.enum(['STRICT', 'MEDIUM', 'RELAXED', 'CUSTOM']).default('MEDIUM'),
  config: z.object({
    eye_gaze: z.boolean(), looking_away: z.boolean(), static_photo: z.boolean(),
    phone_detected: z.boolean(), book_detected: z.boolean(), earphones: z.boolean(),
    audio_analysis: z.boolean(), multiple_person: z.boolean(), tab_switching: z.boolean(),
  }),
  detection_config: z.object({
    DETECT_LOOKING_AWAY: z.boolean(), DETECT_LOOKING_DOWN: z.boolean(), DETECT_LOOKING_UP: z.boolean(),
    DETECT_LOOKING_SIDE: z.boolean(), DETECT_FACE_HIDDEN: z.boolean(), DETECT_PARTIAL_FACE: z.boolean(),
    DETECT_FAKE_PRESENCE: z.boolean(), DETECT_SPEAKER_AUDIO: z.boolean(), DETECT_PHONE: z.boolean(),
    DETECT_BOOK: z.boolean(), DETECT_HEADPHONE: z.boolean(), DETECT_EARBUD: z.boolean(),
    DETECT_MULTIPLE_PEOPLE: z.boolean(),
  }),
  invites_text: z.string().optional(),
}).refine(data => {
  const startD = new Date(data.start_window);
  return startD >= new Date(Date.now() + 9 * 60000);
}, { message: 'Start window must be at least 10 minutes in the future', path: ['start_window'] })
.refine(data => {
  const startD = new Date(data.start_window);
  const endD = new Date(data.end_window);
  return endD >= new Date(startD.getTime() + data.duration_minutes * 60000);
}, { message: 'End window must allow for the full exam duration', path: ['end_window'] })
.refine(data => {
  const d = new Date(data.hard_join_deadline);
  return d >= new Date(data.start_window) && d <= new Date(data.end_window);
}, { message: 'Join deadline must be between the start and end windows', path: ['hard_join_deadline'] });

const PRESETS = {
  STRICT: {
    config: { eye_gaze: true, looking_away: true, static_photo: true, phone_detected: true, book_detected: true, earphones: true, audio_analysis: true, multiple_person: true, tab_switching: true },
    detection: { DETECT_LOOKING_AWAY: true, DETECT_LOOKING_DOWN: true, DETECT_LOOKING_UP: true, DETECT_LOOKING_SIDE: true, DETECT_FACE_HIDDEN: true, DETECT_PARTIAL_FACE: true, DETECT_FAKE_PRESENCE: true, DETECT_SPEAKER_AUDIO: true, DETECT_PHONE: true, DETECT_BOOK: true, DETECT_HEADPHONE: true, DETECT_EARBUD: true, DETECT_MULTIPLE_PEOPLE: true },
  },
  MEDIUM: {
    config: { eye_gaze: false, looking_away: true, static_photo: true, phone_detected: true, book_detected: false, earphones: true, audio_analysis: true, multiple_person: true, tab_switching: true },
    detection: { DETECT_LOOKING_AWAY: true, DETECT_LOOKING_DOWN: false, DETECT_LOOKING_UP: false, DETECT_LOOKING_SIDE: true, DETECT_FACE_HIDDEN: true, DETECT_PARTIAL_FACE: true, DETECT_FAKE_PRESENCE: true, DETECT_SPEAKER_AUDIO: true, DETECT_PHONE: true, DETECT_BOOK: false, DETECT_HEADPHONE: true, DETECT_EARBUD: true, DETECT_MULTIPLE_PEOPLE: true },
  },
  RELAXED: {
    config: { eye_gaze: false, looking_away: false, static_photo: true, phone_detected: true, book_detected: false, earphones: false, audio_analysis: false, multiple_person: true, tab_switching: false },
    detection: { DETECT_LOOKING_AWAY: false, DETECT_LOOKING_DOWN: false, DETECT_LOOKING_UP: false, DETECT_LOOKING_SIDE: false, DETECT_FACE_HIDDEN: true, DETECT_PARTIAL_FACE: true, DETECT_FAKE_PRESENCE: true, DETECT_SPEAKER_AUDIO: false, DETECT_PHONE: true, DETECT_BOOK: false, DETECT_HEADPHONE: false, DETECT_EARBUD: false, DETECT_MULTIPLE_PEOPLE: true },
  },
};

const inputBase = 'w-full px-3 py-2.5 text-sm rounded-lg border outline-none transition-all';
const inputStyle = { borderColor: '#E2E8F0', color: '#0F172A' };
const inputFocus = (e: React.FocusEvent<HTMLInputElement | HTMLTextAreaElement>) => {
  (e.target as HTMLElement).style.borderColor = '#38A3A5';
  (e.target as HTMLElement).style.boxShadow = '0 0 0 3px rgba(56,163,165,0.12)';
};
const inputBlur = (e: React.FocusEvent<HTMLInputElement | HTMLTextAreaElement>) => {
  (e.target as HTMLElement).style.borderColor = '#E2E8F0';
  (e.target as HTMLElement).style.boxShadow = 'none';
};

function FormSection({ icon, title, children }: { icon: React.ReactNode; title: string; children: React.ReactNode }) {
  return (
    <div className="bg-white rounded-xl border overflow-hidden"
      style={{ borderColor: '#E2E8F0', boxShadow: '0 1px 3px rgba(15,23,42,0.04)' }}>
      <div className="flex items-center gap-3 px-5 py-4" style={{ borderBottom: '1px solid #F1F5F9' }}>
        {icon}
        <p className="text-sm font-semibold" style={{ color: '#0F172A' }}>{title}</p>
      </div>
      <div className="p-5">{children}</div>
    </div>
  );
}

export default function CreateExamPage() {
  const router = useRouter();
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [emails, setEmails] = useState<string[]>([]);
  const csvInputRef = useRef<HTMLInputElement>(null);

  const form = useForm({
    resolver: zodResolver(examSchema),
    defaultValues: {
      title: '', exam_mode: 'FLEXIBLE',
      start_window: '', end_window: '', duration_minutes: 60,
      hard_join_deadline: '', late_join_policy: 'REVIEW',
      allow_late_extension: false, max_late_minutes: 0,
      flag_threshold: 100, preset: 'MEDIUM',
      config: PRESETS.MEDIUM.config,
      detection_config: PRESETS.MEDIUM.detection,
      invites_text: '',
    } as any,
  });

  const preset            = form.watch('preset');
  const examMode          = form.watch('exam_mode');
  const startWindow       = form.watch('start_window');
  const endWindow         = form.watch('end_window');
  const durationMinutes   = form.watch('duration_minutes');
  const allowLateExtension = form.watch('allow_late_extension');
  const hardJoinDeadline  = form.watch('hard_join_deadline');

  const minStartString = toLocalInputString(new Date(Date.now() + 10 * 60000));

  let minEndString = '';
  if (startWindow && durationMinutes) {
    const s = new Date(startWindow);
    if (!isNaN(s.getTime()))
      minEndString = toLocalInputString(new Date(s.getTime() + Number(durationMinutes) * 60000));
  }

  let maxHardJoin = '';
  if (examMode === 'FIXED' && startWindow) {
    const s = new Date(startWindow);
    if (!isNaN(s.getTime())) maxHardJoin = toLocalInputString(new Date(s.getTime() + 5 * 60000));
  } else if (examMode === 'FLEXIBLE' && endWindow) {
    maxHardJoin = endWindow;
  }

  useEffect(() => {
    if (examMode === 'FIXED') {
      form.setValue('late_join_policy', 'DENY');
      form.setValue('allow_late_extension', false);
      if (startWindow && durationMinutes) {
        const s = new Date(startWindow);
        if (!isNaN(s.getTime())) {
          form.setValue('end_window', toLocalInputString(new Date(s.getTime() + Number(durationMinutes) * 60000)));
          form.setValue('hard_join_deadline', toLocalInputString(new Date(s.getTime() + 5 * 60000)));
        }
      }
    }
  }, [examMode, startWindow, durationMinutes, form]);

  const showDurationWarning = () => {
    if (!hardJoinDeadline || !durationMinutes || !endWindow) return false;
    const hd  = new Date(hardJoinDeadline).getTime();
    const end = new Date(endWindow).getTime();
    return !isNaN(hd) && !isNaN(end) && hd + Number(durationMinutes) * 60000 > end;
  };

  const handlePresetChange = (val: string) => {
    form.setValue('preset', val as any);
    if (val !== 'CUSTOM') {
      const p = PRESETS[val as keyof typeof PRESETS];
      form.setValue('config', p.config);
      form.setValue('detection_config', p.detection);
    }
  };

  const EMAIL_REGEX = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;

  const addEmails = (raw: string) => {
    const found = raw.match(EMAIL_REGEX) || [];
    if (found.length === 0) { toast.error('No valid emails found'); return; }
    const unique = Array.from(new Set([...emails, ...found.map(e => e.toLowerCase())]));
    setEmails(unique);
    toast.success(`Added ${unique.length - emails.length} new email(s)`);
  };

  const handleExtract = () => {
    const text = form.getValues('invites_text') || '';
    addEmails(text);
    form.setValue('invites_text', '');
  };

  const handleCSVUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = ev => { addEmails(ev.target?.result as string); };
    reader.readAsText(file);
    e.target.value = '';
  };

  const removeEmail = (email: string) => setEmails(emails.filter(e => e !== email));

  async function onSubmit(values: any) {
    if (emails.length === 0) {
      toast.error('Please assign at least one student before creating the exam.');
      return;
    }
    setIsSubmitting(true);
    try {
      await api.post('/admin/exams', {
        title: values.title, exam_mode: values.exam_mode,
        start_window: new Date(values.start_window).toISOString(),
        end_window: new Date(values.end_window).toISOString(),
        duration_minutes: values.duration_minutes,
        hard_join_deadline: new Date(values.hard_join_deadline).toISOString(),
        flag_threshold: values.flag_threshold, late_join_policy: values.late_join_policy,
        allow_late_extension: values.allow_late_extension, max_late_minutes: values.max_late_minutes,
        config: values.config, detection_config: values.detection_config, invites: emails,
      });
      toast.success('Exam created! Invites are being dispatched.');
      router.push('/admin/dashboard/exams');
    } catch (error: any) {
      toast.error(error.response?.data?.detail || 'Failed to create exam');
    } finally {
      setIsSubmitting(false);
    }
  }

  return (
    <div className="max-w-5xl mx-auto space-y-6 pb-20">
      {/* Page header */}
      <div className="flex items-center gap-3 pb-4" style={{ borderBottom: '1px solid #E2E8F0' }}>
        <button
          type="button"
          onClick={() => router.back()}
          className="h-9 w-9 flex items-center justify-center rounded-lg border transition-all duration-150"
          style={{ borderColor: '#E2E8F0', color: '#475569', background: '#fff' }}
          onMouseEnter={e => (e.currentTarget as HTMLElement).style.background = '#F8FAFC'}
          onMouseLeave={e => (e.currentTarget as HTMLElement).style.background = '#fff'}
        >
          <ChevronLeft className="h-5 w-5" />
        </button>
        <div>
          <h1 className="text-2xl font-bold" style={{ color: '#0F172A', letterSpacing: '-0.025em' }}>Create New Exam</h1>
          <p className="text-sm mt-0.5" style={{ color: '#94A3B8' }}>Configure timing, AI proctoring rules, and student invitations.</p>
        </div>
      </div>

      <Form {...form}>
        <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-6">

          {/* ── Basic Details ── */}
          <FormSection
            icon={<div className="h-8 w-8 rounded-lg flex items-center justify-center" style={{ background: '#EFF6FF' }}><FileText className="h-4 w-4" style={{ color: '#22577A' }} /></div>}
            title="Basic Details"
          >
            <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
              <FormField control={form.control} name="title" render={({ field }) => (
                <FormItem className="col-span-1 md:col-span-2">
                  <FormLabel className="text-xs font-semibold uppercase tracking-wider" style={{ color: '#94A3B8' }}>Exam Title</FormLabel>
                  <FormControl>
                    <input type="text" placeholder="e.g. CS401 Midterm Examination"
                      className={inputBase} style={inputStyle}
                      onFocus={inputFocus} onBlur={inputBlur} {...field} />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )} />
              <FormField control={form.control} name="exam_mode" render={({ field }) => (
                <FormItem>
                  <FormLabel className="text-xs font-semibold uppercase tracking-wider" style={{ color: '#94A3B8' }}>Exam Mode</FormLabel>
                  <Select onValueChange={field.onChange} defaultValue={field.value}>
                    <FormControl><SelectTrigger><SelectValue /></SelectTrigger></FormControl>
                    <SelectContent>
                      <SelectItem value="FLEXIBLE">Flexible — anytime within window</SelectItem>
                      <SelectItem value="FIXED">Fixed — strict start &amp; end times</SelectItem>
                    </SelectContent>
                  </Select>
                  <FormDescription>Determines if students have a flexible start buffer.</FormDescription>
                  <FormMessage />
                </FormItem>
              )} />
              <FormField control={form.control} name="duration_minutes" render={({ field }) => (
                <FormItem>
                  <FormLabel className="text-xs font-semibold uppercase tracking-wider" style={{ color: '#94A3B8' }}>Duration (Minutes)</FormLabel>
                  <FormControl>
                    <input type="number" min={1} className={inputBase} style={inputStyle}
                      onFocus={inputFocus} onBlur={inputBlur} {...field} />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )} />
            </div>
          </FormSection>

          {/* ── Timing Windows ── */}
          <FormSection
            icon={<div className="h-8 w-8 rounded-lg flex items-center justify-center" style={{ background: '#FFFBEB' }}><Clock className="h-4 w-4" style={{ color: '#B45309' }} /></div>}
            title="Timing Windows"
          >
            <div className="flex items-center justify-end mb-4">
              <span className="text-xs font-medium px-2 py-0.5 rounded-full"
                style={{ background: '#FFFBEB', color: '#B45309', border: '1px solid #FDE68A' }}>
                All times in IST
              </span>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
              <FormField control={form.control} name="start_window" render={({ field }) => (
                <FormItem>
                  <FormLabel className="text-xs font-semibold uppercase tracking-wider" style={{ color: '#94A3B8' }}>Start Window</FormLabel>
                  <FormControl>
                    <input type="datetime-local" min={minStartString}
                      className={inputBase} style={inputStyle}
                      onFocus={inputFocus} onBlur={inputBlur} {...field} />
                  </FormControl>
                  {field.value && <p className="text-xs mt-1" style={{ color: '#94A3B8' }}>{formatDatePreview(field.value)}</p>}
                  <FormMessage />
                </FormItem>
              )} />

              <FormField control={form.control} name="end_window" render={({ field }) => (
                <FormItem>
                  <FormLabel className="text-xs font-semibold uppercase tracking-wider" style={{ color: '#94A3B8' }}>End Window</FormLabel>
                  <FormControl>
                    <input type="datetime-local"
                      min={minEndString || minStartString}
                      disabled={examMode === 'FIXED'}
                      className={inputBase}
                      style={{ ...inputStyle, background: examMode === 'FIXED' ? '#F8FAFC' : undefined, opacity: examMode === 'FIXED' ? 0.6 : 1 }}
                      onFocus={inputFocus} onBlur={inputBlur} {...field} />
                  </FormControl>
                  {field.value && <p className="text-xs mt-1" style={{ color: '#94A3B8' }}>{formatDatePreview(field.value)}</p>}
                  {examMode === 'FIXED' && <FormDescription>Auto-calculated from duration.</FormDescription>}
                  <FormMessage />
                </FormItem>
              )} />

              <FormField control={form.control} name="hard_join_deadline" render={({ field }) => (
                <FormItem>
                  <FormLabel className="text-xs font-semibold uppercase tracking-wider" style={{ color: '#94A3B8' }}>Hard Join Deadline</FormLabel>
                  <FormControl>
                    <input type="datetime-local"
                      min={startWindow || minStartString}
                      max={maxHardJoin || undefined}
                      className={inputBase} style={inputStyle}
                      onFocus={inputFocus} onBlur={inputBlur} {...field} />
                  </FormControl>
                  {field.value && <p className="text-xs mt-1" style={{ color: '#94A3B8' }}>{formatDatePreview(field.value)}</p>}
                  {examMode === 'FIXED' && <FormDescription>Max 5 minutes past start — auto-set.</FormDescription>}
                  <FormMessage />
                </FormItem>
              )} />

              {showDurationWarning() && (
                <div className="col-span-1 md:col-span-3">
                  <div className="flex items-start gap-3 p-4 rounded-lg border"
                    style={{ background: '#FFFBEB', borderColor: '#FDE68A' }}>
                    <AlertCircle className="h-4 w-4 mt-0.5 shrink-0" style={{ color: '#B45309' }} />
                    <div>
                      <p className="text-sm font-semibold" style={{ color: '#B45309' }}>Duration Warning</p>
                      <p className="text-sm mt-0.5" style={{ color: '#78350F' }}>
                        Students joining near the deadline will not get their full duration before the exam window closes.
                      </p>
                    </div>
                  </div>
                </div>
              )}

              <FormField control={form.control} name="late_join_policy" render={({ field }) => (
                <FormItem>
                  <FormLabel className="text-xs font-semibold uppercase tracking-wider" style={{ color: '#94A3B8' }}>Late Join Policy</FormLabel>
                  <Select onValueChange={field.onChange} value={field.value} disabled={examMode === 'FIXED'}>
                    <FormControl>
                      <SelectTrigger style={examMode === 'FIXED' ? { opacity: 0.6 } : undefined}>
                        <SelectValue />
                      </SelectTrigger>
                    </FormControl>
                    <SelectContent>
                      <SelectItem value="ALLOW">Auto-Allow</SelectItem>
                      <SelectItem value="REVIEW">Requires Admin Review</SelectItem>
                      <SelectItem value="DENY">Strict Deny</SelectItem>
                    </SelectContent>
                  </Select>
                  <FormMessage />
                </FormItem>
              )} />

              <FormField control={form.control} name="allow_late_extension" render={({ field }) => (
                <FormItem className="flex flex-col gap-2 pt-8">
                  <div className="flex items-center gap-3">
                    <FormControl>
                      <Switch checked={field.value} onCheckedChange={field.onChange} disabled={examMode === 'FIXED'} />
                    </FormControl>
                    <FormLabel className="m-0 leading-tight flex flex-col">
                      <span className="text-sm font-medium" style={{ color: '#0F172A' }}>Allow Time Extension</span>
                      {examMode === 'FIXED' && (
                        <span className="text-xs font-normal mt-0.5" style={{ color: '#94A3B8' }}>Disabled in FIXED mode</span>
                      )}
                    </FormLabel>
                  </div>
                </FormItem>
              )} />

              {allowLateExtension && (
                <FormField control={form.control} name="max_late_minutes" render={({ field }) => (
                  <FormItem>
                    <FormLabel className="text-xs font-semibold uppercase tracking-wider" style={{ color: '#94A3B8' }}>Max Late Join (Mins past start)</FormLabel>
                    <FormControl>
                      <input type="number" min={1} className={inputBase} style={inputStyle}
                        onFocus={inputFocus} onBlur={inputBlur} {...field} />
                    </FormControl>
                    <FormDescription>Absolute cutoff: this many minutes after exam start time.</FormDescription>
                    <FormMessage />
                  </FormItem>
                )} />
              )}
            </div>
          </FormSection>

          {/* ── Proctoring ── */}
          <FormSection
            icon={<div className="h-8 w-8 rounded-lg flex items-center justify-center" style={{ background: '#ECFDF5' }}><ShieldCheck className="h-4 w-4" style={{ color: '#15803D' }} /></div>}
            title="Proctoring & AI Modules"
          >
            <div className="space-y-6">
              <FormField control={form.control} name="preset" render={({ field }) => (
                <FormItem>
                  <FormLabel className="text-xs font-semibold uppercase tracking-wider block mb-3" style={{ color: '#94A3B8' }}>Detection Strictness</FormLabel>
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                    {(['STRICT', 'MEDIUM', 'RELAXED', 'CUSTOM'] as const).map(p => (
                      <button key={p} type="button"
                        onClick={() => handlePresetChange(p)}
                        className="px-4 py-2.5 rounded-lg text-sm font-semibold transition-all duration-150 border"
                        style={{
                          background: field.value === p ? '#57CC99' : '#fff',
                          color: field.value === p ? '#0F172A' : '#475569',
                          borderColor: field.value === p ? '#57CC99' : '#E2E8F0',
                        }}
                      >
                        {p}
                      </button>
                    ))}
                  </div>
                </FormItem>
              )} />

              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4 p-5 rounded-xl border"
                style={{ background: '#F8FAFC', borderColor: '#E2E8F0' }}>
                {[
                  { id: 'DETECT_LOOKING_AWAY', label: 'Looking Away' },
                  { id: 'DETECT_LOOKING_DOWN', label: 'Looking Down' },
                  { id: 'DETECT_LOOKING_UP', label: 'Looking Up' },
                  { id: 'DETECT_LOOKING_SIDE', label: 'Looking Side' },
                  { id: 'DETECT_FACE_HIDDEN', label: 'Face Hidden' },
                  { id: 'DETECT_PARTIAL_FACE', label: 'Partial Face' },
                  { id: 'DETECT_FAKE_PRESENCE', label: 'Static Photo Spoofing' },
                  { id: 'DETECT_SPEAKER_AUDIO', label: 'Speaker / Audio' },
                  { id: 'DETECT_PHONE', label: 'Phone Detection' },
                  { id: 'DETECT_BOOK', label: 'Book Detection' },
                  { id: 'DETECT_HEADPHONE', label: 'Headphone Detection' },
                  { id: 'DETECT_EARBUD', label: 'Earbud Detection' },
                  { id: 'DETECT_MULTIPLE_PEOPLE', label: 'Multiple People' },
                ].map(item => (
                  <FormField key={item.id} control={form.control} name={`detection_config.${item.id}` as any} render={({ field }) => (
                    <FormItem className="flex items-center gap-3 space-y-0">
                      <FormControl>
                        <Switch checked={field.value} onCheckedChange={field.onChange} disabled={preset !== 'CUSTOM'} />
                      </FormControl>
                      <FormLabel className="text-sm font-medium" style={{ color: '#475569' }}>{item.label}</FormLabel>
                    </FormItem>
                  )} />
                ))}
                <FormField control={form.control} name="config.tab_switching" render={({ field }) => (
                  <FormItem className="flex items-center gap-3 space-y-0">
                    <FormControl>
                      <Switch checked={field.value} onCheckedChange={field.onChange} disabled={preset !== 'CUSTOM'} />
                    </FormControl>
                    <FormLabel className="text-sm font-medium" style={{ color: '#475569' }}>Tab Switching Tracker</FormLabel>
                  </FormItem>
                )} />
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-5 pt-4" style={{ borderTop: '1px solid #F1F5F9' }}>
                <FormField control={form.control} name="flag_threshold" render={({ field }) => (
                  <FormItem>
                    <FormLabel className="text-xs font-semibold uppercase tracking-wider" style={{ color: '#94A3B8' }}>Flag Threshold (Warnings)</FormLabel>
                    <FormControl>
                      <input type="number" min={0} className={inputBase} style={inputStyle}
                        onFocus={inputFocus} onBlur={inputBlur} {...field} />
                    </FormControl>
                    <FormDescription>Accumulated warnings before admin is notified.</FormDescription>
                    <FormMessage />
                  </FormItem>
                )} />
              </div>
            </div>
          </FormSection>

          {/* ── Students ── */}
          <FormSection
            icon={<div className="h-8 w-8 rounded-lg flex items-center justify-center" style={{ background: '#EFF6FF' }}><Users className="h-4 w-4" style={{ color: '#22577A' }} /></div>}
            title="Authorized Students"
          >
            <div className="space-y-4">
              <div className="flex items-center justify-between mb-1">
                <p className="text-sm font-medium" style={{ color: '#475569' }}>Paste emails or upload a CSV</p>
                <div className="flex items-center gap-3">
                  <span className="text-xs font-semibold px-2.5 py-1 rounded-full"
                    style={{ background: '#EFF6FF', color: '#22577A', border: '1px solid #BFDBFE' }}>
                    {emails.length} assigned
                  </span>
                  <Popover>
                    <PopoverTrigger asChild>
                      <button type="button" className="text-xs font-semibold transition-colors"
                        style={{ color: '#22577A' }}
                        onMouseEnter={e => (e.currentTarget as HTMLElement).style.textDecoration = 'underline'}
                        onMouseLeave={e => (e.currentTarget as HTMLElement).style.textDecoration = 'none'}>
                        Format guide
                      </button>
                    </PopoverTrigger>
                    <PopoverContent className="w-80 p-4">
                      <p className="text-sm font-semibold mb-2">Accepted Formats</p>
                      <p className="text-xs mb-2" style={{ color: '#94A3B8' }}>Paste anything — comma-separated, newline-separated, JSON arrays, or even a block of text. We extract all valid emails.</p>
                      <div className="rounded-lg p-2 text-xs font-mono whitespace-pre-wrap"
                        style={{ background: '#0F172A', color: '#E2E8F0' }}>
{`student1@school.edu, student2@school.edu
["john@gmail.com", "jane@yahoo.com"]
Just raw text with email@uni.edu inside`}
                      </div>
                    </PopoverContent>
                  </Popover>
                </div>
              </div>

              <Textarea
                placeholder="Paste emails here — comma, newline, or space separated..."
                className="min-h-[120px]"
                value={form.watch('invites_text')}
                onChange={e => form.setValue('invites_text', e.target.value)}
              />

              <div className="flex gap-2 justify-end">
                <input ref={csvInputRef} type="file" accept=".csv,.txt" className="hidden" onChange={handleCSVUpload} />
                <button
                  type="button"
                  onClick={() => csvInputRef.current?.click()}
                  className="flex items-center gap-2 px-3 py-2 rounded-lg text-sm font-medium border transition-all duration-150"
                  style={{ borderColor: '#E2E8F0', color: '#475569', background: '#fff' }}
                  onMouseEnter={e => (e.currentTarget as HTMLElement).style.background = '#F8FAFC'}
                  onMouseLeave={e => (e.currentTarget as HTMLElement).style.background = '#fff'}
                >
                  <Upload className="h-4 w-4" /> Upload CSV
                </button>
                <button
                  type="button"
                  onClick={handleExtract}
                  className="flex items-center gap-2 px-3 py-2 rounded-lg text-sm font-semibold text-white transition-all duration-150"
                  style={{ background: '#22577A' }}
                  onMouseEnter={e => (e.currentTarget as HTMLElement).style.background = '#1a4560'}
                  onMouseLeave={e => (e.currentTarget as HTMLElement).style.background = '#22577A'}
                >
                  Extract Emails
                </button>
              </div>

              {emails.length > 0 && (
                <div className="rounded-xl border p-4 max-h-60 overflow-y-auto"
                  style={{ background: '#F8FAFC', borderColor: '#E2E8F0' }}>
                  <div className="flex flex-wrap gap-2">
                    {emails.map(email => (
                      <span key={email} className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-sm font-medium border"
                        style={{ background: '#fff', borderColor: '#E2E8F0', color: '#475569', boxShadow: '0 1px 2px rgba(15,23,42,0.04)' }}>
                        {email}
                        <button type="button" onClick={() => removeEmail(email)}
                          className="transition-colors"
                          style={{ color: '#CBD5E1' }}
                          onMouseEnter={e => (e.currentTarget as HTMLElement).style.color = '#EF4444'}
                          onMouseLeave={e => (e.currentTarget as HTMLElement).style.color = '#CBD5E1'}>
                          <X className="h-3 w-3" />
                        </button>
                      </span>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </FormSection>

          {/* Submit */}
          <div className="flex justify-end gap-3 pt-2">
            <button
              type="button"
              onClick={() => router.back()}
              className="px-4 py-2.5 rounded-lg text-sm font-medium border transition-all duration-150"
              style={{ borderColor: '#E2E8F0', color: '#475569', background: '#fff' }}
              onMouseEnter={e => (e.currentTarget as HTMLElement).style.background = '#F8FAFC'}
              onMouseLeave={e => (e.currentTarget as HTMLElement).style.background = '#fff'}
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={isSubmitting}
              className="flex items-center gap-2 px-6 py-2.5 rounded-lg text-sm font-semibold text-white transition-all duration-150"
              style={{ background: isSubmitting ? '#94A3B8' : '#22577A', cursor: isSubmitting ? 'not-allowed' : 'pointer' }}
              onMouseEnter={e => { if (!isSubmitting) (e.currentTarget as HTMLElement).style.background = '#1a4560'; }}
              onMouseLeave={e => { if (!isSubmitting) (e.currentTarget as HTMLElement).style.background = '#22577A'; }}
            >
              {isSubmitting ? <Loader2 className="h-4 w-4 animate-spin" /> : null}
              Publish Exam
            </button>
          </div>

        </form>
      </Form>
    </div>
  );
}
