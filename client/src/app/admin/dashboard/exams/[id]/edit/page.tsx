'use client';

import { useState, useEffect, useRef } from 'react';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import * as z from 'zod';
import { useRouter, useParams } from 'next/navigation';
import { toast } from 'sonner';

import api from '@/lib/axios';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Form, FormControl, FormDescription, FormField, FormItem, FormLabel, FormMessage } from '@/components/ui/form';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Switch } from '@/components/ui/switch';
import { Textarea } from '@/components/ui/textarea';
import {
  Loader2, Users, ShieldCheck, Clock, FileText, ChevronLeft,
  AlertCircle, ShieldAlert, Upload, X,
} from 'lucide-react';
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
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
    eye_gaze: z.boolean(),
    looking_away: z.boolean(),
    static_photo: z.boolean(),
    phone_detected: z.boolean(),
    book_detected: z.boolean(),
    earphones: z.boolean(),
    audio_analysis: z.boolean(),
    multiple_person: z.boolean(),
    tab_switching: z.boolean(),
  }),

  detection_config: z.object({
    DETECT_LOOKING_AWAY:    z.boolean(),
    DETECT_LOOKING_DOWN:    z.boolean(),
    DETECT_LOOKING_UP:      z.boolean(),
    DETECT_LOOKING_SIDE:    z.boolean(),
    DETECT_FACE_HIDDEN:     z.boolean(),
    DETECT_PARTIAL_FACE:    z.boolean(),
    DETECT_FAKE_PRESENCE:   z.boolean(),
    DETECT_SPEAKER_AUDIO:   z.boolean(),
    DETECT_PHONE:           z.boolean(),
    DETECT_BOOK:            z.boolean(),
    DETECT_HEADPHONE:       z.boolean(),
    DETECT_EARBUD:          z.boolean(),
    DETECT_MULTIPLE_PEOPLE: z.boolean(),
  }),

  invites_text: z.string().optional(),
}).refine(data => {
  const startD = new Date(data.start_window);
  return startD >= new Date(Date.now() + 9 * 60000);
}, {
  message: 'Start window must be at least 10 minutes in the future',
  path: ['start_window'],
}).refine(data => {
  const startD = new Date(data.start_window);
  const endD   = new Date(data.end_window);
  return endD >= new Date(startD.getTime() + data.duration_minutes * 60000);
}, {
  message: 'End window must allow for the full exam duration',
  path: ['end_window'],
}).refine(data => {
  const d = new Date(data.hard_join_deadline);
  return d >= new Date(data.start_window) && d <= new Date(data.end_window);
}, {
  message: 'Join deadline must be between the start and end windows',
  path: ['hard_join_deadline'],
});

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

type LockReason = 'time' | 'ended' | 'cancelled' | null;

export default function EditExamPage() {
  const router   = useRouter();
  const params   = useParams();
  const examId   = params.id as string;

  const [isLoading,    setIsLoading]    = useState(true);
  const [lockReason,   setLockReason]   = useState<LockReason>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [emails,       setEmails]       = useState<string[]>([]);
  const csvInputRef = useRef<HTMLInputElement>(null);

  const form = useForm({
    resolver: zodResolver(examSchema),
    defaultValues: {
      title: '', exam_mode: 'FLEXIBLE',
      start_window: '', end_window: '', duration_minutes: 60,
      hard_join_deadline: '', late_join_policy: 'REVIEW',
      allow_late_extension: false, max_late_minutes: 0,
      flag_threshold: 100, preset: 'CUSTOM',
      config: PRESETS.MEDIUM.config,
      detection_config: PRESETS.MEDIUM.detection,
      invites_text: '',
    } as any,
  });

  useEffect(() => {
    if (!examId) return;
    const fetchExam = async () => {
      try {
        const res  = await api.get(`/admin/exams/${examId}`);
        const data = res.data;

        // Lock: finished or cancelled exams are read-only
        if (data.status === 'ENDED') {
          setLockReason('ended'); setIsLoading(false); return;
        }
        if (data.status === 'CANCELLED') {
          setLockReason('cancelled'); setIsLoading(false); return;
        }

        // Lock: within 10 minutes of start
        // Both are UTC ms — this comparison is correct regardless of timezone.
        if (new Date(data.start_window).getTime() <= Date.now() + 10 * 60000) {
          setLockReason('time'); setIsLoading(false); return;
        }

        // Convert UTC datetimes from server → local datetime-local strings
        form.reset({
          title:               data.title,
          exam_mode:           data.exam_mode,
          start_window:        toLocalInputString(new Date(data.start_window)),
          end_window:          toLocalInputString(new Date(data.end_window)),
          duration_minutes:    data.duration_minutes,
          hard_join_deadline:  data.hard_join_deadline
            ? toLocalInputString(new Date(data.hard_join_deadline))
            : '',
          late_join_policy:    data.late_join_policy,
          allow_late_extension: data.allow_late_extension,
          max_late_minutes:    data.max_late_minutes || 0,
          flag_threshold:      data.flag_threshold,
          preset:              'CUSTOM',
          config:              data.config,
          detection_config:    data.detection_config ?? {
            DETECT_LOOKING_AWAY: true, DETECT_LOOKING_DOWN: true, DETECT_LOOKING_UP: true,
            DETECT_LOOKING_SIDE: true, DETECT_FACE_HIDDEN: true, DETECT_PARTIAL_FACE: true,
            DETECT_FAKE_PRESENCE: true, DETECT_SPEAKER_AUDIO: true, DETECT_PHONE: true,
            DETECT_BOOK: true, DETECT_HEADPHONE: true, DETECT_EARBUD: true,
            DETECT_MULTIPLE_PEOPLE: true,
          },
          invites_text:        '',
        });

        setEmails(data.invites.map((i: any) => i.student_email));
        setIsLoading(false);
      } catch {
        toast.error('Failed to load exam details');
        router.back();
      }
    };
    fetchExam();
  }, [examId, form, router]);

  const preset             = form.watch('preset');
  const examMode           = form.watch('exam_mode');
  const startWindow        = form.watch('start_window');
  const endWindow          = form.watch('end_window');
  const durationMinutes    = form.watch('duration_minutes');
  const allowLateExtension = form.watch('allow_late_extension');
  const hardJoinDeadline   = form.watch('hard_join_deadline');

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
    if (!isNaN(s.getTime()))
      maxHardJoin = toLocalInputString(new Date(s.getTime() + 5 * 60000));
  } else if (examMode === 'FLEXIBLE' && endWindow) {
    maxHardJoin = endWindow;
  }

  // FIXED mode: auto-compute end_window and hard_join_deadline
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

  // ─── Email helpers ────────────────────────────────────────────────────────
  const EMAIL_REGEX = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;

  const addEmails = (raw: string) => {
    const found = raw.match(EMAIL_REGEX) || [];
    if (found.length === 0) { toast.error('No valid emails found'); return; }
    const unique = Array.from(new Set([...emails, ...found.map(e => e.toLowerCase())]));
    setEmails(unique);
    toast.success(`Added ${unique.length - emails.length} new email(s)`);
  };

  const handleExtract = () => {
    addEmails(form.getValues('invites_text') || '');
    form.setValue('invites_text', '');
  };

  const handleCSVUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = ev => addEmails(ev.target?.result as string);
    reader.readAsText(file);
    e.target.value = '';
  };

  const removeEmail = (email: string) => setEmails(emails.filter(e => e !== email));

  async function onSubmit(values: any) {
    if (emails.length === 0) {
      toast.error('Please assign at least one student.');
      return;
    }
    setIsSubmitting(true);
    try {
      await api.put(`/admin/exams/${examId}`, {
        title: values.title,
        exam_mode: values.exam_mode,
        start_window: new Date(values.start_window).toISOString(),
        end_window: new Date(values.end_window).toISOString(),
        duration_minutes: values.duration_minutes,
        hard_join_deadline: new Date(values.hard_join_deadline).toISOString(),
        flag_threshold: values.flag_threshold,
        late_join_policy: values.late_join_policy,
        allow_late_extension: values.allow_late_extension,
        max_late_minutes: values.max_late_minutes,
        config: values.config,
        detection_config: values.detection_config,
        invites: emails,
      });
      toast.success('Exam updated successfully. Changes are being dispatched.');
      router.push(`/admin/dashboard/exams/${examId}`);
    } catch (error: any) {
      toast.error(error.response?.data?.detail || 'Failed to update exam');
    } finally {
      setIsSubmitting(false);
    }
  }

  // ─── Loading / Lock screens ───────────────────────────────────────────────
  if (isLoading) {
    return <div className="flex justify-center p-24"><Loader2 className="h-8 w-8 animate-spin text-slate-400" /></div>;
  }

  if (lockReason) {
    const lockMessages: Record<NonNullable<LockReason>, { title: string; body: string }> = {
      time:      { title: 'Exam Locked',     body: 'This exam starts in less than 10 minutes. Edits are no longer permitted to maintain exam integrity.' },
      ended:     { title: 'Exam Completed',  body: 'This exam has ended. Completed exam records cannot be modified.' },
      cancelled: { title: 'Exam Cancelled',  body: 'This exam has been cancelled and cannot be edited.' },
    };
    const msg = lockMessages[lockReason];
    return (
      <div className="p-24 max-w-xl mx-auto text-center space-y-4 animate-in fade-in zoom-in duration-500">
        <ShieldAlert className="h-16 w-16 mx-auto text-rose-500 opacity-80" />
        <h2 className="text-3xl font-bold text-slate-900 tracking-tight">{msg.title}</h2>
        <p className="text-slate-500 text-lg">{msg.body}</p>
        <div className="pt-6">
          <Button onClick={() => router.back()} size="lg" className="bg-slate-900">Go Back</Button>
        </div>
      </div>
    );
  }

  // ─── Edit Form ────────────────────────────────────────────────────────────
  return (
    <div className="max-w-5xl mx-auto space-y-6 pb-20 animate-in fade-in slide-in-from-bottom-4 duration-500">
      <div className="flex items-center gap-4 border-b pb-4">
        <Button variant="ghost" size="icon" onClick={() => router.back()}>
          <ChevronLeft className="h-5 w-5" />
        </Button>
        <div>
          <h1 className="text-3xl font-bold">Edit Exam</h1>
          <p className="text-muted-foreground">Modify timing, proctoring rules, and manage attendees.</p>
        </div>
      </div>

      <Form {...form}>
        <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-8">

          {/* ── Basic Details ── */}
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2"><FileText className="h-5 w-5 text-indigo-500" /> Basic Details</CardTitle>
            </CardHeader>
            <CardContent className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <FormField control={form.control} name="title" render={({ field }) => (
                <FormItem className="col-span-1 md:col-span-2">
                  <FormLabel>Exam Title</FormLabel>
                  <FormControl><Input placeholder="e.g. CS401 Midterm Examination" {...field} /></FormControl>
                  <FormMessage />
                </FormItem>
              )} />
              <FormField control={form.control} name="exam_mode" render={({ field }) => (
                <FormItem>
                  <FormLabel>Exam Mode</FormLabel>
                  <Select onValueChange={field.onChange} value={field.value}>
                    <FormControl><SelectTrigger><SelectValue /></SelectTrigger></FormControl>
                    <SelectContent>
                      <SelectItem value="FLEXIBLE">Flexible — anytime within window</SelectItem>
                      <SelectItem value="FIXED">Fixed — strict start &amp; end times</SelectItem>
                    </SelectContent>
                  </Select>
                  <FormMessage />
                </FormItem>
              )} />
              <FormField control={form.control} name="duration_minutes" render={({ field }) => (
                <FormItem>
                  <FormLabel>Duration (Minutes)</FormLabel>
                  <FormControl><Input type="number" min={1} {...field} /></FormControl>
                  <FormMessage />
                </FormItem>
              )} />
            </CardContent>
          </Card>

          {/* ── Timing Windows ── */}
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Clock className="h-5 w-5 text-amber-500" /> Timing Windows
                <span className="ml-auto text-xs font-normal bg-amber-100 text-amber-700 px-2 py-0.5 rounded-full">All times in IST</span>
              </CardTitle>
            </CardHeader>
            <CardContent className="grid grid-cols-1 md:grid-cols-3 gap-6">

              <FormField control={form.control} name="start_window" render={({ field }) => (
                <FormItem>
                  <FormLabel>Start Window</FormLabel>
                  <FormControl>
                    <Input type="datetime-local" min={minStartString} {...field} />
                  </FormControl>
                  {field.value && <p className="text-xs text-slate-500 mt-1">{formatDatePreview(field.value)}</p>}
                  <FormMessage />
                </FormItem>
              )} />

              <FormField control={form.control} name="end_window" render={({ field }) => (
                <FormItem>
                  <FormLabel>End Window</FormLabel>
                  <FormControl>
                    <Input
                      type="datetime-local"
                      min={minEndString || minStartString}
                      disabled={examMode === 'FIXED'}
                      className={examMode === 'FIXED' ? 'bg-slate-100' : ''}
                      {...field}
                    />
                  </FormControl>
                  {field.value && <p className="text-xs text-slate-500 mt-1">{formatDatePreview(field.value)}</p>}
                  {examMode === 'FIXED' && <FormDescription>Auto-calculated from duration.</FormDescription>}
                  <FormMessage />
                </FormItem>
              )} />

              <FormField control={form.control} name="hard_join_deadline" render={({ field }) => (
                <FormItem>
                  <FormLabel>Hard Join Deadline</FormLabel>
                  <FormControl>
                    <Input
                      type="datetime-local"
                      min={startWindow || minStartString}
                      max={maxHardJoin || undefined}
                      {...field}
                    />
                  </FormControl>
                  {field.value && <p className="text-xs text-slate-500 mt-1">{formatDatePreview(field.value)}</p>}
                  {examMode === 'FIXED' && <FormDescription>Max 5 minutes past start — auto-set.</FormDescription>}
                  <FormMessage />
                </FormItem>
              )} />

              {showDurationWarning() && (
                <div className="col-span-1 md:col-span-3">
                  <Alert className="bg-amber-50 border-amber-200 text-amber-800">
                    <AlertCircle className="h-4 w-4 text-amber-600" />
                    <AlertTitle>Duration Warning</AlertTitle>
                    <AlertDescription>
                      Students joining near the deadline will not get their full duration before the window closes.
                    </AlertDescription>
                  </Alert>
                </div>
              )}

              <FormField control={form.control} name="late_join_policy" render={({ field }) => (
                <FormItem>
                  <FormLabel>Late Join Policy</FormLabel>
                  <Select onValueChange={field.onChange} value={field.value} disabled={examMode === 'FIXED'}>
                    <FormControl>
                      <SelectTrigger className={examMode === 'FIXED' ? 'bg-slate-100' : ''}>
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
                      <span>Allow Time Extension</span>
                      {examMode === 'FIXED' && (
                        <span className="text-xs text-muted-foreground font-normal mt-0.5">Disabled in FIXED mode</span>
                      )}
                    </FormLabel>
                  </div>
                </FormItem>
              )} />

              {allowLateExtension && (
                <FormField control={form.control} name="max_late_minutes" render={({ field }) => (
                  <FormItem>
                    <FormLabel>Max Late Join (Mins past start)</FormLabel>
                    <FormControl><Input type="number" min={1} {...field} /></FormControl>
                    <FormDescription>Absolute cutoff: this many minutes after exam start time.</FormDescription>
                    <FormMessage />
                  </FormItem>
                )} />
              )}
            </CardContent>
          </Card>

          {/* ── Proctoring ── */}
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2"><ShieldCheck className="h-5 w-5 text-green-500" /> Proctoring &amp; AI Modules</CardTitle>
            </CardHeader>
            <CardContent className="space-y-6">
              <FormField control={form.control} name="preset" render={({ field }) => (
                <FormItem>
                  <FormLabel className="uppercase text-xs font-bold text-muted-foreground tracking-wider mb-2 block">Detection Strictness</FormLabel>
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                    {(['STRICT', 'MEDIUM', 'RELAXED', 'CUSTOM'] as const).map(p => (
                      <Button key={p} type="button"
                        variant={field.value === p ? 'default' : 'outline'}
                        className={field.value === p ? 'bg-green-600 hover:bg-green-700' : ''}
                        onClick={() => handlePresetChange(p)}>
                        {p}
                      </Button>
                    ))}
                  </div>
                </FormItem>
              )} />

              {/* Unified detection toggles */}
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4 p-6 bg-gray-50 dark:bg-gray-800/50 rounded-lg border">
                {[
                  { id: 'DETECT_LOOKING_AWAY',    label: 'Looking Away'          },
                  { id: 'DETECT_LOOKING_DOWN',    label: 'Looking Down'          },
                  { id: 'DETECT_LOOKING_UP',      label: 'Looking Up'            },
                  { id: 'DETECT_LOOKING_SIDE',    label: 'Looking Side'          },
                  { id: 'DETECT_FACE_HIDDEN',     label: 'Face Hidden'           },
                  { id: 'DETECT_PARTIAL_FACE',    label: 'Partial Face'          },
                  { id: 'DETECT_FAKE_PRESENCE',   label: 'Static Photo Spoofing' },
                  { id: 'DETECT_SPEAKER_AUDIO',   label: 'Speaker / Audio'       },
                  { id: 'DETECT_PHONE',           label: 'Phone Detection'       },
                  { id: 'DETECT_BOOK',            label: 'Book Detection'        },
                  { id: 'DETECT_HEADPHONE',       label: 'Headphone Detection'   },
                  { id: 'DETECT_EARBUD',          label: 'Earbud Detection'      },
                  { id: 'DETECT_MULTIPLE_PEOPLE', label: 'Multiple People'       },
                ].map(item => (
                  <FormField key={item.id} control={form.control} name={`detection_config.${item.id}` as any} render={({ field }) => (
                    <FormItem className="flex items-center gap-3 space-y-0">
                      <FormControl>
                        <Switch checked={field.value} onCheckedChange={field.onChange} disabled={preset !== 'CUSTOM'} />
                      </FormControl>
                      <FormLabel className="text-sm font-medium">{item.label}</FormLabel>
                    </FormItem>
                  )} />
                ))}
                {/* Tab switching — browser-side */}
                <FormField control={form.control} name="config.tab_switching" render={({ field }) => (
                  <FormItem className="flex items-center gap-3 space-y-0">
                    <FormControl>
                      <Switch checked={field.value} onCheckedChange={field.onChange} disabled={preset !== 'CUSTOM'} />
                    </FormControl>
                    <FormLabel className="text-sm font-medium">Tab Switching Tracker</FormLabel>
                  </FormItem>
                )} />
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-6 pt-4 border-t">
                <FormField control={form.control} name="flag_threshold" render={({ field }) => (
                  <FormItem>
                    <FormLabel>Flag Threshold (Warnings)</FormLabel>
                    <FormControl><Input type="number" min={0} {...field} /></FormControl>
                    <FormDescription>Accumulated warnings before admin is notified.</FormDescription>
                    <FormMessage />
                  </FormItem>
                )} />
              </div>
            </CardContent>
          </Card>

          {/* ── Students ── */}
          <Card>
            <CardHeader>
              <div className="flex justify-between items-center">
                <CardTitle className="flex items-center gap-2"><Users className="h-5 w-5 text-blue-500" /> Authorized Students</CardTitle>
                <span className="text-sm font-semibold bg-blue-100 text-blue-800 px-3 py-1 rounded-full dark:bg-blue-900/30 dark:text-blue-300">
                  {emails.length} assigned
                </span>
              </div>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <FormLabel>Paste emails or upload a CSV</FormLabel>
                  <Popover>
                    <PopoverTrigger asChild>
                      <Button variant="link" size="sm" className="h-auto p-0 text-indigo-600">Format guide</Button>
                    </PopoverTrigger>
                    <PopoverContent className="w-80 p-4">
                      <p className="text-sm font-semibold mb-2">Accepted Formats</p>
                      <p className="text-xs text-slate-500 mb-2">Paste anything — comma-separated, newline-separated, JSON arrays, or even a block of text. We extract all valid emails.</p>
                      <div className="bg-slate-900 text-slate-200 text-xs p-2 rounded whitespace-pre-wrap font-mono">
{`student1@school.edu, student2@school.edu
["john@gmail.com", "jane@yahoo.com"]
Just raw text with email@uni.edu inside`}
                      </div>
                    </PopoverContent>
                  </Popover>
                </div>

                <Textarea
                  placeholder="Paste emails here — comma, newline, or space separated..."
                  className="min-h-[120px] shadow-inner"
                  value={form.watch('invites_text')}
                  onChange={e => form.setValue('invites_text', e.target.value)}
                />

                <div className="flex gap-2 justify-end">
                  <input
                    ref={csvInputRef}
                    type="file"
                    accept=".csv,.txt"
                    className="hidden"
                    onChange={handleCSVUpload}
                  />
                  <Button type="button" variant="outline" onClick={() => csvInputRef.current?.click()} className="gap-2">
                    <Upload className="h-4 w-4" /> Upload CSV
                  </Button>
                  <Button type="button" onClick={handleExtract} className="bg-slate-900 text-white">
                    Extract Emails
                  </Button>
                </div>
              </div>

              {emails.length > 0 && (
                <div className="border rounded-lg p-4 bg-slate-50 dark:bg-gray-900 max-h-[240px] overflow-y-auto">
                  <div className="flex flex-wrap gap-2">
                    {emails.map(email => (
                      <span key={email} className="inline-flex items-center bg-white border border-slate-200 shadow-sm px-3 py-1 rounded-full text-sm font-medium text-slate-700 gap-1.5">
                        {email}
                        <button type="button" onClick={() => removeEmail(email)} className="text-slate-400 hover:text-red-500 transition-colors">
                          <X className="h-3 w-3" />
                        </button>
                      </span>
                    ))}
                  </div>
                </div>
              )}
            </CardContent>
          </Card>

          <div className="flex justify-end gap-4">
            <Button variant="outline" type="button" onClick={() => router.back()}>Cancel</Button>
            <Button type="submit" disabled={isSubmitting} className="bg-indigo-600 hover:bg-indigo-700 w-36 shadow-md">
              {isSubmitting ? <Loader2 className="h-4 w-4 animate-spin" /> : 'Update Exam'}
            </Button>
          </div>

        </form>
      </Form>
    </div>
  );
}
