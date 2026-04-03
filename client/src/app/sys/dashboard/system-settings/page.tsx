'use client';

import { useState, useEffect } from 'react';
import { toast } from 'sonner';
import { Loader2, SlidersHorizontal, Save, RotateCcw, ToggleLeft, ToggleRight } from 'lucide-react';
import api from '@/lib/axios';

// ── Numeric defaults ──────────────────────────────────────────────────────────
const NUM_DEFAULTS = {
  // Head pose
  look_away_yaw: 0.20, look_down_pitch: 0.13, look_up_pitch: -0.10,
  gaze_left: -0.13, gaze_right: 0.13,
  min_face_width: 110, min_face_height: 120, face_hidden_recency_s: 4.0,

  // Duration gates
  looking_away_threshold: 2.0, gaze_threshold: 1.5, fake_window: 15.0,
  partial_face_duration_gate: 5.0,
  face_hidden_dur_1: 5.0, face_hidden_dur_2: 10.0,
  no_person_dur_1: 5.0, no_person_dur_2: 10.0,
  fake_presence_dur_1: 10.0, fake_presence_dur_2: 25.0,

  // Risk scores
  gaze_score: 5.0,
  phone_score_2nd: 25.0, phone_score_3rd: 50.0,
  book_score: 20.0, headphone_score: 20.0, earbud_score: 20.0,
  tab_switch_score: 15.0,
  multi_people_score_2nd: 20.0, multi_people_score_3rd: 50.0,
  no_person_score_1: 25.0, no_person_score_2: 50.0,
  fake_presence_score_1: 30.0, fake_presence_score_2: 60.0,
  partial_face_score: 2.0,
  face_hidden_score_1: 10.0, face_hidden_score_2: 20.0,

  // State thresholds
  state_warning: 30.0, state_high_risk: 60.0, state_admin_review: 100.0,
  decay_amount: 5.0,

  // Termination
  tab_switch_terminate_count: 3,
  multi_people_terminate_s: 20.0, no_person_terminate_s: 20.0,

  // YOLO confidence
  yolo_phone_conf: 0.65, yolo_book_conf: 0.70,
  yolo_audio_conf: 0.41, yolo_person_conf: 0.30,

  // Score cooldowns (seconds between scoring events)
  score_cd_looking_away: 5.0, score_cd_looking_down: 5.0,
  score_cd_looking_up: 5.0, score_cd_looking_side: 5.0,
  score_cd_partial_face: 5.0, score_cd_face_hidden: 5.0,
  score_cd_fake_presence: 10.0, score_cd_phone: 15.0,
  score_cd_multiple_people: 10.0, score_cd_no_person: 10.0,
  score_cd_book: 30.0, score_cd_headphone: 30.0,
  score_cd_earbud: 30.0, score_cd_speaker_audio: 10.0,

  // Warning cooldowns (seconds between warning banners)
  warn_cd_looking_away: 3.0, warn_cd_looking_down: 3.0,
  warn_cd_looking_up: 3.0, warn_cd_looking_side: 3.0,
  warn_cd_partial_face: 3.0, warn_cd_face_hidden: 3.0,
  warn_cd_fake_presence: 5.0, warn_cd_phone: 8.0,
  warn_cd_multiple_people: 5.0, warn_cd_no_person: 5.0,
  warn_cd_book: 15.0, warn_cd_headphone: 15.0,
  warn_cd_earbud: 15.0, warn_cd_speaker_audio: 3.0,

  // Speaker audio
  speaker_warn_cooldown: 3.0, speaker_alert_cooldown: 10.0,
  speaker_occ1_warn_s: 3.0, speaker_occ1_score: 10.0, speaker_occ1_repeat: 20.0,
  speaker_occ2_warn_s: 5.0, speaker_occ2_score: 20.0, speaker_occ2_repeat: 20.0,
  speaker_repeat_interval: 10.0,

  // Identity verification
  identity_check_count: 5,
  identity_check_retries: 3,
  identity_check_retry_delay: 5.0,

  // Object detection voting
  phone_min_votes: 9,
  book_min_votes: 10,
  headphone_min_votes: 9,
  earbud_min_votes: 9,
  object_min_votes: 5,
  object_window: 15,
};

// ── Boolean defaults ───────────────────────────────────────────────────────────
const BOOL_DEFAULTS = {
  detect_looking_away: true, detect_looking_down: true,
  detect_looking_up: true, detect_looking_side: true,
  detect_face_hidden: true, detect_partial_face: true,
  detect_fake_presence: true, detect_speaker_audio: true,
  detect_phone: true, detect_book: true,
  detect_headphone: true, detect_earbud: true,
  detect_multiple_people: true,
};

type NumKey  = keyof typeof NUM_DEFAULTS;
type BoolKey = keyof typeof BOOL_DEFAULTS;
type NumSettings  = typeof NUM_DEFAULTS;
type BoolSettings = typeof BOOL_DEFAULTS;

interface FieldMeta {
  label: string; key: NumKey; min: number; max: number; step: number;
  unit?: string; desc?: string;
}
interface ToggleMeta { label: string; key: BoolKey; desc?: string; }
interface Section {
  title: string; desc?: string;
  fields?: FieldMeta[];
  toggles?: ToggleMeta[];
}

const SECTIONS: Section[] = [
  {
    title: 'Detection Toggles',
    desc: 'Enable or disable each violation type entirely. Disabled types produce no alerts, warnings, or score.',
    toggles: [
      { key: 'detect_looking_away',    label: 'Looking Away' },
      { key: 'detect_looking_down',    label: 'Looking Down' },
      { key: 'detect_looking_up',      label: 'Looking Up' },
      { key: 'detect_looking_side',    label: 'Gaze Side' },
      { key: 'detect_face_hidden',     label: 'Face Hidden' },
      { key: 'detect_partial_face',    label: 'Partial Face' },
      { key: 'detect_fake_presence',   label: 'Fake Presence' },
      { key: 'detect_speaker_audio',   label: 'Speaker Audio' },
      { key: 'detect_phone',           label: 'Phone' },
      { key: 'detect_book',            label: 'Book' },
      { key: 'detect_headphone',       label: 'Headphone' },
      { key: 'detect_earbud',          label: 'Earbud' },
      { key: 'detect_multiple_people', label: 'Multiple People' },
    ],
  },
  {
    title: 'Head Pose Thresholds',
    desc: 'Angular thresholds for detecting head movement. Lower = more sensitive.',
    fields: [
      { key: 'look_away_yaw',   label: 'Yaw — Look Away',  min: 0.05, max: 0.50, step: 0.01, desc: 'Horizontal head turn angle' },
      { key: 'look_down_pitch', label: 'Pitch — Look Down', min: 0.05, max: 0.40, step: 0.01, desc: 'Downward pitch threshold' },
      { key: 'look_up_pitch',   label: 'Pitch — Look Up',   min: -0.40, max: -0.02, step: 0.01, desc: 'Upward pitch (negative)' },
      { key: 'gaze_left',       label: 'Gaze Left',         min: -0.40, max: -0.02, step: 0.01, desc: 'Leftward gaze (negative)' },
      { key: 'gaze_right',      label: 'Gaze Right',        min: 0.02, max: 0.40, step: 0.01, desc: 'Rightward gaze threshold' },
      { key: 'min_face_width',  label: 'Min Face Width',    min: 50, max: 300, step: 10, unit: 'px', desc: 'Below this = partial face' },
      { key: 'min_face_height', label: 'Min Face Height',   min: 50, max: 300, step: 10, unit: 'px', desc: 'Below this = partial face' },
      { key: 'face_hidden_recency_s', label: 'Face Hidden Recency', min: 1, max: 15, step: 0.5, unit: 's', desc: 'Must have seen face within this many seconds before firing face_hidden' },
    ],
  },
  {
    title: 'Duration Gates',
    desc: 'How long a condition must persist before it fires an event.',
    fields: [
      { key: 'looking_away_threshold',  label: 'Looking Away Hold',     min: 0.5, max: 10, step: 0.5, unit: 's' },
      { key: 'gaze_threshold',          label: 'Off-Gaze Hold',         min: 0.5, max: 10, step: 0.5, unit: 's' },
      { key: 'fake_window',             label: 'Fake Presence Window',  min: 5, max: 60, step: 1, unit: 's', desc: 'Rolling window for liveness detection' },
      { key: 'partial_face_duration_gate', label: 'Partial Face Hold',  min: 1, max: 30, step: 0.5, unit: 's' },
      { key: 'face_hidden_dur_1',       label: 'Face Hidden → Tier 1',  min: 1, max: 30, step: 0.5, unit: 's' },
      { key: 'face_hidden_dur_2',       label: 'Face Hidden → Tier 2',  min: 3, max: 60, step: 1, unit: 's' },
      { key: 'no_person_dur_1',         label: 'No Person → Tier 1',    min: 1, max: 30, step: 0.5, unit: 's' },
      { key: 'no_person_dur_2',         label: 'No Person → Tier 2',    min: 3, max: 60, step: 1, unit: 's' },
      { key: 'fake_presence_dur_1',     label: 'Fake Presence → Tier 1', min: 3, max: 60, step: 1, unit: 's' },
      { key: 'fake_presence_dur_2',     label: 'Fake Presence → Tier 2', min: 5, max: 120, step: 5, unit: 's' },
    ],
  },
  {
    title: 'Risk Scores',
    desc: 'Points added to risk score when each violation is detected.',
    fields: [
      { key: 'gaze_score',             label: 'Gaze Event',             min: 1,  max: 30,  step: 1,  unit: 'pts' },
      { key: 'partial_face_score',     label: 'Partial Face',           min: 1,  max: 30,  step: 1,  unit: 'pts' },
      { key: 'face_hidden_score_1',    label: 'Face Hidden Tier 1',     min: 5,  max: 60,  step: 5,  unit: 'pts' },
      { key: 'face_hidden_score_2',    label: 'Face Hidden Tier 2',     min: 5,  max: 100, step: 5,  unit: 'pts' },
      { key: 'phone_score_2nd',        label: 'Phone — 2nd Offence',    min: 5,  max: 100, step: 5,  unit: 'pts' },
      { key: 'phone_score_3rd',        label: 'Phone — 3rd Offence',    min: 5,  max: 150, step: 5,  unit: 'pts' },
      { key: 'book_score',             label: 'Book Detected',          min: 5,  max: 80,  step: 5,  unit: 'pts' },
      { key: 'headphone_score',        label: 'Headphone',              min: 5,  max: 80,  step: 5,  unit: 'pts' },
      { key: 'earbud_score',           label: 'Earbud',                 min: 5,  max: 80,  step: 5,  unit: 'pts' },
      { key: 'tab_switch_score',       label: 'Tab Switch',             min: 5,  max: 50,  step: 5,  unit: 'pts' },
      { key: 'multi_people_score_2nd', label: 'Multiple People 2nd',    min: 5,  max: 100, step: 5,  unit: 'pts' },
      { key: 'multi_people_score_3rd', label: 'Multiple People 3rd',    min: 5,  max: 150, step: 5,  unit: 'pts' },
      { key: 'no_person_score_1',      label: 'No Person — Tier 1',     min: 5,  max: 100, step: 5,  unit: 'pts' },
      { key: 'no_person_score_2',      label: 'No Person — Tier 2',     min: 5,  max: 150, step: 5,  unit: 'pts' },
      { key: 'fake_presence_score_1',  label: 'Fake Presence Tier 1',   min: 5,  max: 100, step: 5,  unit: 'pts' },
      { key: 'fake_presence_score_2',  label: 'Fake Presence Tier 2',   min: 5,  max: 150, step: 5,  unit: 'pts' },
    ],
  },
  {
    title: 'Risk State Thresholds',
    desc: 'Score levels at which session risk state escalates.',
    fields: [
      { key: 'state_warning',      label: 'Warning Threshold',      min: 10, max: 80,  step: 5, unit: 'pts', desc: 'Enters WARNING state' },
      { key: 'state_high_risk',    label: 'High Risk Threshold',    min: 30, max: 120, step: 5, unit: 'pts', desc: 'Enters HIGH_RISK state' },
      { key: 'state_admin_review', label: 'Admin Review Threshold', min: 60, max: 200, step: 5, unit: 'pts', desc: 'Enters ADMIN_REVIEW state' },
      { key: 'decay_amount',       label: 'Decay per Cycle',        min: 1,  max: 30,  step: 1, unit: 'pts', desc: 'Score reduced each cycle without new events' },
    ],
  },
  {
    title: 'Termination Rules',
    desc: 'Thresholds that trigger automatic session termination.',
    fields: [
      { key: 'tab_switch_terminate_count', label: 'Tab Switches → Terminate',  min: 2, max: 10, step: 1,  desc: 'Number of tab switches before auto-terminate' },
      { key: 'multi_people_terminate_s',   label: 'Multi-Person → Terminate',  min: 5, max: 120, step: 5, unit: 's', desc: 'Continuous multi-person duration before terminate' },
      { key: 'no_person_terminate_s',      label: 'No Person → Terminate',     min: 5, max: 120, step: 5, unit: 's', desc: 'Continuous absence duration before terminate' },
    ],
  },
  {
    title: 'Score Cooldowns',
    desc: 'Minimum gap (seconds) between consecutive scoring events for the same violation. Also controls API alert frequency.',
    fields: [
      { key: 'score_cd_looking_away',    label: 'Looking Away',    min: 1, max: 60, step: 1, unit: 's' },
      { key: 'score_cd_looking_down',    label: 'Looking Down',    min: 1, max: 60, step: 1, unit: 's' },
      { key: 'score_cd_looking_up',      label: 'Looking Up',      min: 1, max: 60, step: 1, unit: 's' },
      { key: 'score_cd_looking_side',    label: 'Gaze Side',       min: 1, max: 60, step: 1, unit: 's' },
      { key: 'score_cd_partial_face',    label: 'Partial Face',    min: 1, max: 60, step: 1, unit: 's' },
      { key: 'score_cd_face_hidden',     label: 'Face Hidden',     min: 1, max: 60, step: 1, unit: 's' },
      { key: 'score_cd_fake_presence',   label: 'Fake Presence',   min: 1, max: 120, step: 5, unit: 's' },
      { key: 'score_cd_phone',           label: 'Phone',           min: 1, max: 120, step: 5, unit: 's' },
      { key: 'score_cd_multiple_people', label: 'Multiple People', min: 1, max: 120, step: 5, unit: 's' },
      { key: 'score_cd_no_person',       label: 'No Person',       min: 1, max: 120, step: 5, unit: 's' },
      { key: 'score_cd_book',            label: 'Book',            min: 5, max: 120, step: 5, unit: 's' },
      { key: 'score_cd_headphone',       label: 'Headphone',       min: 5, max: 120, step: 5, unit: 's' },
      { key: 'score_cd_earbud',          label: 'Earbud',          min: 5, max: 120, step: 5, unit: 's' },
      { key: 'score_cd_speaker_audio',   label: 'Speaker Audio',   min: 1, max: 120, step: 5, unit: 's' },
    ],
  },
  {
    title: 'Warning Cooldowns',
    desc: 'Minimum gap (seconds) between consecutive amber warning banners for the same violation. Must be ≤ score cooldown.',
    fields: [
      { key: 'warn_cd_looking_away',    label: 'Looking Away',    min: 1, max: 60, step: 1, unit: 's' },
      { key: 'warn_cd_looking_down',    label: 'Looking Down',    min: 1, max: 60, step: 1, unit: 's' },
      { key: 'warn_cd_looking_up',      label: 'Looking Up',      min: 1, max: 60, step: 1, unit: 's' },
      { key: 'warn_cd_looking_side',    label: 'Gaze Side',       min: 1, max: 60, step: 1, unit: 's' },
      { key: 'warn_cd_partial_face',    label: 'Partial Face',    min: 1, max: 60, step: 1, unit: 's' },
      { key: 'warn_cd_face_hidden',     label: 'Face Hidden',     min: 1, max: 60, step: 1, unit: 's' },
      { key: 'warn_cd_fake_presence',   label: 'Fake Presence',   min: 1, max: 120, step: 5, unit: 's' },
      { key: 'warn_cd_phone',           label: 'Phone',           min: 1, max: 60,  step: 1, unit: 's' },
      { key: 'warn_cd_multiple_people', label: 'Multiple People', min: 1, max: 60,  step: 1, unit: 's' },
      { key: 'warn_cd_no_person',       label: 'No Person',       min: 1, max: 60,  step: 1, unit: 's' },
      { key: 'warn_cd_book',            label: 'Book',            min: 1, max: 60,  step: 5, unit: 's' },
      { key: 'warn_cd_headphone',       label: 'Headphone',       min: 1, max: 60,  step: 5, unit: 's' },
      { key: 'warn_cd_earbud',          label: 'Earbud',          min: 1, max: 60,  step: 5, unit: 's' },
      { key: 'warn_cd_speaker_audio',   label: 'Speaker Audio',   min: 1, max: 60,  step: 1, unit: 's' },
    ],
  },
  {
    title: 'Speaker Audio',
    desc: 'Controls for speech-without-lip-movement detection. Episode 1 = first continuous speech event; Episode 2+ = subsequent ones.',
    fields: [
      { key: 'speaker_warn_cooldown',   label: 'Warning Cooldown',       min: 1, max: 30, step: 1, unit: 's' },
      { key: 'speaker_alert_cooldown',  label: 'Alert Cooldown',         min: 1, max: 60, step: 1, unit: 's' },
      { key: 'speaker_occ1_warn_s',     label: 'Ep.1 — Warn After',     min: 1, max: 30, step: 0.5, unit: 's', desc: 'Seconds before first warning in episode 1' },
      { key: 'speaker_occ1_score',      label: 'Ep.1 — Score',          min: 1, max: 50, step: 1, unit: 'pts' },
      { key: 'speaker_occ1_repeat',     label: 'Ep.1 — Repeat Score',   min: 1, max: 50, step: 1, unit: 'pts' },
      { key: 'speaker_occ2_warn_s',     label: 'Ep.2+ — Warn After',    min: 1, max: 30, step: 0.5, unit: 's', desc: 'Seconds before first warning in episode 2+' },
      { key: 'speaker_occ2_score',      label: 'Ep.2+ — Score',         min: 1, max: 100, step: 5, unit: 'pts' },
      { key: 'speaker_occ2_repeat',     label: 'Ep.2+ — Repeat Score',  min: 1, max: 100, step: 5, unit: 'pts' },
      { key: 'speaker_repeat_interval', label: 'Repeat Interval',       min: 3, max: 60,  step: 1, unit: 's', desc: 'Gap between repeating score additions within an episode' },
    ],
  },
  {
    title: 'YOLO Confidence',
    desc: 'Minimum detection confidence for object-based violations. Higher = fewer false positives.',
    fields: [
      { key: 'yolo_phone_conf',  label: 'Phone',        min: 0.10, max: 0.95, step: 0.05 },
      { key: 'yolo_book_conf',   label: 'Book',         min: 0.10, max: 0.95, step: 0.05 },
      { key: 'yolo_audio_conf',  label: 'Audio Device', min: 0.10, max: 0.95, step: 0.05 },
      { key: 'yolo_person_conf', label: 'Person',       min: 0.10, max: 0.95, step: 0.05 },
    ],
  },
  {
    title: 'Identity Verification',
    desc: 'In-exam face identity checks run silently at random intervals. Failing all retries terminates the session.',
    fields: [
      { key: 'identity_check_count',       label: 'Checks per Exam',        min: 1,  max: 20,  step: 1,   unit: '' },
      { key: 'identity_check_retries',     label: 'Retries on Failure',     min: 1,  max: 10,  step: 1,   unit: '' },
      { key: 'identity_check_retry_delay', label: 'Delay Between Retries',  min: 3,  max: 60,  step: 1,   unit: 's' },
    ],
  },
  {
    title: 'Object Detection Sensitivity',
    desc: 'Minimum votes (frames within the detection window) required to confirm a physical object detection. Higher = less sensitive, fewer false positives.',
    fields: [
      { key: 'object_window',       label: 'Detection Window',    min: 5,  max: 60, step: 1, unit: 'frames', desc: 'Sliding window size (number of frames evaluated for voting)' },
      { key: 'phone_min_votes',     label: 'Phone Min Votes',     min: 1,  max: 60, step: 1, unit: '' },
      { key: 'book_min_votes',      label: 'Book Min Votes',      min: 1,  max: 60, step: 1, unit: '' },
      { key: 'headphone_min_votes', label: 'Headphone Min Votes', min: 1,  max: 60, step: 1, unit: '' },
      { key: 'earbud_min_votes',    label: 'Earbud Min Votes',    min: 1,  max: 60, step: 1, unit: '' },
      { key: 'object_min_votes',    label: 'Default Min Votes',   min: 1,  max: 60, step: 1, unit: '', desc: 'Fallback vote threshold for unlisted object types' },
    ],
  },
];

// ── Toggle field ──────────────────────────────────────────────────────────────
function ToggleField({ meta, value, savedValue, onChange }: {
  meta: ToggleMeta; value: boolean; savedValue: boolean; onChange: (v: boolean) => void;
}) {
  const isChanged = value !== savedValue;
  return (
    <button
      type="button"
      onClick={() => onChange(!value)}
      className="flex items-center justify-between gap-3 w-full px-3 py-2.5 rounded-lg border text-left transition-colors"
      style={{
        background: value ? '#F0FDF4' : '#F8FAFC',
        borderColor: value ? '#BBF7D0' : '#E2E8F0',
      }}
    >
      <div className="flex items-center gap-2 min-w-0">
        <span className="text-sm font-medium truncate" style={{ color: '#0F172A' }}>{meta.label}</span>
        {isChanged && (
          <span className="shrink-0 text-[10px] px-1.5 py-0.5 rounded font-semibold"
            style={{ background: '#FFFBEB', color: '#B45309', border: '1px solid #FDE68A' }}>
            modified
          </span>
        )}
      </div>
      {value
        ? <ToggleRight className="h-5 w-5 shrink-0" style={{ color: '#15803D' }} />
        : <ToggleLeft  className="h-5 w-5 shrink-0" style={{ color: '#94A3B8' }} />
      }
    </button>
  );
}

// ── Slider ────────────────────────────────────────────────────────────────────
function SettingSlider({ field, value, savedValue, onChange }: {
  field: FieldMeta; value: number; savedValue: number; onChange: (v: number) => void;
}) {
  const [localStr, setLocalStr] = useState(String(value));
  useEffect(() => { setLocalStr(String(value)); }, [value]);

  const commit = (raw: string) => {
    const n = parseFloat(raw);
    if (!isNaN(n)) {
      const c = Math.min(field.max, Math.max(field.min, n));
      onChange(c); setLocalStr(String(c));
    } else { setLocalStr(String(value)); }
  };

  const pct       = field.max === field.min ? 0 : ((value - field.min) / (field.max - field.min)) * 100;
  const isChanged = value !== savedValue;

  return (
    <div className="space-y-1.5">
      <div className="flex items-center justify-between gap-2">
        <div className="flex items-center gap-2 min-w-0">
          <span className="text-sm font-medium truncate" style={{ color: '#0F172A' }}>{field.label}</span>
          {isChanged && (
            <span className="shrink-0 text-[10px] px-1.5 py-0.5 rounded font-semibold"
              style={{ background: '#FFFBEB', color: '#B45309', border: '1px solid #FDE68A' }}>
              modified
            </span>
          )}
        </div>
        {field.unit && (
          <span className="shrink-0 text-[10px] font-semibold uppercase tracking-wider" style={{ color: '#64748B' }}>{field.unit}</span>
        )}
      </div>
      {field.desc && <p className="text-xs font-medium" style={{ color: '#64748B' }}>{field.desc}</p>}
      <div className="flex items-center gap-3">
        <div className="flex-1 relative">
          <input
            type="range" min={field.min} max={field.max} step={field.step} value={value}
            onChange={e => onChange(parseFloat(e.target.value))}
            className="w-full h-1 rounded-full appearance-none cursor-pointer"
            style={{ background: `linear-gradient(to right, #22577A ${pct}%, #E2E8F0 ${pct}%)`, accentColor: '#22577A' }}
          />
        </div>
        <input
          type="number" min={field.min} max={field.max} step={field.step}
          value={localStr}
          onChange={e => setLocalStr(e.target.value)}
          onBlur={e => { commit(e.target.value); (e.target as HTMLElement).style.borderColor = '#E2E8F0'; (e.target as HTMLElement).style.background = '#F8FAFC'; }}
          onKeyDown={e => e.key === 'Enter' && commit(localStr)}
          className="w-[4.5rem] px-2 py-1.5 text-xs text-right rounded-lg font-mono outline-none transition-all"
          style={{ border: '1px solid #E2E8F0', color: '#0F172A', background: '#F8FAFC' }}
          onFocus={e => { (e.target as HTMLElement).style.borderColor = '#38A3A5'; (e.target as HTMLElement).style.background = '#fff'; }}
        />
      </div>
    </div>
  );
}

// ── Page ──────────────────────────────────────────────────────────────────────
export default function SystemSettingsPage() {
  const [numValues,  setNumValues]  = useState<NumSettings>({ ...NUM_DEFAULTS });
  const [boolValues, setBoolValues] = useState<BoolSettings>({ ...BOOL_DEFAULTS });
  const [savedNum,   setSavedNum]   = useState<NumSettings>({ ...NUM_DEFAULTS });
  const [savedBool,  setSavedBool]  = useState<BoolSettings>({ ...BOOL_DEFAULTS });
  const [isLoading,  setIsLoading]  = useState(true);
  const [isSaving,   setIsSaving]   = useState(false);
  const [lastUpdated, setLastUpdated] = useState<string | null>(null);

  useEffect(() => {
    api.get('/admin/system-settings')
      .then(res => {
        const { id, updated_at, ...fields } = res.data;
        const n: any = { ...NUM_DEFAULTS };
        const b: any = { ...BOOL_DEFAULTS };
        Object.entries(fields).forEach(([k, v]) => {
          if (k in NUM_DEFAULTS)  n[k] = v;
          if (k in BOOL_DEFAULTS) b[k] = v;
        });
        setNumValues(n);  setSavedNum(n);
        setBoolValues(b); setSavedBool(b);
        setLastUpdated(updated_at);
      })
      .catch(() => toast.error('Failed to load engine settings'))
      .finally(() => setIsLoading(false));
  }, []);

  const setNum  = (key: NumKey)  => (v: number)  => setNumValues(prev  => ({ ...prev, [key]: v }));
  const setBool = (key: BoolKey) => (v: boolean) => setBoolValues(prev => ({ ...prev, [key]: v }));

  const handleSave = async () => {
    setIsSaving(true);
    try {
      await api.post('/admin/system-settings', { ...numValues, ...boolValues });
      toast.success('Settings saved — click Apply & Restart on Engine Monitor to push to engine');
      setSavedNum({ ...numValues }); setSavedBool({ ...boolValues });
      setLastUpdated(new Date().toISOString());
    } catch (err: any) {
      const detail = err.response?.data?.detail;
      toast.error(typeof detail === 'string' ? detail : Array.isArray(detail) ? detail[0]?.msg : 'Failed to save settings');
    } finally { setIsSaving(false); }
  };

  const handleReset = () => {
    setNumValues({ ...NUM_DEFAULTS });
    setBoolValues({ ...BOOL_DEFAULTS });
    toast.info('Reset to defaults — click Save to apply');
  };

  const numChanged  = Object.entries(numValues).filter(([k, v])  => (savedNum  as any)[k] !== v).length;
  const boolChanged = Object.entries(boolValues).filter(([k, v]) => (savedBool as any)[k] !== v).length;
  const changedCount = numChanged + boolChanged;

  if (isLoading) {
    return (
      <div className="flex items-center justify-center p-24">
        <Loader2 className="h-7 w-7 animate-spin" style={{ color: '#94A3B8' }} />
      </div>
    );
  }

  return (
    <div className="max-w-4xl mx-auto space-y-6 pb-28">
      {/* Header */}
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2.5" style={{ color: '#0F172A', letterSpacing: '-0.025em' }}>
            <SlidersHorizontal className="h-6 w-6" style={{ color: '#22577A' }} />
            Engine Settings
          </h1>
          <p className="text-sm mt-1 font-medium" style={{ color: '#64748B' }}>
            Save here, then go to <span className="font-semibold">Engine Monitor → Apply &amp; Restart</span> to push to the engine.
            {lastUpdated && <span className="ml-1.5">Last saved: {new Date(lastUpdated).toLocaleString()}</span>}
          </p>
        </div>
        <div className="flex gap-2 shrink-0">
          <button onClick={handleReset}
            className="flex items-center gap-2 px-3 py-2 rounded-lg text-sm font-medium border transition-all"
            style={{ borderColor: '#E2E8F0', color: '#475569', background: '#fff' }}>
            <RotateCcw className="h-3.5 w-3.5" /> Reset
          </button>
          <button onClick={handleSave} disabled={isSaving}
            className="flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-semibold text-white transition-all"
            style={{ background: isSaving ? '#94A3B8' : '#22577A' }}>
            {isSaving ? <Loader2 className="h-4 w-4 animate-spin" /> : <Save className="h-4 w-4" />}
            Save{changedCount > 0 ? ` (${changedCount})` : ''}
          </button>
        </div>
      </div>

      {changedCount > 0 && (
        <div className="flex items-center gap-2 px-4 py-3 rounded-xl text-sm border"
          style={{ background: '#FFFBEB', borderColor: '#FDE68A', color: '#B45309' }}>
          <span className="font-semibold">{changedCount} unsaved change{changedCount !== 1 ? 's' : ''}</span>
          — save first, then Apply &amp; Restart on Engine Monitor.
        </div>
      )}

      {/* Sections */}
      {SECTIONS.map(section => (
        <div key={section.title} className="bg-white rounded-xl border overflow-hidden"
          style={{ borderColor: '#E2E8F0', boxShadow: '0 1px 3px rgba(15,23,42,0.04)' }}>
          <div className="px-6 py-4" style={{ borderBottom: '1px solid #F1F5F9' }}>
            <p className="text-sm font-semibold" style={{ color: '#0F172A' }}>{section.title}</p>
            {section.desc && <p className="text-xs mt-0.5 font-medium" style={{ color: '#64748B' }}>{section.desc}</p>}
          </div>
          <div className="p-6">
            {section.toggles && (
              <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 gap-2">
                {section.toggles.map(t => (
                  <ToggleField
                    key={t.key}
                    meta={t}
                    value={boolValues[t.key]}
                    savedValue={savedBool[t.key]}
                    onChange={setBool(t.key)}
                  />
                ))}
              </div>
            )}
            {section.fields && (
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-x-10 gap-y-6">
                {section.fields.map(f => (
                  <SettingSlider
                    key={f.key}
                    field={f}
                    value={numValues[f.key]}
                    savedValue={savedNum[f.key]}
                    onChange={setNum(f.key)}
                  />
                ))}
              </div>
            )}
          </div>
        </div>
      ))}

      {/* Sticky save bar */}
      <div className="fixed bottom-0 left-0 right-0 z-30 lg:left-64"
        style={{ background: '#fff', borderTop: '1px solid #E2E8F0', boxShadow: '0 -4px 12px rgba(15,23,42,0.06)' }}>
        <div className="flex items-center justify-between px-6 py-3 max-w-4xl mx-auto">
          <p className="text-sm">
            {changedCount > 0 ? (
              <span className="font-semibold" style={{ color: '#B45309' }}>
                {changedCount} unsaved change{changedCount !== 1 ? 's' : ''}
              </span>
            ) : (
              <span className="font-medium" style={{ color: '#64748B' }}>All settings saved</span>
            )}
          </p>
          <div className="flex gap-2">
            <button onClick={handleReset}
              className="flex items-center gap-2 px-3 py-2 rounded-lg text-sm font-medium border"
              style={{ borderColor: '#E2E8F0', color: '#475569', background: '#fff' }}>
              <RotateCcw className="h-3.5 w-3.5" /> Defaults
            </button>
            <button onClick={handleSave} disabled={isSaving}
              className="flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-semibold text-white"
              style={{ background: isSaving ? '#94A3B8' : '#22577A' }}>
              {isSaving ? <Loader2 className="h-4 w-4 animate-spin" /> : <Save className="h-4 w-4" />}
              Save Settings
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
