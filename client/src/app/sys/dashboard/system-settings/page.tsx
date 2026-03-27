'use client';

import { useState, useEffect } from 'react';
import { toast } from 'sonner';
import { Loader2, SlidersHorizontal, Save, RotateCcw } from 'lucide-react';
import api from '@/lib/axios';

// ── Defaults ──────────────────────────────────────────────────────────────────
const DEFAULTS = {
  look_away_yaw: 0.20, look_down_pitch: 0.13, look_up_pitch: -0.10,
  gaze_left: -0.13, gaze_right: 0.13,
  looking_away_threshold: 2.0, gaze_threshold: 1.5, fake_window: 15.0,
  gaze_score: 5.0, phone_score_2nd: 25.0, phone_score_3rd: 50.0,
  book_score: 20.0, headphone_score: 20.0, earbud_score: 20.0,
  tab_switch_score: 15.0, multi_people_score_2nd: 20.0, multi_people_score_3rd: 50.0,
  no_person_score_1: 25.0, no_person_score_2: 50.0,
  fake_presence_score_1: 30.0, fake_presence_score_2: 60.0,
  state_warning: 30.0, state_high_risk: 60.0, state_admin_review: 100.0,
  decay_amount: 5.0,
  tab_switch_terminate_count: 3, multi_people_terminate_s: 20.0, no_person_terminate_s: 20.0,
  yolo_phone_conf: 0.65, yolo_book_conf: 0.70, yolo_audio_conf: 0.41, yolo_person_conf: 0.30,
};

type SettingsKey = keyof typeof DEFAULTS;
type Settings = typeof DEFAULTS;

interface FieldMeta {
  label: string; key: SettingsKey; min: number; max: number; step: number;
  unit?: string; desc?: string;
}

const SECTIONS: { title: string; desc?: string; fields: FieldMeta[] }[] = [
  {
    title: 'Head Pose Thresholds',
    desc: 'Angular thresholds for detecting head movement events.',
    fields: [
      { key: 'look_away_yaw',   label: 'Yaw — Look Away',   min: 0.05, max: 0.50, step: 0.01, desc: 'Horizontal head turn angle' },
      { key: 'look_down_pitch', label: 'Pitch — Look Down',  min: 0.05, max: 0.40, step: 0.01, desc: 'Downward pitch threshold' },
      { key: 'look_up_pitch',   label: 'Pitch — Look Up',    min: -0.40, max: -0.02, step: 0.01, desc: 'Upward pitch (negative)' },
      { key: 'gaze_left',       label: 'Gaze Left',          min: -0.40, max: -0.02, step: 0.01, desc: 'Leftward gaze (negative)' },
      { key: 'gaze_right',      label: 'Gaze Right',         min: 0.02, max: 0.40, step: 0.01, desc: 'Rightward gaze threshold' },
    ],
  },
  {
    title: 'Duration Gates',
    desc: 'How long a condition must persist before it triggers an event.',
    fields: [
      { key: 'looking_away_threshold', label: 'Looking Away Hold', min: 0.5, max: 10, step: 0.5, unit: 's', desc: 'Continuous look-away before event fires' },
      { key: 'gaze_threshold',         label: 'Off-Gaze Hold',     min: 0.5, max: 10, step: 0.5, unit: 's', desc: 'Continuous off-gaze before event fires' },
      { key: 'fake_window',            label: 'Fake Presence Window', min: 5, max: 60, step: 1, unit: 's', desc: 'Rolling window for fake presence detection' },
    ],
  },
  {
    title: 'Risk Scores',
    desc: 'Points added to risk score when each event is detected.',
    fields: [
      { key: 'gaze_score',             label: 'Gaze Event',           min: 1,  max: 30,  step: 1,  unit: 'pts' },
      { key: 'phone_score_2nd',        label: 'Phone — 2nd Offence',  min: 5,  max: 100, step: 5,  unit: 'pts' },
      { key: 'phone_score_3rd',        label: 'Phone — 3rd Offence',  min: 5,  max: 150, step: 5,  unit: 'pts' },
      { key: 'book_score',             label: 'Book Detected',        min: 5,  max: 80,  step: 5,  unit: 'pts' },
      { key: 'headphone_score',        label: 'Headphone',            min: 5,  max: 80,  step: 5,  unit: 'pts' },
      { key: 'earbud_score',           label: 'Earbud',               min: 5,  max: 80,  step: 5,  unit: 'pts' },
      { key: 'tab_switch_score',       label: 'Tab Switch',           min: 5,  max: 50,  step: 5,  unit: 'pts' },
      { key: 'multi_people_score_2nd', label: 'Multiple People 2nd',  min: 5,  max: 100, step: 5,  unit: 'pts' },
      { key: 'multi_people_score_3rd', label: 'Multiple People 3rd',  min: 5,  max: 150, step: 5,  unit: 'pts' },
      { key: 'no_person_score_1',      label: 'No Person — Tier 1',   min: 5,  max: 100, step: 5,  unit: 'pts' },
      { key: 'no_person_score_2',      label: 'No Person — Tier 2',   min: 5,  max: 150, step: 5,  unit: 'pts' },
      { key: 'fake_presence_score_1',  label: 'Fake Presence Tier 1', min: 5,  max: 100, step: 5,  unit: 'pts' },
      { key: 'fake_presence_score_2',  label: 'Fake Presence Tier 2', min: 5,  max: 150, step: 5,  unit: 'pts' },
    ],
  },
  {
    title: 'Risk State Thresholds',
    desc: 'Score levels at which session risk state escalates.',
    fields: [
      { key: 'state_warning',      label: 'Warning Threshold',      min: 10, max: 80,  step: 5,  unit: 'pts', desc: 'Enters WARNING state' },
      { key: 'state_high_risk',    label: 'High Risk Threshold',    min: 30, max: 120, step: 5,  unit: 'pts', desc: 'Enters HIGH_RISK state' },
      { key: 'state_admin_review', label: 'Admin Review Threshold', min: 60, max: 200, step: 5,  unit: 'pts', desc: 'Enters ADMIN_REVIEW state' },
      { key: 'decay_amount',       label: 'Decay per Cycle',        min: 1,  max: 30,  step: 1,  unit: 'pts', desc: 'Score reduced each cycle without new events' },
    ],
  },
  {
    title: 'Termination Rules',
    desc: 'Thresholds that trigger automatic session termination.',
    fields: [
      { key: 'tab_switch_terminate_count', label: 'Tab Switches → Terminate', min: 2, max: 10, step: 1,  desc: 'Number of tab switches before auto-terminate' },
      { key: 'multi_people_terminate_s',   label: 'Multi-Person → Terminate', min: 5, max: 60, step: 5, unit: 's', desc: 'Continuous multi-person before terminate' },
      { key: 'no_person_terminate_s',      label: 'No Person → Terminate',    min: 5, max: 60, step: 5, unit: 's', desc: 'Continuous absence before terminate' },
    ],
  },
  {
    title: 'YOLO Confidence',
    desc: 'Minimum confidence scores for object detection triggers.',
    fields: [
      { key: 'yolo_phone_conf',  label: 'Phone Confidence',      min: 0.10, max: 0.95, step: 0.05 },
      { key: 'yolo_book_conf',   label: 'Book Confidence',       min: 0.10, max: 0.95, step: 0.05 },
      { key: 'yolo_audio_conf',  label: 'Audio Device Conf.',    min: 0.10, max: 0.95, step: 0.05 },
      { key: 'yolo_person_conf', label: 'Person Confidence',     min: 0.10, max: 0.95, step: 0.05 },
    ],
  },
];

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
            type="range"
            min={field.min} max={field.max} step={field.step}
            value={value}
            onChange={e => onChange(parseFloat(e.target.value))}
            className="w-full h-1 rounded-full appearance-none cursor-pointer"
            style={{
              background: `linear-gradient(to right, #22577A ${pct}%, #E2E8F0 ${pct}%)`,
              accentColor: '#22577A',
            }}
          />
        </div>
        <input
          type="number"
          min={field.min} max={field.max} step={field.step}
          value={localStr}
          onChange={e => setLocalStr(e.target.value)}
          onBlur={e => {
            commit(e.target.value);
            (e.target as HTMLElement).style.borderColor = '#E2E8F0';
            (e.target as HTMLElement).style.background = '#F8FAFC';
          }}
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
  const [values, setValues]         = useState<Settings>({ ...DEFAULTS });
  const [savedValues, setSavedValues] = useState<Settings>({ ...DEFAULTS });
  const [isLoading, setIsLoading]   = useState(true);
  const [isSaving, setIsSaving]     = useState(false);
  const [lastUpdated, setLastUpdated] = useState<string | null>(null);

  useEffect(() => {
    api.get('/admin/system-settings')
      .then(res => {
        const { id, updated_at, ...fields } = res.data;
        const fetched = { ...DEFAULTS, ...fields };
        setValues(fetched); setSavedValues(fetched); setLastUpdated(updated_at);
      })
      .catch(() => toast.error('Failed to load engine settings'))
      .finally(() => setIsLoading(false));
  }, []);

  const set = (key: SettingsKey) => (v: number) => setValues(prev => ({ ...prev, [key]: v }));

  const handleSave = async () => {
    setIsSaving(true);
    try {
      await api.post('/admin/system-settings', values);
      toast.success('Engine settings saved — applies to new sessions');
      setSavedValues(values); setLastUpdated(new Date().toISOString());
    } catch (err: any) {
      const detail = err.response?.data?.detail;
      toast.error(typeof detail === 'string' ? detail : Array.isArray(detail) ? detail[0]?.msg : 'Failed to save settings');
    } finally { setIsSaving(false); }
  };

  const handleReset = () => { setValues({ ...DEFAULTS }); toast.info('Reset to defaults — click Save to apply'); };

  const changedCount = Object.entries(values).filter(([k, v]) => (savedValues as any)[k] !== v).length;

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
            Global AI proctoring thresholds and scoring rules.
            {lastUpdated && (
              <span className="ml-1.5">Last saved: {new Date(lastUpdated).toLocaleString()}</span>
            )}
          </p>
        </div>
        <div className="flex gap-2 shrink-0">
          <button onClick={handleReset}
            className="flex items-center gap-2 px-3 py-2 rounded-lg text-sm font-medium border transition-all duration-150"
            style={{ borderColor: '#E2E8F0', color: '#475569', background: '#fff' }}>
            <RotateCcw className="h-3.5 w-3.5" /> Reset
          </button>
          <button onClick={handleSave} disabled={isSaving}
            className="flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-semibold text-white transition-all duration-150"
            style={{ background: isSaving ? '#94A3B8' : '#22577A' }}>
            {isSaving ? <Loader2 className="h-4 w-4 animate-spin" /> : <Save className="h-4 w-4" />}
            Save{changedCount > 0 ? ` (${changedCount})` : ''}
          </button>
        </div>
      </div>

      {/* Unsaved changes banner */}
      {changedCount > 0 && (
        <div className="flex items-center gap-2 px-4 py-3 rounded-xl text-sm border"
          style={{ background: '#FFFBEB', borderColor: '#FDE68A', color: '#B45309' }}>
          <span className="font-semibold">{changedCount} unsaved change{changedCount !== 1 ? 's' : ''}</span>
          — click Save to apply to new sessions.
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
          <div className="p-6 grid grid-cols-1 sm:grid-cols-2 gap-x-10 gap-y-6">
            {section.fields.map(f => (
              <SettingSlider
                key={f.key}
                field={f}
                value={values[f.key] as number}
                savedValue={savedValues[f.key] as number}
                onChange={set(f.key)}
              />
            ))}
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
              className="flex items-center gap-2 px-3 py-2 rounded-lg text-sm font-medium border transition-all duration-150"
              style={{ borderColor: '#E2E8F0', color: '#475569', background: '#fff' }}>
              <RotateCcw className="h-3.5 w-3.5" /> Defaults
            </button>
            <button onClick={handleSave} disabled={isSaving}
              className="flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-semibold text-white transition-all duration-150"
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
