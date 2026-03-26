'use client';

import { useState, useEffect } from 'react';
import { toast } from 'sonner';
import { Loader2, SlidersHorizontal, Save, RotateCcw } from 'lucide-react';
import api from '@/lib/axios';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';

// ── Defaults ─────────────────────────────────────────────────────────────────

const DEFAULTS = {
  // Head pose
  look_away_yaw: 0.20,
  look_down_pitch: 0.13,
  look_up_pitch: -0.10,
  gaze_left: -0.13,
  gaze_right: 0.13,
  // Duration gates
  looking_away_threshold: 2.0,
  gaze_threshold: 1.5,
  fake_window: 15.0,
  // Risk scores
  gaze_score: 5.0,
  phone_score_2nd: 25.0,
  phone_score_3rd: 50.0,
  book_score: 20.0,
  headphone_score: 20.0,
  earbud_score: 20.0,
  tab_switch_score: 15.0,
  multi_people_score_2nd: 20.0,
  multi_people_score_3rd: 50.0,
  no_person_score_1: 25.0,
  no_person_score_2: 50.0,
  fake_presence_score_1: 30.0,
  fake_presence_score_2: 60.0,
  // State thresholds
  state_warning: 30.0,
  state_high_risk: 60.0,
  state_admin_review: 100.0,
  // Decay
  decay_amount: 5.0,
  // Termination
  tab_switch_terminate_count: 3,
  multi_people_terminate_s: 20.0,
  no_person_terminate_s: 20.0,
  // YOLO confidence
  yolo_phone_conf: 0.65,
  yolo_book_conf: 0.70,
  yolo_audio_conf: 0.41,
  yolo_person_conf: 0.30,
};

type SettingsKey = keyof typeof DEFAULTS;
type Settings = typeof DEFAULTS;

// ── Field metadata ─────────────────────────────────────────────────────────

interface FieldMeta {
  label: string;
  key: SettingsKey;
  min: number;
  max: number;
  step: number;
  unit?: string;
  desc?: string;
}

const SECTIONS: { title: string; fields: FieldMeta[] }[] = [
  {
    title: 'Head Pose Thresholds',
    fields: [
      { key: 'look_away_yaw',    label: 'Yaw (look away)',      min: 0.05, max: 0.50, step: 0.01,  desc: 'Horizontal head turn angle before "looking away" triggers' },
      { key: 'look_down_pitch',  label: 'Pitch (look down)',    min: 0.05, max: 0.40, step: 0.01,  desc: 'Downward pitch angle threshold' },
      { key: 'look_up_pitch',    label: 'Pitch (look up)',      min: -0.40,max: -0.02, step: 0.01, desc: 'Upward pitch — negative value' },
      { key: 'gaze_left',        label: 'Gaze left',            min: -0.40,max: -0.02, step: 0.01, desc: 'Leftward gaze threshold — negative value' },
      { key: 'gaze_right',       label: 'Gaze right',           min: 0.02, max: 0.40, step: 0.01,  desc: 'Rightward gaze threshold' },
    ],
  },
  {
    title: 'Duration Gates (seconds)',
    fields: [
      { key: 'looking_away_threshold', label: 'Looking away hold', min: 0.5, max: 10, step: 0.5, unit: 's', desc: 'Continuous looking-away before event fires' },
      { key: 'gaze_threshold',         label: 'Gaze hold',         min: 0.5, max: 10, step: 0.5, unit: 's', desc: 'Continuous off-gaze before event fires' },
      { key: 'fake_window',            label: 'Fake presence window', min: 5, max: 60, step: 1,  unit: 's', desc: 'Rolling window used to detect fake presence' },
    ],
  },
  {
    title: 'Risk Scores',
    fields: [
      { key: 'gaze_score',            label: 'Gaze event',          min: 1,  max: 30,  step: 1,  unit: 'pts' },
      { key: 'phone_score_2nd',       label: 'Phone (2nd offence)', min: 5,  max: 100, step: 5,  unit: 'pts' },
      { key: 'phone_score_3rd',       label: 'Phone (3rd offence)', min: 5,  max: 150, step: 5,  unit: 'pts' },
      { key: 'book_score',            label: 'Book',                min: 5,  max: 80,  step: 5,  unit: 'pts' },
      { key: 'headphone_score',       label: 'Headphone',           min: 5,  max: 80,  step: 5,  unit: 'pts' },
      { key: 'earbud_score',          label: 'Earbud',              min: 5,  max: 80,  step: 5,  unit: 'pts' },
      { key: 'tab_switch_score',      label: 'Tab switch',          min: 5,  max: 50,  step: 5,  unit: 'pts' },
      { key: 'multi_people_score_2nd',label: 'Multi-people (2nd)',  min: 5,  max: 100, step: 5,  unit: 'pts' },
      { key: 'multi_people_score_3rd',label: 'Multi-people (3rd)',  min: 5,  max: 150, step: 5,  unit: 'pts' },
      { key: 'no_person_score_1',     label: 'No person (tier 1)', min: 5,  max: 100, step: 5,  unit: 'pts' },
      { key: 'no_person_score_2',     label: 'No person (tier 2)', min: 5,  max: 150, step: 5,  unit: 'pts' },
      { key: 'fake_presence_score_1', label: 'Fake presence (t1)', min: 5,  max: 100, step: 5,  unit: 'pts' },
      { key: 'fake_presence_score_2', label: 'Fake presence (t2)', min: 5,  max: 150, step: 5,  unit: 'pts' },
    ],
  },
  {
    title: 'Risk State Thresholds',
    fields: [
      { key: 'state_warning',      label: 'Warning',       min: 10, max: 80,  step: 5,  unit: 'pts', desc: 'Score at which session enters WARNING state' },
      { key: 'state_high_risk',    label: 'High Risk',     min: 30, max: 120, step: 5,  unit: 'pts', desc: 'Score at which session enters HIGH_RISK state' },
      { key: 'state_admin_review', label: 'Admin Review',  min: 60, max: 200, step: 5,  unit: 'pts', desc: 'Score at which session enters ADMIN_REVIEW state' },
      { key: 'decay_amount',       label: 'Decay amount',  min: 1,  max: 30,  step: 1,  unit: 'pts', desc: 'Score decayed per cycle when no violations occur' },
    ],
  },
  {
    title: 'Termination Rules',
    fields: [
      { key: 'tab_switch_terminate_count', label: 'Tab switches → terminate', min: 2, max: 10, step: 1,  desc: 'Number of tab switches before auto-terminate' },
      { key: 'multi_people_terminate_s',   label: 'Multi-people → terminate', min: 5, max: 60, step: 5, unit: 's', desc: 'Continuous multi-person detection before terminate' },
      { key: 'no_person_terminate_s',      label: 'No person → terminate',    min: 5, max: 60, step: 5, unit: 's', desc: 'Continuous no-person detection before terminate' },
    ],
  },
  {
    title: 'YOLO Confidence Thresholds',
    fields: [
      { key: 'yolo_phone_conf',  label: 'Phone confidence',  min: 0.10, max: 0.95, step: 0.05, desc: 'Minimum YOLO confidence to detect phone' },
      { key: 'yolo_book_conf',   label: 'Book confidence',   min: 0.10, max: 0.95, step: 0.05, desc: 'Minimum YOLO confidence to detect book' },
      { key: 'yolo_audio_conf',  label: 'Audio confidence',  min: 0.10, max: 0.95, step: 0.05, desc: 'Minimum YOLO confidence for headphone/earbud' },
      { key: 'yolo_person_conf', label: 'Person confidence', min: 0.10, max: 0.95, step: 0.05, desc: 'Minimum YOLO confidence for person detection' },
    ],
  },
];

// ── Slider + number input ─────────────────────────────────────────────────────

function SettingSlider({
  field, value, savedValue, onChange,
}: {
  field: FieldMeta;
  value: number;
  savedValue: number;
  onChange: (v: number) => void;
}) {
  const [localStr, setLocalStr] = useState(String(value));

  // Sync when value changes externally
  useEffect(() => { setLocalStr(String(value)); }, [value]);

  function commit(raw: string) {
    const n = parseFloat(raw);
    if (!isNaN(n)) {
      const clamped = Math.min(field.max, Math.max(field.min, n));
      onChange(clamped);
      setLocalStr(String(clamped));
    } else {
      setLocalStr(String(value));
    }
  }

  const pct = field.max === field.min ? 0 : ((value - field.min) / (field.max - field.min)) * 100;
  const isChanged = value !== savedValue;

  return (
    <div className="space-y-1.5">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-1.5">
          <span className="text-sm font-medium text-slate-700">{field.label}</span>
          {isChanged && <span className="text-xs px-1.5 py-0.5 rounded bg-amber-100 text-amber-600 border border-amber-200">modified</span>}
        </div>
        {field.unit && <span className="text-xs text-slate-400">{field.unit}</span>}
      </div>
      {field.desc && <p className="text-xs text-slate-400">{field.desc}</p>}
      <div className="flex items-center gap-3">
        <div className="relative flex-1">
          <input
            type="range"
            min={field.min} max={field.max} step={field.step}
            value={value}
            onChange={e => onChange(parseFloat(e.target.value))}
            className="w-full h-1.5 rounded-full appearance-none cursor-pointer accent-indigo-600"
            style={{
              background: `linear-gradient(to right, #6366f1 ${pct}%, #e2e8f0 ${pct}%)`,
            }}
          />
        </div>
        <input
          type="number"
          min={field.min} max={field.max} step={field.step}
          value={localStr}
          onChange={e => setLocalStr(e.target.value)}
          onBlur={e => commit(e.target.value)}
          onKeyDown={e => e.key === 'Enter' && commit(localStr)}
          className="w-20 px-2 py-1 text-sm text-right rounded-lg border border-slate-200 font-mono bg-white focus:outline-none focus:ring-2 focus:ring-indigo-300"
        />
      </div>
    </div>
  );
}

// ── Page ─────────────────────────────────────────────────────────────────────

export default function SystemSettingsPage() {
  const [values, setValues] = useState<Settings>({ ...DEFAULTS });
  const [savedValues, setSavedValues] = useState<Settings>({ ...DEFAULTS });
  const [isLoading, setIsLoading] = useState(true);
  const [isSaving, setIsSaving] = useState(false);
  const [lastUpdated, setLastUpdated] = useState<string | null>(null);

  useEffect(() => {
    api.get('/admin/system-settings')
      .then(res => {
        const { id, updated_at, ...fields } = res.data;
        const fetched = { ...DEFAULTS, ...fields };
        setValues(fetched);
        setSavedValues(fetched);
        setLastUpdated(updated_at);
      })
      .catch(() => toast.error('Failed to load engine settings'))
      .finally(() => setIsLoading(false));
  }, []);

  const set = (key: SettingsKey) => (v: number) => setValues(prev => ({ ...prev, [key]: v }));

  const handleSave = async () => {
    setIsSaving(true);
    try {
      await api.post('/admin/system-settings', values);
      toast.success('Engine settings saved and will apply to new sessions');
      setSavedValues(values);
      setLastUpdated(new Date().toISOString());
    } catch (err: any) {
      const detail = err.response?.data?.detail;
      toast.error(typeof detail === 'string' ? detail : Array.isArray(detail) ? detail[0]?.msg : 'Failed to save settings');
    } finally {
      setIsSaving(false);
    }
  };

  const handleReset = () => {
    setValues({ ...DEFAULTS });
    toast.info('Values reset to defaults — click Save to apply');
  };

  const changedCount = Object.entries(values).filter(
    ([k, v]) => (savedValues as any)[k] !== v
  ).length;

  if (isLoading) {
    return <div className="flex justify-center p-24"><Loader2 className="h-8 w-8 animate-spin text-slate-400" /></div>;
  }

  return (
    <div className="max-w-4xl mx-auto space-y-6 pb-24">
      {/* Header */}
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2 text-slate-900">
            <SlidersHorizontal className="h-6 w-6 text-indigo-600" /> Engine Settings
          </h1>
          <p className="text-sm text-slate-500 mt-0.5">
            Global AI proctoring thresholds and scoring rules.
            {lastUpdated && <span className="ml-1">Last saved: {new Date(lastUpdated).toLocaleString()}</span>}
          </p>
        </div>
        <div className="flex gap-2 shrink-0">
          <Button variant="outline" size="sm" onClick={handleReset} className="gap-2 border-slate-200">
            <RotateCcw className="h-4 w-4" /> Reset Defaults
          </Button>
          <Button size="sm" onClick={handleSave} disabled={isSaving} className="gap-2 bg-indigo-600 hover:bg-indigo-700 text-white">
            {isSaving ? <Loader2 className="h-4 w-4 animate-spin" /> : <Save className="h-4 w-4" />}
            Save{changedCount > 0 ? ` (${changedCount} changed)` : ''}
          </Button>
        </div>
      </div>

      {changedCount > 0 && (
        <div className="flex items-center gap-2 px-4 py-2.5 bg-amber-50 border border-amber-200 rounded-lg text-sm text-amber-700">
          <span className="font-semibold">{changedCount} unsaved change{changedCount !== 1 ? 's' : ''}</span> — click Save to apply to new sessions.
        </div>
      )}

      {/* Sections */}
      {SECTIONS.map(section => (
        <Card key={section.title} className="border-slate-200 shadow-none">
          <CardHeader className="pb-3 border-b border-slate-100">
            <CardTitle className="text-base text-slate-800">{section.title}</CardTitle>
          </CardHeader>
          <CardContent className="pt-5 grid grid-cols-1 sm:grid-cols-2 gap-x-8 gap-y-6">
            {section.fields.map(f => (
              <SettingSlider
                key={f.key}
                field={f}
                value={values[f.key] as number}
                savedValue={savedValues[f.key] as number}
                onChange={set(f.key)}
              />
            ))}
          </CardContent>
        </Card>
      ))}

      {/* Sticky save bar */}
      <div className="fixed bottom-0 left-0 right-0 z-30 bg-white border-t border-slate-200 px-6 py-3 flex items-center justify-between lg:pl-72">
        <p className="text-sm text-slate-500">
          {changedCount > 0
            ? <span className="text-amber-600 font-medium">{changedCount} unsaved change{changedCount !== 1 ? 's' : ''}</span>
            : 'All changes saved'}
        </p>
        <div className="flex gap-2">
          <Button variant="outline" size="sm" onClick={handleReset} className="gap-2">
            <RotateCcw className="h-4 w-4" /> Defaults
          </Button>
          <Button size="sm" onClick={handleSave} disabled={isSaving} className="gap-2 bg-indigo-600 hover:bg-indigo-700 text-white">
            {isSaving ? <Loader2 className="h-4 w-4 animate-spin" /> : <Save className="h-4 w-4" />}
            Save Settings
          </Button>
        </div>
      </div>
    </div>
  );
}
