'use client';

import { useState, useEffect } from 'react';
import { useForm } from 'react-hook-form';
import { toast } from 'sonner';
import { Loader2, SlidersHorizontal, Save } from 'lucide-react';

import api from '@/lib/axios';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';

type SettingsForm = {
  // Head pose
  look_away_yaw: number;
  look_down_pitch: number;
  look_up_pitch: number;
  gaze_left: number;
  gaze_right: number;
  // Duration gates
  looking_away_threshold: number;
  gaze_threshold: number;
  fake_window: number;
  // Risk scores
  gaze_score: number;
  phone_score_2nd: number;
  phone_score_3rd: number;
  book_score: number;
  headphone_score: number;
  earbud_score: number;
  tab_switch_score: number;
  multi_people_score_2nd: number;
  multi_people_score_3rd: number;
  no_person_score_1: number;
  no_person_score_2: number;
  fake_presence_score_1: number;
  fake_presence_score_2: number;
  // State thresholds
  state_warning: number;
  state_high_risk: number;
  state_admin_review: number;
  // Decay
  decay_amount: number;
  // Termination
  tab_switch_terminate_count: number;
  multi_people_terminate_s: number;
  no_person_terminate_s: number;
  // YOLO confidence
  yolo_phone_conf: number;
  yolo_book_conf: number;
  yolo_audio_conf: number;
  yolo_person_conf: number;
};

function SettingField({ label, name, register, step = '0.01' }: {
  label: string;
  name: keyof SettingsForm;
  register: any;
  step?: string;
}) {
  return (
    <div className="space-y-1">
      <Label className="text-xs text-muted-foreground">{label}</Label>
      <Input
        type="number"
        step={step}
        {...register(name, { valueAsNumber: true })}
        className="h-8 text-sm"
      />
    </div>
  );
}

export default function SystemSettingsPage() {
  const [isLoading, setIsLoading] = useState(true);
  const [isSaving, setIsSaving] = useState(false);
  const [lastUpdated, setLastUpdated] = useState<string | null>(null);

  const { register, reset, handleSubmit } = useForm<SettingsForm>();

  useEffect(() => {
    api.get('/admin/system-settings')
      .then(res => {
        const { id, updated_at, ...fields } = res.data;
        reset(fields);
        setLastUpdated(updated_at);
      })
      .catch(() => toast.error('Failed to load engine settings'))
      .finally(() => setIsLoading(false));
  }, [reset]);

  const onSubmit = async (values: SettingsForm) => {
    setIsSaving(true);
    try {
      await api.post('/admin/system-settings', values);
      toast.success('Engine settings saved');
    } catch (err: any) {
      toast.error(err.response?.data?.detail || 'Failed to save settings');
    } finally {
      setIsSaving(false);
    }
  };

  if (isLoading) {
    return <div className="flex justify-center p-24"><Loader2 className="h-8 w-8 animate-spin text-slate-400" /></div>;
  }

  return (
    <div className="max-w-5xl mx-auto space-y-6 pb-20 animate-in fade-in slide-in-from-bottom-4 duration-500">
      <div className="border-b pb-4">
        <h1 className="text-3xl font-bold flex items-center gap-2">
          <SlidersHorizontal className="h-7 w-7 text-blue-600" /> Engine System Settings
        </h1>
        <p className="text-muted-foreground mt-1">
          Global AI proctoring engine thresholds and scoring parameters.
          {lastUpdated && (
            <span className="ml-2 text-xs">Last updated: {new Date(lastUpdated).toLocaleString()}</span>
          )}
        </p>
      </div>

      <form onSubmit={handleSubmit(onSubmit)} className="space-y-6">

        {/* Head Pose Thresholds */}
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Head Pose Thresholds</CardTitle>
          </CardHeader>
          <CardContent className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-5 gap-4">
            <SettingField label="Look Away Yaw"    name="look_away_yaw"    register={register} />
            <SettingField label="Look Down Pitch"  name="look_down_pitch"  register={register} />
            <SettingField label="Look Up Pitch"    name="look_up_pitch"    register={register} />
            <SettingField label="Gaze Left"        name="gaze_left"        register={register} />
            <SettingField label="Gaze Right"       name="gaze_right"       register={register} />
          </CardContent>
        </Card>

        {/* Duration Gates */}
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Duration Gates (seconds)</CardTitle>
          </CardHeader>
          <CardContent className="grid grid-cols-2 md:grid-cols-3 gap-4">
            <SettingField label="Looking Away Threshold" name="looking_away_threshold" register={register} />
            <SettingField label="Gaze Threshold"         name="gaze_threshold"         register={register} />
            <SettingField label="Fake Presence Window"   name="fake_window"            register={register} />
          </CardContent>
        </Card>

        {/* Risk Scores */}
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Risk Scores</CardTitle>
          </CardHeader>
          <CardContent className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-4">
            <SettingField label="Gaze Score"            name="gaze_score"            register={register} />
            <SettingField label="Phone 2nd Offence"     name="phone_score_2nd"       register={register} />
            <SettingField label="Phone 3rd Offence"     name="phone_score_3rd"       register={register} />
            <SettingField label="Book Score"            name="book_score"            register={register} />
            <SettingField label="Headphone Score"       name="headphone_score"       register={register} />
            <SettingField label="Earbud Score"          name="earbud_score"          register={register} />
            <SettingField label="Tab Switch Score"      name="tab_switch_score"      register={register} />
            <SettingField label="Multi People 2nd"      name="multi_people_score_2nd" register={register} />
            <SettingField label="Multi People 3rd"      name="multi_people_score_3rd" register={register} />
            <SettingField label="No Person Score 1"     name="no_person_score_1"     register={register} />
            <SettingField label="No Person Score 2"     name="no_person_score_2"     register={register} />
            <SettingField label="Fake Presence Score 1" name="fake_presence_score_1" register={register} />
            <SettingField label="Fake Presence Score 2" name="fake_presence_score_2" register={register} />
          </CardContent>
        </Card>

        {/* State Thresholds */}
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Risk State Thresholds</CardTitle>
          </CardHeader>
          <CardContent className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <SettingField label="Warning"       name="state_warning"      register={register} />
            <SettingField label="High Risk"     name="state_high_risk"    register={register} />
            <SettingField label="Admin Review"  name="state_admin_review" register={register} />
            <SettingField label="Decay Amount"  name="decay_amount"       register={register} />
          </CardContent>
        </Card>

        {/* Termination Rules */}
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Termination Rules</CardTitle>
          </CardHeader>
          <CardContent className="grid grid-cols-2 md:grid-cols-3 gap-4">
            <SettingField label="Tab Switches Before Terminate" name="tab_switch_terminate_count" register={register} step="1" />
            <SettingField label="Multi People Duration (s)"     name="multi_people_terminate_s"  register={register} />
            <SettingField label="No Person Duration (s)"        name="no_person_terminate_s"     register={register} />
          </CardContent>
        </Card>

        {/* YOLO Confidence */}
        <Card>
          <CardHeader>
            <CardTitle className="text-base">YOLO Confidence Thresholds</CardTitle>
          </CardHeader>
          <CardContent className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <SettingField label="Phone Confidence"  name="yolo_phone_conf"  register={register} />
            <SettingField label="Book Confidence"   name="yolo_book_conf"   register={register} />
            <SettingField label="Audio Confidence"  name="yolo_audio_conf"  register={register} />
            <SettingField label="Person Confidence" name="yolo_person_conf" register={register} />
          </CardContent>
        </Card>

        <div className="flex justify-end">
          <Button type="submit" disabled={isSaving} className="bg-blue-600 hover:bg-blue-700 w-40 shadow-md">
            {isSaving ? <Loader2 className="h-4 w-4 animate-spin" /> : <><Save className="h-4 w-4 mr-2" />Save Settings</>}
          </Button>
        </div>

      </form>
    </div>
  );
}
