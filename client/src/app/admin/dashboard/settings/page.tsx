'use client';

import { useState, useEffect } from 'react';
import { User, Lock, Save, Loader2, Eye, EyeOff, ShieldCheck } from 'lucide-react';
import { toast } from 'sonner';
import api from '@/lib/axios';

interface Profile {
  full_name: string;
  email: string;
  role: string;
  last_login: string | null;
  created_at: string | null;
}

function Section({ title, icon: Icon, children }: { title: string; icon: any; children: React.ReactNode }) {
  return (
    <div className="bg-white rounded-xl border overflow-hidden"
      style={{ borderColor: '#E2E8F0', boxShadow: '0 1px 3px rgba(15,23,42,0.04)' }}>
      <div className="flex items-center gap-2.5 px-5 py-4" style={{ borderBottom: '1px solid #F1F5F9' }}>
        <Icon className="h-4 w-4" style={{ color: '#22577A' }} />
        <p className="text-sm font-semibold" style={{ color: '#0F172A' }}>{title}</p>
      </div>
      <div className="p-5">{children}</div>
    </div>
  );
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <p className="text-[11px] font-semibold uppercase tracking-wider mb-1.5" style={{ color: '#94A3B8' }}>{label}</p>
      <div className="text-sm font-medium" style={{ color: '#0F172A' }}>{children}</div>
    </div>
  );
}

export default function AdminSettingsPage() {
  const [profile, setProfile] = useState<Profile | null>(null);
  const [loading, setLoading] = useState(true);
  const [current, setCurrent]     = useState('');
  const [newPass, setNewPass]     = useState('');
  const [confirm, setConfirm]     = useState('');
  const [showCurrent, setShowCurrent] = useState(false);
  const [showNew, setShowNew]         = useState(false);
  const [savingPw, setSavingPw]       = useState(false);

  useEffect(() => {
    api.get('/auth/me')
      .then(r => setProfile(r.data))
      .catch(() => toast.error('Failed to load profile'))
      .finally(() => setLoading(false));
  }, []);

  const handleChangePassword = async (e: React.FormEvent) => {
    e.preventDefault();
    if (newPass.length < 8) { toast.error('Password must be at least 8 characters'); return; }
    if (newPass !== confirm) { toast.error('Passwords do not match'); return; }
    setSavingPw(true);
    try {
      await api.post('/auth/change-password', { current_password: current, new_password: newPass });
      toast.success('Password updated successfully');
      setCurrent(''); setNewPass(''); setConfirm('');
    } catch (err: any) {
      toast.error(err.response?.data?.detail || 'Failed to change password');
    } finally { setSavingPw(false); }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center p-24">
        <Loader2 className="h-7 w-7 animate-spin" style={{ color: '#CBD5E1' }} />
      </div>
    );
  }

  const inputBase = 'w-full px-3 py-2.5 text-sm rounded-lg border outline-none transition-all';

  return (
    <div className="max-w-xl space-y-6 pb-12">
      <div>
        <h1 className="text-2xl font-bold" style={{ color: '#0F172A', letterSpacing: '-0.025em' }}>Settings</h1>
        <p className="text-sm mt-1" style={{ color: '#94A3B8' }}>Manage your account and security preferences</p>
      </div>

      <Section title="Account Info" icon={User}>
        <div className="grid grid-cols-2 gap-5">
          <Field label="Full Name">{profile?.full_name ?? '—'}</Field>
          <Field label="Email">{profile?.email ?? '—'}</Field>
          <Field label="Role">
            <span className="inline-flex items-center gap-1.5">
              <ShieldCheck className="h-3.5 w-3.5" style={{ color: '#22577A' }} />
              {profile?.role ?? '—'}
            </span>
          </Field>
          <Field label="Last Login">
            <span style={{ color: '#475569', fontWeight: 400 }}>
              {profile?.last_login ? new Date(profile.last_login).toLocaleString() : 'Never'}
            </span>
          </Field>
        </div>
      </Section>

      <Section title="Change Password" icon={Lock}>
        <form onSubmit={handleChangePassword} className="space-y-4">
          <div>
            <label className="block text-sm font-medium mb-1.5" style={{ color: '#475569' }}>Current Password</label>
            <div className="relative">
              <input
                type={showCurrent ? 'text' : 'password'}
                value={current}
                onChange={e => setCurrent(e.target.value)}
                placeholder="Enter current password"
                required
                className={inputBase}
                style={{ borderColor: '#E2E8F0', color: '#0F172A', paddingRight: '2.5rem' }}
                onFocus={e => { (e.target as HTMLElement).style.borderColor = '#38A3A5'; (e.target as HTMLElement).style.boxShadow = '0 0 0 3px rgba(56,163,165,0.12)'; }}
                onBlur={e => { (e.target as HTMLElement).style.borderColor = '#E2E8F0'; (e.target as HTMLElement).style.boxShadow = 'none'; }}
              />
              <button type="button" onClick={() => setShowCurrent(v => !v)}
                className="absolute right-3 top-1/2 -translate-y-1/2 transition-colors"
                style={{ color: '#94A3B8' }}>
                {showCurrent ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
              </button>
            </div>
          </div>

          <div>
            <label className="block text-sm font-medium mb-1.5" style={{ color: '#475569' }}>New Password</label>
            <div className="relative">
              <input
                type={showNew ? 'text' : 'password'}
                value={newPass}
                onChange={e => setNewPass(e.target.value)}
                placeholder="At least 8 characters"
                required minLength={8}
                className={inputBase}
                style={{ borderColor: '#E2E8F0', color: '#0F172A', paddingRight: '2.5rem' }}
                onFocus={e => { (e.target as HTMLElement).style.borderColor = '#38A3A5'; (e.target as HTMLElement).style.boxShadow = '0 0 0 3px rgba(56,163,165,0.12)'; }}
                onBlur={e => { (e.target as HTMLElement).style.borderColor = '#E2E8F0'; (e.target as HTMLElement).style.boxShadow = 'none'; }}
              />
              <button type="button" onClick={() => setShowNew(v => !v)}
                className="absolute right-3 top-1/2 -translate-y-1/2 transition-colors"
                style={{ color: '#94A3B8' }}>
                {showNew ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
              </button>
            </div>
          </div>

          <div>
            <label className="block text-sm font-medium mb-1.5" style={{ color: '#475569' }}>Confirm New Password</label>
            <input
              type="password"
              value={confirm}
              onChange={e => setConfirm(e.target.value)}
              placeholder="Repeat new password"
              required
              className={inputBase}
              style={{
                borderColor: confirm && confirm !== newPass ? '#EF4444' : '#E2E8F0',
                color: '#0F172A',
                boxShadow: confirm && confirm !== newPass ? '0 0 0 3px rgba(239,68,68,0.10)' : 'none',
              }}
              onFocus={e => { if (!confirm || confirm === newPass) { (e.target as HTMLElement).style.borderColor = '#38A3A5'; (e.target as HTMLElement).style.boxShadow = '0 0 0 3px rgba(56,163,165,0.12)'; } }}
              onBlur={e => { if (!confirm || confirm === newPass) { (e.target as HTMLElement).style.borderColor = '#E2E8F0'; (e.target as HTMLElement).style.boxShadow = 'none'; } }}
            />
            {confirm && confirm !== newPass && (
              <p className="text-xs mt-1.5" style={{ color: '#EF4444' }}>Passwords do not match</p>
            )}
          </div>

          <button
            type="submit"
            disabled={savingPw || !current || !newPass || newPass !== confirm}
            className="flex items-center gap-2 px-4 py-2.5 rounded-lg text-sm font-semibold text-white transition-all duration-150"
            style={{
              background: savingPw || !current || !newPass || newPass !== confirm ? '#94A3B8' : '#22577A',
              cursor: savingPw || !current || !newPass || newPass !== confirm ? 'not-allowed' : 'pointer',
            }}
          >
            {savingPw ? <Loader2 className="h-4 w-4 animate-spin" /> : <Save className="h-4 w-4" />}
            Update Password
          </button>
        </form>
      </Section>
    </div>
  );
}
