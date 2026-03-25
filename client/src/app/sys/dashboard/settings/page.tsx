'use client';

import { useState, useEffect } from 'react';
import {
  User, Lock, Save, Loader2, Eye, EyeOff, ShieldCheck,
} from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { toast } from 'sonner';
import api from '@/lib/axios';

interface Profile {
  full_name: string;
  email: string;
  role: string;
  last_login: string | null;
  created_at: string | null;
}

export default function SettingsPage() {
  const [profile, setProfile] = useState<Profile | null>(null);
  const [loading, setLoading] = useState(true);

  // Password change state
  const [current, setCurrent] = useState('');
  const [newPass, setNewPass] = useState('');
  const [confirm, setConfirm] = useState('');
  const [showCurrent, setShowCurrent] = useState(false);
  const [showNew, setShowNew] = useState(false);
  const [savingPw, setSavingPw] = useState(false);

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
    } finally {
      setSavingPw(false);
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center p-24">
        <Loader2 className="h-8 w-8 animate-spin text-slate-400" />
      </div>
    );
  }

  return (
    <div className="max-w-2xl space-y-6 pb-12">
      <div>
        <h1 className="text-2xl font-bold text-slate-900">Settings</h1>
        <p className="text-sm text-slate-500 mt-0.5">Manage your account and security preferences</p>
      </div>

      {/* Profile card (read-only) */}
      <Card className="border-slate-200 shadow-none">
        <CardHeader className="pb-3 border-b border-slate-100">
          <CardTitle className="text-base flex items-center gap-2 text-slate-800">
            <User className="h-4 w-4 text-indigo-500" /> Account Info
          </CardTitle>
        </CardHeader>
        <CardContent className="pt-5 space-y-4">
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
              <Label className="text-xs text-slate-400">Full Name</Label>
              <p className="text-sm font-medium text-slate-800 mt-0.5">{profile?.full_name ?? '—'}</p>
            </div>
            <div>
              <Label className="text-xs text-slate-400">Email</Label>
              <p className="text-sm font-medium text-slate-800 mt-0.5">{profile?.email ?? '—'}</p>
            </div>
            <div>
              <Label className="text-xs text-slate-400">Role</Label>
              <div className="flex items-center gap-1.5 mt-0.5">
                <ShieldCheck className="h-3.5 w-3.5 text-purple-500" />
                <p className="text-sm font-medium text-slate-800">{profile?.role ?? '—'}</p>
              </div>
            </div>
            <div>
              <Label className="text-xs text-slate-400">Last Login</Label>
              <p className="text-sm text-slate-600 mt-0.5">
                {profile?.last_login ? new Date(profile.last_login).toLocaleString() : 'Never'}
              </p>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Change password */}
      <Card className="border-slate-200 shadow-none">
        <CardHeader className="pb-3 border-b border-slate-100">
          <CardTitle className="text-base flex items-center gap-2 text-slate-800">
            <Lock className="h-4 w-4 text-indigo-500" /> Change Password
          </CardTitle>
        </CardHeader>
        <CardContent className="pt-5">
          <form onSubmit={handleChangePassword} className="space-y-4">
            <div className="space-y-1.5">
              <Label className="text-sm">Current Password</Label>
              <div className="relative">
                <Input
                  type={showCurrent ? 'text' : 'password'}
                  value={current}
                  onChange={e => setCurrent(e.target.value)}
                  placeholder="Enter current password"
                  className="pr-10 border-slate-200"
                  required
                />
                <button type="button" className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-600"
                  onClick={() => setShowCurrent(v => !v)}>
                  {showCurrent ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                </button>
              </div>
            </div>

            <div className="space-y-1.5">
              <Label className="text-sm">New Password</Label>
              <div className="relative">
                <Input
                  type={showNew ? 'text' : 'password'}
                  value={newPass}
                  onChange={e => setNewPass(e.target.value)}
                  placeholder="At least 8 characters"
                  className="pr-10 border-slate-200"
                  required minLength={8}
                />
                <button type="button" className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-600"
                  onClick={() => setShowNew(v => !v)}>
                  {showNew ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                </button>
              </div>
            </div>

            <div className="space-y-1.5">
              <Label className="text-sm">Confirm New Password</Label>
              <Input
                type="password"
                value={confirm}
                onChange={e => setConfirm(e.target.value)}
                placeholder="Repeat new password"
                className={`border-slate-200 ${confirm && confirm !== newPass ? 'border-rose-300 focus-visible:ring-rose-300' : ''}`}
                required
              />
              {confirm && confirm !== newPass && (
                <p className="text-xs text-rose-500">Passwords do not match</p>
              )}
            </div>

            <Button type="submit" disabled={savingPw || !current || !newPass || newPass !== confirm} className="gap-2 bg-indigo-600 hover:bg-indigo-700 text-white">
              {savingPw ? <Loader2 className="h-4 w-4 animate-spin" /> : <Save className="h-4 w-4" />}
              Update Password
            </Button>
          </form>
        </CardContent>
      </Card>
    </div>
  );
}
