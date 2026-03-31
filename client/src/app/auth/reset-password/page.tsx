'use client';

import { useState } from 'react';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import * as z from 'zod';
import { useRouter, useSearchParams } from 'next/navigation';
import { Loader2 } from 'lucide-react';
import { toast } from 'sonner';

import api from '@/lib/axios';
import { AuthShell, AuthField, PasswordInput } from '@/components/auth/AuthShell';

const formSchema = z.object({
  new_password: z.string().min(8, 'Password must be at least 8 characters'),
  confirmPassword: z.string(),
}).refine(d => d.new_password === d.confirmPassword, {
  message: "Passwords don't match",
  path: ['confirmPassword'],
});

type FormValues = z.infer<typeof formSchema>;

export default function ResetPasswordPage() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const token = searchParams.get('token');
  const [isLoading, setIsLoading] = useState(false);

  const { register, handleSubmit, formState: { errors } } = useForm<FormValues>({
    resolver: zodResolver(formSchema),
    defaultValues: { new_password: '', confirmPassword: '' },
  });

  async function onSubmit(values: FormValues) {
    if (!token) { toast.error('Invalid or expired reset link.'); return; }
    setIsLoading(true);
    try {
      await api.post('/auth/reset-password', { token, new_password: values.new_password });
      toast.success('Password reset successfully. Please sign in.');
      router.push('/auth/login');
    } catch (error: any) {
      toast.error(error.response?.data?.detail || 'Failed to reset password.');
    } finally {
      setIsLoading(false);
    }
  }

  return (
    <AuthShell
      title="Set new password"
      subtitle="Choose a strong password you haven't used before."
      backHref="/auth/login"
      backLabel="Back to sign in"
      leftHeading={'New password,\nnew start.'}
      leftBody="Your account security matters. Choose a strong, unique password to keep your profile protected."
      eyebrow="Password Reset"
    >
      <form onSubmit={handleSubmit(onSubmit)}>
        <AuthField label="New password" error={errors.new_password?.message} required>
          <PasswordInput
            placeholder="At least 8 characters"
            hasError={!!errors.new_password}
            {...register('new_password')}
          />
        </AuthField>

        <AuthField label="Confirm new password" error={errors.confirmPassword?.message} required>
          <PasswordInput
            placeholder="Repeat your password"
            hasError={!!errors.confirmPassword}
            {...register('confirmPassword')}
          />
        </AuthField>

        {/* Password hint */}
        <div style={{
          display: 'flex', alignItems: 'center', gap: '6px', marginBottom: '16px',
          padding: '10px 12px', borderRadius: '8px',
          background: '#F8FAFC', border: '1px solid #E2E8F0',
        }}>
          <span style={{ color: '#64748B', fontSize: '12px', lineHeight: 1.5 }}>
            Use at least 8 characters with a mix of letters, numbers and symbols.
          </span>
        </div>

        <button type="submit" className="auth-btn" disabled={isLoading}>
          {isLoading && <Loader2 style={{ width: '15px', height: '15px', animation: 'spin 1s linear infinite' }} />}
          Reset Password
        </button>
      </form>
    </AuthShell>
  );
}
