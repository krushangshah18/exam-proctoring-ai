'use client';

import { useState } from 'react';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import * as z from 'zod';
import { useRouter } from 'next/navigation';
import { Loader2, CheckCircle2 } from 'lucide-react';
import { toast } from 'sonner';

import api from '@/lib/axios';
import { AuthShell, AuthField, PasswordInput } from '@/components/auth/AuthShell';

const setupSchema = z.object({
  new_password: z.string().min(8, { message: 'Password must be at least 8 characters.' }),
  confirm_password: z.string(),
}).refine(d => d.new_password === d.confirm_password, {
  message: "Passwords don't match",
  path: ['confirm_password'],
});

type FormValues = z.infer<typeof setupSchema>;

export default function SetupPasswordPage() {
  const router = useRouter();
  const [isLoading, setIsLoading] = useState(false);

  const { register, handleSubmit, formState: { errors } } = useForm<FormValues>({
    resolver: zodResolver(setupSchema),
    defaultValues: { new_password: '', confirm_password: '' },
  });

  async function onSubmit(values: FormValues) {
    setIsLoading(true);
    try {
      await api.post('/auth/setup-password', { new_password: values.new_password });
      toast.success('Password set successfully!');

      const meResponse = await api.get('/auth/me');
      const { role } = meResponse.data;

      if (role === 'SYSADMIN') router.push('/sys/dashboard');
      else if (role === 'ADMIN') router.push('/admin/dashboard');
      else router.push('/student/dashboard');
    } catch (error: any) {
      toast.error(error.response?.data?.detail || 'Failed to set password.');
    } finally {
      setIsLoading(false);
    }
  }

  return (
    <AuthShell
      title="Set your password"
      subtitle="Your account was created with a temporary password. Set a new secure one to continue."
      leftHeading={'Welcome to\nProctorAI.'}
      leftBody="Your account is ready. Just set a secure password and you'll be inside your dashboard in seconds."
      eyebrow="First-Time Setup"
      features={[
        'Access your assigned exams',
        'Real-time AI proctoring protection',
        'Instant session monitoring',
        'Full exam history & reports',
      ]}
    >
      {/* Welcome note */}
      <div style={{
        display: 'flex', alignItems: 'flex-start', gap: '10px',
        padding: '12px 14px', borderRadius: '8px',
        background: 'rgba(87,204,153,0.08)', border: '1px solid rgba(87,204,153,0.25)',
        marginBottom: '20px',
      }}>
        <CheckCircle2 style={{ width: '16px', height: '16px', color: '#57CC99', flexShrink: 0, marginTop: '1px' }} />
        <p style={{ fontSize: '13px', color: '#475569', lineHeight: 1.55, margin: 0 }}>
          For security, you must change your temporary password before accessing your account.
        </p>
      </div>

      <form onSubmit={handleSubmit(onSubmit)}>
        <AuthField label="New password" error={errors.new_password?.message} required>
          <PasswordInput
            placeholder="At least 8 characters"
            hasError={!!errors.new_password}
            {...register('new_password')}
          />
        </AuthField>

        <AuthField label="Confirm new password" error={errors.confirm_password?.message} required>
          <PasswordInput
            placeholder="Repeat your password"
            hasError={!!errors.confirm_password}
            {...register('confirm_password')}
          />
        </AuthField>

        <div style={{ marginTop: '4px' }}>
          <button type="submit" className="auth-btn" disabled={isLoading}>
            {isLoading && <Loader2 style={{ width: '15px', height: '15px', animation: 'spin 1s linear infinite' }} />}
            Complete Setup
          </button>
        </div>
      </form>
    </AuthShell>
  );
}
