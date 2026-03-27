'use client';

import { useState } from 'react';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import * as z from 'zod';
import { useRouter } from 'next/navigation';
import { Loader2, LockOpen } from 'lucide-react';
import { toast } from 'sonner';

import api from '@/lib/axios';
import { AuthShell, AuthField } from '@/components/auth/AuthShell';

const formSchema = z.object({
  email: z.string().email({ message: 'Please enter a valid email address.' }),
});

type FormValues = z.infer<typeof formSchema>;

export default function UnlockAccountPage() {
  const router = useRouter();
  const [isLoading, setIsLoading] = useState(false);

  const { register, handleSubmit, formState: { errors } } = useForm<FormValues>({
    resolver: zodResolver(formSchema),
    defaultValues: { email: '' },
  });

  async function onSubmit(values: FormValues) {
    setIsLoading(true);
    try {
      await api.post('/auth/unlock/request', values);
      toast.success('Unlock OTP sent to your email.');
      router.push(`/auth/verify-otp?type=unlock&email=${values.email}`);
    } catch (error: any) {
      toast.error(error.response?.data?.detail || 'Request failed. Please try again.');
    } finally {
      setIsLoading(false);
    }
  }

  return (
    <AuthShell
      title="Unlock your account"
      subtitle="Too many failed attempts locked your account. Enter your email and we'll send an unlock code."
      backHref="/auth/login"
      backLabel="Back to sign in"
      leftHeading={'Account\nlocked?'}
      leftBody="After too many failed sign-in attempts, your account is locked for security. We'll send a one-time code to restore your access."
      eyebrow="Account Security"
    >
      {/* Lock icon */}
      <div style={{ display: 'flex', justifyContent: 'center', marginBottom: '24px' }}>
        <div style={{
          width: '52px', height: '52px', borderRadius: '50%',
          background: 'rgba(239,68,68,0.08)', display: 'flex',
          alignItems: 'center', justifyContent: 'center',
        }}>
          <LockOpen style={{ width: '24px', height: '24px', color: '#EF4444' }} />
        </div>
      </div>

      <form onSubmit={handleSubmit(onSubmit)}>
        <AuthField label="Email address" error={errors.email?.message} required>
          <input
            type="email"
            placeholder="you@example.com"
            className={`auth-input${errors.email ? ' has-error' : ''}`}
            {...register('email')}
          />
        </AuthField>

        <div style={{ marginTop: '4px' }}>
          <button type="submit" className="auth-btn" disabled={isLoading}>
            {isLoading && <Loader2 style={{ width: '15px', height: '15px', animation: 'spin 1s linear infinite' }} />}
            Send Unlock Code
          </button>
        </div>
      </form>

      {/* Info note */}
      <div style={{
        marginTop: '16px', padding: '12px 14px', borderRadius: '8px',
        background: '#FFFBEB', border: '1px solid #FDE68A',
        fontSize: '12px', color: '#B45309', lineHeight: 1.6,
      }}>
        <strong>Note:</strong> If your account was locked due to suspicious activity, please contact your administrator as well.
      </div>
    </AuthShell>
  );
}
