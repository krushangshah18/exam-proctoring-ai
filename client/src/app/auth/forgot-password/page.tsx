'use client';

import { useState } from 'react';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import * as z from 'zod';
import { Loader2, MailCheck } from 'lucide-react';
import { toast } from 'sonner';

import api from '@/lib/axios';
import { AuthShell, AuthField } from '@/components/auth/AuthShell';

const formSchema = z.object({
  email: z.string().email({ message: 'Please enter a valid email address.' }),
});

type FormValues = z.infer<typeof formSchema>;

export default function ForgotPasswordPage() {
  const [isLoading, setIsLoading] = useState(false);
  const [sent, setSent] = useState(false);

  const { register, handleSubmit, getValues, formState: { errors } } = useForm<FormValues>({
    resolver: zodResolver(formSchema),
    defaultValues: { email: '' },
  });

  async function onSubmit(values: FormValues) {
    setIsLoading(true);
    try {
      await api.post('/auth/forgot-password', values);
      setSent(true);
      toast.success('Reset link sent if that account exists.');
    } catch {
      toast.error('Failed to send reset link. Please try again.');
    } finally {
      setIsLoading(false);
    }
  }

  return (
    <AuthShell
      title={sent ? 'Check your inbox' : 'Forgot password?'}
      subtitle={
        sent
          ? `We've sent a password reset link to ${getValues('email')}. Check your spam folder if you don't see it.`
          : 'Enter your email and we\'ll send you a reset link.'
      }
      backHref="/auth/login"
      backLabel="Back to sign in"
      leftHeading={'Locked out?\nWe\'ve got you.'}
      leftBody="Password resets are quick and secure. You'll be back to your exams in no time."
      eyebrow="Account Recovery"
      footer={
        <>
          Remembered it?{' '}
          <a href="/auth/login" className="auth-link">Sign in instead</a>
        </>
      }
    >
      {sent ? (
        <div style={{
          display: 'flex', flexDirection: 'column', alignItems: 'center',
          padding: '28px 0', gap: '12px', textAlign: 'center',
        }}>
          <div style={{
            width: '56px', height: '56px', borderRadius: '50%',
            background: 'rgba(87,204,153,0.12)', display: 'flex',
            alignItems: 'center', justifyContent: 'center',
          }}>
            <MailCheck style={{ width: '26px', height: '26px', color: '#57CC99' }} />
          </div>
          <p style={{ color: '#94A3B8', fontSize: '13px' }}>
            Didn&apos;t receive it?{' '}
            <button
              type="button"
              onClick={() => setSent(false)}
              style={{ background: 'none', border: 'none', cursor: 'pointer', padding: 0 }}
              className="auth-link"
            >
              Try again
            </button>
          </p>
        </div>
      ) : (
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
              Send Reset Link
            </button>
          </div>
        </form>
      )}
    </AuthShell>
  );
}
