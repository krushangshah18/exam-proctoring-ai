'use client';

import { useState } from 'react';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import * as z from 'zod';
import { useRouter } from 'next/navigation';
import { Loader2 } from 'lucide-react';
import { toast } from 'sonner';

import api from '@/lib/axios';
import { AuthShell, AuthField, PasswordInput } from '@/components/auth/AuthShell';

const formSchema = z.object({
  email: z.string().email({ message: 'Please enter a valid email address.' }),
  password: z.string().min(1, { message: 'Password is required.' }),
});

type FormValues = z.infer<typeof formSchema>;

export default function LoginPage() {
  const router = useRouter();
  const [isLoading, setIsLoading] = useState(false);

  const { register, handleSubmit, formState: { errors } } = useForm<FormValues>({
    resolver: zodResolver(formSchema),
    defaultValues: { email: '', password: '' },
  });

  async function onSubmit(values: FormValues) {
    setIsLoading(true);
    try {
      const response = await api.post('/auth/login', values);

      if (response.data.access_token) {
        localStorage.setItem('access_token', response.data.access_token);
        localStorage.setItem('refresh_token', response.data.refresh_token);
        toast.success('Login successful');

        const meResponse = await api.get('/auth/me');
        const { role, must_change_password } = meResponse.data;

        if (must_change_password) {
          router.push('/auth/setup-password');
        } else if (role === 'SYSADMIN') {
          router.push('/sys/dashboard');
        } else if (role === 'ADMIN') {
          router.push('/admin/dashboard');
        } else {
          router.push('/student/dashboard');
        }
      } else if (response.data.message?.includes('OTP')) {
        toast.info('New device detected. OTP sent to your email.');
        router.push(`/auth/verify-otp?type=device&email=${values.email}`);
      }
    } catch (error: any) {
      const status = error.response?.status;
      const msg = error.response?.data?.detail || 'Authentication failed';
      if (status === 403 && msg.includes('locked')) {
        toast.error('Account is locked due to too many failed attempts.');
        setTimeout(() => router.push('/auth/unlock-account'), 2000);
      } else {
        toast.error(msg);
      }
    } finally {
      setIsLoading(false);
    }
  }

  return (
    <AuthShell
      title="Welcome back"
      subtitle="Sign in to your ProctorAI account to continue."
      leftHeading={'Monitor Smarter,\nNot Harder.'}
      leftBody="ProctorAI's AI engine watches, learns, and alerts — so exam integrity is never a question."
      features={[
        'Real-time face & gaze tracking',
        'Automatic tab-switch detection',
        'Instant risk scoring & alerts',
        'Proof capture & detailed reports',
      ]}
      footer={
        <span style={{ display: 'inline-flex', alignItems: 'center', justifyContent: 'center', flexWrap: 'wrap', columnGap: '8px', rowGap: '4px' }}>
          Don&apos;t have an account?{' '}
          <a href="/auth/register" className="auth-link">Register</a>
          <span style={{ color: '#94A3B8', fontWeight: 500 }}>|</span>
          <a href="/auth/teacher-apply" className="auth-link">Apply as Teacher</a>
        </span>
      }
    >
      <form onSubmit={handleSubmit(onSubmit)}>
        <AuthField label="Email address" error={errors.email?.message} required>
          <input
            type="email"
            placeholder="you@example.com"
            className={`auth-input${errors.email ? ' has-error' : ''}`}
            {...register('email')}
          />
        </AuthField>

        <AuthField
          label={
            <span style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', width: '100%' }}>
              <span>
                Password
                <span style={{ color: '#EF4444', marginLeft: '3px', whiteSpace: 'nowrap' }}>*</span>
              </span>
              <a href="/auth/forgot-password" className="auth-link" style={{ fontSize: '12px', fontWeight: 500 }}>
                Forgot password?
              </a>
            </span> as any
          }
          error={errors.password?.message}
        >
          <PasswordInput hasError={!!errors.password} {...register('password')} />
        </AuthField>

        <div style={{ marginTop: '8px' }}>
          <button type="submit" className="auth-btn" disabled={isLoading}>
            {isLoading && <Loader2 style={{ width: '15px', height: '15px', animation: 'spin 1s linear infinite' }} />}
            Sign In
          </button>
        </div>
      </form>
    </AuthShell>
  );
}
