'use client';

import { useRef, useState } from 'react';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import * as z from 'zod';
import { useRouter, useSearchParams } from 'next/navigation';
import { Loader2, ShieldCheck } from 'lucide-react';
import { toast } from 'sonner';

import api from '@/lib/axios';
import { AuthShell } from '@/components/auth/AuthShell';

const formSchema = z.object({
  otp: z.string().length(6, { message: 'OTP must be exactly 6 digits.' }),
});

type FormValues = z.infer<typeof formSchema>;

export default function VerifyOTPPage() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const email = searchParams.get('email');
  const type = searchParams.get('type') || 'device';
  const [isLoading, setIsLoading] = useState(false);
  const [digits, setDigits] = useState<string[]>(Array(6).fill(''));
  const inputRefs = useRef<(HTMLInputElement | null)[]>([]);

  const { handleSubmit, setValue, formState: { errors } } = useForm<FormValues>({
    resolver: zodResolver(formSchema),
    defaultValues: { otp: '' },
  });

  function handleDigitChange(index: number, value: string) {
    const digit = value.replace(/\D/g, '').slice(-1);
    const newDigits = [...digits];
    newDigits[index] = digit;
    setDigits(newDigits);
    setValue('otp', newDigits.join(''));
    if (digit && index < 5) inputRefs.current[index + 1]?.focus();
  }

  function handleKeyDown(index: number, e: React.KeyboardEvent<HTMLInputElement>) {
    if (e.key === 'Backspace' && !digits[index] && index > 0) {
      inputRefs.current[index - 1]?.focus();
    }
  }

  function handlePaste(e: React.ClipboardEvent<HTMLInputElement>) {
    e.preventDefault();
    const pasted = e.clipboardData.getData('text').replace(/\D/g, '').slice(0, 6);
    const newDigits = [...digits];
    for (let i = 0; i < 6; i++) newDigits[i] = pasted[i] || '';
    setDigits(newDigits);
    setValue('otp', newDigits.join(''));
    const nextEmpty = pasted.length < 6 ? pasted.length : 5;
    inputRefs.current[nextEmpty]?.focus();
  }

  async function onSubmit(values: FormValues) {
    if (!email) { toast.error('Email missing. Please sign in again.'); router.push('/auth/login'); return; }
    setIsLoading(true);
    try {
      const endpoint = type === 'device' ? '/auth/device/verify' : '/auth/unlock/verify';
      await api.post(endpoint, { email, otp: values.otp });
      toast.success('Verification successful! You can now sign in.');
      router.push('/auth/login');
    } catch (error: any) {
      toast.error(error.response?.data?.detail || 'Verification failed.');
    } finally {
      setIsLoading(false);
    }
  }

  const isDeviceVerify = type === 'device';
  const otpFilled = digits.every(d => d !== '');

  return (
    <AuthShell
      title="Verify your identity"
      subtitle={
        email
          ? `We sent a 6-digit code to ${email}. Enter it below to continue.`
          : `Enter the 6-digit verification code sent to your email.`
      }
      backHref="/auth/login"
      backLabel="Back to sign in"
      leftHeading={isDeviceVerify ? 'New device\ndetected.' : 'Let\'s get\nyou unlocked.'}
      leftBody={
        isDeviceVerify
          ? "We noticed a sign-in from a new device. Verify your identity with the OTP sent to your email."
          : "Enter the OTP we sent to your email to unlock your account and regain access."
      }
      eyebrow={isDeviceVerify ? 'Device Verification' : 'Account Unlock'}
    >
      <form onSubmit={handleSubmit(onSubmit)}>
        {/* OTP icon header */}
        <div style={{ display: 'flex', justifyContent: 'center', marginBottom: '28px' }}>
          <div style={{
            width: '56px', height: '56px', borderRadius: '50%',
            background: 'rgba(34,87,122,0.08)', display: 'flex',
            alignItems: 'center', justifyContent: 'center',
          }}>
            <ShieldCheck style={{ width: '26px', height: '26px', color: '#22577A' }} />
          </div>
        </div>

        {/* 6-digit OTP boxes */}
        <div style={{ display: 'flex', gap: '10px', justifyContent: 'center', marginBottom: '8px' }}>
          {digits.map((digit, i) => (
            <input
              key={i}
              ref={el => { inputRefs.current[i] = el; }}
              type="text"
              inputMode="numeric"
              maxLength={1}
              value={digit}
              className={`auth-otp-box${digit ? ' filled' : ''}`}
              onChange={e => handleDigitChange(i, e.target.value)}
              onKeyDown={e => handleKeyDown(i, e)}
              onPaste={handlePaste}
            />
          ))}
        </div>

        {errors.otp && (
          <p style={{ textAlign: 'center', fontSize: '12px', color: '#EF4444', marginBottom: '12px' }}>
            {errors.otp.message}
          </p>
        )}

        <div style={{ marginTop: '20px' }}>
          <button type="submit" className="auth-btn" disabled={isLoading || !otpFilled}>
            {isLoading && <Loader2 style={{ width: '15px', height: '15px', animation: 'spin 1s linear infinite' }} />}
            Verify Code
          </button>
        </div>

        <p style={{ textAlign: 'center', fontSize: '13px', color: '#94A3B8', marginTop: '16px' }}>
          Didn&apos;t receive the code?{' '}
          <button
            type="button"
            style={{ background: 'none', border: 'none', cursor: 'pointer', padding: 0 }}
            className="auth-link"
            onClick={() => toast.info('Please request a new code from the previous step.')}
          >
            Resend
          </button>
        </p>
      </form>
    </AuthShell>
  );
}
