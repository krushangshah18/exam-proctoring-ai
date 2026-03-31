'use client';

import { useState, useRef, useCallback } from 'react';
import { useForm, Controller } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import * as z from 'zod';
import { useRouter } from 'next/navigation';
import Webcam from 'react-webcam';
import { Camera, RefreshCw, Loader2, CheckCircle2, AlertCircle } from 'lucide-react';
import { toast } from 'sonner';

import api from '@/lib/axios';
import { AuthShell, AuthField, PasswordInput } from '@/components/auth/AuthShell';

const formSchema = z.object({
  full_name: z.string().min(2, { message: 'Name must be at least 2 characters.' }),
  email: z.string().email({ message: 'Please enter a valid email address.' }),
  password: z.string().min(8, { message: 'Password must be at least 8 characters.' }),
  confirmPassword: z.string(),
  consent: z.boolean().refine(v => v === true, { message: 'You must agree to the privacy policy.' }),
}).refine(d => d.password === d.confirmPassword, {
  message: "Passwords don't match",
  path: ['confirmPassword'],
});

type FormValues = z.infer<typeof formSchema>;

// Step indicator
function StepDots({ step }: { step: number }) {
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '20px' }}>
      {[1, 2].map(n => (
        <div key={n} style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <div style={{
            width: n === step ? '28px' : '8px', height: '8px', borderRadius: '4px',
            background: n <= step ? '#22577A' : '#E2E8F0',
            transition: 'all 300ms ease',
          }} />
        </div>
      ))}
      <span style={{ fontSize: '11px', fontWeight: 600, color: '#64748B', marginLeft: '4px' }}>
        Step {step} of 2
      </span>
    </div>
  );
}

export default function RegisterPage() {
  const router = useRouter();
  const [step, setStep] = useState(1);
  const [imgSrc, setImgSrc] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [camError, setCamError] = useState(false);
  const webcamRef = useRef<Webcam>(null);

  const { register, handleSubmit, control, trigger, formState: { errors } } = useForm<FormValues>({
    resolver: zodResolver(formSchema),
    defaultValues: { full_name: '', email: '', password: '', confirmPassword: '', consent: false },
  });

  const capture = useCallback(() => {
    const src = webcamRef.current?.getScreenshot();
    if (src) setImgSrc(src);
  }, []);

  const handleNext = async () => {
    const ok = await trigger(['full_name', 'email', 'password', 'confirmPassword', 'consent']);
    if (ok) setStep(2);
  };

  async function onSubmit(values: FormValues) {
    if (!imgSrc) { toast.error('Please capture a selfie to continue.'); return; }
    setIsLoading(true);
    try {
      const res = await fetch(imgSrc);
      const blob = await res.blob();
      const file = new File([blob], 'selfie.jpg', { type: 'image/jpeg' });

      const formData = new FormData();
      formData.append('email', values.email);
      formData.append('password', values.password);
      formData.append('full_name', values.full_name);
      formData.append('consent', 'true');
      formData.append('selfie', file);

      await api.post('/auth/register/student', formData, { headers: { 'Content-Type': 'multipart/form-data' } });
      toast.success('Registration successful! Please sign in.');
      router.push('/auth/login');
    } catch (error: any) {
      toast.error(error.response?.data?.detail || 'Registration failed.');
    } finally {
      setIsLoading(false);
    }
  }

  return (
    <AuthShell
      title={step === 1 ? 'Create your account' : 'Verify your identity'}
      subtitle={
        step === 1
          ? 'Join ProctorAI as a student to participate in proctored exams.'
          : 'We need a clear, well-lit selfie for biometric proctoring verification.'
      }
      leftHeading={'Join ProctorAI\nas a Student.'}
      leftBody="Create your account to participate in AI-proctored exams — secure, fair, and stress-free."
      features={[
        'Secure biometric verification',
        'Privacy-first data handling',
        'Real-time AI monitoring',
        'Full exam history access',
      ]}
      footer={
        step === 1 ? (
          <>
            Already have an account?{' '}
            <a href="/auth/login" className="auth-link">Sign in</a>
          </>
        ) : undefined
      }
    >
      <StepDots step={step} />

      <form onSubmit={handleSubmit(onSubmit)}>
        {step === 1 && (
          <>
            <AuthField label="Full name" error={errors.full_name?.message} required>
              <input
                type="text"
                placeholder="Your full legal name"
                className={`auth-input${errors.full_name ? ' has-error' : ''}`}
                {...register('full_name')}
              />
            </AuthField>

            <AuthField label="Email address" error={errors.email?.message} required>
              <input
                type="email"
                placeholder="you@example.com"
                className={`auth-input${errors.email ? ' has-error' : ''}`}
                {...register('email')}
              />
            </AuthField>

            <AuthField label="Password" error={errors.password?.message} required>
              <PasswordInput
                placeholder="At least 8 characters"
                hasError={!!errors.password}
                {...register('password')}
              />
            </AuthField>

            <AuthField label="Confirm password" error={errors.confirmPassword?.message} required>
              <PasswordInput
                placeholder="Repeat your password"
                hasError={!!errors.confirmPassword}
                {...register('confirmPassword')}
              />
            </AuthField>

            {/* Consent */}
            <Controller
              name="consent"
              control={control}
              render={({ field }) => (
                <div style={{
                  display: 'flex', alignItems: 'flex-start', gap: '10px',
                  padding: '12px 14px', borderRadius: '8px', marginBottom: '16px',
                  border: `1.5px solid ${errors.consent ? '#EF4444' : '#E2E8F0'}`,
                  background: '#F8FAFC',
                }}>
                  <input
                    type="checkbox"
                    checked={field.value}
                    onChange={field.onChange}
                    id="consent"
                    style={{
                      width: '16px', height: '16px', marginTop: '2px', flexShrink: 0,
                      accentColor: '#22577A', cursor: 'pointer',
                    }}
                  />
                  <label htmlFor="consent" style={{ cursor: 'pointer' }}>
                    <p style={{ fontSize: '13px', fontWeight: 600, color: '#475569', marginBottom: '2px' }}>
                      Privacy Policy Consent
                    </p>
                    <p style={{ fontSize: '12px', color: '#64748B', lineHeight: 1.5 }}>
                      I authorize the collection of my biometric face data for AI proctoring purposes.
                    </p>
                    {errors.consent && (
                      <p style={{ fontSize: '12px', color: '#EF4444', marginTop: '4px' }}>{errors.consent.message}</p>
                    )}
                  </label>
                </div>
              )}
            />

            <button type="button" className="auth-btn" onClick={handleNext}>
              Continue to Selfie Verification
            </button>
          </>
        )}

        {step === 2 && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
            {/* Camera viewport */}
            <div style={{
              borderRadius: '12px', overflow: 'hidden',
              border: '2px solid #E2E8F0', background: '#0F172A',
              aspectRatio: '4/3', position: 'relative',
            }}>
              {!imgSrc ? (
                <>
                  {!camError ? (
                    <Webcam
                      audio={false}
                      ref={webcamRef}
                      screenshotFormat="image/jpeg"
                      videoConstraints={{ facingMode: 'user' }}
                      onUserMediaError={() => setCamError(true)}
                      style={{ width: '100%', height: '100%', objectFit: 'cover', display: 'block' }}
                    />
                  ) : (
                    <div style={{
                      width: '100%', height: '100%', display: 'flex',
                      flexDirection: 'column', alignItems: 'center', justifyContent: 'center', gap: '10px',
                    }}>
                      <AlertCircle style={{ width: '32px', height: '32px', color: '#EF4444' }} />
                      <p style={{ color: '#64748B', fontSize: '13px', textAlign: 'center', padding: '0 16px' }}>
                        Camera access denied. Please allow camera access in your browser settings.
                      </p>
                    </div>
                  )}
                  {/* Corner guides */}
                  {!camError && (
                    <>
                      {[{ top: '10px', left: '10px' }, { top: '10px', right: '10px' }, { bottom: '10px', left: '10px' }, { bottom: '10px', right: '10px' }].map((pos, i) => (
                        <div key={i} style={{
                          position: 'absolute', ...pos,
                          width: '20px', height: '20px',
                          borderTop: i < 2 ? '2px solid rgba(87,204,153,0.6)' : 'none',
                          borderBottom: i >= 2 ? '2px solid rgba(87,204,153,0.6)' : 'none',
                          borderLeft: i % 2 === 0 ? '2px solid rgba(87,204,153,0.6)' : 'none',
                          borderRight: i % 2 === 1 ? '2px solid rgba(87,204,153,0.6)' : 'none',
                        }} />
                      ))}
                    </>
                  )}
                </>
              ) : (
                <img src={imgSrc} alt="Captured selfie" style={{ width: '100%', height: '100%', objectFit: 'cover', display: 'block' }} />
              )}

              {/* Captured overlay */}
              {imgSrc && (
                <div style={{
                  position: 'absolute', top: '10px', right: '10px',
                  padding: '4px 10px', borderRadius: '20px',
                  background: 'rgba(87,204,153,0.9)', display: 'flex', alignItems: 'center', gap: '5px',
                }}>
                  <CheckCircle2 style={{ width: '12px', height: '12px', color: '#fff' }} />
                  <span style={{ fontSize: '11px', fontWeight: 700, color: '#fff' }}>Captured</span>
                </div>
              )}
            </div>

            {/* Camera controls */}
            <div style={{ display: 'flex', justifyContent: 'center', gap: '10px' }}>
              {!imgSrc ? (
                <button
                  type="button"
                  onClick={capture}
                  disabled={camError}
                  className="auth-btn-accent"
                  style={{ paddingLeft: '20px', paddingRight: '20px' }}
                >
                  <Camera style={{ width: '15px', height: '15px' }} />
                  Take Selfie
                </button>
              ) : (
                <button type="button" onClick={() => setImgSrc(null)} className="auth-btn-ghost">
                  <RefreshCw style={{ width: '14px', height: '14px' }} />
                  Retake
                </button>
              )}
            </div>

            <p style={{ fontSize: '12px', color: '#64748B', textAlign: 'center', lineHeight: 1.5 }}>
              Ensure your face is clearly visible, well-lit, and centred in the frame.
            </p>

            {/* Action buttons */}
            <div style={{ display: 'flex', gap: '10px', paddingTop: '4px' }}>
              <button
                type="button"
                className="auth-btn-ghost"
                onClick={() => setStep(1)}
                style={{ flexShrink: 0 }}
              >
                Back
              </button>
              <button
                type="submit"
                className="auth-btn"
                disabled={isLoading || !imgSrc}
                style={{ flex: 1 }}
              >
                {isLoading && <Loader2 style={{ width: '15px', height: '15px', animation: 'spin 1s linear infinite' }} />}
                Complete Registration
              </button>
            </div>
          </div>
        )}
      </form>
    </AuthShell>
  );
}
