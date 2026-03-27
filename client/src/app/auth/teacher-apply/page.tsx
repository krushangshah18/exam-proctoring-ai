'use client';

import { useState } from 'react';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import * as z from 'zod';
import { Loader2, CheckCircle2 } from 'lucide-react';
import { toast } from 'sonner';

import api from '@/lib/axios';
import { AuthShell, AuthField } from '@/components/auth/AuthShell';

const applySchema = z.object({
  full_name: z.string().min(2, 'Full name must be at least 2 characters'),
  email: z.string().email('Invalid email address'),
  organization: z.string().optional(),
  contact_number: z.string().optional().refine(v => !v || /^\d{10}$/.test(v), {
    message: 'Contact number must be exactly 10 digits.',
  }),
  reason: z.string().min(10, 'Please provide a detailed reason (min 10 characters)'),
});

type FormValues = z.infer<typeof applySchema>;

export default function TeacherApplyPage() {
  const [isLoading, setIsLoading] = useState(false);
  const [isSuccess, setIsSuccess] = useState(false);

  const { register, handleSubmit, formState: { errors } } = useForm<FormValues>({
    resolver: zodResolver(applySchema),
    defaultValues: { full_name: '', email: '', organization: '', contact_number: '', reason: '' },
  });

  async function onSubmit(data: FormValues) {
    setIsLoading(true);
    try {
      await api.post('/admin-applications/apply', {
        ...data,
        contact_number: data.contact_number === '' ? null : data.contact_number,
        organization: data.organization === '' ? null : data.organization,
      });
      setIsSuccess(true);
      toast.success('Application submitted successfully');
    } catch (error: any) {
      const detail = error.response?.data?.detail;
      if (Array.isArray(detail)) {
        const first = detail[0];
        toast.error(first?.msg || 'Validation failed');
      } else {
        toast.error(typeof detail === 'string' ? detail : 'Failed to submit application.');
      }
    } finally {
      setIsLoading(false);
    }
  }

  if (isSuccess) {
    return (
      <AuthShell
        title="Application received!"
        subtitle="Thank you for your interest. Our system administrators will review your request and contact you by email."
        leftHeading={'Become an\nExaminer.'}
        leftBody="Join our growing network of educators using AI-powered proctoring to run fair, secure assessments."
        eyebrow="Teacher Applications"
        features={[
          'Create & schedule exams',
          'Live student monitoring',
          'AI-powered detection rules',
          'Detailed session reports',
        ]}
        footer={<a href="/auth/login" className="auth-link">Return to sign in</a>}
      >
        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', padding: '20px 0 8px', gap: '16px', textAlign: 'center' }}>
          <div style={{
            width: '64px', height: '64px', borderRadius: '50%',
            background: 'rgba(87,204,153,0.12)', display: 'flex',
            alignItems: 'center', justifyContent: 'center',
          }}>
            <CheckCircle2 style={{ width: '32px', height: '32px', color: '#57CC99' }} />
          </div>
          <div>
            <p style={{ color: '#475569', fontSize: '14px', lineHeight: 1.65, maxWidth: '340px', margin: '0 auto' }}>
              Your application is pending review. You&apos;ll receive an email when your status changes.
            </p>
          </div>
        </div>
      </AuthShell>
    );
  }

  return (
    <AuthShell
      title="Teacher application"
      subtitle="Apply for admin access to create and proctor exams on ProctorAI."
      backHref="/auth/login"
      backLabel="Back to sign in"
      leftHeading={'Become an\nExaminer.'}
      leftBody="Join educators across institutions who trust ProctorAI to keep their assessments secure and fair."
      eyebrow="Teacher Applications"
      features={[
        'Create & schedule exams with ease',
        'Monitor students in real-time',
        'Review detailed proctoring reports',
        'Configure AI detection per exam',
      ]}
      maxWidth="480px"
      footer={
        <>
          Already have an account?{' '}
          <a href="/auth/login" className="auth-link">Sign in</a>
        </>
      }
    >
      <form onSubmit={handleSubmit(onSubmit)}>
        <AuthField label="Full name" error={errors.full_name?.message} required>
          <input
            type="text"
            placeholder="Dr. Jane Smith"
            className={`auth-input${errors.full_name ? ' has-error' : ''}`}
            {...register('full_name')}
          />
        </AuthField>

        <AuthField label="Email address" error={errors.email?.message} required>
          <input
            type="email"
            placeholder="jane@university.edu"
            className={`auth-input${errors.email ? ' has-error' : ''}`}
            {...register('email')}
          />
        </AuthField>

        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '14px' }}>
          <AuthField label="Organization" error={errors.organization?.message}>
            <input
              type="text"
              placeholder="University / School"
              className={`auth-input${errors.organization ? ' has-error' : ''}`}
              {...register('organization')}
            />
          </AuthField>

          <AuthField label="Contact number" error={errors.contact_number?.message}>
            <input
              type="tel"
              placeholder="10-digit number"
              className={`auth-input${errors.contact_number ? ' has-error' : ''}`}
              {...register('contact_number')}
            />
          </AuthField>
        </div>

        <AuthField label="Reason for application" error={errors.reason?.message} required>
          <textarea
            placeholder="Describe your role and why you need a teacher account..."
            className={`auth-textarea${errors.reason ? ' has-error' : ''}`}
            {...register('reason')}
          />
        </AuthField>

        <button type="submit" className="auth-btn" disabled={isLoading}>
          {isLoading && <Loader2 style={{ width: '15px', height: '15px', animation: 'spin 1s linear infinite' }} />}
          Submit Application
        </button>
      </form>
    </AuthShell>
  );
}
