'use client';

import { useState } from 'react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import * as z from 'zod';
import { Loader2, ArrowLeft, School, GraduationCap } from 'lucide-react';
import { toast } from 'sonner';

import { Button } from '@/components/ui/button';
import {
  Form,
  FormControl,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
  FormDescription,
} from '@/components/ui/form';
import { Input } from '@/components/ui/input';
import { Textarea } from '@/components/ui/textarea';
import api from '@/lib/axios';
import { Card, CardContent, CardDescription, CardHeader, CardTitle, CardFooter } from '@/components/ui/card';

const applySchema = z.object({
  full_name: z.string().min(2, 'Full name must be at least 2 characters'),
  email: z.string().email('Invalid email address'),
  organization: z.string().optional(),
  contact_number: z.string().optional().refine((val) => !val || /^\d{10}$/.test(val), {
    message: 'Contact number must be exactly 10 digits.',
  }),
  reason: z.string().min(10, 'Please provide a detailed reason (min 10 characters)'),
});

type ApplyFormValues = z.infer<typeof applySchema>;

export default function TeacherApplyPage() {
  const router = useRouter();
  const [isLoading, setIsLoading] = useState(false);
  const [isSuccess, setIsSuccess] = useState(false);

  const form = useForm<ApplyFormValues>({
    resolver: zodResolver(applySchema),
    defaultValues: {
      full_name: '',
      email: '',
      organization: '',
      contact_number: '',
      reason: '',
    },
  });

  async function onSubmit(data: ApplyFormValues) {
    setIsLoading(true);
    try {
      // Ensure empty strings are sent as null for optional fields
      const payload = {
        ...data,
        contact_number: data.contact_number === '' ? null : data.contact_number,
        organization: data.organization === '' ? null : data.organization,
      };

      await api.post('/admin-applications/apply', payload);
      setIsSuccess(true);
      toast.success('Application submitted successfully');
    } catch (error: any) {
      console.error(error);
      
      const detail = error.response?.data?.detail;
      
      if (Array.isArray(detail)) {
        // Handle Pydantic validation errors
        // detail is usually [{ "loc": ["body", "field"], "msg": "...", "type": "..." }]
        const firstError = detail[0];
        const msg = firstError?.msg || 'Validation failed';
        const field = firstError?.loc?.[1]; // Usually ["body", "field_name"]
        
        if (field) {
            toast.error(`${field}: ${msg}`);
        } else {
            toast.error(msg);
        }
      } else if (typeof detail === 'string') {
        toast.error(detail);
      } else {
        toast.error('Failed to submit application. Please try again.');
      }
    } finally {
      setIsLoading(false);
    }
  }

  if (isSuccess) {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center p-4">
        <Card className="w-full max-w-md">
          <CardHeader>
            <div className="mx-auto bg-green-100 dark:bg-green-900/30 p-3 rounded-full w-fit mb-4">
              <School className="h-8 w-8 text-green-600 dark:text-green-400" />
            </div>
            <CardTitle className="text-center text-2xl">Application Received</CardTitle>
            <CardDescription className="text-center pt-2">
              Thank you for your interest in joining as a teacher/admin.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4 text-center text-muted-foreground">
            <p>
              Your application has been submitted successfully and is pending review by our system administrators.
            </p>
            <p>
              You will receive an email confirmation once your application status changes.
            </p>
          </CardContent>
          <CardFooter className="flex justify-center">
            <Button asChild variant="outline">
              <Link href="/">Return to Home</Link>
            </Button>
          </CardFooter>
        </Card>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-background flex flex-col">
      <div className="p-4 md:p-8">
        <Button variant="ghost" size="sm" asChild className="mb-8">
          <Link href="/auth/login">
            <ArrowLeft className="mr-2 h-4 w-4" />
            Back to Login
          </Link>
        </Button>

        <div className="mx-auto w-full max-w-lg">
          <div className="mb-8 text-center">
            <div className="mx-auto bg-primary/10 p-3 rounded-full w-fit mb-4">
              <GraduationCap className="h-8 w-8 text-primary" />
            </div>
            <h1 className="text-3xl font-bold tracking-tight">Teacher Application</h1>
            <p className="text-muted-foreground mt-2">
              Join our platform to proctor exams and manage students.
            </p>
          </div>

          <Card>
            <CardHeader>
              <CardTitle>Application Form</CardTitle>
              <CardDescription>
                Please fill out your details below. All fields marked with * are required.
              </CardDescription>
            </CardHeader>
            <CardContent>
              <Form {...form}>
                <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-6">
                  <FormField
                    control={form.control}
                    name="full_name"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel>Full Name *</FormLabel>
                        <FormControl>
                          <Input placeholder="John Doe" {...field} />
                        </FormControl>
                        <FormMessage />
                      </FormItem>
                    )}
                  />

                  <FormField
                    control={form.control}
                    name="email"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel>Email Address *</FormLabel>
                        <FormControl>
                          <Input placeholder="john@school.edu" type="email" {...field} />
                        </FormControl>
                        <FormMessage />
                      </FormItem>
                    )}
                  />

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <FormField
                      control={form.control}
                      name="organization"
                      render={({ field }) => (
                        <FormItem>
                          <FormLabel>Organization</FormLabel>
                          <FormControl>
                            <Input placeholder="University Name" {...field} />
                          </FormControl>
                          <FormMessage />
                        </FormItem>
                      )}
                    />

                    <FormField
                      control={form.control}
                      name="contact_number"
                      render={({ field }) => (
                        <FormItem>
                          <FormLabel>Contact Number</FormLabel>
                          <FormControl>
                            <Input placeholder="+1 (555) 000-0000" {...field} />
                          </FormControl>
                          <FormMessage />
                        </FormItem>
                      )}
                    />
                  </div>

                  <FormField
                    control={form.control}
                    name="reason"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel>Reason for Application *</FormLabel>
                        <FormControl>
                          <Textarea 
                            placeholder="Please explain why you need a teacher/admin account..." 
                            className="min-h-[100px]"
                            {...field} 
                          />
                        </FormControl>
                        <FormDescription>
                          Briefly describe your role and requirements (min 10 characters).
                        </FormDescription>
                        <FormMessage />
                      </FormItem>
                    )}
                  />

                  <Button type="submit" className="w-full" disabled={isLoading}>
                    {isLoading && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                    Submit Application
                  </Button>
                </form>
              </Form>
            </CardContent>
          </Card>

          <p className="mt-8 text-center text-sm text-muted-foreground">
            Already have an account?{' '}
            <Link href="/auth/login" className="underline underline-offset-4 hover:text-primary">
              Sign in
            </Link>
          </p>
        </div>
      </div>
    </div>
  );
}
