'use client';

import { useState, useRef, useCallback } from 'react';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import * as z from 'zod';
import { useRouter } from 'next/navigation';
import Webcam from 'react-webcam';
import { Camera, RefreshCw, Loader2, CheckCircle2 } from 'lucide-react';
import { toast } from 'sonner';

import api from '@/lib/axios';

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
import { Checkbox } from '@/components/ui/checkbox';
import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from '@/components/ui/card';

const formSchema = z.object({
  full_name: z.string().min(2, {
    message: 'Name must be at least 2 characters.',
  }),
  email: z.string().email({
    message: 'Please enter a valid email address.',
  }),
  password: z.string().min(8, {
    message: 'Password must be at least 8 characters.',
  }),
  confirmPassword: z.string(),
  consent: z.boolean().refine((val) => val === true, {
    message: 'You must agree to the privacy policy.',
  }),
}).refine((data) => data.password === data.confirmPassword, {
  message: "Passwords don't match",
  path: ["confirmPassword"],
});

export default function RegisterPage() {
  const router = useRouter();
  const [step, setStep] = useState(1);
  const [imgSrc, setImgSrc] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const webcamRef = useRef<Webcam>(null);

  const form = useForm<z.infer<typeof formSchema>>({
    resolver: zodResolver(formSchema),
    defaultValues: {
      full_name: '',
      email: '',
      password: '',
      confirmPassword: '',
      consent: false,
    },
  });

  const capture = useCallback(() => {
    const imageSrc = webcamRef.current?.getScreenshot();
    if (imageSrc) {
      setImgSrc(imageSrc);
    }
  }, [webcamRef]);

  const retake = () => {
    setImgSrc(null);
  };

  const handleNext = async () => {
    const output = await form.trigger(['full_name', 'email', 'password', 'confirmPassword', 'consent']);
    if (output) {
      if (step === 1) {
        setStep(2);
      }
    }
  };

  async function onSubmit(values: z.infer<typeof formSchema>) {
    if (!imgSrc) {
      toast.error('Please capture a selfie to continue.');
      return;
    }

    setIsLoading(true);

    try {
      // Convert base64 to blob
      const res = await fetch(imgSrc);
      const blob = await res.blob();
      const file = new File([blob], "selfie.jpg", { type: "image/jpeg" });

      const formData = new FormData();
      formData.append('email', values.email);
      formData.append('password', values.password);
      formData.append('full_name', values.full_name);
      formData.append('consent', 'true');
      formData.append('selfie', file);

      await api.post('/auth/register/student', formData, {
        headers: {
          'Content-Type': 'multipart/form-data',
        },
      });

      toast.success('Registration successful! Please login.');
      router.push('/auth/login');

    } catch (error: any) {
      console.error(error);
      const msg = error.response?.data?.detail || 'Registration failed';
      toast.error(msg);
    } finally {
      setIsLoading(false);
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-gray-50 dark:bg-gray-900 py-12 px-4 sm:px-6 lg:px-8">
      <Card className="w-full max-w-md">
        <CardHeader>
          <CardTitle className="text-2xl font-bold text-center">
            {step === 1 ? 'Create Account' : 'Identity Verification'}
          </CardTitle>
          <CardDescription className="text-center">
            {step === 1 
              ? 'Enter your details to get started' 
              : 'we need a clear selfie for proctoring verification'}
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Form {...form}>
            <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-6">
              
              {step === 1 && (
                <>
                  <FormField
                    control={form.control}
                    name="full_name"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel>Full Name</FormLabel>
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
                        <FormLabel>Email</FormLabel>
                        <FormControl>
                          <Input placeholder="student@example.com" {...field} />
                        </FormControl>
                        <FormMessage />
                      </FormItem>
                    )}
                  />
                  <FormField
                    control={form.control}
                    name="password"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel>Password</FormLabel>
                        <FormControl>
                          <Input type="password" placeholder="••••••••" {...field} />
                        </FormControl>
                        <FormMessage />
                      </FormItem>
                    )}
                  />
                  <FormField
                    control={form.control}
                    name="confirmPassword"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel>Confirm Password</FormLabel>
                        <FormControl>
                          <Input type="password" placeholder="••••••••" {...field} />
                        </FormControl>
                        <FormMessage />
                      </FormItem>
                    )}
                  />
                  
                  <FormField
                    control={form.control}
                    name="consent"
                    render={({ field }) => (
                      <FormItem className="flex flex-row items-start space-x-3 space-y-0 rounded-md border p-4">
                        <FormControl>
                          <Checkbox
                            checked={field.value}
                            onCheckedChange={field.onChange}
                          />
                        </FormControl>
                        <div className="space-y-1 leading-none">
                          <FormLabel>
                            Privacy Policy Consent
                          </FormLabel>
                          <FormDescription>
                            I authorize the collection of my face data for proctoring purposes.
                          </FormDescription>
                          <FormMessage />
                        </div>
                      </FormItem>
                    )}
                  />

                  <Button type="button" onClick={handleNext} className="w-full">
                    Next: Selfie Verification
                  </Button>
                </>
              )}

              {step === 2 && (
                <div className="space-y-4">
                  <div className="relative aspect-video w-full overflow-hidden rounded-lg border bg-black">
                    {!imgSrc ? (
                      <Webcam
                        audio={false}
                        ref={webcamRef}
                        screenshotFormat="image/jpeg"
                        videoConstraints={{ facingMode: "user" }}
                        className="h-full w-full object-cover"
                      />
                    ) : (
                      <img 
                        src={imgSrc} 
                        alt="Selfie" 
                        className="h-full w-full object-cover" 
                      />
                    )}
                  </div>

                  <div className="flex justify-center gap-4">
                    {!imgSrc ? (
                      <Button type="button" onClick={capture} variant="secondary">
                        <Camera className="mr-2 h-4 w-4" />
                        Capture
                      </Button>
                    ) : (
                      <Button type="button" onClick={retake} variant="outline">
                        <RefreshCw className="mr-2 h-4 w-4" />
                        Retake
                      </Button>
                    )}
                  </div>

                  <div className="flex gap-4 pt-4">
                    <Button type="button" variant="ghost" onClick={() => setStep(1)}>
                      Back
                    </Button>
                    <Button type="submit" className="flex-1" disabled={isLoading || !imgSrc}>
                      {isLoading && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                      Register
                    </Button>
                  </div>
                </div>
              )}

            </form>
          </Form>
        </CardContent>
        {step === 1 && (
          <CardFooter className="flex justify-center">
            <p className="text-sm text-gray-500">
              Already have an account?{' '}
              <a href="/auth/login" className="font-medium text-blue-600 hover:text-blue-500">
                Login
              </a>
            </p>
          </CardFooter>
        )}
      </Card>
    </div>
  );
}
