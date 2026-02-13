'use client';

import { useState } from 'react';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import * as z from 'zod';
import { useRouter } from 'next/navigation';
import { Loader2 } from 'lucide-react';
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
} from '@/components/ui/form';
import { Input } from '@/components/ui/input';
import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from '@/components/ui/card';

const formSchema = z.object({
  email: z.string().email({
    message: 'Please enter a valid email address.',
  }),
  password: z.string().min(1, {
    message: 'Password is required.',
  }),
});

export default function LoginPage() {
  const router = useRouter();
  const [isLoading, setIsLoading] = useState(false);

  const form = useForm<z.infer<typeof formSchema>>({
    resolver: zodResolver(formSchema),
    defaultValues: {
      email: '',
      password: '',
    },
  });

  async function onSubmit(values: z.infer<typeof formSchema>) {
    setIsLoading(true);
    try {
      // 1. Login to get tokens
      const response = await api.post('/auth/login', values);

      if (response.data.access_token) {
        // Store tokens
        localStorage.setItem('access_token', response.data.access_token);
        localStorage.setItem('refresh_token', response.data.refresh_token);
        
        toast.success('Login successful');

        // 2. Fetch User Role
        const meResponse = await api.get('/auth/me');
        const role = meResponse.data.role; // "STUDENT", "ADMIN", "SYSADMIN"
        
        // 3. Redirect based on role
        if (role === 'SYSADMIN') {
           router.push('/sys/dashboard');
        } else if (role === 'ADMIN') {
           router.push('/admin/dashboard');
        } else {
           router.push('/student/dashboard');
        }

      } else if (response.data.message && response.data.message.includes('OTP')) {
        // OTP Required for New Device validation
        toast.info('New device detected. OTP sent to your email.');
        router.push(`/auth/verify-otp?type=device&email=${values.email}`);
      }
    } catch (error: any) {
      console.error(error);
      const status = error.response?.status;
      const msg = error.response?.data?.detail || 'Authentication failed';
      
      if (status === 403 && msg.includes('locked')) {
        toast.error("Account is locked due to too many failed attempts.");
        // Optional: Redirect to unlock page immediately or let them click a link
        setTimeout(() => {
           router.push('/auth/unlock-account');
        }, 2000);
      } else {
        toast.error(msg);
      }
    } finally {
      setIsLoading(false);
    }
  }

  return (
    <div className="flex h-screen items-center justify-center bg-gray-50 dark:bg-gray-900">
      <Card className="w-[400px]">
        <CardHeader>
          <CardTitle className="text-2xl font-bold text-center">Login</CardTitle>
          <CardDescription className="text-center">
            Enter your credentials to access the proctoring system
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Form {...form}>
            <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-6">
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
                    <div className="flex items-center justify-between">
                      <FormLabel>Password</FormLabel>
                      <a 
                        href="/auth/forgot-password" 
                        className="text-sm font-medium text-blue-600 hover:text-blue-500"
                      >
                        Forgot password?
                      </a>
                    </div>
                    <FormControl>
                      <Input type="password" placeholder="••••••••" {...field} />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />
              <Button type="submit" className="w-full" disabled={isLoading}>
                {isLoading && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                Sign In
              </Button>
            </form>
          </Form>
        </CardContent>
        <CardFooter className="flex justify-center">
          <p className="text-sm text-gray-500">
            Don't have an account?{' '}
            <a href="/auth/register" className="font-medium text-blue-600 hover:text-blue-500">
              Register
            </a>
          </p>
        </CardFooter>
      </Card>
    </div>
  );
}
