'use client';

import { useState } from 'react';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import * as z from 'zod';
import { useRouter } from 'next/navigation';
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
import { Loader2, Lock } from 'lucide-react';
import { toast } from 'sonner';
import api from '@/lib/axios';

const formSchema = z.object({
  email: z.string().email(),
});

export default function UnlockAccountPage() {
  const router = useRouter();
  const [isLoading, setIsLoading] = useState(false);

  const form = useForm<z.infer<typeof formSchema>>({
    resolver: zodResolver(formSchema),
    defaultValues: {
      email: '',
    },
  });

  async function onSubmit(values: z.infer<typeof formSchema>) {
    setIsLoading(true);
    try {
      await api.post('/auth/unlock/request', values);
      toast.success('Unlock OTP sent to your email.');
      router.push(`/auth/verify-otp?type=unlock&email=${values.email}`);
    } catch (error: any) {
        // Even if account doesn't exist or isn't locked, we usually don't want to reveal too much,
        // but the backend might return specific errors.
        const msg = error.response?.data?.detail || "Request failed";
        toast.error(msg);
    } finally {
      setIsLoading(false);
    }
  }

  return (
    <div className="flex h-screen items-center justify-center bg-gray-50 dark:bg-gray-900">
      <Card className="w-[400px]">
        <CardHeader>
            <div className="flex justify-center mb-4">
                <div className="p-3 bg-red-100 rounded-full">
                    <Lock className="h-6 w-6 text-red-600" />
                </div>
            </div>
          <CardTitle className="text-2xl font-bold text-center">Account Locked?</CardTitle>
          <CardDescription className="text-center">
            Enter your email to request an unlock OTP.
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
              <Button type="submit" className="w-full" disabled={isLoading}>
                {isLoading && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                Request Unlock OTP
              </Button>
            </form>
          </Form>
        </CardContent>
        <CardFooter className="flex justify-center">
          <a href="/auth/login" className="text-sm text-blue-600 hover:text-blue-500">
            Back to Login
          </a>
        </CardFooter>
      </Card>
    </div>
  );
}
