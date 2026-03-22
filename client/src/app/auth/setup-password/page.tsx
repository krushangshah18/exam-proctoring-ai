'use client';

import { useState } from 'react';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import * as z from 'zod';
import { useRouter } from 'next/navigation';
import { Loader2, LockKeyhole } from 'lucide-react';
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
  CardHeader,
  CardTitle,
} from '@/components/ui/card';

const setupSchema = z.object({
  new_password: z.string().min(8, {
    message: 'Password must be at least 8 characters long.',
  }),
  confirm_password: z.string()
}).refine((data) => data.new_password === data.confirm_password, {
  message: "Passwords don't match",
  path: ["confirm_password"],
});

export default function SetupPasswordPage() {
  const router = useRouter();
  const [isLoading, setIsLoading] = useState(false);

  const form = useForm<z.infer<typeof setupSchema>>({
    resolver: zodResolver(setupSchema),
    defaultValues: {
      new_password: '',
      confirm_password: '',
    },
  });

  async function onSubmit(values: z.infer<typeof setupSchema>) {
    setIsLoading(true);
    try {
      await api.post('/auth/setup-password', {
        new_password: values.new_password
      });

      toast.success('Password setup completed successfully!');
      
      // Fetch user profile again to redirect appropriately
      const meResponse = await api.get('/auth/me');
      const { role } = meResponse.data;

      if (role === 'SYSADMIN') {
         router.push('/sys/dashboard');
      } else if (role === 'ADMIN') {
         router.push('/admin/dashboard');
      } else {
         router.push('/student/dashboard');
      }

    } catch (error: any) {
      console.error(error);
      const msg = error.response?.data?.detail || 'Failed to setup password';
      toast.error(msg);
    } finally {
      setIsLoading(false);
    }
  }

  return (
    <div className="flex h-screen items-center justify-center bg-gray-50 dark:bg-gray-900">
      <Card className="w-[450px]">
        <CardHeader className="text-center">
          <div className="flex justify-center mb-4">
            <div className="h-12 w-12 bg-blue-100 dark:bg-blue-900/40 rounded-full flex items-center justify-center">
              <LockKeyhole className="h-6 w-6 text-blue-600 dark:text-blue-400" />
            </div>
          </div>
          <CardTitle className="text-2xl font-bold">Welcome to Proctor AI</CardTitle>
          <CardDescription className="pt-2 text-md">
            For security reasons, you must change your auto-generated password before continuing.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Form {...form}>
            <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-6">
              <FormField
                control={form.control}
                name="new_password"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>New Password</FormLabel>
                    <FormControl>
                      <Input type="password" placeholder="••••••••" {...field} />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />
              <FormField
                control={form.control}
                name="confirm_password"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Confirm New Password</FormLabel>
                    <FormControl>
                      <Input type="password" placeholder="••••••••" {...field} />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />
              <Button type="submit" className="w-full" disabled={isLoading}>
                {isLoading && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                Complete Setup
              </Button>
            </form>
          </Form>
        </CardContent>
      </Card>
    </div>
  );
}
