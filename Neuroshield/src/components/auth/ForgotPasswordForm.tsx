
'use client';

import { zodResolver } from '@hookform/resolvers/zod';
import { useForm } from 'react-hook-form';
import * as z from 'zod';
import { useAuthContext } from '@/contexts/AuthContext';
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
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from '@/components/ui/card';
import { useState } from 'react';
import { Loader2, Mail } from 'lucide-react';
import Link from 'next/link';

const forgotPasswordSchema = z.object({
  email: z.string().email({ message: 'Invalid email address.' }),
});

type ForgotPasswordFormValues = z.infer<typeof forgotPasswordSchema>;

export function ForgotPasswordForm() {
  const [isLoading, setIsLoading] = useState(false);
  const [emailSent, setEmailSent] = useState(false);
  const { sendPasswordReset } = useAuthContext();

  const form = useForm<ForgotPasswordFormValues>({
    resolver: zodResolver(forgotPasswordSchema),
    defaultValues: {
      email: '',
    },
  });

  async function onSubmit(values: ForgotPasswordFormValues) {
    setIsLoading(true);
    setEmailSent(false);
    try {
      const success = await sendPasswordReset(values.email);
      if (success) {
        setEmailSent(true);
        form.reset();
      }
    } catch (error) {
      // Error toast is handled by AuthContext
      console.error("Forgot password form submission error:", error);
    } finally {
      setIsLoading(false);
    }
  }

  if (emailSent) {
    return (
      <Card className="w-full max-w-md shadow-xl border-primary/20 text-left">
        <CardHeader>
          <CardTitle className="text-xl text-primary flex items-center gap-2">
            <Mail className="h-5 w-5" /> Email Sent
          </CardTitle>
          <CardDescription>
            If an account exists for the email provided, a password reset link has been sent. Please check your inbox (and spam folder).
          </CardDescription>
        </CardHeader>
        <CardContent>
            <p className="text-sm text-muted-foreground">
            You can now close this page or{' '}
            <Link href="/auth/login" className="font-medium text-primary hover:text-accent hover:underline">
                return to login
            </Link>
            .
            </p>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card className="w-full max-w-md shadow-xl border-primary/20 text-left">
      <CardHeader>
        <CardTitle className="text-xl text-primary">Account Recovery</CardTitle>
        <CardDescription>Enter your registered email address below.</CardDescription>
      </CardHeader>
      <Form {...form}>
        <form onSubmit={form.handleSubmit(onSubmit)}>
          <CardContent className="space-y-5">
            <FormField
              control={form.control}
              name="email"
              render={({ field }) => (
                <FormItem>
                  <FormLabel className="text-muted-foreground">Email Address</FormLabel>
                  <FormControl>
                    <Input 
                      type="email"
                      placeholder="operator@neuro.sh" 
                      {...field} 
                      className="bg-input/50 border-primary/30 focus:border-primary focus:ring-primary"
                      autoComplete="email"
                    />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />
          </CardContent>
          <CardFooter className="flex flex-col gap-4 pt-4">
            <Button type="submit" className="w-full btn-glow" disabled={isLoading}>
              {isLoading ? <Loader2 className="animate-spin" /> : 'Send Reset Link'}
            </Button>
          </CardFooter>
        </form>
      </Form>
    </Card>
  );
}
