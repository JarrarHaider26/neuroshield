
'use client';

import { zodResolver } from '@hookform/resolvers/zod';
import { useForm } from 'react-hook-form';
import * as z from 'zod';
import Link from 'next/link';
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
import { Eye, EyeOff, Loader2 } from 'lucide-react'; 
// Removed Smartphone, KeyRound, RecaptchaVerifier, ConfirmationResult

// Simplified schema, removed phone and otp fields
const loginSchema = z.object({
  email: z.string().email({ message: 'Invalid email address.' }),
  password: z.string().min(1, { message: 'Password is required.' }), // Password is required for email login
});

type LoginFormValues = z.infer<typeof loginSchema>;

export function LoginForm() {
  const [isSubmittingEmail, setIsSubmittingEmail] = useState(false);
  const [showPassword, setShowPassword] = useState(false);
  const { login } = useAuthContext();
  
  const form = useForm<LoginFormValues>({
    resolver: zodResolver(loginSchema),
    mode: 'onSubmit',
    defaultValues: {
      email: '',
      password: '',
    },
  });

  async function onEmailSubmit(values: LoginFormValues) {
    if (!values.email || !values.password) {
      form.setError("email", { type: "manual", message: "Email and password are required." });
      return;
    }
    
    // Mark that a login attempt is happening
    if (typeof window !== 'undefined') {
      sessionStorage.setItem('hasAttemptedLogin', 'true');
    }
    
    setIsSubmittingEmail(true);
    
    try {
      await login(values.email, values.password);
      // Success - redirect will happen
    } catch (error) {
      console.error("Login form submission error:", error);
      
      // Reset form but keep email value
      form.reset({
        email: values.email, // Keep the email
        password: '', // Clear password
      });
      
      // Focus back on password field
      setTimeout(() => {
        const passwordInput = document.querySelector('input[name="password"]') as HTMLInputElement;
        passwordInput?.focus();
      }, 100);
      
      setIsSubmittingEmail(false);
    }
  }

  const isLoading = isSubmittingEmail;

  return (
    <Card className="w-full max-w-md shadow-xl border-primary/20 text-left">
      <CardHeader>
        <CardTitle className="text-xl text-primary">Terminal Access</CardTitle>
        <CardDescription>
          Enter your credentials to proceed.
        </CardDescription>
      </CardHeader>
      
      {/* Removed login method toggle buttons */}

      <Form {...form}>
        <form onSubmit={form.handleSubmit(onEmailSubmit)}>
          <CardContent className="space-y-5 pt-5">
            {/* Email and Password fields always visible */}
            <FormField
              control={form.control}
              name="email"
              render={({ field }) => (
                <FormItem>
                  <FormLabel className="text-muted-foreground">Email Address / Callsign</FormLabel>
                  <FormControl>
                    <Input 
                      placeholder="operator@neuro.sh" 
                      {...field} 
                      className="bg-input/50 border-primary/30 focus:border-primary focus:ring-primary"
                      autoComplete="email"
                      disabled={isLoading}
                    />
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
                  <div className="flex items-center justify-between mb-1">
                    <FormLabel className="text-muted-foreground">Password</FormLabel>
                    <Link href="/auth/forgot-password" className={`text-xs text-primary hover:text-accent hover:underline ${isLoading ? 'pointer-events-none opacity-50' : ''}`}>
                      Forgot password?
                    </Link>
                  </div>
                  <FormControl>
                    <div className="relative">
                      <Input 
                        type={showPassword ? "text" : "password"}
                        placeholder="************" 
                        {...field} 
                        className="bg-input/50 border-primary/30 focus:border-primary focus:ring-primary pr-10"
                        autoComplete="current-password"
                        disabled={isLoading}
                      />
                      <Button 
                        type="button" 
                        variant="ghost" 
                        size="icon" 
                        className="absolute right-1 top-1/2 -translate-y-1/2 h-7 w-7 text-muted-foreground hover:text-primary"
                        onClick={() => setShowPassword(!showPassword)}
                        aria-label={showPassword ? "Hide password" : "Show password"}
                        disabled={isLoading}
                      >
                        {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                      </Button>
                    </div>
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />
            {/* Removed phone and OTP input fields and reCAPTCHA container */}
          </CardContent>
          <CardFooter className="flex flex-col gap-4 pt-4">
            <Button type="submit" className="w-full btn-glow" disabled={isLoading}>
              {isLoading ? <Loader2 className="animate-spin" /> : 'Authorize Access'}
            </Button>
            {/* Removed phone auth related buttons */}
          </CardFooter>
        </form>
      </Form>
    </Card>
  );
}
