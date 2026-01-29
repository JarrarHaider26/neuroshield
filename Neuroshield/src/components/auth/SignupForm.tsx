
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
import { Checkbox } from '@/components/ui/checkbox';
import { useState } from 'react';
import { Eye, EyeOff, Loader2 } from 'lucide-react';
import Link from 'next/link';

const signupSchema = z.object({
  callsign: z.string().min(3, { message: 'Callsign must be at least 3 characters.' }),
  email: z.string().email({ message: 'Invalid email address.' }),
  password: z.string().min(8, { message: 'Password must be at least 8 characters.' })
    .regex(/[A-Z]/, { message: "Password must contain at least one uppercase letter." })
    .regex(/[a-z]/, { message: "Password must contain at least one lowercase letter." })
    .regex(/[0-9]/, { message: "Password must contain at least one number." })
    .regex(/[^A-Za-z0-9]/, { message: "Password must contain at least one special character." }),
  confirmPassword: z.string(),
  terms: z.boolean().refine(val => val === true, { message: 'You must accept the terms and conditions.' }),
}).refine(data => data.password === data.confirmPassword, {
  message: 'Passwords do not match.',
  path: ['confirmPassword'],
});

type SignupFormValues = z.infer<typeof signupSchema>;

export function SignupForm() {
  const [isSubmittingEmail, setIsSubmittingEmail] = useState(false);
  const [showPassword, setShowPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);
  const { signup, loading: authLoading } = useAuthContext();

  const form = useForm<SignupFormValues>({
    resolver: zodResolver(signupSchema),
    defaultValues: {
      callsign: '',
      email: '',
      password: '',
      confirmPassword: '',
      terms: false,
    },
  });

  async function onSubmit(values: SignupFormValues) {
    setIsSubmittingEmail(true);
    try {
      await signup(values.email, values.password, values.callsign);
      // Navigation will be handled by AuthContext or SignupPage useEffect
    } catch (error) {
      // Error toast is handled by AuthContext
      console.error("Signup form submission error:", error);
    } finally {
      setIsSubmittingEmail(false);
    }
  }
  
  const isLoading = isSubmittingEmail || authLoading;

  return (
    <Card className="w-full max-w-md shadow-xl border-primary/20 text-left">
      <CardHeader>
        <CardTitle className="text-xl text-primary">Register Operative ID</CardTitle>
        <CardDescription>Create your secure access credentials.</CardDescription>
      </CardHeader>
      <Form {...form}>
        <form onSubmit={form.handleSubmit(onSubmit)}>
          <CardContent className="space-y-4">
            <FormField
              control={form.control}
              name="callsign"
              render={({ field }) => (
                <FormItem>
                  <FormLabel className="text-muted-foreground">Callsign</FormLabel>
                  <FormControl>
                    <Input placeholder="e.g., Ghost" {...field} className="bg-input/50 border-primary/30 focus:border-primary focus:ring-primary" disabled={isLoading} />
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
                  <FormLabel className="text-muted-foreground">Email Address</FormLabel>
                  <FormControl>
                    <Input placeholder="operator@secure.domain" type="email" {...field} className="bg-input/50 border-primary/30 focus:border-primary focus:ring-primary" autoComplete="email" disabled={isLoading} />
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
                  <FormLabel className="text-muted-foreground">Secure Password</FormLabel>
                  <FormControl>
                     <div className="relative">
                      <Input 
                        type={showPassword ? "text" : "password"}
                        placeholder="Min. 8 chars, 1 UC, 1 LC, 1 Num, 1 Special" 
                        {...field} 
                        className="bg-input/50 border-primary/30 focus:border-primary focus:ring-primary pr-10"
                        autoComplete="new-password"
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
            <FormField
              control={form.control}
              name="confirmPassword"
              render={({ field }) => (
                <FormItem>
                  <FormLabel className="text-muted-foreground">Confirm Password</FormLabel>
                  <FormControl>
                     <div className="relative">
                        <Input 
                          type={showConfirmPassword ? "text" : "password"}
                          placeholder="Re-enter your password" 
                          {...field} 
                          className="bg-input/50 border-primary/30 focus:border-primary focus:ring-primary pr-10"
                          autoComplete="new-password"
                          disabled={isLoading}
                        />
                        <Button 
                          type="button" 
                          variant="ghost" 
                          size="icon" 
                          className="absolute right-1 top-1/2 -translate-y-1/2 h-7 w-7 text-muted-foreground hover:text-primary"
                          onClick={() => setShowConfirmPassword(!showConfirmPassword)}
                          aria-label={showConfirmPassword ? "Hide confirm password" : "Show confirm password"}
                          disabled={isLoading}
                        >
                          {showConfirmPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                        </Button>
                      </div>
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />
            <FormField
              control={form.control}
              name="terms"
              render={({ field }) => (
                <FormItem className="flex flex-row items-start space-x-3 space-y-0 rounded-md p-0 pt-2">
                  <FormControl>
                    <Checkbox
                      checked={field.value}
                      onCheckedChange={field.onChange}
                      className="border-primary/50 data-[state=checked]:bg-primary data-[state=checked]:text-primary-foreground mt-0.5"
                      disabled={isLoading}
                    />
                  </FormControl>
                  <div className="space-y-1 leading-none">
                    <FormLabel className="text-xs text-muted-foreground">
                      I agree to the{' '}
                      <Link href="/terms" className={`text-primary hover:underline ${isLoading ? 'pointer-events-none opacity-50' : ''}`}>
                        Operational Protocols & Service Agreement
                      </Link>
                      .
                    </FormLabel>
                    <FormMessage />
                  </div>
                </FormItem>
              )}
            />
          </CardContent>
          <CardFooter className="flex flex-col gap-4 pt-4">
            <Button type="submit" className="w-full btn-glow" disabled={isLoading}>
              {isSubmittingEmail ? <Loader2 className="animate-spin" /> : 'Create Secure ID'}
            </Button>
            {/* Google Login button and divider removed */}
          </CardFooter>
        </form>
      </Form>
    </Card>
  );
}
