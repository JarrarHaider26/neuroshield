
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
import { Eye, EyeOff, Loader2 } from 'lucide-react';

const loginSchema = z.object({
  email: z.string().email({ message: 'Invalid email address.' }),
  password: z.string().min(1, { message: 'Password is required.' }),
});

type LoginFormValues = z.infer<typeof loginSchema>;

export function AdminLoginForm() {
  const [isSubmitting, setIsSubmitting] = useState(false);
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

  async function onSubmit(values: LoginFormValues) {
    setIsSubmitting(true);
    
    try {
      await login(values.email, values.password, true);
      // Success - redirect will happen
    } catch (error: any) {
      console.error("Admin login failed:", error.message);
      
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
      
      setIsSubmitting(false);
    }
  }

  return (
    <Card className="w-full max-w-md shadow-xl border-primary/20 text-left">
      <CardHeader>
        <CardTitle className="text-xl text-primary">Admin Terminal</CardTitle>
        <CardDescription>
          Enter your administrator credentials.
        </CardDescription>
      </CardHeader>
      
      <Form {...form}>
        <form onSubmit={form.handleSubmit(onSubmit)}>
          <CardContent className="space-y-5 pt-5">
            <FormField
              control={form.control}
              name="email"
              render={({ field }) => (
                <FormItem>
                  <FormLabel className="text-muted-foreground">Admin Email</FormLabel>
                  <FormControl>
                    <Input 
                      placeholder="admin@neuroshield.io" 
                      {...field} 
                      className="bg-input/50 border-primary/30 focus:border-primary focus:ring-primary"
                      autoComplete="email"
                      disabled={isSubmitting}
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
                  </div>
                  <FormControl>
                    <div className="relative">
                      <Input 
                        type={showPassword ? "text" : "password"}
                        placeholder="************" 
                        {...field} 
                        className="bg-input/50 border-primary/30 focus:border-primary focus:ring-primary pr-10"
                        autoComplete="current-password"
                        disabled={isSubmitting}
                      />
                      <Button 
                        type="button" 
                        variant="ghost" 
                        size="icon" 
                        className="absolute right-1 top-1/2 -translate-y-1/2 h-7 w-7 text-muted-foreground hover:text-primary"
                        onClick={() => setShowPassword(!showPassword)}
                        aria-label={showPassword ? "Hide password" : "Show password"}
                        disabled={isSubmitting}
                      >
                        {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                      </Button>
                    </div>
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />
          </CardContent>
          <CardFooter className="flex flex-col gap-4 pt-4">
            <Button type="submit" className="w-full btn-glow" disabled={isSubmitting}>
              {isSubmitting ? <Loader2 className="animate-spin" /> : 'Authorize Access'}
            </Button>
          </CardFooter>
        </form>
      </Form>
    </Card>
  );
}
