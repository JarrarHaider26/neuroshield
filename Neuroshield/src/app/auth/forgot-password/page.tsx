
'use client';

import { ForgotPasswordForm } from '@/components/auth/ForgotPasswordForm';
import { Logo } from '@/components/icons/Logo';
import Link from 'next/link';
import { useAuthContext } from '@/contexts/AuthContext';
import { useRouter } from 'next/navigation';
import { useEffect } from 'react';
import { Loader2 } from 'lucide-react';

export default function ForgotPasswordPage() {
  const { user, loading } = useAuthContext();
  const router = useRouter();

  useEffect(() => {
    if (!loading && user) {
      router.push('/'); // Redirect if already logged in
    }
  }, [user, loading, router]);

  if (loading && !user) { // Show loader only if loading and not already redirecting
    return (
      <div className="flex min-h-screen flex-col items-center justify-center bg-background p-4">
        <Loader2 className="h-16 w-16 animate-spin text-primary" />
        <p className="mt-4 text-muted-foreground">Loading...</p>
      </div>
    );
  }
  
  return (
    <div className="flex min-h-screen flex-col items-center bg-background p-6">
      <div className="flex flex-col items-center justify-center flex-grow w-full max-w-md space-y-6 text-center">
        <div>
          <Link href="/" className="inline-block mb-6">
            <Logo className="h-12 w-12 text-primary" />
          </Link>
          <h1 className="text-3xl font-bold tracking-tight text-primary">Reset Password</h1>
          <p className="mt-2 text-muted-foreground">
            Enter your email to receive password reset instructions.
          </p>
        </div>
        <ForgotPasswordForm />
        <p className="text-sm text-muted-foreground">
          Remember your password?{' '}
          <Link href="/auth/login" className="font-medium text-primary hover:text-accent hover:underline">
            Access terminal
          </Link>
        </p>
      </div>
      <footer className="w-full py-4 text-center text-xs text-muted-foreground">
         © {new Date().getFullYear()} NeuroShield. Password recovery protocols active.
      </footer>
    </div>
  );
}
