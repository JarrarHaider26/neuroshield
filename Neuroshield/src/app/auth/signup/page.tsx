
'use client';

import { SignupForm } from '@/components/auth/SignupForm';
import { Logo } from '@/components/icons/Logo';
import Link from 'next/link';
import { useAuthContext } from '@/contexts/AuthContext';
import { useRouter } from 'next/navigation';
import { useEffect } from 'react';
import { Loader2 } from 'lucide-react';

export default function SignupPage() {
  const { user, loading, settings, settingsLoading } = useAuthContext();
  const router = useRouter();

  useEffect(() => {
    if (!loading && user) {
      // After signup, always redirect to verification page
      // The verification page will handle checking actual verification status
      router.push('/auth/verify-email');
    }
  }, [user, loading, router]);
  
  // If settings are loaded and registrations are disabled, we don't need to show a loader,
  // as the AppShell will handle showing the maintenance/disabled dialog.
  if (!settingsLoading && settings && !settings.newRegistrationsEnabled) {
    return (
       <div className="flex min-h-screen flex-col items-center justify-center bg-background p-4">
        <Loader2 className="h-16 w-16 animate-spin text-primary" />
        <p className="mt-4 text-muted-foreground">Verifying system status...</p>
      </div>
    );
  }

  // Show loader if auth/settings are loading OR if user exists (implying redirect is imminent)
  if (loading || settingsLoading || (!loading && user)) {
    return (
      <div className="flex min-h-screen flex-col items-center justify-center bg-background p-4">
        <Loader2 className="h-16 w-16 animate-spin text-primary" />
        <p className="mt-4 text-muted-foreground">Establishing secure link...</p>
      </div>
    );
  }

  // Only render form if not loading, no user, and registrations are enabled
  return (
    <div className="flex min-h-screen flex-col items-center justify-center bg-background p-6">
      <div className="z-10 flex flex-col items-center justify-center flex-grow w-full max-w-md space-y-6 text-center">
        <div>
          <Link href="/" className="inline-block mb-6">
            <Logo className="h-12 w-12 text-primary" />
          </Link>
          <h1 className="text-3xl font-bold tracking-tight text-primary">Establish Secure Connection</h1>
          <p className="text-muted-foreground">
            Register your credentials for NeuroShield access.
          </p>
        </div>
        <SignupForm />
        <p className="text-sm text-muted-foreground">
          Already an operative?{' '}
          <Link href="/auth/login" className="font-medium text-primary hover:text-accent hover:underline">
            SignIn to NeuroShield
          </Link>
        </p>
      </div>
      <footer className="z-10 w-full py-4 text-center text-xs text-muted-foreground">
        © {new Date().getFullYear()} NeuroShield. Identity verification protocols active.
      </footer>
    </div>
  );
}
