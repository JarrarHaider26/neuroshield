'use client';

import { AdminLoginForm } from '@/components/auth/AdminLoginForm';
import { Logo } from '@/components/icons/Logo';
import Link from 'next/link';
import { useAuthContext } from '@/contexts/AuthContext';
import { useRouter } from 'next/navigation';
import { useEffect } from 'react';
import { Loader2 } from 'lucide-react';

export default function AdminLoginPage() {
  const { user, isAdmin, loading } = useAuthContext();
  const router = useRouter();

  useEffect(() => {
    // If the logged-in user is an admin, redirect them to the admin dashboard.
    if (!loading && user && isAdmin) {
      router.push('/admin/dashboard');
    }
    // If a non-admin user somehow lands here, push them to the main dashboard.
    else if (!loading && user && !isAdmin) {
      router.push('/');
    }
  }, [user, isAdmin, loading, router]);


  // Show loader if auth is loading or a redirect is imminent
  if (loading || (!loading && user && isAdmin)) {
    return (
      <div className="flex min-h-screen flex-col items-center justify-center bg-background p-4">
        <Loader2 className="h-16 w-16 animate-spin text-primary" />
        <p className="mt-4 text-muted-foreground">Verifying administrator credentials...</p>
      </div>
    );
  }

  // Only render the form if not loading and no admin is logged in.
  return (
    <div className="flex min-h-screen flex-col items-center justify-center bg-background p-6">
      <div className="z-10 flex flex-col items-center justify-center flex-grow w-full max-w-md space-y-6 text-center">
        <div>
          <Link href="/" className="inline-block mb-6">
            <Logo className="h-12 w-12 text-primary" />
          </Link>
          <h1 className="text-3xl font-bold tracking-tight text-primary">Administrator Login</h1>
          <p className="mt-2 text-muted-foreground">
            Access the NeuroShield Control Panel.
          </p>
        </div>
        <AdminLoginForm />
        <p className="text-sm text-muted-foreground">
          Standard access?{' '}
          <Link href="/auth/login" className="font-medium text-primary hover:text-accent hover:underline">
            Login here
          </Link>
        </p>
      </div>
       <footer className="z-10 w-full py-4 text-center text-xs text-muted-foreground">
        © {new Date().getFullYear()} NeuroShield. Admin authentication protocols active.
      </footer>
    </div>
  );
}
