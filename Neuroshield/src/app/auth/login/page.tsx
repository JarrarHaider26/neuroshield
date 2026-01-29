'use client';

import { LoginForm } from '@/components/auth/LoginForm';
import { Logo } from '@/components/icons/Logo';
import Link from 'next/link';
import { useAuthContext } from '@/contexts/AuthContext';
import { useRouter } from 'next/navigation';
import { useEffect, useState } from 'react';
import { Loader2, ShieldQuestion } from 'lucide-react';
import { motion } from 'framer-motion';

export default function LoginPage() {
  const { user, loading } = useAuthContext();
  const router = useRouter();
  const [adminClickCount, setAdminClickCount] = useState(0);

  useEffect(() => {
    if (!loading && user) {
      router.push('/'); // Redirect if already logged in
    }
  }, [user, loading, router]);
  
  useEffect(() => {
    if (adminClickCount === 5) {
      router.push('/auth/admin-gate');
    }
  }, [adminClickCount, router]);

  const handleAdminIconClick = () => {
    setAdminClickCount(prev => prev + 1);
  };

  // Show loader ONLY on initial load when we don't know auth state yet
  // Don't show loader during login attempts (let the form handle its own loading state)
  if (loading && user === null && typeof window !== 'undefined') {
    // Check if this is truly initial load (no login attempt in progress)
    const isInitialLoad = !sessionStorage.getItem('hasAttemptedLogin');
    if (isInitialLoad) {
      return (
        <div className="flex min-h-screen flex-col items-center justify-center bg-background p-4">
          <Loader2 className="h-16 w-16 animate-spin text-primary" />
          <p className="mt-4 text-muted-foreground">Verifying credentials...</p>
        </div>
      );
    }
  }

  // If user exists and not loading, show redirect loader
  if (!loading && user) {
    return (
      <div className="flex min-h-screen flex-col items-center justify-center bg-background p-4">
        <Loader2 className="h-16 w-16 animate-spin text-primary" />
        <p className="mt-4 text-muted-foreground">Redirecting...</p>
      </div>
    );
  }

  // Only render form if not loading and no user (i.e., needs to log in)
  return (
    <div className="flex min-h-screen flex-col items-center justify-center bg-background p-6 relative">
       <motion.div
        className="absolute top-4 right-4 text-primary cursor-pointer"
        whileHover={{ scale: 1.2, rotate: 10 }}
        whileTap={{ scale: 0.9 }}
        transition={{ type: 'spring', stiffness: 300 }}
        onClick={handleAdminIconClick}
        title="Admin Access"
      >
        <ShieldQuestion className="h-8 w-8" />
      </motion.div>
      <div className="z-10 flex flex-col items-center justify-center flex-grow w-full max-w-md space-y-6 text-center">
        <div>
          <Link href="/" className="inline-block mb-6">
            <Logo className="h-12 w-12 text-primary" />
          </Link>
          <h1 className="text-3xl font-bold tracking-tight text-primary">Welcome Back, Operator</h1>
          <p className="mt-2 text-muted-foreground">
            Access NeuroShield.
          </p>
        </div>
        <LoginForm />
        <p className="text-sm text-muted-foreground">
          New operative?{' '}
          <Link href="/auth/signup" className="font-medium text-primary hover:text-accent hover:underline">
            Register In NeuroShield
          </Link>
        </p>
      </div>
      <footer className="z-10 w-full py-4 text-center text-xs text-muted-foreground">
        © {new Date().getFullYear()} NeuroShield. All systems operational.
      </footer>
    </div>
  );
}
