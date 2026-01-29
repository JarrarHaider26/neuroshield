'use client';

import { useAuthContext } from '@/contexts/AuthContext';
import { useRouter } from 'next/navigation';
import { useEffect, useState, useRef } from 'react';
import Link from 'next/link';
import { Logo } from '@/components/icons/Logo';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Loader2, Mail, CheckCircle2, AlertCircle } from 'lucide-react';
import { getAuth, sendEmailVerification } from 'firebase/auth';
import { app, db } from '@/lib/firebase';
import { doc, updateDoc } from 'firebase/firestore';
import { useToast } from '@/hooks/use-toast';

const EMAIL_VERIFIED_CACHE_KEY = 'neuroshield_email_verified';

// Helper to clear cached verification status
const clearCachedEmailVerified = (uid: string): void => {
  try {
    sessionStorage.removeItem(`${EMAIL_VERIFIED_CACHE_KEY}_${uid}`);
  } catch (e) {
    console.warn('[VerifyEmail] Error clearing email verification cache:', e);
  }
};

// Helper to set cached verification status
const setCachedEmailVerified = (uid: string, verified: boolean): void => {
  try {
    sessionStorage.setItem(`${EMAIL_VERIFIED_CACHE_KEY}_${uid}`, JSON.stringify({
      verified,
      timestamp: Date.now()
    }));
  } catch (e) {
    console.warn('[VerifyEmail] Error setting email verification cache:', e);
  }
};

export default function VerifyEmailPage() {
  const { user, loading, logout } = useAuthContext();
  const router = useRouter();
  const { toast } = useToast();
  const auth = getAuth(app);
  const [isResending, setIsResending] = useState(false);
  const [resendCooldown, setResendCooldown] = useState(0);
  const [isRedirecting, setIsRedirecting] = useState(false);
  const pollingIntervalRef = useRef<NodeJS.Timeout | null>(null);

  // Redirect if no user
  useEffect(() => {
    if (!loading && !user) {
      router.push('/auth/login');
    }
  }, [user, loading, router]);

  // Auto-polling to check email verification status every 3 seconds
  useEffect(() => {
    if (!user || loading || isRedirecting) return;

    const checkEmailVerification = async () => {
      try {
        // Reload user to get latest email verification status
        await user.reload();
        const currentUser = auth.currentUser;
        
        if (currentUser?.emailVerified) {
          console.log('[VerifyEmail] Email verified detected via polling!');
          setIsRedirecting(true);
          
          // Clear the polling interval
          if (pollingIntervalRef.current) {
            clearInterval(pollingIntervalRef.current);
            pollingIntervalRef.current = null;
          }
          
          // Update Firestore emailVerified status
          if (db) {
            const userDocRef = doc(db, 'users', user.uid);
            await updateDoc(userDocRef, { emailVerified: true });
          }
          
          // Update the session cache with verified status
          setCachedEmailVerified(user.uid, true);
          
          toast({
            title: 'Email Verified',
            description: 'Redirecting to dashboard...',
            duration: 3000,
          });
          
          // Redirect to dashboard
          setTimeout(() => {
            router.push('/');
          }, 1000);
        }
      } catch (error) {
        console.error('[VerifyEmail] Error checking verification status:', error);
      }
    };

    // Initial check
    checkEmailVerification();

    // Set up polling every 3 seconds
    pollingIntervalRef.current = setInterval(checkEmailVerification, 3000);

    // Cleanup on unmount
    return () => {
      if (pollingIntervalRef.current) {
        clearInterval(pollingIntervalRef.current);
        pollingIntervalRef.current = null;
      }
    };
  }, [user, loading, auth, router, toast, isRedirecting]);

  useEffect(() => {
    if (resendCooldown > 0) {
      const timer = setTimeout(() => setResendCooldown(resendCooldown - 1), 1000);
      return () => clearTimeout(timer);
    }
  }, [resendCooldown]);

  const handleResendEmail = async () => {
    if (!user || resendCooldown > 0) return;
    
    setIsResending(true);
    try {
      await sendEmailVerification(user);
      toast({
        title: 'Email Sent',
        description: 'Please check your inbox for the verification link.',
        duration: 5000,
      });
      setResendCooldown(60); // 60 second cooldown
    } catch (error: any) {
      console.error('Error sending verification email:', error);
      
      // Handle Firebase rate limiting specifically
      if (error.code === 'auth/too-many-requests') {
        toast({
          title: 'Too Many Requests',
          description: 'Please wait a few minutes before requesting another email. Check your spam folder in the meantime.',
          variant: 'destructive',
          duration: 8000,
        });
        // Set a longer cooldown when rate limited
        setResendCooldown(300); // 5 minutes
      } else {
        toast({
          title: 'Failed to Send',
          description: error.message || 'Please try again later.',
          variant: 'destructive',
        });
      }
    } finally {
      setIsResending(false);
    }
  };

  const handleLogout = async () => {
    try {
      await logout();
      router.push('/auth/login');
    } catch (error) {
      console.error('Error logging out:', error);
    }
  };

  if (loading || !user || isRedirecting) {
    return (
      <div className="flex min-h-screen flex-col items-center justify-center bg-background p-4">
        <Loader2 className="h-16 w-16 animate-spin text-primary" />
        <p className="mt-4 text-muted-foreground">
          {isRedirecting ? 'Email verified! Redirecting...' : 'Loading...'}
        </p>
      </div>
    );
  }

  return (
    <div className="flex min-h-screen flex-col items-center justify-center bg-background p-6">
      <div className="z-10 flex flex-col items-center justify-center flex-grow w-full max-w-md space-y-6 text-center">
        <div>
          <Logo className="h-12 w-12 text-primary mx-auto mb-6" />
          <h1 className="text-3xl font-bold tracking-tight text-primary">Verify Your Email</h1>
          <p className="text-muted-foreground mt-2">
            Please verify your email address to continue.
          </p>
        </div>

        <Card className="w-full shadow-xl border-primary/20">
          <CardHeader>
            <div className="flex justify-center mb-4">
              <div className="rounded-full bg-primary/10 p-4 relative">
                <Mail className="h-8 w-8 text-primary" />
                {!isRedirecting && (
                  <div className="absolute -top-1 -right-1">
                    <span className="relative flex h-3 w-3">
                      <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-primary opacity-75"></span>
                      <span className="relative inline-flex rounded-full h-3 w-3 bg-primary"></span>
                    </span>
                  </div>
                )}
              </div>
            </div>
            <CardTitle className="text-xl text-primary">Verification Email Sent</CardTitle>
            <CardDescription>
              A verification link has been sent to:
              <br />
              <span className="font-semibold text-foreground mt-1 inline-block">{user.email}</span>
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            {!isRedirecting && (
              <div className="bg-primary/5 border border-primary/20 rounded-lg p-3 text-sm">
                <div className="flex items-center justify-center gap-2 text-primary">
                  <Loader2 className="h-4 w-4 animate-spin" />
                  <span className="font-medium">Checking verification status...</span>
                </div>
              </div>
            )}
            
            <div className="bg-muted/50 rounded-lg p-4 text-sm text-left space-y-2.5">
              <div className="flex items-start gap-2">
                <CheckCircle2 className="h-4 w-4 text-primary mt-0.5 flex-shrink-0" />
                <span>Check your inbox and click the verification link</span>
              </div>
              <div className="flex items-start gap-2">
                <CheckCircle2 className="h-4 w-4 text-primary mt-0.5 flex-shrink-0" />
                <span>You will be redirected automatically once verified</span>
              </div>
              <div className="flex items-start gap-2">
                <AlertCircle className="h-4 w-4 text-muted-foreground mt-0.5 flex-shrink-0" />
                <span className="text-muted-foreground">Check spam folder if email is not received</span>
              </div>
            </div>

            <Button
              onClick={handleResendEmail}
              variant="outline"
              className="w-full"
              disabled={isResending || resendCooldown > 0 || isRedirecting}
            >
              {isResending ? (
                <>
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                  Sending...
                </>
              ) : resendCooldown > 0 ? (
                `Resend in ${resendCooldown}s`
              ) : (
                'Resend Verification Email'
              )}
            </Button>
          </CardContent>
        </Card>

        <p className="text-sm text-muted-foreground">
          Want to go back?{' '}
          <button
            onClick={handleLogout}
            className="font-medium text-primary hover:text-accent hover:underline cursor-pointer bg-transparent border-none p-0"
            disabled={isRedirecting}
          >
            Return to login
          </button>
        </p>
      </div>

      <footer className="z-10 w-full py-4 text-center text-xs text-muted-foreground">
        © {new Date().getFullYear()} NeuroShield. All rights reserved.
      </footer>
    </div>
  );
}
