
'use client';

import Link from 'next/link';
import {
  Sidebar,
  SidebarContent,
  SidebarHeader,
  SidebarFooter,
  SidebarInset,
  SidebarMenu,
  SidebarMenuItem,
  SidebarMenuButton,
  SidebarTrigger,
  SidebarGroup,
  SidebarGroupLabel,
  useSidebar,
} from '@/components/ui/sidebar';
import { Button } from '@/components/ui/button';
import { Avatar, AvatarFallback, AvatarImage } from '@/components/ui/avatar';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import { Bell, LogOut, Search, Settings, User, Loader2, Sun, Moon, Hammer } from 'lucide-react';
import { Logo } from '@/components/icons/Logo';
import { mainNav, adminNav } from '@/config/nav';
import React, { useState, useEffect, useCallback, useRef } from 'react';
import { useAuthContext } from '@/contexts/AuthContext';
import { usePathname, useRouter } from 'next/navigation';
import { useTheme } from 'next-themes';
import { MaintenanceDialog } from '@/components/layout/MaintenanceDialog';
import { MobileHeader } from '@/components/layout/MobileHeader';
import { MobileBottomNav } from '@/components/layout/MobileBottomNav';
import { AdminMobileBottomNav } from '@/components/layout/AdminMobileBottomNav';
import { db } from '@/lib/firebase';
import { doc, getDoc } from 'firebase/firestore';
import { useToast } from '@/hooks/use-toast';

const STATIC_PROFILE_PIC_URL = '/images/rr.png';
const ADMIN_INACTIVITY_TIMEOUT = 3 * 60 * 1000; // 3 minutes in milliseconds
const EMAIL_VERIFIED_CACHE_KEY = 'neuroshield_email_verified';
const EMAIL_VERIFIED_CACHE_DURATION = 5 * 60 * 1000; // 5 minutes cache for unverified users

// Helper to get cached verification status
// Once verified, cache is permanent for the session (no expiry check)
const getCachedEmailVerified = (uid: string): boolean | null => {
  try {
    const cached = sessionStorage.getItem(`${EMAIL_VERIFIED_CACHE_KEY}_${uid}`);
    if (cached) {
      const { verified, timestamp } = JSON.parse(cached);
      // If user is verified, trust the cache permanently (until logout clears it)
      // Only apply expiry for unverified status to allow re-checking
      if (verified === true) {
        return true;
      }
      // For unverified users, check if cache is still valid
      if (Date.now() - timestamp < EMAIL_VERIFIED_CACHE_DURATION) {
        return verified;
      }
      // Cache expired for unverified status, remove it
      sessionStorage.removeItem(`${EMAIL_VERIFIED_CACHE_KEY}_${uid}`);
    }
  } catch (e) {
    console.warn('[AppShell] Error reading email verification cache:', e);
  }
  return null;
};

// Helper to set cached verification status
const setCachedEmailVerified = (uid: string, verified: boolean): void => {
  try {
    sessionStorage.setItem(`${EMAIL_VERIFIED_CACHE_KEY}_${uid}`, JSON.stringify({
      verified,
      timestamp: Date.now()
    }));
  } catch (e) {
    console.warn('[AppShell] Error setting email verification cache:', e);
  }
};

export function AppShell({ children }: { children: React.ReactNode }) {
  const { user, isAdmin, loading: authLoading, logout, settings, settingsLoading } = useAuthContext();
  const pathname = usePathname();
  const router = useRouter();
  const { isMobile, setOpenMobile, openMobile } = useSidebar();
  const { theme, setTheme } = useTheme();
  const { toast } = useToast();
  const [mounted, setMounted] = useState(false);
  const [firestoreEmailVerified, setFirestoreEmailVerified] = useState<boolean | null>(null);
  const inactivityTimerRef = useRef<NodeJS.Timeout | null>(null);
  const verificationFetchedRef = useRef<string | null>(null); // Track which user we've fetched for

  const isAdminPage = pathname.startsWith('/admin');

  // Admin inactivity auto-logout
  const resetInactivityTimer = useCallback(() => {
    if (inactivityTimerRef.current) {
      clearTimeout(inactivityTimerRef.current);
    }
    
    if (isAdminPage && isAdmin && user) {
      inactivityTimerRef.current = setTimeout(async () => {
        console.log('[AppShell] Admin inactivity timeout - logging out');
        toast({
          title: 'Session Expired',
          description: 'You have been logged out due to inactivity.',
          variant: 'destructive',
          duration: 5000,
        });
        await logout();
        router.push('/auth/login');
      }, ADMIN_INACTIVITY_TIMEOUT);
    }
  }, [isAdminPage, isAdmin, user, logout, router, toast]);

  // Set up activity listeners for admin pages
  useEffect(() => {
    if (!isAdminPage || !isAdmin || !user) {
      // Clear timer if not on admin page
      if (inactivityTimerRef.current) {
        clearTimeout(inactivityTimerRef.current);
        inactivityTimerRef.current = null;
      }
      return;
    }

    // Activity events to track
    const activityEvents = ['mousedown', 'mousemove', 'keydown', 'scroll', 'touchstart', 'click'];
    
    // Reset timer on any activity
    const handleActivity = () => {
      resetInactivityTimer();
    };

    // Add event listeners
    activityEvents.forEach(event => {
      document.addEventListener(event, handleActivity);
    });

    // Start the initial timer
    resetInactivityTimer();

    // Cleanup
    return () => {
      activityEvents.forEach(event => {
        document.removeEventListener(event, handleActivity);
      });
      if (inactivityTimerRef.current) {
        clearTimeout(inactivityTimerRef.current);
      }
    };
  }, [isAdminPage, isAdmin, user, resetInactivityTimer]);

  useEffect(() => {
    console.log('[AppShell] Theme provider mounted check.');
    setMounted(true);
  }, []);

  // Fetch emailVerified status from Firestore with caching
  // Skip Firestore call entirely for already-verified users (cached as true)
  useEffect(() => {
    const fetchEmailVerifiedStatus = async () => {
      if (user && db) {
        // Check sessionStorage cache first - verified users skip all checks
        const cachedStatus = getCachedEmailVerified(user.uid);
        if (cachedStatus === true) {
          // User is verified - no need to check Firestore ever again this session
          console.log('[AppShell] User already verified (cached). Skipping Firestore check.');
          if (firestoreEmailVerified !== true) {
            setFirestoreEmailVerified(true);
          }
          verificationFetchedRef.current = user.uid;
          return;
        }

        // Check if we already fetched for this user in this session (for unverified users)
        if (verificationFetchedRef.current === user.uid && firestoreEmailVerified !== null) {
          console.log('[AppShell] Email verification already fetched for this user, skipping.');
          return;
        }

        // Use cached unverified status if still valid
        if (cachedStatus === false) {
          console.log('[AppShell] Using cached unverified status');
          setFirestoreEmailVerified(false);
          verificationFetchedRef.current = user.uid;
          return;
        }

        try {
          // Create a timeout promise (5 seconds)
          const timeoutPromise = new Promise<never>((_, reject) => {
            setTimeout(() => reject(new Error('Firestore fetch timeout')), 5000);
          });

          // Race between Firestore fetch and timeout
          const userDocRef = doc(db, 'users', user.uid);
          const userDoc = await Promise.race([
            getDoc(userDocRef),
            timeoutPromise
          ]);

          if (userDoc.exists()) {
            const emailVerified = userDoc.data().emailVerified;
            console.log('[AppShell] Firestore emailVerified status:', emailVerified);
            const verifiedStatus = emailVerified === true;
            setFirestoreEmailVerified(verifiedStatus);
            // Cache the result - verified status will be permanent, unverified will expire
            setCachedEmailVerified(user.uid, verifiedStatus);
            verificationFetchedRef.current = user.uid;
          } else {
            // User doc doesn't exist, default to false
            console.warn('[AppShell] User doc does not exist, defaulting to unverified');
            setFirestoreEmailVerified(false);
            verificationFetchedRef.current = user.uid;
          }
        } catch (error) {
          console.error('[AppShell] Error fetching emailVerified status:', error);
          // On error or timeout, check Firebase Auth as fallback
          console.log('[AppShell] Falling back to Firebase Auth emailVerified:', user.emailVerified);
          const fallbackStatus = user.emailVerified || false;
          setFirestoreEmailVerified(fallbackStatus);
          verificationFetchedRef.current = user.uid;
        }
      } else if (user && !db) {
        // If Firestore is not available, fall back to Firebase Auth
        console.warn('[AppShell] Firestore not available, using Firebase Auth emailVerified');
        setFirestoreEmailVerified(user.emailVerified || false);
        verificationFetchedRef.current = user.uid;
      } else {
        setFirestoreEmailVerified(null);
        verificationFetchedRef.current = null;
      }
    };

    fetchEmailVerifiedStatus();
  }, [user, firestoreEmailVerified]);

  useEffect(() => {
    if (isMobile && openMobile && typeof setOpenMobile === 'function') {
      console.log('[AppShell] Mobile sidebar open, closing on path change:', pathname);
      setOpenMobile(false);
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [pathname, isMobile, openMobile]); 

  // This useEffect handles redirection based on auth state
  useEffect(() => {
    console.log('[AppShell] Auth effect. Path:', pathname, 'AuthLoading:', authLoading, 'User:', user ? user.uid : 'null', 'FirestoreVerified:', firestoreEmailVerified, 'isAdmin:', isAdmin);

    // Wait for auth to resolve first
    if (authLoading) {
      console.log('[AppShell] Auth loading. No redirection action yet.');
      return;
    }

    // If there's a user, wait for Firestore status to resolve
    if (user && firestoreEmailVerified === null) {
      console.log('[AppShell] User exists but Firestore status loading. No redirection action yet.');
      return;
    }

    const isAuthPage = pathname.startsWith('/auth/');
    const isVerifyEmailPage = pathname === '/auth/verify-email';
    const currentIsAdminPage = pathname.startsWith('/admin');

    if (!user && !isAuthPage) {
      console.log('[AppShell] Auth resolved: No user & not on auth page. Redirecting to /auth/login.');
      router.push('/auth/login');
    } else if (user && !firestoreEmailVerified && !isVerifyEmailPage && !currentIsAdminPage) {
      // Check Firestore emailVerified status instead of Firebase Auth
      // Don't redirect admins on admin pages to verification - they handle their own auth
      console.log('[AppShell] Auth resolved: User email not verified in Firestore. Redirecting to /auth/verify-email.');
      router.push('/auth/verify-email');
    } else if (user && firestoreEmailVerified && isAuthPage && !isVerifyEmailPage) {
      // Redirect verified users away from auth pages - admins go to admin dashboard, users go to user dashboard
      const redirectPath = isAdmin ? '/admin/dashboard' : '/';
      console.log('[AppShell] Auth resolved: User logged in and verified but on auth page. Redirecting to', redirectPath);
      router.push(redirectPath);
    } else {
      console.log('[AppShell] Auth resolved: State OK for current page. No redirect needed from AppShell effect.');
    }
  }, [user, authLoading, pathname, router, firestoreEmailVerified, isAdmin]);


  // --- Conditional rendering based on authentication status and current path ---
  const isAuthPage = pathname.startsWith('/auth/');

  // Show maintenance dialog if maintenance mode is on and user is not an admin
  const showMaintenance = Boolean(settings?.maintenanceMode && !isAdmin && user);

  // 1. If auth is still loading (initial check or during login/logout/signup),
  //    and we are NOT on an auth page, show a global loader.
  //    Auth pages manage their own loading UI if `authLoading` is true.
  //    NOTE: Only wait for firestoreEmailVerified if there IS a user
  const isFirestoreLoading = user && firestoreEmailVerified === null;
  if ((authLoading || settingsLoading || isFirestoreLoading) && !isAuthPage) {
    console.log('[AppShell] Render Case 1: Auth, settings, or Firestore loading, not on auth page. Showing main loader. authLoading:', authLoading, 'settingsLoading:', settingsLoading, 'isFirestoreLoading:', isFirestoreLoading);
    return (
      <div className="flex min-h-screen w-full items-center justify-center bg-background">
        <Loader2 className="h-16 w-16 animate-spin text-primary" />
        <p className="ml-3 text-muted-foreground">Initializing NeuroShield Interface...</p>
      </div>
    );
  }

  // 2. If auth is loading BUT we ARE on an auth page, let the auth page render its children
  //    (which might include its own loading indicators).
  if (authLoading && isAuthPage) {
     console.log('[AppShell] Render Case 2: Auth loading, IS on auth page. Rendering children.');
     return <>{children}</>;
  }

  // --- Auth is resolved (not loading) from this point for the rendering logic below ---

  // 3. Auth resolved, NO user, and NOT on an auth page (redirect to login is imminent or happening).
  //    Show a loader while the redirect from useEffect takes place.
  if (!user && !isAuthPage) {
    console.log('[AppShell] Render Case 3: Auth resolved, no user, not on auth page. Redirecting to login. Showing loader.');
    return (
        <div className="flex min-h-screen w-full items-center justify-center bg-background">
            <Loader2 className="h-16 w-16 animate-spin text-primary" />
            <p className="ml-3 text-muted-foreground">Securing connection...</p>
        </div>
    );
  }
  
  // 4. Auth resolved, USER exists, BUT on an auth page (redirect to dashboard is imminent or happening).
  //    Show a loader while the redirect from useEffect takes place.
  //    Exception: Allow access to verify-email page if user is not verified
  if (user && isAuthPage) {
    const isVerifyEmailPage = pathname === '/auth/verify-email';
    
    // Allow unverified users to stay on verify-email page (check Firestore status)
    if (!firestoreEmailVerified && isVerifyEmailPage) {
      console.log('[AppShell] Render Case 4a: User on verify-email page, not verified in Firestore. Rendering page.');
      return <>{children}</>;
    }
    
    console.log('[AppShell] Render Case 4: Auth resolved, user exists, on auth page. Redirecting to dashboard. Showing loader.');
     return (
        <div className="flex min-h-screen w-full items-center justify-center bg-background">
            <Loader2 className="h-16 w-16 animate-spin text-primary" />
            <p className="ml-3 text-muted-foreground">Redirecting to dashboard...</p>
        </div>
    );
  }

  // 5. If it's an auth page, and we are here, it means: !authLoading and !user.
  //    This is a valid state to render the auth page content (login/signup forms).
  if (isAuthPage && !user) {
    // If registrations are disabled, show a message on the signup page
    if (pathname === '/auth/signup' && settings && !settings.newRegistrationsEnabled) {
        return <MaintenanceDialog isOpen={true} title="Registrations Disabled" description="New user registrations are currently disabled by the administrator." />;
    }
    console.log('[AppShell] Render Case 5: Rendering auth page children (e.g., login form). Pathname:', pathname);
    return <>{children}</>;
  }
  
  // 6. If we reach here, it implies: !authLoading, USER exists, and NOT on an auth page.
  //    But we need to ensure Firestore verification status is loaded and user is verified
  if (!user) {
      // This case should ideally be caught by redirect logic if !isAuthPage.
      // It's a fallback if somehow user becomes null after initial checks on a protected route.
      console.warn('[AppShell] Render Case 6 Fallback: User is unexpectedly null. Path:', pathname);
      return (
        <div className="flex min-h-screen w-full items-center justify-center bg-background">
          <Loader2 className="h-16 w-16 animate-spin text-primary" />
          <p className="ml-3 text-muted-foreground">Verifying access credentials...</p>
        </div>
      );
  }
  
  if (firestoreEmailVerified === null) {
      // Still loading Firestore status
      console.log('[AppShell] Render Case 6a: Firestore status still loading. Path:', pathname);
      return (
        <div className="flex min-h-screen w-full items-center justify-center bg-background">
          <Loader2 className="h-16 w-16 animate-spin text-primary" />
          <p className="ml-3 text-muted-foreground">Checking verification status...</p>
        </div>
      );
  }

  // 7. Check if user is verified before rendering main app
  // Skip verification check for admin pages - they handle their own auth
  if (!firestoreEmailVerified && !isAdminPage) {
    console.log('[AppShell] Render Case 7: User not verified, redirecting to verification page.');
    return (
      <div className="flex min-h-screen w-full items-center justify-center bg-background">
        <Loader2 className="h-16 w-16 animate-spin text-primary" />
        <p className="ml-3 text-muted-foreground">Verifying email status...</p>
      </div>
    );
  }

  const currentNav = isAdminPage ? adminNav : mainNav;

  // --- Main AppShell UI for authenticated users on protected routes ---
  console.log('[AppShell] Render Case 7: Rendering main application shell UI for user:', user.uid, 'on path:', pathname);
  
  // Mobile-only layout
  if (isMobile) {
    return (
      <div className="w-full min-h-screen">
        <MaintenanceDialog isOpen={showMaintenance} />
        <MobileHeader user={user} isAdmin={isAdmin} onLogout={logout} />
        <main className="pb-20 pt-4 px-3 min-h-screen bg-background w-full max-w-full">
          {children}
        </main>
        {isAdminPage ? <AdminMobileBottomNav /> : <MobileBottomNav />}
      </div>
    );
  }

  // Desktop layout with sidebar
  return (
    <>
      <MaintenanceDialog isOpen={showMaintenance} />
      <Sidebar variant="sidebar" collapsible="icon" side="left">
        <SidebarHeader className="p-4 justify-between items-center">
          <Link href={isAdminPage ? "/admin/dashboard" : "/"} className="flex items-center gap-2">
            <Logo className="h-8 w-8 text-primary" />
            <span className="font-bold text-xl text-primary group-data-[collapsible=icon]:hidden">NeuroShield</span>
          </Link>
        </SidebarHeader>

        <SidebarContent className="flex-1 overflow-y-auto">
          {currentNav.map((section, sectionIndex) => (
            <SidebarGroup key={sectionIndex} className="p-2">
              {section.title && (
                <SidebarGroupLabel className="text-xs font-semibold text-muted-foreground group-data-[collapsible=icon]:hidden">
                  {section.title}
                </SidebarGroupLabel>
              )}
              <SidebarMenu>
                {section.items.map((item) => (
                  <SidebarMenuItem key={item.href}>
                    <SidebarMenuButton
                      asChild
                      variant="default"
                      size="default"
                      tooltip={item.tooltip}
                      className="justify-start"
                      isActive={pathname === item.href}
                      disabled={item.disabled}
                    >
                      <Link href={item.href}>
                        <item.icon className="h-5 w-5" />
                        <span className="group-data-[collapsible=icon]:hidden">{item.title}</span>
                      </Link>
                    </SidebarMenuButton>
                  </SidebarMenuItem>
                ))}
              </SidebarMenu>
            </SidebarGroup>
          ))}
        </SidebarContent>

        <SidebarFooter className="p-4 mt-auto border-t border-sidebar-border group-data-[collapsible=icon]:hidden">
          <p className="text-xs text-muted-foreground">© {new Date().getFullYear()} NeuroShield</p>
        </SidebarFooter>
      </Sidebar>

      <SidebarInset className="flex flex-col flex-1">
        <header className="sticky top-0 z-10 flex h-16 items-center gap-2 sm:gap-4 border-b bg-background/80 backdrop-blur-sm px-3 sm:px-6 shadow-sm">
          <SidebarTrigger className="lg:hidden flex-shrink-0 -ml-2" aria-label="Toggle sidebar" />
          <div className="flex-1 min-w-0">
            {/* Optional: Breadcrumbs or Page Title can go here */}
          </div>
          <div className="flex items-center gap-1 sm:gap-2 md:gap-4">
            {mounted && (
              <Button
                variant="ghost"
                size="icon"
                className="rounded-full"
                onClick={() => setTheme(theme === 'dark' ? 'light' : 'dark')}
                aria-label={theme === 'dark' ? "Switch to light mode" : "Switch to dark mode"}
              >
                {theme === 'dark' ? <Sun className="h-4 w-4 sm:h-5 sm:w-5" /> : <Moon className="h-4 w-4 sm:h-5 sm:w-5" />}
              </Button>
            )}
            {authLoading ? ( 
              <Loader2 className="h-6 w-6 animate-spin text-primary" />
            ) : user ? (
              <UserMenu user={user} onLogout={logout} />
            ) : (
              <Button asChild className="btn-glow">
                <Link href="/auth/login">Login</Link>
              </Button>
            )}
          </div>
        </header>
        <main className="flex-1 p-3 sm:p-4 md:p-6 overflow-auto bg-background">
          {children}
        </main>
      </SidebarInset>
    </>
  );
}

function UserMenu({ user, onLogout }: { user: { displayName?: string | null, email?: string | null, photoURL?: string | null }, onLogout: () => Promise<void> }) {
  const [isLoggingOut, setIsLoggingOut] = useState(false);

  const handleLogout = async () => {
    setIsLoggingOut(true);
    try {
        await onLogout();
    } catch (error) {
        console.error("[UserMenu] Error during logout:", error);
    } finally {
      // Only set to false if the component is still mounted.
      // If logout leads to immediate unmount/redirect, this might not be necessary
      // or could cause a warning if called on an unmounted component.
      // However, for robustness if onLogout itself fails and doesn't cause unmount:
      setIsLoggingOut(false); 
    }
  };

  const fallbackInitial = user.displayName ? user.displayName.charAt(0).toUpperCase() : (user.email ? user.email.charAt(0).toUpperCase() : 'N');
  const avatarSrc = user.photoURL || STATIC_PROFILE_PIC_URL; // Use photoURL from context if available, else static

  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button variant="ghost" className="relative h-10 w-10 rounded-full p-0">
          <Avatar className="h-10 w-10 border-2 border-primary">
            <AvatarImage src={avatarSrc} alt={user.displayName ?? 'User avatar'} data-ai-hint="profile picture"/>
            <AvatarFallback className="bg-secondary text-secondary-foreground text-lg">
              {fallbackInitial}
            </AvatarFallback>
          </Avatar>
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent className="w-56" align="end" forceMount>
        <DropdownMenuLabel className="font-normal">
          <div className="flex flex-col space-y-1">
            <p className="text-sm font-medium leading-none">{user.displayName ?? 'Operative'}</p>
            <p className="text-xs leading-none text-muted-foreground">
              {user.email ?? 'No email'}
            </p>
          </div>
        </DropdownMenuLabel>
        <DropdownMenuSeparator />
        <DropdownMenuItem asChild>
          <Link href="/profile"><User className="mr-2 h-4 w-4" /> Profile</Link>
        </DropdownMenuItem>
        <DropdownMenuSeparator />
        <DropdownMenuItem onClick={handleLogout} disabled={isLoggingOut}>
          {isLoggingOut ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <LogOut className="mr-2 h-4 w-4" />}
          {isLoggingOut ? 'Logging out...' : 'Log out'}
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}
