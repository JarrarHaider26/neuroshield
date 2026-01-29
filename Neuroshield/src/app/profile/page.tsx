
'use client';

import { AppShell } from '@/components/layout/AppShell';
import { UserProfileCard } from '@/components/profile/UserProfileCard';
import { Button } from '@/components/ui/button';
import { ShieldCheck, Loader2, UserCircle } from 'lucide-react';
import { useAuthContext } from '@/contexts/AuthContext';
import { useRouter } from 'next/navigation';
import React, { useEffect, useState, useCallback } from 'react';

interface UserProfileData {
  uid: string;
  name: string;
  email: string;
  role: string;
  joinDate: string;
  avatarUrl?: string | null;
  bio?: string;
}

const STATIC_PROFILE_PIC_URL = '/images/rr.png';

export default function ProfilePage() {
  const { user: authUser, isAdmin, loading: authLoading } = useAuthContext();
  const router = useRouter();
  const [profileData, setProfileData] = useState<UserProfileData | null>(null);
  const [dataFetchLoading, setDataFetchLoading] = useState(true);

  const loadProfileData = useCallback(() => {
    if (!authUser) {
      setDataFetchLoading(false); 
      return;
    }

    setDataFetchLoading(true);
    try {
      const creationTime = authUser.metadata.creationTime;
      const joinDate = creationTime ? new Date(creationTime).toLocaleDateString() : 'N/A';
      
      const currentAvatarUrl = STATIC_PROFILE_PIC_URL; // Always use static URL

      setProfileData({
        uid: authUser.uid,
        name: authUser.displayName || 'Operative',
        email: authUser.email || 'N/A',
        role: isAdmin ? 'Administrator' : 'Analyst',
        joinDate: joinDate,
        avatarUrl: currentAvatarUrl,
        bio: 'Specializing in advanced threat detection and AI-driven cybersecurity analysis. Keeping the digital world safe, one scan at a time.',
      });
    } catch (error) {
        console.error("Error loading profile data:", error);
        setProfileData(null); 
    } finally {
        setDataFetchLoading(false);
    }
  }, [authUser, isAdmin]);

  useEffect(() => {
    if (authLoading) {
      return; 
    }
    if (!authUser) { 
      router.push('/auth/login'); 
    } else { 
      loadProfileData(); 
    }
  }, [authUser, authLoading, router, loadProfileData]);

  if (authLoading) {
    return (
      <AppShell>
        <div className="flex items-center justify-center h-full">
          <Loader2 className="h-16 w-16 animate-spin text-primary" />
          <p className="ml-3 text-muted-foreground">Authenticating Operative...</p>
        </div>
      </AppShell>
    );
  }

  if (!authUser) {
    return (
      <AppShell>
        <div className="flex flex-col items-center justify-center h-full p-4 text-center">
          <ShieldCheck className="h-16 w-16 text-destructive mb-4" />
          <p className="text-lg text-muted-foreground">Authentication required. Redirecting to login terminal...</p>
          <Loader2 className="h-8 w-8 animate-spin text-primary mt-4" />
        </div>
      </AppShell>
    );
  }
  
  if (dataFetchLoading) {
    return (
      <AppShell>
        <div className="flex items-center justify-center h-full">
          <Loader2 className="h-16 w-16 animate-spin text-primary" />
          <p className="ml-3 text-muted-foreground">Loading operative profile...</p>
        </div>
      </AppShell>
    );
  }

  if (!profileData) {
    return (
      <AppShell>
        <div className="flex flex-col items-center justify-center h-full p-4 text-center">
          <UserCircle className="h-16 w-16 text-destructive mb-4" />
          <p className="text-lg text-muted-foreground">Could not load profile data.</p>
          <p className="text-sm text-muted-foreground">Please try refreshing the page or contact support if the issue persists.</p>
          <Button onClick={() => loadProfileData()} className="mt-4 p-2 border rounded hover:bg-muted">Retry Load</Button>
        </div>
      </AppShell>
    );
  }

  return (
    <AppShell>
      <div className="flex flex-col gap-6 md:gap-8">
        <header>
          <h1 className="text-2xl sm:text-3xl font-bold tracking-tight text-primary flex items-center gap-2">
            <UserCircle className="h-6 w-6 sm:h-8 sm:w-8" /> Operative Profile
          </h1>
          <p className="text-muted-foreground mt-1 text-sm sm:text-base">
            Manage your NeuroShield identity and preferences.
          </p>
        </header>
        <UserProfileCard user={profileData} />
      </div>
    </AppShell>
  );
}
