
'use client';

import type { ReactNode } from 'react';
import { createContext, useContext, useEffect, useState, useCallback } from 'react';
import {
  getAuth,
  onAuthStateChanged,
  createUserWithEmailAndPassword,
  signInWithEmailAndPassword,
  signOut,
  updateProfile,
  sendPasswordResetEmail,
  sendEmailVerification,
  type User as FirebaseUser,
  type AuthError,
} from 'firebase/auth';
import { app, db } from '@/lib/firebase';
import { useRouter, usePathname } from 'next/navigation';
import { useToast } from '@/hooks/use-toast';
import { doc, setDoc, serverTimestamp, getDoc, onSnapshot } from 'firebase/firestore';

interface GlobalSettings {
    maintenanceMode: boolean;
    newRegistrationsEnabled: boolean;
}

interface AuthContextType {
  user: FirebaseUser | null;
  isAdmin: boolean;
  loading: boolean;
  settings: GlobalSettings | null;
  settingsLoading: boolean;
  login: (email: string, pass: string, adminOnly?: boolean) => Promise<void>;
  signup: (email: string, pass: string, callsign: string) => Promise<void>;
  logout: () => Promise<void>;
  sendPasswordReset: (email: string) => Promise<boolean>;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

const STATIC_PROFILE_PIC_URL = '/images/rr.png';
const EMAIL_VERIFIED_CACHE_KEY = 'neuroshield_email_verified';

// Helper to clear all email verification caches on logout
const clearAllEmailVerificationCaches = (): void => {
  try {
    // Clear all cached email verification entries from sessionStorage
    const keysToRemove: string[] = [];
    for (let i = 0; i < sessionStorage.length; i++) {
      const key = sessionStorage.key(i);
      if (key && key.startsWith(EMAIL_VERIFIED_CACHE_KEY)) {
        keysToRemove.push(key);
      }
    }
    keysToRemove.forEach(key => sessionStorage.removeItem(key));
  } catch (e) {
    console.warn('[AuthContext] Error clearing email verification caches:', e);
  }
};

export const AuthProvider = ({ children }: { children: ReactNode }) => {
  const [user, setUser] = useState<FirebaseUser | null>(null);
  const [loading, setLoading] = useState(true);
  const [isAdmin, setIsAdmin] = useState(false);
  const [settings, setSettings] = useState<GlobalSettings | null>(null);
  const [settingsLoading, setSettingsLoading] = useState(true);
  
  const auth = getAuth(app);
  const { toast } = useToast();

  // Global Settings Listener
  useEffect(() => {
    if (!db) {
        console.warn("Firestore not available, cannot listen for global settings.");
        setSettings({ maintenanceMode: false, newRegistrationsEnabled: true }); // Fallback to defaults
        setSettingsLoading(false);
        return;
    }
    const settingsDocRef = doc(db, 'settings', 'global');
    const unsubscribe = onSnapshot(settingsDocRef, (docSnap) => {
        if (docSnap.exists()) {
            console.log("Global settings updated:", docSnap.data());
            setSettings(docSnap.data() as GlobalSettings);
        } else {
            console.warn("Global settings document does not exist. Using defaults.");
            setSettings({ maintenanceMode: false, newRegistrationsEnabled: true });
        }
        setSettingsLoading(false);
    }, (error) => {
        console.error("Error listening to global settings:", error.message);
        console.warn("Falling back to default system settings due to listener error.");
        setSettings({ maintenanceMode: false, newRegistrationsEnabled: true });
        setSettingsLoading(false);
    });

    return () => unsubscribe();
  }, []);


  // Auth State Listener
  useEffect(() => {
    const unsubscribe = onAuthStateChanged(auth, async (currentUser) => {
      try {
        if (currentUser) {
          const userDocRef = doc(db, 'users', currentUser.uid);
          // Get the user doc to check for role.
          const userDoc = await getDoc(userDocRef);
          const userRole = userDoc.exists() ? userDoc.data().role : 'user';
          
          setIsAdmin(userRole === 'admin');
          setUser(currentUser);

          // Update last login time only - DO NOT update emailVerified here
          // emailVerified should only be updated from the verification page
          await setDoc(userDocRef, { 
              lastLogin: serverTimestamp(),
              email: currentUser.email,
              displayName: currentUser.displayName,
          }, { merge: true });

        } else {
          setUser(null);
          setIsAdmin(false);
        }
      } catch (error: any) {
        console.error("AuthContext: Error during auth state change processing:", error);
        toast({ title: 'Authentication Error', description: `Could not sync user session: ${error.message}`, variant: 'destructive' });
        setUser(null);
        setIsAdmin(false);
      } finally {
        setLoading(false);
      }
    });

    return () => unsubscribe();
  }, [auth, toast]);

  const login = async (email: string, pass: string, adminOnly: boolean = false) => {
    setLoading(true); 
    try {
      const userCredential = await signInWithEmailAndPassword(auth, email, pass);
      const loggedInUser = userCredential.user;

      if (adminOnly) {
        if (!db) {
            await signOut(auth);
            throw new Error("Database connection is unavailable to verify admin status.");
        }
        const userDocRef = doc(db, 'users', loggedInUser.uid);
        const userDoc = await getDoc(userDocRef);

        if (!userDoc.exists() || userDoc.data().role !== 'admin') {
          await signOut(auth);
          const error = new Error("This account does not have administrator privileges.");
          (error as any).code = 'auth/not-an-admin';
          throw error;
        }
      }
      
      toast({ title: 'Login Successful', description: 'Welcome back, Operator!', duration: 3000 });
      // State update will be handled by onAuthStateChanged listener, no need to call setLoading(false) here.
    } catch (error) {
      const authError = error as AuthError & { code?: string };
      console.error('AuthContext: Login failed:', authError.code, authError.message);
      let description = 'An unexpected error occurred. Please try again.';
      
      switch (authError.code) {
          case 'auth/network-request-failed':
              description = 'Network error. Please check your internet connection.';
              break;
          case 'auth/invalid-credential':
          case 'auth/wrong-password':
              description = 'Invalid credentials. Please check your email and password.';
              break;
          case 'auth/too-many-requests':
              description = 'Access to this account has been temporarily disabled due to too many login attempts.';
              break;
          case 'auth/not-an-admin':
              description = authError.message;
              break;
          default:
              description = authError.message || description;
              break;
      }
      
      toast({ title: 'Login Failed', description, variant: 'destructive', duration: 8000 });
      setLoading(false); // Ensure loading is stopped on failure
      throw authError;
    }
  };

  const signup = async (email: string, pass: string, callsign: string) => {
    if (settings && !settings.newRegistrationsEnabled) {
        toast({ title: 'Signup Disabled', description: 'New user registrations are currently disabled.', variant: 'destructive' });
        return;
    }

    setLoading(true);
    try {
      const userCredential = await createUserWithEmailAndPassword(auth, email, pass);
      await updateProfile(userCredential.user, {
        displayName: callsign,
        photoURL: STATIC_PROFILE_PIC_URL,
      });
      
      // Send email verification
      await sendEmailVerification(userCredential.user);
      
      if (db) {
        const userDocRef = doc(db, 'users', userCredential.user.uid);
        await setDoc(userDocRef, {
            uid: userCredential.user.uid,
            email: userCredential.user.email,
            displayName: callsign,
            profilePicUrl: STATIC_PROFILE_PIC_URL,
            role: 'user', // New signups are always 'user'
            emailVerified: false, // Initially not verified
            createdAt: serverTimestamp(),
            lastLogin: serverTimestamp(),
        });
      }

      toast({ title: 'Signup Successful', description: 'Please check your email to verify your account.', duration: 5000 });
      // State update will be handled by onAuthStateChanged listener
    } catch (error) {
      const authError = error as AuthError;
      console.error('AuthContext: Signup failed:', authError.code, authError.message);
      let toastDescription = authError.message || 'Could not create account.';
      if (authError.code === 'auth/email-already-in-use') {
        toastDescription = 'This email address is already registered. Please try logging in.';
      }
      toast({ title: 'Signup Failed', description: toastDescription, variant: 'destructive' });
      setLoading(false); // Stop loading on failure
      throw authError;
    }
  };
  
  const logout = async () => {
    setLoading(true);
    try {
      // Clear email verification cache on logout
      clearAllEmailVerificationCaches();
      
      await signOut(auth);
      toast({ title: 'Logged Out', description: 'Connection terminated securely.', duration: 3000 });
      // onAuthStateChanged will handle setting user to null and loading to false
    } catch (error) {
      const authError = error as AuthError;
      console.error('AuthContext: Logout failed:', authError.code, authError.message);
      toast({ title: 'Logout Failed', description: authError.message, variant: 'destructive' });
      setLoading(false); // Stop loading on failure
    }
  };

  const sendPasswordReset = async (email: string): Promise<boolean> => {
    setLoading(true);
    try {
      await sendPasswordResetEmail(auth, email);
      toast({ title: 'Password Reset Email Sent', description: 'Check your inbox for instructions.' });
      setLoading(false);
      return true;
    } catch (error) {
      const authError = error as AuthError;
      let message = authError.message || 'Could not send reset email.';
      if(authError.code === 'auth/user-not-found'){
        message = 'No account found with this email address.'
      }
      console.error('AuthContext: Password Reset failed:', authError.code, authError.message);
      toast({ title: 'Password Reset Failed', description: message, variant: 'destructive' });
      setLoading(false);
      return false;
    }
  };

  return (
    <AuthContext.Provider value={{
      user,
      isAdmin,
      loading,
      settings,
      settingsLoading,
      login,
      signup,
      logout,
      sendPasswordReset,
    }}>
      {children}
    </AuthContext.Provider>
  );
};

export const useAuthContext = () => {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error('useAuthContext must be used within an AuthProvider');
  }
  return context;
};
