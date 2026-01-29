
'use client';

import { zodResolver } from '@hookform/resolvers/zod';
import { useForm } from 'react-hook-form';
import * as z from 'zod';
import { AppShell } from '@/components/layout/AppShell';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Form, FormControl, FormField, FormItem, FormLabel, FormDescription } from '@/components/ui/form';
import { Switch } from '@/components/ui/switch';
import { Settings as SettingsIcon, Loader2, ShieldCheck } from 'lucide-react';
import { useAuthContext } from '@/contexts/AuthContext';
import { useRouter } from 'next/navigation';
import { doc, getDoc, setDoc } from 'firebase/firestore';
import { db } from '@/lib/firebase';
import { useEffect, useState, useCallback } from 'react';
import { useToast } from '@/hooks/use-toast';

const settingsFormSchema = z.object({
  maintenanceMode: z.boolean().default(false),
  newRegistrationsEnabled: z.boolean().default(true),
});

type SettingsFormValues = z.infer<typeof settingsFormSchema>;

export default function AdminSettingsPage() {
  const { user, isAdmin, loading: authLoading } = useAuthContext();
  const router = useRouter();
  const { toast } = useToast();
  const [isLoadingData, setIsLoadingData] = useState(true);

  const form = useForm<SettingsFormValues>({
    resolver: zodResolver(settingsFormSchema),
    defaultValues: {
      maintenanceMode: false,
      newRegistrationsEnabled: true,
    },
  });
  
  const settingsDocRef = useCallback(() => db ? doc(db, 'settings', 'global') : null, []);

  useEffect(() => {
    if (authLoading) return;
    if (!user || !isAdmin) {
      router.push('/auth/admin-login');
      return;
    }

    const fetchSettings = async () => {
      const ref = settingsDocRef();
      if (!ref) {
        toast({ title: "Error", description: "Database connection not available.", variant: "destructive"});
        setIsLoadingData(false);
        return;
      }

      try {
        const docSnap = await getDoc(ref);
        if (docSnap.exists()) {
          const data = docSnap.data();
          form.reset({
            maintenanceMode: data.maintenanceMode ?? false,
            newRegistrationsEnabled: data.newRegistrationsEnabled ?? true,
          });
        } else {
            console.log("No global settings document found, using defaults.");
        }
      } catch (error: any) {
        console.error("Error fetching settings:", error);
        toast({
          title: "Failed to load settings",
          description: error.message,
          variant: "destructive",
        });
      } finally {
        setIsLoadingData(false);
      }
    };

    fetchSettings();
  }, [user, isAdmin, authLoading, router, form, toast, settingsDocRef]);
  
  async function onSubmit(values: SettingsFormValues) {
    const ref = settingsDocRef();
    if (!ref) {
      toast({ title: "Error", description: "Database connection not available.", variant: "destructive"});
      return;
    }

    try {
        await setDoc(ref, values, { merge: true });
        toast({
            title: "Settings Saved",
            description: "System-wide settings have been updated successfully.",
        });
        form.reset(values); // Re-sync form state with latest saved data
    } catch(error: any) {
        console.error("Error saving settings:", error);
        toast({
          title: "Save Failed",
          description: error.message,
          variant: "destructive",
        });
    }
  }
  
  if (authLoading || isLoadingData) {
    return (
      <AppShell>
        <div className="flex items-center justify-center h-full">
          <Loader2 className="h-16 w-16 animate-spin text-primary" />
          <p className="ml-3 text-muted-foreground">Loading System Configuration...</p>
        </div>
      </AppShell>
    );
  }

  if (!isAdmin) {
    return (
      <AppShell>
        <div className="flex flex-col items-center justify-center h-full p-4 text-center">
          <ShieldCheck className="h-16 w-16 text-destructive mb-4" />
          <p className="text-lg text-muted-foreground">Access Denied. Redirecting...</p>
        </div>
      </AppShell>
    );
  }

  return (
    <AppShell>
      <div className="flex flex-col gap-8">
        <header>
          <h1 className="text-3xl font-bold tracking-tight text-primary flex items-center gap-2">
            <SettingsIcon className="h-8 w-8" />
            System Settings
          </h1>
          <p className="text-muted-foreground mt-1">
            Manage global configurations for the NeuroShield platform.
          </p>
        </header>

        <Card className="shadow-xl border-primary/20 max-w-2xl">
            <CardHeader>
                <CardTitle>Global Configuration</CardTitle>
                <CardDescription>Changes made here will affect all users. Proceed with caution.</CardDescription>
            </CardHeader>
            <CardContent>
                <Form {...form}>
                    <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-8">
                        <FormField
                            control={form.control}
                            name="maintenanceMode"
                            render={({ field }) => (
                                <FormItem className="flex flex-row items-center justify-between rounded-lg border p-4">
                                <div className="space-y-0.5">
                                    <FormLabel className="text-base">Maintenance Mode</FormLabel>
                                    <FormDescription>
                                        Temporarily disable access for all non-admin users.
                                    </FormDescription>
                                </div>
                                <FormControl>
                                    <Switch
                                        checked={field.value}
                                        onCheckedChange={field.onChange}
                                    />
                                </FormControl>
                                </FormItem>
                            )}
                        />
                         <FormField
                            control={form.control}
                            name="newRegistrationsEnabled"
                            render={({ field }) => (
                                <FormItem className="flex flex-row items-center justify-between rounded-lg border p-4">
                                <div className="space-y-0.5">
                                    <FormLabel className="text-base">Enable New Registrations</FormLabel>
                                    <FormDescription>
                                        Allow new users to sign up for NeuroShield.
                                    </FormDescription>
                                </div>
                                <FormControl>
                                    <Switch
                                        checked={field.value}
                                        onCheckedChange={field.onChange}
                                    />
                                </FormControl>
                                </FormItem>
                            )}
                        />
                        <Button type="submit" className="btn-glow" disabled={form.formState.isSubmitting}>
                            {form.formState.isSubmitting && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                            Save Changes
                        </Button>
                    </form>
                </Form>
            </CardContent>
        </Card>
      </div>
    </AppShell>
  );
}
