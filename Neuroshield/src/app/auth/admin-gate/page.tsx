'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { useToast } from '@/hooks/use-toast';
import { KeyRound, Loader2 } from 'lucide-react';
import Link from 'next/link';
import { Logo } from '@/components/icons/Logo';

export default function AdminGatePage() {
  const [password, setPassword] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState('');
  const router = useRouter();
  const { toast } = useToast();

  const handlePasswordSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsLoading(true);
    setError('');

    try {
      // Verify password server-side
      const response = await fetch('/api/admin/verify-gate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ password }),
      });

      const result = await response.json();

      if (response.ok && result.success) {
        toast({ title: 'Gate Unlocked', description: 'Redirecting to Admin Terminal...' });
        router.push('/auth/admin-login');
      } else if (response.status === 429) {
        // Rate limited
        setError(result.error || 'Too many attempts. Please wait before trying again.');
        toast({ title: 'Rate Limited', description: result.error, variant: 'destructive' });
        setIsLoading(false);
      } else {
        setError('Incorrect password. Access denied.');
        toast({ title: 'Access Denied', description: 'The password you entered is incorrect.', variant: 'destructive' });
        setIsLoading(false);
      }
    } catch (err) {
      setError('Connection error. Please try again.');
      toast({ title: 'Error', description: 'Could not verify password. Please try again.', variant: 'destructive' });
      setIsLoading(false);
    }
  };

  return (
    <div className="flex min-h-screen flex-col items-center justify-center bg-background p-6">
      <div className="z-10 flex flex-col items-center justify-center flex-grow w-full max-w-md space-y-6 text-center">
        <div>
           <Link href="/" className="inline-block mb-6">
            <Logo className="h-12 w-12 text-primary" />
          </Link>
          <h1 className="text-3xl font-bold tracking-tight text-primary">Admin Access Gate</h1>
          <p className="mt-2 text-muted-foreground">
            Administrative override requires special authorization.
          </p>
        </div>
        <Card className="w-full max-w-sm shadow-xl border-primary/20">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-xl text-primary"><KeyRound /> Enter Override Password</CardTitle>
            <CardDescription>This entry point is restricted and logged.</CardDescription>
          </CardHeader>
          <form onSubmit={handlePasswordSubmit}>
            <CardContent className="space-y-4">
              <div className="space-y-2">
                <Input
                  id="password"
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="************"
                  required
                  className="bg-input/50 border-primary/30 focus:border-primary focus:ring-primary"
                  disabled={isLoading}
                />
                {error && <p className="text-sm font-medium text-destructive">{error}</p>}
              </div>
              <Button type="submit" className="w-full btn-glow" disabled={isLoading}>
                {isLoading ? <Loader2 className="animate-spin" /> : 'Authorize'}
              </Button>
            </CardContent>
          </form>
        </Card>
         <p className="text-sm text-muted-foreground">
          Not an administrator?{' '}
          <Link href="/auth/login" className="font-medium text-primary hover:text-accent hover:underline">
            Return to standard terminal
          </Link>
        </p>
      </div>
       <footer className="z-10 w-full py-4 text-center text-xs text-muted-foreground">
        © {new Date().getFullYear()} NeuroShield. High-security access layer active.
      </footer>
    </div>
  );
}
