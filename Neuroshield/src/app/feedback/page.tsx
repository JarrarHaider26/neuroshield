
'use client';

import { AppShell } from '@/components/layout/AppShell';
import { FeedbackForm } from '@/components/feedback/FeedbackForm';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Mail, Phone, MessageSquare, HelpCircle, CheckSquare, Info } from 'lucide-react';
import Link from 'next/link';

export default function FeedbackPage() {
  const adminEmail = "jarrarhaider26@gmail.com";
  const adminPhoneNumber = "03164709282";

  return (
    <AppShell>
      <div className="flex flex-col gap-8">
        <header>
          <h1 className="text-3xl font-bold tracking-tight text-primary flex items-center gap-2">
            <MessageSquare className="h-8 w-8" /> Feedback & Support
          </h1>
          <p className="text-muted-foreground mt-1">
            We value your input. Use the form below to send us your feedback or report issues.
          </p>
        </header>

        <div className="grid lg:grid-cols-3 gap-6 items-start">
          <div className="lg:col-span-2">
            <FeedbackForm />
          </div>

          <div className="space-y-6">
            <Card className="shadow-lg border-accent/20 card-hover-effect-accent">
              <CardHeader>
                <CardTitle className="text-xl text-accent flex items-center gap-2">
                    <HelpCircle className="h-6 w-6" />
                    Alternative Contact
                </CardTitle>
                <CardDescription>
                  For urgent matters or if you prefer direct contact:
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div>
                    <h3 className="font-semibold text-primary flex items-center gap-1.5 text-sm">
                        <Mail className="h-5 w-5" /> Email Directly
                    </h3>
                    <Button asChild variant="link" className="p-0 h-auto text-muted-foreground hover:text-accent text-sm">
                        <Link href={`mailto:${adminEmail}`}>{adminEmail}</Link>
                    </Button>
                </div>
                 <div>
                    <h3 className="font-semibold text-primary flex items-center gap-1.5 text-sm">
                        <Phone className="h-5 w-5" /> Call Us
                    </h3>
                    <Button asChild variant="link" className="p-0 h-auto text-muted-foreground hover:text-accent text-sm">
                        <Link href={`tel:${adminPhoneNumber}`}>{adminPhoneNumber}</Link>
                    </Button>
                </div>
              </CardContent>
            </Card>
            
            <Card className="shadow-lg border-primary/10 card-hover-effect-primary">
                <CardHeader>
                    <CardTitle className="text-lg text-primary flex items-center gap-2">
                        <Info className="h-5 w-5" />
                        Effective Reporting
                    </CardTitle>
                    <CardDescription className="text-xs">
                        To help us resolve your issue quickly, please include:
                    </CardDescription>
                </CardHeader>
                <CardContent>
                    <ul className="space-y-2 text-muted-foreground text-xs">
                        <li className="flex items-start gap-2">
                            <CheckSquare className="h-4 w-4 text-primary mt-0.5 shrink-0" />
                            <span>Steps to reproduce the problem.</span>
                        </li>
                        <li className="flex items-start gap-2">
                            <CheckSquare className="h-4 w-4 text-primary mt-0.5 shrink-0" />
                            <span>What you expected to happen.</span>
                        </li>
                        <li className="flex items-start gap-2">
                             <CheckSquare className="h-4 w-4 text-primary mt-0.5 shrink-0" />
                            <span>What actually happened.</span>
                        </li>
                        <li className="flex items-start gap-2">
                             <CheckSquare className="h-4 w-4 text-primary mt-0.5 shrink-0" />
                            <span>Screenshots or error messages, if applicable.</span>
                        </li>
                        <li className="flex items-start gap-2">
                             <CheckSquare className="h-4 w-4 text-primary mt-0.5 shrink-0" />
                            <span>The browser and operating system you are using.</span>
                        </li>
                    </ul>
                </CardContent>
            </Card>
          </div>
        </div>
      </div>
    </AppShell>
  );
}
