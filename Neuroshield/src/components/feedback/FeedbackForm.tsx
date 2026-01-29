
'use client';

import React from 'react';
import { useForm, ValidationError } from '@formspree/react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Textarea } from '@/components/ui/textarea';
import { Label } from '@/components/ui/label';
import { Card, CardContent, CardDescription, CardHeader, CardTitle, CardFooter } from '@/components/ui/card';
import { Loader2, Send, CheckCircle } from 'lucide-react';

export function FeedbackForm() {
  const [state, handleSubmit] = useForm("mnndwdbe");

  if (state.succeeded) {
    return (
      <Card className="w-full max-w-lg shadow-xl border-primary/20 card-hover-effect-primary">
        <CardHeader>
          <CardTitle className="text-xl text-primary flex items-center gap-2">
            <CheckCircle className="h-6 w-6 text-green-500" />
            Feedback Sent!
          </CardTitle>
        </CardHeader>
        <CardContent>
          <p className="text-muted-foreground">
            Thank you for your feedback. We've received your message and will review it shortly.
          </p>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card className="w-full max-w-lg shadow-xl border-primary/20 card-hover-effect-primary">
      <CardHeader>
        <CardTitle className="text-xl text-primary flex items-center gap-2">
          <Send className="h-6 w-6" />
          Submit Your Feedback
        </CardTitle>
        <CardDescription>
          Have an issue or suggestion? Let us know.
        </CardDescription>
      </CardHeader>
      <form onSubmit={handleSubmit}>
        <CardContent className="space-y-6">
          <div>
            <Label htmlFor="name" className="text-muted-foreground">Your Name (Optional)</Label>
            <Input
              id="name"
              type="text"
              name="name"
              placeholder="Operative Name"
              className="mt-1 bg-input/50 border-primary/30 focus:border-primary focus:ring-primary"
            />
          </div>

          <div>
            <Label htmlFor="email" className="text-muted-foreground">Your Email Address</Label>
            <Input
              id="email"
              type="email"
              name="email"
              placeholder="operator@neuro.sh"
              className="mt-1 bg-input/50 border-primary/30 focus:border-primary focus:ring-primary"
              required
            />
            <ValidationError
              prefix="Email"
              field="email"
              errors={state.errors}
              className="text-destructive text-xs mt-1"
            />
          </div>

          <div>
            <Label htmlFor="message" className="text-muted-foreground">Message / Issue Details</Label>
            <Textarea
              id="message"
              name="message"
              placeholder="Please describe the issue or your feedback in detail..."
              className="mt-1 bg-input/50 border-primary/30 focus:border-primary focus:ring-primary min-h-[120px]"
              required
            />
            <ValidationError
              prefix="Message"
              field="message"
              errors={state.errors}
              className="text-destructive text-xs mt-1"
            />
          </div>
        </CardContent>
        <CardFooter>
          <Button type="submit" disabled={state.submitting} className="w-full btn-glow">
            {state.submitting ? (
              <>
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                Submitting...
              </>
            ) : (
              <>
                <Send className="mr-2 h-4 w-4" />
                Send Feedback
              </>
            )}
          </Button>
        </CardFooter>
      </form>
    </Card>
  );
}
