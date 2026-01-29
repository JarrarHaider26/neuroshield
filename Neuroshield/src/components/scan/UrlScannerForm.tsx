
'use client';

import { zodResolver } from '@hookform/resolvers/zod';
import { useForm } from 'react-hook-form';
import * as z from 'zod';
// Removed useState as loading state will be managed by the parent page
// import { useState } from 'react'; 

import { Button } from '@/components/ui/button';
import {
  Form,
  FormControl,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from '@/components/ui/form';
import { Input } from '@/components/ui/input';
import { Link2, Loader2 } from 'lucide-react';

const urlSchema = z.object({
  url: z.string().url({ message: 'Please enter a valid URL (e.g., http://example.com).' }),
});

type UrlFormValues = z.infer<typeof urlSchema>;

interface UrlScannerFormProps {
  onSubmit: (url: string) => void;
  isScanning: boolean; // Added prop to receive scanning state
}

export function UrlScannerForm({ onSubmit, isScanning }: UrlScannerFormProps) {
  // const [isLoading, setIsLoading] = useState(false); // isLoading is now managed by parent

  const form = useForm<UrlFormValues>({
    resolver: zodResolver(urlSchema),
    defaultValues: {
      url: '',
    },
  });

  async function handleSubmit(values: UrlFormValues) {
    // setIsLoading(true); // Parent will set its own loading state
    // await new Promise(resolve => setTimeout(resolve, 1000)); // Simulation removed
    onSubmit(values.url);
    // setIsLoading(false); // Parent will manage this
    // form.reset(); // Optionally reset form - can be decided by parent or kept here
  }

  return (
    <Form {...form}>
      <form onSubmit={form.handleSubmit(handleSubmit)} className="space-y-6">
        <FormField
          control={form.control}
          name="url"
          render={({ field }) => (
            <FormItem>
              <FormLabel className="text-muted-foreground">URL to Analyze</FormLabel>
              <FormControl>
                <div className="relative flex items-center">
                  <Link2 className="absolute left-3 top-1/2 h-5 w-5 -translate-y-1/2 text-muted-foreground" />
                  <Input
                    type="url"
                    placeholder="https://example.com/suspicious-link"
                    {...field}
                    className="pl-10 bg-input/50 border-primary/30 focus:border-primary focus:ring-primary"
                    autoComplete="url"
                    disabled={isScanning} // Disable input while scanning
                  />
                </div>
              </FormControl>
              <FormMessage />
            </FormItem>
          )}
        />
        <Button type="submit" className="w-full btn-glow" disabled={isScanning}>
          {isScanning ? (
            <>
              <Loader2 className="mr-2 h-4 w-4 animate-spin" />
              Scanning URL...
            </>
          ) : (
            'Scan URL'
          )}
        </Button>
      </form>
    </Form>
  );
}
