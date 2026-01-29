
'use client';

import {
  AlertDialog,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogHeader,
  AlertDialogTitle,
} from '@/components/ui/alert-dialog';
import { Hammer } from 'lucide-react';

interface MaintenanceDialogProps {
  isOpen: boolean;
  title?: string;
  description?: string;
}

export function MaintenanceDialog({ 
  isOpen, 
  title = "Under Maintenance", 
  description = "The NeuroShield platform is currently undergoing scheduled maintenance. We'll be back online shortly. Thank you for your patience." 
}: MaintenanceDialogProps) {
  return (
    <AlertDialog open={isOpen}>
      <AlertDialogContent className="max-w-md">
        <AlertDialogHeader>
          <div className="flex justify-center mb-4">
            <Hammer className="h-12 w-12 text-primary animate-pulse" />
          </div>
          <AlertDialogTitle className="text-center text-2xl">{title}</AlertDialogTitle>
          <AlertDialogDescription className="text-center pt-2">
            {description}
          </AlertDialogDescription>
        </AlertDialogHeader>
      </AlertDialogContent>
    </AlertDialog>
  );
}
