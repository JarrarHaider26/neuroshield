
'use client';

import { zodResolver } from '@hookform/resolvers/zod';
import { useForm } from 'react-hook-form';
import * as z from 'zod';
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
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { Loader2 } from 'lucide-react';
import { useEffect, useState } from 'react';
import type { NeuroUser } from '@/app/admin/users/page';

const userFormSchemaBase = z.object({
  displayName: z.string().min(2, { message: 'Display name must be at least 2 characters.' }),
  email: z.string().email({ message: 'Please enter a valid email address.' }),
  role: z.enum(['user', 'admin'], { required_error: 'Role is required.' }),
});

const newUserFormSchema = userFormSchemaBase.extend({
  password: z.string().min(8, { message: 'Password must be at least 8 characters.' }),
});

const editUserFormSchema = userFormSchemaBase;


interface UserEditDialogProps {
  user: NeuroUser | null;
  isOpen: boolean;
  onOpenChange: (isOpen: boolean) => void;
  onSave: (user: NeuroUser, values: any) => Promise<void>;
}

export function UserEditDialog({ user, isOpen, onOpenChange, onSave }: UserEditDialogProps) {
  const [isSaving, setIsSaving] = useState(false);
  const isNewUser = user ? user.id === 'new' : false;

  const form = useForm({
    resolver: zodResolver(isNewUser ? newUserFormSchema : editUserFormSchema),
    defaultValues: {
      displayName: '',
      email: '',
      role: 'user' as 'user' | 'admin',
      password: '',
    },
  });

  useEffect(() => {
    if (user && isOpen) {
      form.reset({
        displayName: user.displayName,
        email: user.email,
        role: user.role,
        password: '',
      });
    } else if (!isOpen) {
      form.reset();
    }
  }, [user, isOpen, form]);

  const handleSave = async (values: any) => {
    if (!user) return;
    setIsSaving(true);
    await onSave(user, values);
    setIsSaving(false);
    onOpenChange(false);
  };

  return (
    <Dialog open={isOpen} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-[425px]">
        <DialogHeader>
          <DialogTitle>{isNewUser ? 'Add New User' : 'Edit User'}</DialogTitle>
          <DialogDescription>
            {isNewUser ? "Create a new operative. The password will be set here." : `Modify details for ${user?.displayName}.`}
          </DialogDescription>
        </DialogHeader>
        <Form {...form}>
          <form onSubmit={form.handleSubmit(handleSave)} id="user-edit-form" className="space-y-4 py-4">
            <FormField
              control={form.control}
              name="displayName"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Display Name / Callsign</FormLabel>
                  <FormControl>
                    <Input placeholder="e.g., Ghost" {...field} disabled={isSaving} />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />
            <FormField
              control={form.control}
              name="email"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Email Address</FormLabel>
                  <FormControl>
                    <Input type="email" placeholder="operator@neuro.sh" {...field} disabled={isSaving || !isNewUser} />
                  </FormControl>
                   {!isNewUser && <p className="text-xs text-muted-foreground pt-1">Email address cannot be changed after creation.</p>}
                  <FormMessage />
                </FormItem>
              )}
            />
             {isNewUser && (
              <FormField
                control={form.control}
                name="password"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Password</FormLabel>
                    <FormControl>
                      <Input type="password" placeholder="Min. 8 characters" {...field} disabled={isSaving} />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />
            )}
             <FormField
              control={form.control}
              name="role"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Role</FormLabel>
                   <Select onValueChange={field.onChange} defaultValue={field.value} disabled={isSaving}>
                    <FormControl>
                      <SelectTrigger>
                        <SelectValue placeholder="Select a role" />
                      </SelectTrigger>
                    </FormControl>
                    <SelectContent>
                      <SelectItem value="user">User</SelectItem>
                      <SelectItem value="admin">Administrator</SelectItem>
                    </SelectContent>
                  </Select>
                  <FormMessage />
                </FormItem>
              )}
            />
          </form>
        </Form>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)} disabled={isSaving}>
            Cancel
          </Button>
          <Button type="submit" form="user-edit-form" disabled={isSaving}>
            {isSaving ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : null}
            {isSaving ? 'Saving...' : 'Save Changes'}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

    