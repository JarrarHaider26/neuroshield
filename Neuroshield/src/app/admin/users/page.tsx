
'use client';

import { AppShell } from '@/components/layout/AppShell';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import { Avatar, AvatarFallback, AvatarImage } from '@/components/ui/avatar';
import { UserPlus, Search, AlertTriangle, Users, FileText, RefreshCw, MoreVertical, Pencil, Trash2 } from 'lucide-react';
import { useAuthContext } from '@/contexts/AuthContext';
import { app, db } from '@/lib/firebase';
import React, { useEffect, useState, useMemo, useCallback } from 'react';
import { Badge } from '@/components/ui/badge';
import { ScrollArea } from '@/components/ui/scroll-area';
import { useToast } from '@/hooks/use-toast';

import { UserEditDialog } from '@/components/admin/UserEditDialog';
import { DeleteUserDialog } from '@/components/admin/DeleteUserDialog';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { collection, getDocs, query, Timestamp } from 'firebase/firestore';
import { Loader } from '@/components/ui/loader';


export interface NeuroUser {
  id: string;
  displayName: string;
  email: string;
  createdAt: Date | null;
  lastLogin?: Date | null;
  profilePicUrl?: string;
  role: 'admin' | 'user';
  reportCount: number;
  emailVerified?: boolean;
}


export default function AdminUsersPage() {
  const { user: adminUser, isAdmin } = useAuthContext();
  const [users, setUsers] = useState<NeuroUser[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [searchTerm, setSearchTerm] = useState('');
  const { toast } = useToast();

  const [isEditUserDialogOpen, setIsEditUserDialogOpen] = useState(false);
  const [isDeleteUserDialogOpen, setIsDeleteUserDialogOpen] = useState(false);
  const [selectedUser, setSelectedUser] = useState<NeuroUser | null>(null);



  const fetchUsers = useCallback(async () => {
    if (!isAdmin || !db) {
      setError("Access Denied or Database not available.");
      setIsLoading(false);
      return;
    }

    setIsLoading(true);
    setError(null);

    try {
      const usersCollectionRef = collection(db, "users");
      const usersSnapshot = await getDocs(usersCollectionRef);

      const fetchedUsersData = usersSnapshot.docs.map(doc => ({
        id: doc.id,
        ...doc.data()
      }));

      const reportsCollectionRef = collection(db, "scanReports");
      const reportsSnapshot = await getDocs(reportsCollectionRef);
      const reportCounts = new Map<string, number>();
      reportsSnapshot.forEach(doc => {
        const userId = doc.data().userId;
        if (userId) {
          reportCounts.set(userId, (reportCounts.get(userId) || 0) + 1);
        }
      });

      const usersWithCounts: NeuroUser[] = fetchedUsersData.map((user: any) => {
        const createdAt = user.createdAt instanceof Timestamp ? user.createdAt.toDate() : null;
        const lastLogin = user.lastLogin instanceof Timestamp ? user.lastLogin.toDate() : null;

        return {
          id: user.uid,
          displayName: user.displayName || 'N/A',
          email: user.email || 'N/A',
          role: user.role || 'user',
          createdAt: createdAt,
          lastLogin: lastLogin,
          profilePicUrl: user.profilePicUrl || '/images/rr.png',
          reportCount: reportCounts.get(user.uid) || 0,
          emailVerified: user.emailVerified === true, // Only true if explicitly set to true
        };
      });

      // Filter out unverified users - only show users with emailVerified === true
      const verifiedUsers = usersWithCounts.filter(user => user.emailVerified === true);

      verifiedUsers.sort((a, b) => {
        const dateA = a.createdAt ? new Date(a.createdAt).getTime() : 0;
        const dateB = b.createdAt ? new Date(b.createdAt).getTime() : 0;
        return dateB - dateA;
      });

      setUsers(verifiedUsers);

    } catch (err: any) {
      console.error("Error fetching users from Firestore:", err);
      setError(`Failed to fetch user data. Firestore rules might be incorrect. Message: ${err.message}`);
    } finally {
      setIsLoading(false);
    }
  }, [isAdmin]);

  useEffect(() => {
    if (isAdmin) {
      fetchUsers();
    }
  }, [isAdmin, fetchUsers]);

  const handleOpenEditDialog = (user: NeuroUser | null) => {
    setSelectedUser(user);
    setIsEditUserDialogOpen(true);
  };

  const handleOpenDeleteDialog = (user: NeuroUser) => {
    setSelectedUser(user);
    setIsDeleteUserDialogOpen(true);
  };

  const handleSaveUser = async (userToSave: NeuroUser, values: any) => {
    const isNewUser = userToSave.id === 'new';
    const endpoint = isNewUser ? '/api/admin/users/add' : '/api/admin/users/edit';
    const payload = isNewUser ? values : { uid: userToSave.id, ...values };

    try {
      const token = await adminUser?.getIdToken();
      const response = await fetch(endpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`,
        },
        body: JSON.stringify(payload),
      });

      const result = await response.json();

      if (!response.ok) {
        throw new Error(result.error?.message || result.error || 'An error occurred');
      }

      toast({
        title: `User ${isNewUser ? 'Created' : 'Updated'}`,
        description: result.data.message,
      });

      await fetchUsers();
    } catch (error: any) {
      console.error(`Error ${isNewUser ? 'creating' : 'updating'} user:`, error);
      toast({
        title: `Error ${isNewUser ? 'Creating' : 'Updating'} User`,
        description: error.message || 'An unexpected error occurred.',
        variant: 'destructive',
      });
    }
  };

  const handleDeleteUser = async (userToDelete: NeuroUser) => {
    try {
      const token = await adminUser?.getIdToken();
      const response = await fetch('/api/admin/users/delete', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`,
        },
        body: JSON.stringify({ uid: userToDelete.id }),
      });

      const result = await response.json();

      if (!response.ok) {
        throw new Error(result.error?.message || result.error || 'An error occurred');
      }

      setUsers(prev => prev.filter(u => u.id !== userToDelete.id));
      toast({
        title: "User Deleted",
        description: `User ${userToDelete.displayName} has been deleted.`,
      });
    } catch (error: any) {
      console.error("Error deleting user:", error);
      toast({
        title: "Deletion Failed",
        description: error.message || "An unexpected error occurred while deleting the user.",
        variant: "destructive",
      });
    }
  };

  const filteredUsers = useMemo(() => {
    if (!searchTerm) return users;
    return users.filter(user =>
      user.displayName.toLowerCase().includes(searchTerm.toLowerCase()) ||
      user.email.toLowerCase().includes(searchTerm.toLowerCase())
    );
  }, [users, searchTerm]);

  return (
    <>
      <AppShell>
        <div className="flex flex-col gap-8">
          <header className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
            <div>
              <h1 className="text-3xl font-bold tracking-tight text-primary flex items-center gap-2">
                <Users className="h-8 w-8" />
                User Roster
              </h1>
              <p className="text-muted-foreground mt-1">
                View and manage NeuroShield operatives.
              </p>
            </div>
            <div className="flex items-center gap-2">
              <Button onClick={fetchUsers} variant="outline" disabled={isLoading}>
                <RefreshCw className={`mr-2 h-4 w-4 ${isLoading ? 'animate-spin' : ''}`} />
                Refresh
              </Button>
              <Button onClick={() => handleOpenEditDialog({ id: 'new', role: 'user', displayName: '', email: '', createdAt: new Date(), reportCount: 0 })}>
                <UserPlus className="mr-2 h-4 w-4" />
                Add User
              </Button>
            </div>
          </header>

          <Card className="shadow-xl border-primary/20">
            <CardHeader className="flex-row items-center justify-between gap-4">
              <div>
                <CardTitle className="text-xl">Registered Operatives</CardTitle>
                <CardDescription>A total of {users.length} users found.</CardDescription>
              </div>
              <div className="relative">
                <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
                <Input
                  type="search"
                  placeholder="Search by name or email..."
                  className="pl-8 sm:w-[300px] md:w-[200px] lg:w-[300px] bg-input/50"
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                />
              </div>
            </CardHeader>
            <CardContent>
              {isLoading ? (
                <div className="flex flex-col items-center justify-center py-16 text-muted-foreground">
                  <Loader />
                  <p className="mt-4">Loading user roster...</p>
                </div>
              ) : error ? (
                <div className="flex flex-col items-center justify-center py-16 text-destructive">
                  <AlertTriangle className="h-12 w-12 mb-4" />
                  <p className="text-lg font-semibold">Error Loading Data</p>
                  <p className="text-sm text-center max-w-md">{error}</p>
                </div>
              ) : (
                <ScrollArea className="h-[600px] w-full rounded-md border">
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead>User</TableHead>
                        <TableHead className="hidden md:table-cell">Status</TableHead>
                        <TableHead className="hidden lg:table-cell">Joined Date</TableHead>
                        <TableHead className="hidden lg:table-cell">Last Login</TableHead>
                        <TableHead className="text-right">Actions</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {filteredUsers.map((user) => (
                        <TableRow key={user.id}>
                          <TableCell>
                            <div className="flex items-center gap-3">
                              <Avatar className="h-10 w-10 border-2 border-primary/50">
                                <AvatarImage src={user.profilePicUrl} alt={user.displayName} />
                                <AvatarFallback>{user.displayName.charAt(0)}</AvatarFallback>
                              </Avatar>
                              <div className="grid gap-0.5">
                                <p className="font-medium text-foreground">{user.displayName}</p>
                                <p className="text-xs text-muted-foreground">{user.email}</p>
                              </div>
                            </div>
                          </TableCell>
                          <TableCell className="hidden md:table-cell">
                            <Badge variant={user.role === 'admin' ? 'destructive' : 'secondary'}>
                              {user.role === 'admin' ? 'Admin' : 'User'}
                            </Badge>
                          </TableCell>
                          <TableCell className="hidden lg:table-cell text-muted-foreground">
                            {user.createdAt ? user.createdAt.toLocaleDateString() : 'N/A'}
                          </TableCell>
                          <TableCell className="hidden lg:table-cell text-muted-foreground">
                            {user.lastLogin ? user.lastLogin.toLocaleString() : 'Never'}
                          </TableCell>
                          <TableCell className="text-right">
                            <DropdownMenu>
                              <DropdownMenuTrigger asChild>
                                <Button variant="ghost" size="icon" disabled={user.id === adminUser?.uid}>
                                  <MoreVertical className="h-4 w-4" />
                                </Button>
                              </DropdownMenuTrigger>
                              <DropdownMenuContent align="end">
                                <DropdownMenuItem onClick={() => handleOpenEditDialog(user)}>
                                  <Pencil className="mr-2 h-4 w-4" />
                                  <span>Edit</span>
                                </DropdownMenuItem>
                                <DropdownMenuItem
                                  onClick={() => handleOpenDeleteDialog(user)}
                                  className="text-destructive focus:bg-destructive/10 focus:text-destructive"
                                >
                                  <Trash2 className="mr-2 h-4 w-4" />
                                  <span>Delete</span>
                                </DropdownMenuItem>
                              </DropdownMenuContent>
                            </DropdownMenu>
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </ScrollArea>
              )}
            </CardContent>
          </Card>
        </div>
      </AppShell>

      <UserEditDialog
        user={selectedUser}
        isOpen={isEditUserDialogOpen}
        onOpenChange={setIsEditUserDialogOpen}
        onSave={handleSaveUser}
      />
      <DeleteUserDialog
        user={selectedUser}
        isOpen={isDeleteUserDialogOpen}
        onOpenChange={setIsDeleteUserDialogOpen}
        onConfirm={handleDeleteUser}
      />
    </>
  );
}
