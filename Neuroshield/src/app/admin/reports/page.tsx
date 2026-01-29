'use client';

import { AppShell } from '@/components/layout/AppShell';
import { ReportList, type SavedReport } from '@/components/reports/ReportList';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { FileText, Loader2, AlertTriangle, RefreshCw, ShieldCheck } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { useAuthContext } from '@/contexts/AuthContext';
import { db } from '@/lib/firebase';
import { collection, query, orderBy, getDocs, Timestamp, doc, deleteDoc } from 'firebase/firestore';
import React, { useEffect, useState, useCallback, useMemo } from 'react';
import type { ScanFileOutput } from '@/ai/flows/scan-file-flow';
import type { ScanUrlOutput } from '@/ai/flows/scan-url-flow';
import { ScrollArea } from '@/components/ui/scroll-area';
import { useRouter } from 'next/navigation';
import { DeleteReportDialog } from '@/components/reports/DeleteReportDialog';
import { useToast } from '@/hooks/use-toast';

interface UserMap {
  [key: string]: {
    email: string;
    displayName: string;
  }
}

export default function AdminReportCenterPage() {
  const { user: adminUser, isAdmin, loading: authLoading } = useAuthContext();
  const router = useRouter();
  const { toast } = useToast();
  const [allReports, setAllReports] = useState<SavedReport[]>([]);
  const [userMap, setUserMap] = useState<UserMap>({});
  const [verifiedUserIds, setVerifiedUserIds] = useState<Set<string>>(new Set());
  const [isLoadingReports, setIsLoadingReports] = useState(true);
  const [error, setError] = useState<string | null>(null);
  
  // Dialog state
  const [isDeleteDialogOpen, setIsDeleteDialogOpen] = useState(false);
  const [selectedReport, setSelectedReport] = useState<SavedReport | null>(null);
  
  // Filtering & Sorting State
  const [searchTerm, setSearchTerm] = useState('');
  const [sortOption, setSortOption] = useState('createdAt_desc');
  const [scanTypeFilter, setScanTypeFilter] = useState<'all' | 'file' | 'url'>('all');
  const [threatLabelFilter, setThreatLabelFilter] = useState<string>('all');
  const [userFilter, setUserFilter] = useState<string>('all');

  const fetchAdminData = useCallback(async () => {
    if (!isAdmin) {
      setError("Access Denied. Administrator privileges required.");
      setIsLoadingReports(false);
      return;
    }
    if (!db) {
        setError("Database connection not available.");
        setIsLoadingReports(false);
        return;
    }
    setIsLoadingReports(true);
    setError(null);
    
    try {
      // Fetch all users to create a map of userId -> user info
      const usersRef = collection(db, 'users');
      const usersSnapshot = await getDocs(usersRef);
      const fetchedUserMap: UserMap = {};
      const verifiedUserIds = new Set<string>(); // Track verified user IDs
      
      usersSnapshot.forEach(doc => {
        const data = doc.data();
        fetchedUserMap[doc.id] = {
          email: data.email || 'N/A',
          displayName: data.displayName || 'N/A',
        };
        // Track verified users
        if (data.emailVerified === true) {
          verifiedUserIds.add(doc.id);
        }
      });
      setUserMap(fetchedUserMap);
      setVerifiedUserIds(verifiedUserIds);
      
      // Fetch all reports
      const reportsRef = collection(db, 'scanReports');
      // Admin query: just order by date, don't filter by userId
      const q = query(reportsRef, orderBy('createdAt', 'desc'));
      
      const querySnapshot = await getDocs(q);
      const fetchedReports: SavedReport[] = querySnapshot.docs
        .filter(doc => {
          const data = doc.data();
          // Only include reports from verified users
          return verifiedUserIds.has(data.userId);
        })
        .map(doc => {
        const data = doc.data();

        const reportDataObject: ScanFileOutput | ScanUrlOutput = data.reportData || {
          analysisId: data.analysisId,
          status: data.status,
          threatLabel: data.threatLabel
        };

        return {
          id: doc.id,
          userId: data.userId,
          scanType: data.scanType,
          targetIdentifier: data.targetIdentifier,
          scanDate: (data.scanDate instanceof Timestamp ? data.scanDate.toDate() : new Date(0)),
          status: data.status,
          threatLabel: data.threatLabel || null,
          analysisId: data.analysisId, 
          permalink: data.permalink || null, 
          reportData: reportDataObject, 
          createdAt: (data.createdAt instanceof Timestamp ? data.createdAt.toDate() : new Date()),
        };
      });
      
      setAllReports(fetchedReports);
    } catch (err: any) {
      console.error("[AdminReports] Error fetching data:", err);
      setError(`Failed to fetch reports. ${err.message}`);
    } finally {
      setIsLoadingReports(false);
    }
  }, [isAdmin]);

  useEffect(() => {
    if (authLoading) return;
    if (!adminUser || !isAdmin) {
      router.push('/auth/admin-login');
      return;
    }
    fetchAdminData();
  }, [adminUser, isAdmin, authLoading, router, fetchAdminData]);

  const uniqueThreatLabels = useMemo(() => {
    const labels = new Set(allReports.map(r => r.threatLabel).filter(Boolean) as string[]);
    return ['all', ...Array.from(labels).sort()];
  }, [allReports]);

  const filteredAndSortedReports = useMemo(() => {
    let reports = [...allReports];

    // Apply filters
    if (userFilter !== 'all') {
      reports = reports.filter(report => report.userId === userFilter);
    }
    if (searchTerm) {
      reports = reports.filter(report =>
        report.targetIdentifier?.toLowerCase().includes(searchTerm.toLowerCase()) ||
        (userMap[report.userId]?.email.toLowerCase().includes(searchTerm.toLowerCase())) ||
        (userMap[report.userId]?.displayName.toLowerCase().includes(searchTerm.toLowerCase()))
      );
    }
    if (scanTypeFilter !== 'all') {
      reports = reports.filter(report => report.scanType === scanTypeFilter);
    }
    if (threatLabelFilter !== 'all') {
        reports = reports.filter(report => report.threatLabel === threatLabelFilter);
    }

    // Apply sorting
    const [sortField, sortDirection] = sortOption.split('_');
    reports.sort((a, b) => {
      let valA: any, valB: any;
      
      if (sortField === 'user') {
        valA = userMap[a.userId]?.displayName || '';
        valB = userMap[b.userId]?.displayName || '';
      } else {
        valA = a[sortField as keyof SavedReport];
        valB = b[sortField as keyof SavedReport];
      }

      if (valA instanceof Date && valB instanceof Date) {
        return sortDirection === 'asc' ? valA.getTime() - valB.getTime() : valB.getTime() - valA.getTime();
      }
      if (typeof valA === 'string' && typeof valB === 'string') {
        valA = valA.toLowerCase();
        valB = valB.toLowerCase();
      }
      
      if (valA < valB) return sortDirection === 'asc' ? -1 : 1;
      if (valA > valB) return sortDirection === 'asc' ? 1 : -1;
      return 0;
    });

    return reports;
  }, [allReports, userMap, searchTerm, sortOption, scanTypeFilter, threatLabelFilter, userFilter]);

  const handleOpenDeleteDialog = (report: SavedReport) => {
    setSelectedReport(report);
    setIsDeleteDialogOpen(true);
  };
  
  const handleDeleteReport = async (reportToDelete: SavedReport) => {
    if (!db) {
        toast({ title: "Deletion Failed", description: "Database not connected.", variant: "destructive" });
        return;
    }
    try {
      const reportRef = doc(db, 'scanReports', reportToDelete.id);
      await deleteDoc(reportRef);
      setAllReports(prev => prev.filter(r => r.id !== reportToDelete.id));
      toast({
        title: "Report Deleted",
        description: `The report for "${reportToDelete.targetIdentifier}" has been permanently deleted.`,
      });
    } catch (err: any) {
      console.error("[AdminReports] Error deleting report:", err);
      toast({
        title: "Deletion Failed",
        description: `Could not delete the report. ${err.message}`,
        variant: "destructive",
      });
    }
  };
  
  if (authLoading || (isLoadingReports && allReports.length === 0)) {
    return (
      <AppShell>
        <div className="flex flex-col items-center justify-center h-full text-muted-foreground">
          <Loader2 className="h-12 w-12 animate-spin text-primary mb-4" />
          <p>{authLoading ? "Verifying admin credentials..." : "Loading system-wide reports..."}</p>
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
    <>
      <AppShell>
        <div className="flex flex-col gap-8">
          <header className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
            <div>
              <h1 className="text-3xl font-bold tracking-tight text-primary flex items-center gap-2">
                <FileText className="h-8 w-8" />
                System Report Archive
              </h1>
              <p className="text-muted-foreground mt-1">
                Browse, filter, and manage all reports submitted by verified users.
              </p>
            </div>
            <Button onClick={fetchAdminData} variant="outline" disabled={isLoadingReports}>
              <RefreshCw className={`mr-2 h-4 w-4 ${isLoadingReports ? 'animate-spin' : ''}`} />
              Refresh
            </Button>
          </header>

          <Card className="shadow-xl border-primary/20">
            <CardHeader>
              <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4">
                  <div>
                      <CardTitle className="text-xl">All User Reports</CardTitle>
                      <CardDescription>A total of {filteredAndSortedReports.length} reports found matching filters.</CardDescription>
                  </div>
              </div>
              <div className="mt-4 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-5 gap-4 items-end">
                  <Input 
                    type="search" 
                    placeholder="Search target or user..." 
                    className="bg-input/50 border-primary/30"
                    value={searchTerm}
                    onChange={(e) => setSearchTerm(e.target.value)} 
                    disabled={isLoadingReports || !!error}
                  />
                  <Select value={userFilter} onValueChange={setUserFilter} disabled={isLoadingReports || !!error}>
                      <SelectTrigger className="bg-input/50 border-primary/30"><SelectValue placeholder="Filter by User..." /></SelectTrigger>
                      <SelectContent>
                          <SelectItem value="all">All Users</SelectItem>
                          {Object.entries(userMap)
                            .filter(([uid]) => verifiedUserIds.has(uid)) // Only show verified users
                            .map(([uid, user]) => (
                              <SelectItem key={uid} value={uid}>{user.displayName} ({user.email})</SelectItem>
                          ))}
                      </SelectContent>
                  </Select>
                  <Select value={scanTypeFilter} onValueChange={(value) => setScanTypeFilter(value as any)} disabled={isLoadingReports || !!error}>
                      <SelectTrigger className="bg-input/50 border-primary/30"><SelectValue placeholder="Filter by Type..." /></SelectTrigger>
                      <SelectContent>
                          <SelectItem value="all">All Types</SelectItem>
                          <SelectItem value="file">File Scans</SelectItem>
                          <SelectItem value="url">URL Scans</SelectItem>
                      </SelectContent>
                  </Select>
                  <Select value={threatLabelFilter} onValueChange={setThreatLabelFilter} disabled={isLoadingReports || !!error}>
                      <SelectTrigger className="bg-input/50 border-primary/30"><SelectValue placeholder="Filter by Threat..." /></SelectTrigger>
                      <SelectContent>
                          {uniqueThreatLabels.map(label => (
                              <SelectItem key={label} value={label}>{label === 'all' ? 'All Threats' : (label || 'N/A')}</SelectItem>
                          ))}
                      </SelectContent>
                  </Select>
                  <Select value={sortOption} onValueChange={setSortOption} disabled={isLoadingReports || !!error}>
                      <SelectTrigger className="bg-input/50 border-primary/30"><SelectValue placeholder="Sort by..." /></SelectTrigger>
                      <SelectContent>
                          <SelectItem value="createdAt_desc">Date (Newest)</SelectItem>
                          <SelectItem value="createdAt_asc">Date (Oldest)</SelectItem>
                          <SelectItem value="user_asc">User (A-Z)</SelectItem>
                          <SelectItem value="user_desc">User (Z-A)</SelectItem>
                          <SelectItem value="threatLabel_asc">Threat (Asc)</SelectItem>
                          <SelectItem value="threatLabel_desc">Threat (Desc)</SelectItem>
                      </SelectContent>
                  </Select>
              </div>
            </CardHeader>
            <CardContent>
              {isLoadingReports && allReports.length === 0 ? (
                  <div className="flex flex-col items-center justify-center py-16 text-muted-foreground">
                      <Loader2 className="h-12 w-12 animate-spin text-primary mb-4" />
                      <p>Loading reports...</p>
                  </div>
              ) : error ? (
                <div className="flex flex-col items-center justify-center py-16 text-destructive">
                  <AlertTriangle className="h-12 w-12 mb-4" />
                  <p className="text-lg font-semibold">Error Loading Reports</p>
                  <p className="text-sm text-center max-w-md">{error}</p>
                  <Button onClick={fetchAdminData} variant="outline" className="mt-4">Try Again</Button>
                </div>
              ) : (
                <ScrollArea className="h-[600px] w-full rounded-md border p-4">
                  <ReportList 
                    reports={filteredAndSortedReports} 
                    userMap={userMap} 
                    isAdminView={true}
                    onDeleteReport={handleOpenDeleteDialog} 
                  />
                </ScrollArea>
              )}
            </CardContent>
          </Card>
        </div>
      </AppShell>
      <DeleteReportDialog
        report={selectedReport}
        isOpen={isDeleteDialogOpen}
        onConfirm={handleDeleteReport}
        onOpenChange={setIsDeleteDialogOpen}
      />
    </>
  );
}
