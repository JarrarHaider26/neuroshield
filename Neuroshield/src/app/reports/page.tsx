
'use client';

import { AppShell } from '@/components/layout/AppShell';
import { ReportList, type SavedReport } from '@/components/reports/ReportList';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { FileText, Loader2, AlertTriangle, RefreshCw } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { useAuthContext } from '@/contexts/AuthContext';
import { db } from '@/lib/firebase';
import { collection, query, where, orderBy, getDocs, Timestamp, deleteDoc, doc } from 'firebase/firestore';
import React, { useEffect, useState, useCallback, useMemo } from 'react';
import type { ScanFileOutput } from '@/ai/flows/scan-file-flow';
import type { ScanUrlOutput } from '@/ai/flows/scan-url-flow';
import { ScrollArea } from '@/components/ui/scroll-area';

export default function ReportCenterPage() {
  const { user, loading: authLoading } = useAuthContext();
  const [allReports, setAllReports] = useState<SavedReport[]>([]);
  const [isLoadingReports, setIsLoadingReports] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [sortOption, setSortOption] = useState('createdAt_desc');
  const [scanTypeFilter, setScanTypeFilter] = useState<'all' | 'file' | 'url'>('all');
  const [threatLabelFilter, setThreatLabelFilter] = useState<string>('all');

  const handleDeleteReport = async (report: SavedReport) => {
    if (!confirm(`Are you sure you want to delete this ${report.scanType} scan report for "${report.targetIdentifier}"?`)) {
      return;
    }

    try {
      await deleteDoc(doc(db, 'scanReports', report.id));
      setAllReports(prev => prev.filter(r => r.id !== report.id));
      console.log('[ReportCenterPage] Report deleted successfully:', report.id);
    } catch (err: any) {
      console.error('[ReportCenterPage] Error deleting report:', err);
      alert(`Failed to delete report: ${err.message}`);
    }
  };

  const fetchReports = useCallback(async () => {
    if (!user) {
      setAllReports([]);
      setIsLoadingReports(false);
      return;
    }
    setIsLoadingReports(true);
    setError(null);
    
    try {
      if (!db) {
        console.error('[ReportCenterPage] Firestore db instance is not available.');
        setError("Database connection is not available. Please try again later.");
        setIsLoadingReports(false);
        return;
      }
      if (!user.uid) {
        console.error('[ReportCenterPage] User UID is not available.');
        setError("User authentication error. Cannot fetch reports.");
        setIsLoadingReports(false);
        return;
      }
      console.log('[ReportCenterPage] Fetching reports for user:', user.uid);

      const reportsRef = collection(db, 'scanReports');
      const q = query(reportsRef, where('userId', '==', user.uid), orderBy('createdAt', 'desc'));
      
      const querySnapshot = await getDocs(q);
      const fetchedReports: SavedReport[] = querySnapshot.docs.map((doc) => {
        const data = doc.data();

        // Helper to safely convert Firestore Timestamps or numbers to Date
        const toDate = (field: any): Date => {
          if (field instanceof Timestamp) {
            return field.toDate();
          }
          // Handle case where it might be a Unix timestamp in seconds
          if (typeof field === 'number' && field > 1000) { // Check for a reasonable timestamp value
            return new Date(field * 1000);
          }
          // Default to now for invalid/missing data to avoid epoch date
          return new Date();
        };

        const scanDate = toDate(data.scanDate);
        const createdAt = toDate(data.createdAt);

        let reportDataObject: ScanFileOutput | ScanUrlOutput;
        if (data.reportData && typeof data.reportData === 'object') {
          reportDataObject = data.reportData;
        } else {
          // Reconstruct a minimal reportData object if it's missing
          reportDataObject = {
            analysisId: data.analysisId || '',
            status: data.status || 'unknown',
            threatLabel: data.threatLabel || 'Unknown',
            permalink: data.permalink,
            // Ensure scanDate is a number (seconds) in reportData
            scanDate: scanDate.getTime() / 1000,
          } as ScanFileOutput | ScanUrlOutput;
        }
        
        return {
          id: doc.id,
          userId: data.userId,
          scanType: data.scanType as 'file' | 'url',
          targetIdentifier: data.targetIdentifier,
          scanDate: scanDate,
          status: data.status,
          threatLabel: data.threatLabel || null,
          analysisId: data.analysisId,
          permalink: data.permalink || null,
          reportData: reportDataObject,
          createdAt: createdAt,
        };
      });
      setAllReports(fetchedReports);
      console.log('[ReportCenterPage] Fetched reports count:', fetchedReports.length);
    } catch (err: any) {
      console.error("[ReportCenterPage] Error fetching reports from Firestore:", err.code, err.message, err.stack);
      setError(`Failed to fetch reports. ${err.message} (Code: ${err.code || 'N/A'})`);
    } finally {
      setIsLoadingReports(false);
    }
  }, [user]);

  useEffect(() => {
    if (!authLoading && user) { // Ensure user is loaded and available
      fetchReports();
    } else if (!authLoading && !user) { // If not loading and no user, clear reports and stop loading
      setAllReports([]);
      setIsLoadingReports(false);
      setError("Please log in to view your reports.");
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [user, authLoading]); // fetchReports is memoized, so it's safe here

  const uniqueThreatLabels = useMemo(() => {
    const labels = new Set(allReports.map(r => r.threatLabel).filter(Boolean) as string[]);
    return ['all', ...Array.from(labels).sort()];
  }, [allReports]);

  const filteredAndSortedReports = useMemo(() => {
    let reports = [...allReports];

    if (searchTerm) {
      reports = reports.filter(report =>
        report.targetIdentifier?.toLowerCase().includes(searchTerm.toLowerCase()) ||
        (report.threatLabel && report.threatLabel.toLowerCase().includes(searchTerm.toLowerCase())) ||
        report.scanType?.toLowerCase().includes(searchTerm.toLowerCase())
      );
    }

    if (scanTypeFilter !== 'all') {
      reports = reports.filter(report => report.scanType === scanTypeFilter);
    }
    
    if (threatLabelFilter !== 'all') {
        reports = reports.filter(report => report.threatLabel === threatLabelFilter);
    }

    const [sortField, sortDirection] = sortOption.split('_') as [keyof SavedReport, 'asc' | 'desc'];
    reports.sort((a, b) => {
      let valA: any = a[sortField];
      let valB: any = b[sortField];

      if (valA instanceof Date && valB instanceof Date) {
        return sortDirection === 'asc' ? valA.getTime() - valB.getTime() : valB.getTime() - valA.getTime();
      }
      if (typeof valA === 'string' && typeof valB === 'string') {
        valA = valA.toLowerCase();
        valB = valB.toLowerCase();
      }
      if (valA === null || valA === undefined) valA = sortDirection === 'asc' ? Infinity : -Infinity;
      if (valB === null || valB === undefined) valB = sortDirection === 'asc' ? Infinity : -Infinity;
      
      if (valA != null && valB != null && valA < valB) return sortDirection === 'asc' ? -1 : 1;
      if (valA != null && valB != null && valA > valB) return sortDirection === 'asc' ? 1 : -1;
      return 0;
    });

    return reports;
  }, [allReports, searchTerm, sortOption, scanTypeFilter, threatLabelFilter]);
  

  return (
    <AppShell>
      <div className="flex flex-col gap-6 md:gap-8">
        <header className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
          <div>
            <h1 className="text-2xl sm:text-3xl font-bold tracking-tight text-primary flex items-center gap-2">
              <FileText className="h-6 w-6 sm:h-8 sm:w-8" />
              Scan Report Archive
            </h1>
            <p className="text-muted-foreground mt-1 text-sm sm:text-base">
              Access, filter, and manage your past scan reports.
            </p>
          </div>
           <Button onClick={fetchReports} variant="outline" disabled={isLoadingReports} className="text-sm sm:text-base">
            <RefreshCw className={`h-4 w-4 mr-2 ${isLoadingReports ? 'animate-spin' : ''}`} />
            Refresh
          </Button>
        </header>

        <Card className="shadow-xl border-primary/20">
          <CardHeader>
            <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4">
                <div>
                    <CardTitle className="text-lg sm:text-xl">Archived Intelligence</CardTitle>
                    <CardDescription className="text-xs sm:text-sm">Browse your generated scan reports.</CardDescription>
                </div>
            </div>
            <div className="mt-4 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 sm:gap-4 items-end">
                <Input 
                  type="search" 
                  placeholder="Search target, type, threat..." 
                  className="bg-input/50 border-primary/30 focus:border-primary focus:ring-primary "
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)} 
                  disabled={isLoadingReports || !!error}
                />
                <Select value={scanTypeFilter} onValueChange={(value) => setScanTypeFilter(value as 'all' | 'file' | 'url')} disabled={isLoadingReports || !!error}>
                    <SelectTrigger className="bg-input/50 border-primary/30 focus:border-primary focus:ring-primary">
                        <SelectValue placeholder="Filter by Type..." />
                    </SelectTrigger>
                    <SelectContent>
                        <SelectItem value="all">All Types</SelectItem>
                        <SelectItem value="file">File Scans</SelectItem>
                        <SelectItem value="url">URL Scans</SelectItem>
                    </SelectContent>
                </Select>
                <Select value={threatLabelFilter} onValueChange={setThreatLabelFilter} disabled={isLoadingReports || !!error}>
                    <SelectTrigger className="bg-input/50 border-primary/30 focus:border-primary focus:ring-primary">
                        <SelectValue placeholder="Filter by Threat..." />
                    </SelectTrigger>
                    <SelectContent>
                        {uniqueThreatLabels.map(label => (
                            <SelectItem key={label} value={label}>{label === 'all' ? 'All Threats' : (label || 'N/A')}</SelectItem>
                        ))}
                    </SelectContent>
                </Select>
                <Select value={sortOption} onValueChange={setSortOption} disabled={isLoadingReports || !!error}>
                    <SelectTrigger className="bg-input/50 border-primary/30 focus:border-primary focus:ring-primary">
                        <SelectValue placeholder="Sort by..." />
                    </SelectTrigger>
                    <SelectContent>
                        <SelectItem value="createdAt_desc">Date (Newest)</SelectItem>
                        <SelectItem value="createdAt_asc">Date (Oldest)</SelectItem>
                        <SelectItem value="scanDate_desc">Scan Date (Newest)</SelectItem>
                        <SelectItem value="scanDate_asc">Scan Date (Oldest)</SelectItem>
                        <SelectItem value="threatLabel_asc">Threat Level (Asc)</SelectItem>
                        <SelectItem value="threatLabel_desc">Threat Level (Desc)</SelectItem>
                        <SelectItem value="scanType_asc">Scan Type (Asc)</SelectItem>
                        <SelectItem value="scanType_desc">Scan Type (Desc)</SelectItem>
                        <SelectItem value="targetIdentifier_asc">Target (A-Z)</SelectItem>
                        <SelectItem value="targetIdentifier_desc">Target (Z-A)</SelectItem>
                    </SelectContent>
                </Select>
            </div>
          </CardHeader>
          <CardContent>
            {authLoading || isLoadingReports ? (
              <div className="flex flex-col items-center justify-center py-16 text-muted-foreground">
                <Loader2 className="h-12 w-12 animate-spin text-primary mb-4" />
                <p>{authLoading ? "Authenticating..." : "Loading reports..."}</p>
              </div>
            ) : error ? (
              <div className="flex flex-col items-center justify-center py-16 text-destructive">
                <AlertTriangle className="h-12 w-12 mb-4" />
                <p className="text-lg font-semibold">Error Loading Reports</p>
                <p className="text-sm text-center max-w-md">{error}</p>
                <Button onClick={fetchReports} variant="outline" className="mt-4">Try Again</Button>
              </div>
            ) : (
              <ScrollArea className="h-[600px] w-full rounded-md border p-4">
                <ReportList reports={filteredAndSortedReports} onDeleteReport={handleDeleteReport} />
              </ScrollArea>
            )}
          </CardContent>
        </Card>
      </div>
    </AppShell>
  );
}
    

    
