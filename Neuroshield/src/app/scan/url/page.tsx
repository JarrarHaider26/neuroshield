'use client';

import { AppShell } from '@/components/layout/AppShell';
import { UrlScannerForm } from '@/components/scan/UrlScannerForm';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { AlertTriangle, CheckCircle, Download, Globe, Loader2, Info, FileDown, ShieldCheck, AlertCircle as AlertIcon, FileText, FileType } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { useState, useCallback } from 'react';
import type { ScanUrlOutput } from '@/ai/flows/scan-url-flow';
import { Badge } from '@/components/ui/badge';
import { generateScanReportDocx, generateScanReportPdf } from '@/lib/report-generator';
import { useAuthContext } from '@/contexts/AuthContext';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { useToast } from '@/hooks/use-toast';
import { db } from '@/lib/firebase';
import { collection, addDoc, serverTimestamp } from 'firebase/firestore';
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from '@/components/ui/dropdown-menu';

type ScanStatus = 'idle' | 'scanning' | 'completed' | 'error';

export default function UrlScanPage() {
  const { user } = useAuthContext();
  const { toast } = useToast();
  const [scanStatus, setScanStatus] = useState<ScanStatus>('idle');
  const [scanResult, setScanResult] = useState<ScanUrlOutput | null>(null);
  const [scannedUrl, setScannedUrl] = useState<string | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const saveReport = useCallback(async (result: ScanUrlOutput) => {
    if (!user || !db) {
      console.warn('[UrlScanPage] User not logged in or DB not available. Skipping report save.');
      return;
    }
    if (result.status === 'error' || result.error) {
      console.log('[UrlScanPage] Scan resulted in an error. Skipping report save.');
      return;
    }

    try {
      const reportToSave = {
        userId: user.uid,
        scanType: 'url' as const,
        targetIdentifier: result.submittedUrl,
        scanDate: result.scanDate || Math.floor(Date.now() / 1000),
        status: result.status,
        threatLabel: result.threatLabel || 'N/A',
        analysisId: result.analysisId,
        permalink: result.permalink,
        reportData: { ...result },
        createdAt: serverTimestamp(),
      };
      await addDoc(collection(db, "scanReports"), reportToSave);
      console.log("[UrlScanPage] URL scan report successfully saved to Firestore by client.");
      toast({ title: "Report Saved", description: "The scan report has been saved to your Report Center." });
    } catch (firestoreError: any) {
      console.error("[UrlScanPage] Error saving URL scan report to Firestore:", firestoreError);
      toast({ title: "Save Failed", description: `Could not save the report to your Report Center: ${firestoreError.message}`, variant: "destructive" });
    }
  }, [user, toast]);

  const handleUrlSubmit = async (urlToScan: string) => {
    setScannedUrl(urlToScan);
    setScanResult(null);
    setErrorMessage(null);
    setScanStatus('scanning');

    if (!user) {
      setScanStatus('error');
      setErrorMessage('You must be logged in to scan URLs.');
      return;
    }

    try {
      console.log('[UrlScanPage] Calling API /api/scan/url with input:', { url: urlToScan });

      const response = await fetch('/api/scan/url', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: urlToScan }),
      });

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({ error: 'Failed to parse error response from server.'}));
        throw new Error(errorData.error || `Server error: ${response.status}`);
      }
      
      const result: ScanUrlOutput = await response.json();
      console.log('[UrlScanPage] Received result from API:', result.status, result.threatLabel);
      
      setScanResult(result);

      if (result.status === 'error' || result.error) {
        setScanStatus('error');
        setErrorMessage(result.error || 'An unexpected error occurred during the scan.');
      } else {
        setScanStatus('completed');
        // Save the report from the client-side after scan completes
        await saveReport(result);
      }
    } catch (err: any) {
      console.error('[UrlScanPage] URL scan error:', err);
      setScanStatus('error');
      let detailedError = 'An unexpected error occurred during scan.';
      if (err.message) {
        detailedError = err.message;
      }
      setErrorMessage(detailedError);
      setScanResult(null);
    }
  };

  const handleDownloadDocxReport = async () => {
    if (scanResult && (scanResult.status === 'completed' || (scanResult.status !== 'error' && scanResult.analysisId)) && !scanResult.error) {
      await generateScanReportDocx(scanResult, 'url');
    } else {
      toast({ title: "Cannot Download Report", description: "Report can only be downloaded for successfully processed scans.", variant: "destructive" });
    }
  };
  
  const handleDownloadPdfReport = async () => {
    if (scanResult && (scanResult.status === 'completed' || (scanResult.status !== 'error' && scanResult.analysisId)) && !scanResult.error) {
      await generateScanReportPdf(scanResult, 'url');
    } else {
      toast({ title: "Cannot Download Report", description: "Report can only be downloaded for successfully processed scans.", variant: "destructive" });
    }
  };
  
  const getThreatBadgeVariant = (threatLabel?: string) => {
    switch (threatLabel?.toLowerCase()) {
      case 'critical':
      case 'high':
        return 'destructive';
      case 'medium':
        return 'secondary';
      case 'low':
      case 'clean':
        return 'default'; 
      default:
        return 'outline';
    }
  };

  const getThreatIcon = (threatLabel?: string) => {
    switch (threatLabel?.toLowerCase()) {
      case 'critical':
      case 'high':
        return <AlertTriangle className="h-5 w-5 mr-1 text-destructive" />;
      case 'medium':
        return <Info className="h-5 w-5 mr-1 text-yellow-400" />; 
      case 'low':
      case 'clean':
        return <CheckCircle className="h-5 w-5 mr-1 text-green-400" />; 
      default:
        return <ShieldCheck className="h-5 w-5 mr-1 text-muted-foreground" />;
    }
  };


  return (
    <AppShell>
      <div className="flex flex-col gap-6 md:gap-8">
        <header>
          <h1 className="text-2xl sm:text-3xl font-bold tracking-tight text-primary">URL Threat Analysis</h1>
          <p className="text-muted-foreground mt-1 text-sm sm:text-base">
            Enter a URL for analysis.
          </p>
        </header>

        <Card className="shadow-xl border-primary/20 card-hover-effect-primary">
          <CardHeader>
            <CardTitle className="text-lg sm:text-xl flex items-center gap-2">
              <Globe className="h-5 w-5 sm:h-6 sm:w-6 text-primary" /> URL Analysis Input
            </CardTitle>
            <CardDescription className="text-xs sm:text-sm">Provide the full URL (e.g., https://example.com) for analysis.</CardDescription>
          </CardHeader>
          <CardContent>
            <UrlScannerForm onSubmit={handleUrlSubmit} isScanning={scanStatus === 'scanning'} />
          </CardContent>
        </Card>

        {scanStatus === 'scanning' && scannedUrl && (
          <Card className="shadow-lg border-accent/20 card-hover-effect-accent">
            <CardHeader>
              <CardTitle className="text-lg sm:text-xl text-accent">Scan In Progress</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="flex flex-col items-center justify-center py-8 sm:py-10 text-center px-2">
                <Loader2 className="h-10 w-10 sm:h-12 sm:w-12 animate-spin text-primary mb-4" />
                <p className="text-base sm:text-lg font-semibold">Scanning URL: <span className="text-accent break-all">{scannedUrl}</span></p>
                <p className="text-muted-foreground text-sm sm:text-base mt-2">Cross-referencing security databases... This may take a moment.</p>
                 <div className="w-full bg-muted rounded-full h-2.5 mt-4 overflow-hidden">
                  <div className="bg-primary h-2.5 rounded-full animate-pulse" style={{ width: '60%' }}></div>
                </div>
              </div>
            </CardContent>
          </Card>
        )}

        {scanStatus === 'completed' && scanResult && !scanResult.error && (
          <Card className="shadow-lg border-green-500/30 card-hover-effect-primary">
            <CardHeader>
               <div className="flex flex-col sm:flex-row sm:justify-between sm:items-start gap-2">
                <CardTitle className="text-lg sm:text-xl text-green-400">Scan Complete</CardTitle>
                 {scanResult.threatLabel && (
                   <Badge variant={getThreatBadgeVariant(scanResult.threatLabel)} className="text-xs sm:text-sm flex items-center w-fit">
                      {getThreatIcon(scanResult.threatLabel)}
                     <span>{scanResult.threatLabel}</span>
                   </Badge>
                 )}
              </div>
              <CardDescription className="text-xs sm:text-sm break-all">Analysis for: <span className="font-semibold text-foreground">{scanResult.submittedUrl}</span></CardDescription>
            </CardHeader>
            <CardContent className="space-y-3 sm:space-y-4">
              {scanResult.stats ? (
                <p className="text-sm sm:text-base"><strong className="text-primary">Detections:</strong> {scanResult.stats.malicious} malicious / {scanResult.stats.harmless + scanResult.stats.malicious + scanResult.stats.suspicious + scanResult.stats.timeout + scanResult.stats.undetected} total vendors</p>
              ) : (
                <p className="text-sm sm:text-base text-muted-foreground">Detection statistics not available from VirusTotal</p>
              )}
              {scanResult.scanDate && ( 
                <p className="text-sm sm:text-base"><strong className="text-primary">Scan Date:</strong> {new Date(scanResult.scanDate * 1000).toLocaleString()}</p>
              )}
              <div className="flex flex-wrap gap-2 mt-4">
                <DropdownMenu>
                    <DropdownMenuTrigger asChild>
                        <Button className="btn-glow w-full sm:w-auto text-sm sm:text-base" variant="default" disabled={!scanResult || (scanResult.status !== 'completed' && !scanResult.analysisId) || !!scanResult.error}>
                            <FileDown className="mr-2 h-4 w-4" /> Download Report
                        </Button>
                    </DropdownMenuTrigger>
                    <DropdownMenuContent>
                        <DropdownMenuItem onClick={handleDownloadDocxReport}>
                            <FileText className="mr-2 h-4 w-4" />
                            <span>Download as DOCX</span>
                        </DropdownMenuItem>
                        <DropdownMenuItem onClick={handleDownloadPdfReport}>
                            <FileType className="mr-2 h-4 w-4" />
                            <span>Download as PDF</span>
                        </DropdownMenuItem>
                    </DropdownMenuContent>
                </DropdownMenu>
              </div>
            </CardContent>
          </Card>
        )}
        
        {scanResult && (scanResult.status === 'queued' || scanResult.status === 'inprogress') && !scanResult.error && (
           <Card className="shadow-lg border-yellow-500/30 card-hover-effect-accent">
            <CardHeader>
                <CardTitle className="text-xl text-yellow-400 flex items-center gap-2"><Info className="h-6 w-6" />Scan Status: {scanResult.status}</CardTitle>
                <CardDescription>URL: <span className="font-semibold text-foreground break-all">{scannedUrl}</span></CardDescription>
            </CardHeader>
            <CardContent>
                <p className="text-muted-foreground">Security services are still processing the URL. Results will be updated. You can check the permalink for live status.</p>
                {scanResult.error && <p className="text-destructive text-sm mt-1">{scanResult.error}</p>}
            </CardContent>
           </Card>
        )}

        {(scanStatus === 'error' || (scanResult && scanResult.error)) && (
          <Card className="shadow-lg border-destructive/30 card-hover-effect">
            <CardHeader>
              <CardTitle className="text-xl text-destructive flex items-center gap-2">
                <AlertTriangle className="h-6 w-6" /> URL Scan Failed
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="flex flex-col items-center justify-center py-10 text-center text-destructive">
                <p className="text-lg font-semibold">Error Analyzing URL: <span className="break-all">{scannedUrl}</span></p>
                <p className="mt-2 max-w-md break-words">{errorMessage || scanResult?.error || 'Could not analyze the URL. It might be offline, invalid, or an API issue occurred.'}</p>
                <Button onClick={() => { setScanStatus('idle'); setScannedUrl(null); setScanResult(null); setErrorMessage(null); }} variant="outline" className="mt-6">
                    Try Another URL
                </Button>
              </div>
            </CardContent>
          </Card>
        )}

        {scanStatus === 'idle' && !errorMessage && (
             <Alert variant="default" className="mt-4">
                <AlertIcon className="h-4 w-4" />
                <AlertTitle>Ready to Scan</AlertTitle>
                <AlertDescription>
                     Enter a URL using the form above to begin your security analysis.
                </AlertDescription>
            </Alert>
        )}
      </div>
    </AppShell>
  );
}
