'use client';

import { AppShell } from '@/components/layout/AppShell';
import { FileUploader } from '@/components/scan/FileUploader';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { AlertTriangle, CheckCircle, Download, Loader2, ShieldCheck, Info, FileDown, AlertCircle as AlertIcon, FileText, FileType } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { useState, useCallback } from 'react';
import type { ScanFileOutput } from '@/ai/flows/scan-file-flow';
import { Badge } from '@/components/ui/badge';
import { generateScanReportDocx, generateScanReportPdf } from '@/lib/report-generator';
import { useAuthContext } from '@/contexts/AuthContext';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { useToast } from '@/hooks/use-toast';
import { db } from '@/lib/firebase';
import { collection, addDoc, serverTimestamp } from 'firebase/firestore';
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from '@/components/ui/dropdown-menu';

type ScanStatus = 'idle' | 'uploading' | 'scanning' | 'completed' | 'error';

export default function FileScanPage() {
  const { user } = useAuthContext();
  const { toast } = useToast();
  const [scanStatus, setScanStatus] = useState<ScanStatus>('idle');
  const [scanResult, setScanResult] = useState<ScanFileOutput | null>(null);
  const [uploadedFile, setUploadedFile] = useState<File | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const saveReport = useCallback(async (result: ScanFileOutput, file: File) => {
    if (!user || !db) {
      console.warn('[FileScanPage] User not logged in or DB not available. Skipping report save.');
      return;
    }
    if (result.status === 'error' || result.error) {
      console.log('[FileScanPage] Scan resulted in an error. Skipping report save.');
      return;
    }

    try {
      const reportToSave = {
        userId: user.uid,
        scanType: 'file' as const,
        targetIdentifier: file.name,
        scanDate: result.scanDate || Math.floor(Date.now() / 1000),
        status: result.status,
        threatLabel: result.threatLabel || 'N/A',
        analysisId: result.analysisId,
        permalink: result.permalink,
        reportData: { ...result },
        createdAt: serverTimestamp(),
      };
      await addDoc(collection(db, "scanReports"), reportToSave);
      console.log("[FileScanPage] File scan report successfully saved to Firestore by client.");
      toast({ title: "Report Saved", description: "The scan report has been saved to your Report Center." });
    } catch (firestoreError: any) {
      console.error("[FileScanPage] Error saving file scan report to Firestore:", firestoreError);
      toast({ title: "Save Failed", description: `Could not save the report to your Report Center: ${firestoreError.message}`, variant: "destructive" });
    }
  }, [user, toast]);

  const handleFileUpload = async (file: File) => {
    setUploadedFile(file);
    setScanResult(null);
    setErrorMessage(null);

    if (!user) {
      setScanStatus('error');
      setErrorMessage('You must be logged in to scan files.');
      return;
    }

    try {
      console.log('[FileScanPage] Starting file upload process for:', file.name, `(${(file.size / 1024 / 1024).toFixed(2)} MB)`);
      const startTime = Date.now();
      
      const reader = new FileReader();
      reader.readAsDataURL(file);
      reader.onload = async () => {
        const fileDataUri = reader.result as string;
        const readTime = Date.now() - startTime;
        console.log('[FileScanPage] File read completed in', readTime, 'ms');
        console.log('[FileScanPage] Base64 data size:', fileDataUri.length, 'chars');
        
        setScanStatus('scanning');
        
        console.log('[FileScanPage] Calling API /api/scan/file with input:', {fileName: file.name});
        const apiStartTime = Date.now();

        const response = await fetch('/api/scan/file', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ fileDataUri, fileName: file.name }),
        });
        
        const apiTime = Date.now() - apiStartTime;
        console.log('[FileScanPage] API response received in', apiTime, 'ms');

        const result: ScanFileOutput = await response.json();
        const totalTime = Date.now() - startTime;
        console.log('[FileScanPage] Received result from API:', result.status, result.threatLabel);
        console.log('[FileScanPage] Total scan time:', totalTime, 'ms');

        setScanResult(result);

        // Check if scan had an error
        if (!response.ok || result.status === 'error' || result.error) {
          setScanStatus('error');
          const errorMsg = result.error || 'An unexpected error occurred during the scan.';
          setErrorMessage(errorMsg);
          
          // Check if it's a connection error to Python API
          if (errorMsg.includes('fetch') || errorMsg.includes('NeuroShield API') || errorMsg.includes('localhost:5000')) {
            setErrorMessage('Cannot connect to NeuroShield scanner. Please ensure the Python API is running on port 5000. Run: python web_scanner.py');
          }
        } else {
          setScanStatus('completed');
          // Save the report from the client-side after scan completes
          await saveReport(result, file);
        }
      };
      reader.onerror = (error) => {
        console.error('[FileScanPage] Error reading file:', error);
        setScanStatus('error');
        setErrorMessage('Failed to read file for upload.');
      };
    } catch (err: any) {
      console.error('[FileScanPage] File scan error:', err);
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
      await generateScanReportDocx(scanResult, 'file');
    } else {
      toast({ title: "Cannot Download Report", description: "Report can only be downloaded for successfully processed scans.", variant: "destructive" });
    }
  };
  
  const handleDownloadPdfReport = async () => {
    if (scanResult && (scanResult.status === 'completed' || (scanResult.status !== 'error' && scanResult.analysisId)) && !scanResult.error) {
      await generateScanReportPdf(scanResult, 'file');
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
        return <AlertTriangle className="h-6 w-6 text-destructive" />;
      case 'medium':
        return <Info className="h-6 w-6 text-yellow-500" />;
      case 'low':
      case 'clean':
        return <CheckCircle className="h-6 w-6 text-green-500" />;
      default:
        return <ShieldCheck className="h-6 w-6 text-muted-foreground" />;
    }
  };


  return (
    <AppShell>
      <div className="flex flex-col gap-6 md:gap-8">
        <header>
          <h1 className="text-2xl sm:text-3xl font-bold tracking-tight text-primary">File Threat Analysis</h1>
          <p className="text-muted-foreground mt-1 text-sm sm:text-base">
            Upload files for real-time malware scanning.
          </p>
        </header>

        <Card className="shadow-xl border-primary/20 card-hover-effect-primary">
          <CardHeader>
            <CardTitle className="text-lg sm:text-xl flex items-center gap-2">
              <ShieldCheck className="h-5 w-5 sm:h-6 sm:w-6 text-primary" /> Secure File Upload
            </CardTitle>
            <CardDescription className="text-xs sm:text-sm">Drag & drop your file or click to browse. Max file size: 32MB.</CardDescription>
          </CardHeader>
          <CardContent>
            <FileUploader onFileUpload={handleFileUpload} />
          </CardContent>
        </Card>

        {(scanStatus === 'uploading' || scanStatus === 'scanning') && uploadedFile && (
          <Card className="shadow-lg border-accent/20 card-hover-effect-accent">
            <CardHeader>
              <CardTitle className="text-lg sm:text-xl text-accent">Scan In Progress</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="flex flex-col items-center justify-center py-8 sm:py-10 text-center px-2">
                <Loader2 className="h-10 w-10 sm:h-12 sm:w-12 animate-spin text-primary mb-4" />
                <p className="text-base sm:text-lg font-semibold break-words max-w-full">
                  {scanStatus === 'uploading' ? 'Preparing file...' : `Analyzing file: ${uploadedFile.name}`}
                </p>
                <p className="text-muted-foreground text-sm sm:text-base mt-2">
                  {scanStatus === 'uploading' ? 'Encrypting and transmitting...' : 'Communicating with security services... This may take a few minutes.'}
                </p>
                <div className="w-full bg-muted rounded-full h-2.5 mt-4 overflow-hidden">
                  <div className="bg-primary h-2.5 rounded-full animate-pulse" style={{ width: scanStatus === 'uploading' ? '25%' : '65%' }}></div>
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
                   <Badge variant={getThreatBadgeVariant(scanResult.threatLabel)} className="text-xs sm:text-sm w-fit">
                     {getThreatIcon(scanResult.threatLabel)}
                     <span className="ml-2">{scanResult.threatLabel}</span>
                   </Badge>
                )}
              </div>
              <CardDescription className="text-xs sm:text-sm break-words">Analysis for: <span className="font-semibold text-foreground">{scanResult.fileInfo?.name || uploadedFile?.name}</span></CardDescription>
            </CardHeader>
            <CardContent className="space-y-3 sm:space-y-4">
              {scanResult.results?.['NeuroShield_AI_Model'] && (() => {
                const emberResult = scanResult.results['NeuroShield_AI_Model'];
                const resultText = emberResult.result || 'N/A';
                // Remove percentage from verdict text
                const verdictWithoutPercentage = resultText.replace(/\s*\(\d+\.?\d*%\)/, '');
                
                return (
                  <div className="text-sm sm:text-base mb-4 p-3 bg-primary/5 rounded-lg border border-primary/20">
                    <strong className="text-primary">NeuroShield AI Analysis:</strong>
                    <div className="mt-2 space-y-1 text-xs sm:text-sm">
                      <p><strong>Verdict:</strong> {verdictWithoutPercentage}</p>
                      <p><strong>Detection Method:</strong> {emberResult.method === 'machine_learning' ? 'Machine Learning' : emberResult.method}</p>
                      <p><strong>Engine:</strong> {emberResult.engine_name}</p>
                    </div>
                  </div>
                );
              })()}
              <div className="text-sm sm:text-base">
                <strong className="text-primary">Detection Summary:</strong>
                <div className="mt-2 space-y-1 text-xs sm:text-sm">
                  {scanResult.stats && (
                    <>
                      {scanResult.stats.malicious > 0 && (
                        <p className="text-red-500">• Malicious</p>
                      )}
                      {scanResult.stats.suspicious > 0 && (
                        <p className="text-yellow-500">• Suspicious</p>
                      )}
                      {scanResult.stats.harmless > 0 && (
                        <p className="text-green-500">• Harmless</p>
                      )}
                      {scanResult.stats.undetected > 0 && (
                        <p className="text-gray-500">• Undetected</p>
                      )}
                    </>
                  )}
                </div>
              </div>
               {scanResult.scanDate && (
                <p className="text-sm sm:text-base"><strong className="text-primary">Scan Date:</strong> {new Date(scanResult.scanDate * 1000).toLocaleString()}</p>
              )}
              {scanResult.fileInfo && (
                <div>
                  <h3 className="font-semibold text-primary mb-1 text-sm sm:text-base">File Hashes:</h3>
                  <ul className="list-disc list-inside text-xs sm:text-sm space-y-1 text-muted-foreground pl-2 break-all">
                    {scanResult.fileInfo.md5 && <li><strong>MD5:</strong> {scanResult.fileInfo.md5}</li>}
                    {scanResult.fileInfo.sha1 && <li><strong>SHA1:</strong> {scanResult.fileInfo.sha1}</li>}
                    {scanResult.fileInfo.sha256 && <li><strong>SHA256:</strong> {scanResult.fileInfo.sha256}</li>}
                  </ul>
                </div>
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
                <CardDescription>File: <span className="font-semibold text-foreground">{uploadedFile?.name}</span></CardDescription>
            </CardHeader>
            <CardContent>
                <p className="text-muted-foreground">Security services are still processing the file. Results will be updated. You can check the permalink for live status.</p>
                {scanResult.error && <p className="text-destructive text-sm mt-1">{scanResult.error}</p>}
            </CardContent>
           </Card>
        )}

        {(scanStatus === 'error' || (scanResult && scanResult.error)) && (
          <Card className="shadow-lg border-destructive/30 card-hover-effect">
            <CardHeader>
              <CardTitle className="text-xl text-destructive flex items-center gap-2">
                <AlertTriangle className="h-6 w-6" /> Scan Failed
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="flex flex-col items-center justify-center py-10 text-center text-destructive">
                <p className="text-lg font-semibold">Error Analyzing File: {uploadedFile?.name || "N/A"}</p>
                <p className="mt-2 max-w-md break-words">{errorMessage || scanResult?.error || 'An unexpected error occurred. Please check the console or try again.'}</p>
                 <Button onClick={() => { setScanStatus('idle'); setUploadedFile(null); setScanResult(null); setErrorMessage(null); }} variant="outline" className="mt-6">
                    Try Another File
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
                    Upload a file using the form above to begin your security analysis.
                </AlertDescription>
            </Alert>
        )}
      </div>
    </AppShell>
  );
}
