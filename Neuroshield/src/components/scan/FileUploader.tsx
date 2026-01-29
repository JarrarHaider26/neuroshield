
'use client';

import { useState, useCallback } from 'react';
import { useDropzone } from 'react-dropzone';
import { UploadCloud, FileText, XCircle, Loader2 } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Progress } from "@/components/ui/progress";

interface FileUploaderProps {
  onFileUpload: (file: File) => void;
  maxSize?: number; // in bytes
  accept?: Record<string, string[]>; // e.g. { 'application/pdf': ['.pdf'] }
}

export function FileUploader({ 
  onFileUpload, 
  maxSize = 100 * 1024 * 1024, // 100MB for NeuroShield model
  accept = { 
    'application/vnd.microsoft.portable-executable': ['.exe', '.dll', '.sys', '.scr', '.com'],
    'application/x-msdownload': ['.exe', '.dll', '.sys', '.scr', '.com'],
    'application/octet-stream': ['.exe', '.dll', '.sys', '.scr', '.com'],
   }
}: FileUploaderProps) {
  const [file, setFile] = useState<File | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [isProcessingClientSide, setIsProcessingClientSide] = useState<boolean>(false);


  const onDrop = useCallback((acceptedFiles: File[], fileRejections: any[]) => {
    setError(null);
    setFile(null);
    setIsProcessingClientSide(false);

    if (fileRejections.length > 0) {
      const firstRejection = fileRejections[0];
      if (firstRejection.errors[0].code === 'file-too-large') {
        setError(`File is too large. Max size is ${maxSize / (1024*1024)}MB.`);
      } else if (firstRejection.errors[0].code === 'file-invalid-type') {
        setError('Invalid file type. Please upload supported file types.');
      } else {
        setError(firstRejection.errors[0].message);
      }
      return;
    }

    if (acceptedFiles.length > 0) {
      setFile(acceptedFiles[0]);
    }
  }, [maxSize, accept]); // Added 'accept' to dependency array

  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    onDrop,
    maxSize,
    accept, 
    multiple: false,
  });

  const handleScan = async () => {
    if (!file) return;
    setIsProcessingClientSide(true);
    setError(null);

    // Simulate a very quick client-side processing/preparation step
    // then immediately hand off to the parent for the actual backend scan.
    setTimeout(() => {
      onFileUpload(file);
      // The FileUploader's job is done here. 
      // The parent FileScanPage will handle the "scanning" state.
      // We can reset the uploader if desired, or let the parent manage its lifecycle.
      // For now, let's keep 'file' selected to show what was submitted.
      setIsProcessingClientSide(false); 
    }, 300); // Short delay for visual feedback
  };

  const removeFile = () => {
    setFile(null);
    setError(null);
    setIsProcessingClientSide(false);
  };

  return (
    <div className="w-full space-y-4">
      <div
        {...getRootProps()}
        className={`p-8 border-2 border-dashed rounded-lg cursor-pointer transition-colors
                    ${isDragActive ? 'border-primary bg-primary/10' : 'border-border hover:border-primary/70'}
                    ${error ? 'border-destructive' : ''}
                    text-center flex flex-col items-center justify-center min-h-[200px]`}
      >
        <input {...getInputProps()} />
        <UploadCloud className={`h-16 w-16 mb-4 ${isDragActive ? 'text-primary' : 'text-muted-foreground'}`} />
        {isDragActive ? (
          <p className="text-primary font-semibold">Drop the file here ...</p>
        ) : (
          <p className="text-muted-foreground">Drag 'n' drop a file here, or click to select file</p>
        )}
        <p className="text-xs text-muted-foreground mt-2">
          Supported: .exe, .dll, .sys, .scr, .com (Max {maxSize / (1024*1024)}MB)
        </p>
      </div>

      {error && (
        <div className="flex items-center p-3 rounded-md bg-destructive/10 text-destructive text-sm">
          <XCircle className="h-5 w-5 mr-2 shrink-0" />
          {error}
        </div>
      )}

      {file && !isProcessingClientSide && (
        <div className="p-4 border rounded-lg bg-card flex items-center justify-between">
          <div className="flex items-center gap-3">
            <FileText className="h-8 w-8 text-primary" />
            <div>
              <p className="font-semibold text-foreground truncate max-w-xs sm:max-w-sm md:max-w-md">{file.name}</p>
              <p className="text-xs text-muted-foreground">{(file.size / (1024)).toFixed(2)} KB</p>
            </div>
          </div>
          <Button variant="ghost" size="icon" onClick={removeFile} aria-label="Remove file" disabled={isProcessingClientSide}>
            <XCircle className="h-5 w-5 text-muted-foreground hover:text-destructive" />
          </Button>
        </div>
      )}
      
      {isProcessingClientSide && file && (
        <div className="p-4 border rounded-lg bg-card space-y-2">
            <div className="flex items-center gap-3">
                <Loader2 className="h-8 w-8 text-primary animate-spin" />
                <div>
                    <p className="font-semibold text-foreground">Preparing: {file.name}</p>
                    <p className="text-xs text-muted-foreground">{(file.size / (1024)).toFixed(2)} KB</p>
                </div>
            </div>
            <Progress value={100} className="h-2 [&>div]:bg-primary" />
            <p className="text-xs text-primary text-center">Processing...</p>
        </div>
      )}

      {file && !isProcessingClientSide && (
        <Button onClick={handleScan} className="w-full btn-glow" disabled={isProcessingClientSide}>
          {isProcessingClientSide ? 'Processing...' : 'Initiate Scan'}
        </Button>
      )}
    </div>
  );
}
