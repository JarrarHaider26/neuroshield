'use server';
/**
 * @fileOverview A flow for scanning files using NeuroShield AI malware detection model.
 * This flow is responsible ONLY for the malware scan and does NOT save to the database.
 *
 * - scanFile - Submits a file for analysis and retrieves the NeuroShield model report.
 * - ScanFileInput - The input type for the scanFile function.
 * - ScanFileOutput - The return type for the scanFile function.
 */

import { ai } from '@/ai/genkit';
import { z } from 'genkit';

// NOTE: Firestore logic has been removed from this flow.
// The client is now responsible for saving the report to the database.

const FileInfoSchema = z.object({
  name: z.string().optional().describe("Original name of the scanned file."),
  size: z.number().optional().describe("Size of the file in bytes."),
  md5: z.string().optional().describe("MD5 hash of the file."),
  sha1: z.string().optional().describe("SHA1 hash of the file."),
  sha256: z.string().optional().describe("SHA256 hash of the file."),
});

const ScanFileInputSchema = z.object({
  fileDataUri: z
    .string()
    .describe(
      "The file content as a data URI. Expected format: 'data:<mimetype>;base64,<encoded_data>'."
    ),
  fileName: z.string().describe('The original name of the file.'),
  // userId is no longer needed here as the flow doesn't save to DB.
});
export type ScanFileInput = z.infer<typeof ScanFileInputSchema>;

const ScanFileOutputSchema = z.object({
  analysisId: z.string().describe("The NeuroShield analysis ID."),
  status: z.string().describe("Status of the scan (e.g., 'completed', 'error')."),
  scanDate: z.number().optional().describe("Unix timestamp of when the scan was completed."),
  stats: z.object({
    harmless: z.number().default(0),
    malicious: z.number().default(0),
    suspicious: z.number().default(0),
    timeout: z.number().default(0),
    undetected: z.number().default(0),
  }).optional().describe("Summary statistics of the NeuroShield scan results."),
  results: z.record(z.string(), z.object({
    category: z.string(),
    result: z.string().nullable(),
    method: z.string(),
    engine_name: z.string(),
  })).optional().describe("Detailed results from NeuroShield AI model."),
  fileInfo: FileInfoSchema.optional().describe("Information about the scanned file, including hashes."),
  threatLabel: z.string().optional().describe("A human-readable threat label (Critical, High, Medium, Low, Clean)."),
  permalink: z.string().optional().describe("Link to the full scan report data."),
  error: z.string().optional().describe("Error message if the scan process failed."),
});
export type ScanFileOutput = z.infer<typeof ScanFileOutputSchema>;

function dataUriToBuffer(dataUri: string): { buffer: Buffer; fileNamePart: string } {
  const parts = dataUri.split(',');
  const meta = parts[0];
  const data = parts[1];
  const nameMatch = meta.match(/name=(.*?);/); 
  const fileNamePart = nameMatch ? decodeURIComponent(nameMatch[1]) : 'uploaded_file';
  const buffer = Buffer.from(data, 'base64');
  return { buffer, fileNamePart };
}

export async function scanFile(input: ScanFileInput): Promise<ScanFileOutput> {
  return scanFileFlow(input);
}

// NeuroShield Model Integration
async function scanWithEmberModel(buffer: Buffer, fileName: string): Promise<Partial<ScanFileOutput>> {
  try {
    console.log('[scanFileFlow] Scanning with NeuroShield model:', fileName);
    console.log('[scanFileFlow] Buffer size:', buffer.length, 'bytes');
    
    // Create form data for EMBER API
    const formData = new FormData();
    // Convert Buffer to Uint8Array for Blob compatibility
    const uint8Array = new Uint8Array(buffer);
    formData.append('file', new Blob([uint8Array]), fileName);
    
    // Get EMBER API URL from environment or use default
    const emberApiUrl = process.env.EMBER_API_URL || 'http://127.0.0.1:5000';
    console.log('[scanFileFlow] Calling EMBER API at', emberApiUrl + '/scan');
    const startTime = Date.now();
    
    // Call EMBER malware scanner API (running on localhost:5000)
    const emberResponse = await fetch(emberApiUrl + '/scan', {
      method: 'POST',
      body: formData,
    });
    
    const fetchTime = Date.now() - startTime;
    console.log('[scanFileFlow] EMBER API responded in', fetchTime, 'ms');
    
    if (!emberResponse.ok) {
      const errorText = await emberResponse.text();
      console.error('[scanFileFlow] EMBER API error response:', errorText);
      throw new Error(`EMBER API error: ${emberResponse.status} ${emberResponse.statusText} - ${errorText}`);
    }
    
    const emberResult = await emberResponse.json();
    console.log('[scanFileFlow] EMBER result:', emberResult);
    console.log('[scanFileFlow] Total scan time:', Date.now() - startTime, 'ms');
    
    if (emberResult.error) {
      throw new Error(`EMBER scan error: ${emberResult.error}`);
    }
    
    // Convert EMBER results to compatible format
    const isMalicious = emberResult.verdict === 'Malicious';
    const malwareProb = emberResult.malware_probability || 0;
    
    // Map threat severity to stats
    // Threshold: 7% - Critical: >50%, High: >35%, Medium: >20%, Low: >7% && <20%
    let maliciousCount = 0;
    let suspiciousCount = 0;
    let harmlessCount = 1;
    
    if (emberResult.threat_severity === 'Critical') {
      maliciousCount = 8;  // >50% probability
      harmlessCount = 0;
    } else if (emberResult.threat_severity === 'High') {
      maliciousCount = 5;  // >35% probability
      harmlessCount = 0;
    } else if (emberResult.threat_severity === 'Medium') {
      suspiciousCount = 3;  // >20% probability
      harmlessCount = 0;
    } else if (emberResult.threat_severity === 'Low') {
      suspiciousCount = 1;  // >7% && <20% probability
      harmlessCount = 0;
    }
    
    return {
      analysisId: `ember_${Date.now()}`,
      status: 'completed',
      scanDate: Math.floor(Date.now() / 1000),
      stats: {
        harmless: harmlessCount,
        malicious: maliciousCount,
        suspicious: suspiciousCount,
        timeout: 0,
        undetected: 0,
      },
      results: {
        'NeuroShield_AI_Model': {
          category: isMalicious ? 'malicious' : 'undetected',
          result: isMalicious 
            ? `${emberResult.threat_severity} (${(malwareProb * 100).toFixed(1)}%)` 
            : `Clean (${((1 - malwareProb) * 100).toFixed(1)}%)`,
          method: 'machine_learning',
          engine_name: 'NeuroShield_Analysis_Engine',
        }
      },
      fileInfo: {
        name: fileName,
        size: emberResult.file_size,
        sha256: emberResult.file_hash,
      },
      threatLabel: emberResult.threat_severity === 'None' ? 'Clean' : emberResult.threat_severity,
      permalink: `data:application/json;base64,${Buffer.from(JSON.stringify(emberResult)).toString('base64')}`,
    };
    
  } catch (error: unknown) {
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    console.error('[scanFileFlow] EMBER scan error:', error);
    throw new Error(`EMBER model scan failed: ${errorMessage}`);
  }
}

const scanFileFlow = ai.defineFlow(
  {
    name: 'scanFileFlow',
    inputSchema: ScanFileInputSchema,
    outputSchema: ScanFileOutputSchema,
  },
  async (input: ScanFileInput): Promise<ScanFileOutput> => {
    let scanOutput: ScanFileOutput = { 
        analysisId: '', 
        status: 'error', 
        error: 'Scan not initiated.',
        fileInfo: { name: input.fileName }
    };

    console.log('[scanFileFlow] Received input:', { fileName: input.fileName });

    // Use EMBER model instead of VirusTotal
    try {
      const { buffer } = dataUriToBuffer(input.fileDataUri);

      const MAX_FILE_SIZE_BYTES = 100 * 1024 * 1024; // 100MB for EMBER model
      if (buffer.length > MAX_FILE_SIZE_BYTES) {
        const fileSizeError = `File size (${(buffer.length / (1024*1024)).toFixed(2)}MB) exceeds EMBER model limit of 100MB.`;
        console.error('[scanFileFlow]', fileSizeError);
        return { ...scanOutput, status: 'error', error: fileSizeError, fileInfo: { name: input.fileName, size: buffer.length } };
      }

      // Validate file type (PE files only)
      const allowedExtensions = ['.exe', '.dll', '.sys', '.scr', '.com'];
      const fileExtension = input.fileName.toLowerCase().substring(input.fileName.lastIndexOf('.'));
      if (!allowedExtensions.includes(fileExtension)) {
        const fileTypeError = `File type ${fileExtension} not supported. Only PE files (.exe, .dll, .sys, .scr, .com) are supported.`;
        console.error('[scanFileFlow]', fileTypeError);
        return { ...scanOutput, status: 'error', error: fileTypeError, fileInfo: { name: input.fileName, size: buffer.length } };
      }

      // Scan with EMBER model
      const emberResult = await scanWithEmberModel(buffer, input.fileName);
      // Completely replace scanOutput with emberResult to avoid keeping initial error state
      scanOutput = emberResult as ScanFileOutput;
      
      console.log('[scanFileFlow] EMBER scan completed successfully.');
      console.log('[scanFileFlow] Scan status:', scanOutput.status);
      
    } catch (error: unknown) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      console.error('[scanFileFlow] EMBER scan failed:', error);
      
      // Provide helpful error message if Python API is not running
      let userFriendlyError = errorMessage;
      if (errorMessage.includes('fetch failed') || errorMessage.includes('ECONNREFUSED') || errorMessage.includes('Failed to fetch')) {
        userFriendlyError = 'Cannot connect to EMBER scanner API. Please ensure the Python API is running: python web_scanner.py';
      }
      
      scanOutput = { 
        ...scanOutput, 
        status: 'error', 
        error: userFriendlyError
      };
    }

    if (!scanOutput.status) {
        console.error('[scanFileFlow] ScanOutput status was not properly set. Defaulting to error.');
        scanOutput.status = 'error';
        scanOutput.error = scanOutput.error || 'An unexpected error occurred setting scan output status.';
    }
    if (!scanOutput.analysisId) {
        scanOutput.analysisId = '';
    }

    console.log('[scanFileFlow] EMBER scan flow finished, returning scan output to be handled by client.');
    console.log('[scanFileFlow] Final scanOutput:', JSON.stringify(scanOutput, null, 2));
    return scanOutput;
  }
);
