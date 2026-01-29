
import { NextResponse, type NextRequest } from 'next/server';
import { scanFile, type ScanFileInput, type ScanFileOutput } from '@/ai/flows/scan-file-flow';

// Increase timeout for large file processing (5 minutes)
export const maxDuration = 300;

export async function POST(request: NextRequest) {
  try {
    console.log('[API /api/scan/file] Request received');
    const startTime = Date.now();
    
    const body = await request.json();
    console.log('[API /api/scan/file] Body parsed in', Date.now() - startTime, 'ms');
    
    // The userId is no longer needed here, as the flow doesn't save to the DB.
    const { fileDataUri, fileName } = body; 

    if (!fileDataUri || typeof fileDataUri !== 'string') {
      return NextResponse.json({ error: 'fileDataUri is required and must be a string.' }, { status: 400 });
    }
    if (!fileName || typeof fileName !== 'string') {
      return NextResponse.json({ error: 'fileName is required and must be a string.' }, { status: 400 });
    }
    
    // The input for the flow no longer contains userId.
    const scanInput: ScanFileInput = { fileDataUri, fileName };
    
    console.log('[API /api/scan/file] Received file for scan:', fileName);
    console.log('[API /api/scan/file] File data size:', fileDataUri.length, 'chars');
    
    // Call the Genkit flow
    const flowStartTime = Date.now();
    const result: ScanFileOutput = await scanFile(scanInput);
    console.log('[API /api/scan/file] Flow completed in', Date.now() - flowStartTime, 'ms');
    console.log('[API /api/scan/file] Scan result:', result.status, result.threatLabel);
    console.log('[API /api/scan/file] Total request time:', Date.now() - startTime, 'ms');
    
    if (result.status === 'error' || result.error) {
      // It's better to return a 502 (Bad Gateway) if the downstream service (VT) fails.
      return NextResponse.json({ error: result.error || 'Scan failed with an unspecified error from the flow.' }, { status: 502 });
    }

    // Return the full result to the client. The client is now responsible for saving it.
    return NextResponse.json(result, { status: 200 });

  } catch (error: any) {
    console.error('[API /api/scan/file] Error processing request:', error);
    let errorMessage = 'An unexpected error occurred.';
    if (error.message) {
      errorMessage = error.message;
    }
     if (error instanceof SyntaxError) { 
      errorMessage = 'Invalid JSON payload received.';
       return NextResponse.json({ error: errorMessage }, { status: 400 });
    }
    return NextResponse.json({ error: errorMessage }, { status: 500 });
  }
}

export async function GET() {
  return NextResponse.json({ 
    message: 'This endpoint expects a POST request with fileDataUri and fileName to scan.' 
  }, { status: 405 });
}
