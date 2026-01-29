
import { NextResponse, type NextRequest } from 'next/server';
import { scanUrl, type ScanUrlInput, type ScanUrlOutput } from '@/ai/flows/scan-url-flow';

export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    // The userId is no longer needed here, as the flow doesn't save to the DB.
    const { url } = body; 

    if (!url || typeof url !== 'string') {
      return NextResponse.json({ error: 'URL is required and must be a string.' }, { status: 400 });
    }

    // The input for the flow no longer contains userId.
    const scanInput: ScanUrlInput = { url };

    console.log('[API /api/scan/url] Received URL for scan:', url);
    // Call the Genkit flow
    const result: ScanUrlOutput = await scanUrl(scanInput);
    console.log('[API /api/scan/url] Scan result:', result.status, result.threatLabel);

    if (result.status === 'error' || result.error) {
      // It's better to return a 502 (Bad Gateway) if the downstream service (VT) fails.
      return NextResponse.json({ error: result.error || 'Scan failed with an unspecified error from the flow.' }, { status: 502 });
    }

    // Return the full result to the client. The client is now responsible for saving it.
    return NextResponse.json(result, { status: 200 });
    
  } catch (error: any) {
    console.error('[API /api/scan/url] Error processing request:', error);
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
    message: 'This endpoint expects a POST request with a URL to scan.' 
  }, { status: 405 });
}
