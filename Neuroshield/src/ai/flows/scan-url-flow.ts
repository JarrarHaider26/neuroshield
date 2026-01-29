
'use server';
/**
 * @fileOverview A Genkit flow for scanning URLs using VirusTotal API.
 * This flow is responsible ONLY for the VirusTotal scan and does NOT save to the database.
 *
 * - scanUrl - Submits a URL for analysis and retrieves the VT report.
 * - ScanUrlInput - The input type for the scanUrl function.
 * - ScanUrlOutput - The return type for the scanUrl function.
 */

import { ai } from '@/ai/genkit';
import { z } from 'genkit';

// NOTE: Firestore logic has been removed from this flow.
// The client is now responsible for saving the report to the database.

const ScanUrlInputSchema = z.object({
  url: z.string().url().describe('The URL to be scanned.'),
  // userId is no longer needed here as the flow doesn't save to DB.
});
export type ScanUrlInput = z.infer<typeof ScanUrlInputSchema>;

const ScanUrlOutputSchema = z.object({
  analysisId: z.string().describe("The VirusTotal analysis ID."),
  status: z.string().describe("Status of the VirusTotal scan (e.g., 'queued', 'in-progress', 'completed', 'error')."),
  scanDate: z.number().optional().describe("Unix timestamp of when the VT scan was completed or last updated."),
  stats: z.object({
    harmless: z.number().default(0),
    malicious: z.number().default(0),
    suspicious: z.number().default(0),
    timeout: z.number().default(0),
    undetected: z.number().default(0),
  }).optional().describe("Summary statistics of the VirusTotal scan results."),
  results: z.record(z.string(), z.object({
    category: z.string(),
    result: z.string().nullable(),
    method: z.string(),
    engine_name: z.string(),
  })).optional().describe("Detailed results from each VirusTotal antivirus engine."),
  submittedUrl: z.string().url().describe("The URL that was submitted for scanning."),
  threatLabel: z.string().optional().describe("A human-readable threat label derived from VirusTotal scan statistics."),
  permalink: z.string().optional().describe("Permanent link to the full VirusTotal report for this URL analysis."),
  error: z.string().optional().describe("Error message if the VirusTotal scan process failed."),
});
export type ScanUrlOutput = z.infer<typeof ScanUrlOutputSchema>;

const VT_API_URL = 'https://www.virustotal.com/api/v3';
const POLLING_INTERVAL_VT = 10000; // 10 seconds for VT URL
const MAX_POLLS_VT = 6; // Max 1 minute for VT URL

function determineThreatLabel(vtStats?: ScanUrlOutput['stats']): string {
    if (vtStats?.malicious && vtStats.malicious > 5) return 'Critical';
    if (vtStats?.malicious && vtStats.malicious > 0) return 'High';
    if (vtStats?.suspicious && vtStats.suspicious > 0) return 'Medium';
    if (vtStats && vtStats.malicious === 0 && vtStats.suspicious === 0 && (vtStats.harmless > 0 || vtStats.undetected > 0)) return 'Clean';
    if (vtStats) return 'Low';
    return 'Unknown';
}

export async function scanUrl(input: ScanUrlInput): Promise<ScanUrlOutput> {
  return scanUrlFlow(input);
}

const scanUrlFlow = ai.defineFlow(
  {
    name: 'scanUrlFlow',
    inputSchema: ScanUrlInputSchema,
    outputSchema: ScanUrlOutputSchema,
  },
  async (input): Promise<ScanUrlOutput> => {
    const vtApiKey = process.env.VIRUSTOTAL_API_KEY;
    let scanOutput: ScanUrlOutput = { analysisId: '', submittedUrl: input.url, status: 'error', error: 'Scan not initiated.'};

    console.log('[scanUrlFlow] Received input:', { url: input.url });

    if (!vtApiKey) {
      console.error('[scanUrlFlow] VirusTotal API key is not configured.');
      scanOutput = { analysisId: '', submittedUrl: input.url, status: 'error', error: 'VirusTotal API key is not configured.' };
      return scanOutput;
    }
    
    let analysisId: string = '';
    try {
      const formData = new URLSearchParams();
      formData.append('url', input.url);

      console.log('[scanUrlFlow] Submitting URL to VirusTotal...');
      const submitResponse = await fetch(`${VT_API_URL}/urls`, {
        method: 'POST',
        headers: { 'x-apikey': vtApiKey, 'Content-Type': 'application/x-www-form-urlencoded' },
        body: formData.toString(),
      });
      if (!submitResponse.ok) {
          let errorDetail = `VirusTotal API Error (Submit URL): ${submitResponse.status} ${submitResponse.statusText}.`;
          try { 
              const errorData = await submitResponse.json(); 
              const specificError = errorData?.error?.message || JSON.stringify(errorData);
              errorDetail += ` Message: ${specificError.substring(0, 150)}`;
          } catch (e) { 
              try { 
                  const textError = await submitResponse.text(); 
                  errorDetail += ` Response: ${textError.substring(0,100)}`; 
              } catch (e2) {} 
          }
          console.error('[scanUrlFlow] VirusTotal URL Submit Error:', errorDetail);
          throw new Error(errorDetail);
      }
      
      const submitResult = await submitResponse.json();
      analysisId = submitResult?.data?.id;
      console.log('[scanUrlFlow] VirusTotal Analysis ID:', analysisId);

      if (!analysisId) {
        const errorMsg = 'Failed to get analysis ID from VirusTotal URL submission. Resp: ' + JSON.stringify(submitResult).substring(0,100);
        console.error('[scanUrlFlow]', errorMsg);
        throw new Error(errorMsg);
      }
      
      scanOutput.analysisId = analysisId;
      let pollAttempt = 0;
      let completed = false;
      let currentStatus = 'queued';
      let errorMsgFromPolling;

      console.log('[scanUrlFlow] Starting to poll VirusTotal for analysis results...');
      while (pollAttempt < MAX_POLLS_VT && !completed) {
        await new Promise(resolve => setTimeout(resolve, POLLING_INTERVAL_VT));
        console.log(`[scanUrlFlow] Polling attempt ${pollAttempt + 1}/${MAX_POLLS_VT}...`);
        
        let analysisResponse;
        try {
            analysisResponse = await fetch(`${VT_API_URL}/analyses/${analysisId}`, {
                headers: { 'x-apikey': vtApiKey },
            });
        } catch (fetchPollError: any) {
            console.error(`[scanUrlFlow] Network error during polling attempt ${pollAttempt + 1} for ${analysisId}:`, fetchPollError.message);
            if (pollAttempt === MAX_POLLS_VT - 1) {
                currentStatus = 'error';
                errorMsgFromPolling = `Network error during final VirusTotal analysis poll: ${fetchPollError.message}. Scan for ${analysisId} may be incomplete.`;
            }
            pollAttempt++;
            continue;
        }

        if (!analysisResponse.ok) {
            if (pollAttempt === MAX_POLLS_VT - 1) {
              let analysisErrorDetail = `VirusTotal API Error (URL Analysis - final attempt): ${analysisResponse.status} ${analysisResponse.statusText}.`;
              try { const errorData = await analysisResponse.json(); analysisErrorDetail += ` Message: ${errorData?.error?.message || JSON.stringify(errorData)}`; } catch (e) { try { const textError = await analysisResponse.text(); analysisErrorDetail += ` Response: ${textError.substring(0,100)}`; } catch (e2) {} }
              currentStatus = 'error';
              errorMsgFromPolling = analysisErrorDetail;
              console.error('[scanUrlFlow] VirusTotal URL Analysis Error (final attempt):', errorMsgFromPolling);
              break;
            }
            pollAttempt++;
            continue;
        }
        const analysisResult = await analysisResponse.json();
        const attributes = analysisResult?.data?.attributes;
        currentStatus = attributes?.status || 'error'; 
        console.log('[scanUrlFlow] Poll status:', currentStatus);

        if (!attributes) {
          errorMsgFromPolling = 'URL Scan failed: Unexpected VT analysis structure. Resp: ' + JSON.stringify(analysisResult).substring(0,100);
          console.error('[scanUrlFlow]', errorMsgFromPolling);
          completed = true;
        } else if (attributes.status === 'completed') {
          // Fetch the full URL report to get complete stats
          console.log('[scanUrlFlow] Analysis completed, fetching full URL report...');
          try {
            const urlId = Buffer.from(input.url).toString('base64').replace(/=/g, '');
            const urlReportResponse = await fetch(`${VT_API_URL}/urls/${urlId}`, {
              headers: { 'x-apikey': vtApiKey },
            });
            
            if (urlReportResponse.ok) {
              const urlReport = await urlReportResponse.json();
              const urlAttributes = urlReport?.data?.attributes;
              if (urlAttributes && urlAttributes.last_analysis_stats) {
                console.log('[scanUrlFlow] Got full URL report with stats:', urlAttributes.last_analysis_stats);
                scanOutput = {
                  analysisId,
                  submittedUrl: input.url,
                  status: 'completed',
                  scanDate: urlAttributes.last_analysis_date || attributes.date,
                  stats: urlAttributes.last_analysis_stats,
                  results: urlAttributes.last_analysis_results,
                  permalink: `https://www.virustotal.com/gui/url/${urlId}`,
                  threatLabel: determineThreatLabel(urlAttributes.last_analysis_stats),
                };
              } else {
                // Fallback to analysis attributes if URL report doesn't have stats
                scanOutput = {
                  analysisId,
                  submittedUrl: input.url,
                  status: attributes.status,
                  scanDate: attributes.date,
                  stats: attributes.stats,
                  results: attributes.results,
                  permalink: `https://www.virustotal.com/gui/url-analysis/${analysisId}`,
                  threatLabel: determineThreatLabel(attributes.stats),
                };
              }
            } else {
              // If URL report fetch fails, use analysis attributes
              console.warn('[scanUrlFlow] Could not fetch URL report, using analysis attributes');
              scanOutput = {
                analysisId,
                submittedUrl: input.url,
                status: attributes.status,
                scanDate: attributes.date,
                stats: attributes.stats,
                results: attributes.results,
                permalink: `https://www.virustotal.com/gui/url-analysis/${analysisId}`,
                threatLabel: determineThreatLabel(attributes.stats),
              };
            }
          } catch (reportError: any) {
            console.error('[scanUrlFlow] Error fetching URL report:', reportError.message);
            // Fallback to analysis attributes
            scanOutput = {
              analysisId,
              submittedUrl: input.url,
              status: attributes.status,
              scanDate: attributes.date,
              stats: attributes.stats,
              results: attributes.results,
              permalink: `https://www.virustotal.com/gui/url-analysis/${analysisId}`,
              threatLabel: determineThreatLabel(attributes.stats),
            };
          }
          completed = true;
          console.log('[scanUrlFlow] Scan completed successfully.');
        } else if (attributes.status === 'queued' || attributes.status === 'inprogress') {
          scanOutput.status = attributes.status;
          if (pollAttempt === MAX_POLLS_VT - 1) {
              errorMsgFromPolling = 'URL Scan timed out on VirusTotal.';
              console.warn('[scanUrlFlow] Scan timed out.');
              break;
          }
        } else {
          errorMsgFromPolling = `URL Scan ended with unexpected VT status: ${attributes.status}`;
          console.error('[scanUrlFlow] Unexpected scan status:', attributes.status);
          completed = true;
        }
        pollAttempt++;
      }
      
      if (!completed) {
        scanOutput.status = currentStatus;
        scanOutput.error = errorMsgFromPolling || `VirusTotal URL scan did not complete within the time limit. Status: ${currentStatus}`;
      } else if (errorMsgFromPolling && scanOutput.status !== 'completed') {
        scanOutput.status = currentStatus;
        scanOutput.error = errorMsgFromPolling;
      }
      
    } catch (err: any) {
      console.error('[scanUrlFlow] An exception occurred during the scan process:', err);
      scanOutput = { analysisId, submittedUrl: input.url, status: 'error', error: `Scan process failed: ${err.message}` };
    }

    console.log('[scanUrlFlow] Flow finished, returning scan output to be handled by client.');
    return scanOutput;
  }
);

    