
import { config } from 'dotenv';
config(); // This loads variables from .env into process.env for the Genkit server

// Import your flows here to make them available to the Genkit dev UI
import '@/ai/flows/summarize-malware-trends.ts';
import '@/ai/flows/scan-file-flow.ts';
import '@/ai/flows/scan-url-flow.ts';
