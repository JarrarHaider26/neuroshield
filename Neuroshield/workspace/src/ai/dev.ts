
import { config } from 'dotenv';
config(); // This loads variables from .env into process.env for the Genkit server

// Genkit functionality is temporarily disabled to resolve npm installation issues.
// Please resolve local npm environment problems and then re-add Genkit dependencies and uncomment this file.

// import '@/ai/flows/summarize-malware-trends.ts';
// import '@/ai/flows/scan-file-flow.ts';
// import '@/ai/flows/scan-url-flow.ts';
