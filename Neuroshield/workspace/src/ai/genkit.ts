
// import {genkit} from 'genkit'; // Genkit functionality is temporarily disabled to resolve npm installation issues.
// import {googleAI} from '@genkit-ai/googleai'; // Google AI plugin (requires @genkit-ai/googleai package)

// Genkit functionality is temporarily disabled to resolve npm installation issues.
// Please resolve local npm environment problems and then re-add Genkit dependencies and uncomment this file.
// When re-enabling, ensure GOOGLE_API_KEY is set in your .env file.

/*
export const ai = genkit({
  plugins: [
    googleAI(), // Only Google AI plugin enabled
  ],
  // Default model is provided by googleAI() if not overridden in prompts
  // e.g., model: 'googleai/gemini-1.5-flash-latest',
});
*/

// Placeholder export to avoid breaking imports if 'ai' object is expected elsewhere (though it shouldn't be if fully disabled)
// When re-enabling Genkit, replace this with the actual genkit configuration.
export const ai: any = {
    defineFlow: (config: any, handler: any) => handler,
    definePrompt: (config: any) => (input: any) => Promise.resolve({ output: null, usage: {} }),
    // Add other Genkit methods if they are directly called from disabled flows to prevent errors
};
