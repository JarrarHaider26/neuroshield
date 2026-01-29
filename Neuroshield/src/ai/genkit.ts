
import {genkit} from 'genkit';
import {googleAI} from '@genkit-ai/googleai'; // Google AI plugin

export const ai = genkit({
  plugins: [
    googleAI(), // Google AI plugin enabled
  ],
  // Default model is provided by googleAI() if not overridden in prompts
  // We will use gemini-1.5-flash-latest for its balance of speed and intelligence.
  // model: 'googleai/gemini-1.5-flash-latest',
});
