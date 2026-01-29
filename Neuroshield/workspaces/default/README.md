# Firebase Studio (NeuroShield App)

This is a NextJS starter in Firebase Studio, evolved into the NeuroShield application.

To get started, take a look at `src/app/page.tsx`.

## Running Locally

1.  **Install Dependencies:**
    ```bash
    npm install
    ```
2.  **Environment Variables:**
    *   Copy `.env.example` to a new file named `.env`.
    *   Fill in your actual API keys and Firebase configuration in the `.env` file.
        *   `NEXT_PUBLIC_FIREBASE_...`: From your Firebase project settings (Project settings -> General -> Your apps -> Web app -> SDK setup and configuration).
        *   `GOOGLE_API_KEY`: Your Google AI (Gemini) API key from Google AI Studio or Google Cloud.
        *   `VIRUSTOTAL_API_KEY`: Your VirusTotal API key.
3.  **Firebase Project Setup:**
    *   Ensure you have a Firebase project created at [console.firebase.google.com](https://console.firebase.google.com/).
    *   Enable **Authentication** in your Firebase project and add "Email/Password" as a sign-in method.
    *   Enable **Cloud Firestore** database in your Firebase project.
    *   Apply appropriate security rules for Cloud Firestore (see example below or in previous discussions).
    *   In Firebase Authentication settings, go to the "Settings" tab and add `localhost` to the "Authorized domains" list for local development.
4.  **Run Genkit Development Server:**
    This server runs your AI flows.
    ```bash
    npm run genkit:watch
    ```
    (This usually starts on `http://localhost:4000`)
5.  **Run Next.js Development Server:**
    This server runs your Next.js frontend application.
    ```bash
    npm run dev
    ```
    (This usually starts on `http://localhost:9002` as configured in `package.json`)

Access the application at `http://localhost:9002`.

## Deploying to Vercel (from GitHub)

1.  **Push to GitHub:**
    *   Ensure your latest code is pushed to your GitHub repository.
    *   Your `.gitignore` file should prevent `.env` (with your actual keys) and `node_modules` from being committed.

2.  **Import Project on Vercel:**
    *   Log in to your Vercel account ([vercel.com](https://vercel.com/)).
    *   Click "Add New..." -> "Project".
    *   Import your GitHub repository. Vercel typically auto-detects Next.js projects and configures build settings correctly.

3.  **Configure Environment Variables on Vercel:**
    *   This is the **most crucial step** for your deployed app to work.
    *   In your Vercel project settings, navigate to "Settings" -> "Environment Variables".
    *   Add all the environment variables listed in `.env.example` with their **actual, secret values**. For example:
        *   `NEXT_PUBLIC_FIREBASE_API_KEY` (Value: Your actual Firebase API key)
        *   `GOOGLE_API_KEY` (Value: Your actual Google AI/Gemini API key)
        *   `VIRUSTOTAL_API_KEY` (Value: Your actual VirusTotal API key)
        *   And so on for all Firebase configuration variables.
    *   Ensure these are set for "Production", and "Preview" environments on Vercel. You can also set them for "Development" if you plan to use Vercel's local development tools (`vercel dev`).

4.  **Configure Firebase Authorized Domains:**
    *   In your Firebase project console (Authentication -> Settings tab -> Authorized domains):
    *   Click "Add domain".
    *   Add your Vercel deployment URL (e.g., `your-app-name.vercel.app`). Vercel provides this URL after the first successful deployment.
    *   If you later add custom domains to your Vercel deployment, add those custom domains to this list as well.
    *   **Without this step, Firebase Authentication (login, signup) will fail on your deployed Vercel site with an "auth/unauthorized-domain" error.**

5.  **Build and Deploy:**
    *   Vercel will automatically trigger a build and deployment when you push new commits to the connected GitHub branch (usually `main`).
    *   You can monitor the build process and logs in your Vercel project dashboard.

6.  **Cloud Firestore Security Rules (Reminder):**
    Ensure your Cloud Firestore security rules are appropriate for production to protect your data. Example rules that allow users to manage their own data:
    ```firestore
    rules_version = '2';
    service cloud.firestore {
      match /databases/{database}/documents {
        // Rules for user profile documents
        match /users/{userId} {
          allow read, write: if request.auth != null && request.auth.uid == userId;
          allow create: if request.auth != null && request.auth.uid == request.resource.data.uid;
        }
        // Rules for scan reports
        match /scanReports/{reportId} {
          // Allow creation if the report's userId matches the authenticated user's ID
          allow create: if request.auth != null && request.auth.uid == request.resource.data.userId;
          // Allow users to read and delete their own reports
          allow read, delete: if request.auth != null && request.auth.uid == resource.data.userId;
        }
      }
    }
    ```
    Apply these rules in your Firebase console (Firestore Database -> Rules tab).

Once deployed, your NeuroShield application will be accessible via the Vercel URL. Unauthenticated users will be redirected to the login page, and your API keys will be securely managed by Vercel.
