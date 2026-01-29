'use client';

import { AppShell } from '@/components/layout/AppShell';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Download, Globe, Shield, Zap, Lock, CheckCircle, FileDown, Link2 } from 'lucide-react';

export default function ExtensionPage() {
  const EXTENSION_DOWNLOAD_LINK = 'https://drive.google.com/uc?export=download&id=1R4_v04QgH2LFwfuERhLM09JNN8IuCUee';

  return (
    <AppShell>
      <div className="flex flex-col gap-6 md:gap-8 max-w-5xl mx-auto">
        <header className="text-center">
          <h1 className="text-3xl sm:text-4xl font-bold tracking-tight text-primary mb-3">
            NeuroShield Browser Extension
          </h1>
          <p className="text-muted-foreground text-base sm:text-lg max-w-2xl mx-auto">
            Real-time protection for downloads and browsing. Scan EXE/DLL files and URLs automatically.
          </p>
          <p className="text-sm text-muted-foreground mt-2">
            Compatible with Chrome & Microsoft Edge
          </p>
        </header>

        {/* Hero Card */}
        <Card className="shadow-2xl border-primary/30 card-hover-effect-primary overflow-hidden">
          <div className="bg-gradient-to-br from-primary/10 via-accent/5 to-background p-8 sm:p-12">
            <div className="flex flex-col md:flex-row items-center gap-8">
              <div className="flex-shrink-0">
                <div className="w-32 h-32 bg-primary/20 rounded-3xl flex items-center justify-center backdrop-blur-sm border-2 border-primary/30">
                  <Globe className="h-16 w-16 text-primary" />
                </div>
              </div>
              <div className="flex-1 text-center md:text-left">
                <h2 className="text-2xl sm:text-3xl font-bold mb-3">Download for Chrome & Edge</h2>
                <p className="text-muted-foreground mb-6">
                  Get instant protection while browsing. Automatically scans downloaded EXE and DLL files, plus real-time URL scanning when you visit websites.
                </p>
                <Button 
                  asChild 
                  size="lg" 
                  className="btn-glow text-base sm:text-lg px-8 py-6"
                >
                  <a href={EXTENSION_DOWNLOAD_LINK} download>
                    <Download className="mr-2 h-5 w-5" />
                    Download Extension
                  </a>
                </Button>
              </div>
            </div>
          </div>
        </Card>

        {/* Features */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 sm:gap-6">
          <Card className="shadow-lg border-primary/20 card-hover-effect">
            <CardHeader>
              <div className="w-12 h-12 bg-primary/10 rounded-lg flex items-center justify-center mb-3">
                <FileDown className="h-6 w-6 text-primary" />
              </div>
              <CardTitle className="text-lg">File Scanning</CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-sm text-muted-foreground">
                Automatically scans EXE and DLL files when downloaded to detect malware before execution.
              </p>
            </CardContent>
          </Card>

          <Card className="shadow-lg border-primary/20 card-hover-effect">
            <CardHeader>
              <div className="w-12 h-12 bg-primary/10 rounded-lg flex items-center justify-center mb-3">
                <Link2 className="h-6 w-6 text-primary" />
              </div>
              <CardTitle className="text-lg">URL Scanning</CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-sm text-muted-foreground">
                Real-time scanning of URLs when you visit websites to detect phishing and malicious sites.
              </p>
            </CardContent>
          </Card>

          <Card className="shadow-lg border-primary/20 card-hover-effect">
            <CardHeader>
              <div className="w-12 h-12 bg-primary/10 rounded-lg flex items-center justify-center mb-3">
                <Zap className="h-6 w-6 text-primary" />
              </div>
              <CardTitle className="text-lg">AI-Powered</CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-sm text-muted-foreground">
                Powered by NeuroShield AI and VirusTotal for advanced threat detection.
              </p>
            </CardContent>
          </Card>

          <Card className="shadow-lg border-primary/20 card-hover-effect">
            <CardHeader>
              <div className="w-12 h-12 bg-primary/10 rounded-lg flex items-center justify-center mb-3">
                <Lock className="h-6 w-6 text-primary" />
              </div>
              <CardTitle className="text-lg">Privacy First</CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-sm text-muted-foreground">
                Your browsing data stays private. Only scans downloads and URLs for threats.
              </p>
            </CardContent>
          </Card>
        </div>

        {/* Installation Instructions */}
        <Card className="shadow-lg border-accent/20">
          <CardHeader>
            <CardTitle className="text-xl sm:text-2xl">Installation Instructions</CardTitle>
            <CardDescription>Follow these simple steps to install the extension</CardDescription>
          </CardHeader>
          <CardContent>
            <ol className="space-y-4">
              <li className="flex gap-3">
                <div className="flex-shrink-0 w-8 h-8 bg-primary/10 rounded-full flex items-center justify-center font-bold text-primary">
                  1
                </div>
                <div>
                  <p className="font-semibold mb-1">Download the Extension</p>
                  <p className="text-sm text-muted-foreground">
                    Click the download button above to get the extension ZIP file.
                  </p>
                </div>
              </li>
              <li className="flex gap-3">
                <div className="flex-shrink-0 w-8 h-8 bg-primary/10 rounded-full flex items-center justify-center font-bold text-primary">
                  2
                </div>
                <div>
                  <p className="font-semibold mb-1">Extract the ZIP File</p>
                  <p className="text-sm text-muted-foreground">
                    Unzip the downloaded file to a folder on your computer.
                  </p>
                </div>
              </li>
              <li className="flex gap-3">
                <div className="flex-shrink-0 w-8 h-8 bg-primary/10 rounded-full flex items-center justify-center font-bold text-primary">
                  3
                </div>
                <div>
                  <p className="font-semibold mb-1">Open Browser Extensions</p>
                  <p className="text-sm text-muted-foreground">
                    Go to <code className="bg-muted px-2 py-1 rounded">chrome://extensions/</code> in your browser.
                  </p>
                </div>
              </li>
              <li className="flex gap-3">
                <div className="flex-shrink-0 w-8 h-8 bg-primary/10 rounded-full flex items-center justify-center font-bold text-primary">
                  4
                </div>
                <div>
                  <p className="font-semibold mb-1">Enable Developer Mode</p>
                  <p className="text-sm text-muted-foreground">
                    Toggle the "Developer mode" switch in the top right corner.
                  </p>
                </div>
              </li>
              <li className="flex gap-3">
                <div className="flex-shrink-0 w-8 h-8 bg-primary/10 rounded-full flex items-center justify-center font-bold text-primary">
                  5
                </div>
                <div>
                  <p className="font-semibold mb-1">Load Unpacked Extension</p>
                  <p className="text-sm text-muted-foreground">
                    Click "Load unpacked" and select the extracted folder.
                  </p>
                </div>
              </li>
              <li className="flex gap-3">
                <div className="flex-shrink-0 w-8 h-8 bg-primary/10 rounded-full flex items-center justify-center font-bold text-primary">
                  <CheckCircle className="h-5 w-5" />
                </div>
                <div>
                  <p className="font-semibold mb-1">You're All Set!</p>
                  <p className="text-sm text-muted-foreground">
                    The extension will now scan URLs when you visit sites and check EXE/DLL files when downloaded.
                  </p>
                </div>
              </li>
            </ol>
          </CardContent>
        </Card>

        {/* CTA */}
        <Card className="shadow-lg border-primary/20 bg-gradient-to-br from-primary/5 to-accent/5">
          <CardContent className="p-8 text-center">
            <h3 className="text-xl sm:text-2xl font-bold mb-3">Ready to Get Started?</h3>
            <p className="text-muted-foreground">
              Download the extension and browse safely with automatic file and URL scanning.
            </p>
          </CardContent>
        </Card>
      </div>
    </AppShell>
  );
}
