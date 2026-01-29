
'use client';

import { AppShell } from '@/components/layout/AppShell';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { UploadCloud, Link2, TrendingUp } from 'lucide-react';
import Link from 'next/link';
import React, { useState } from 'react';
import { CosmicPortalLoader } from '@/components/cosmic/CosmicPortalLoader';
import { motion } from 'framer-motion';

const containerVariants = {
  hidden: { opacity: 0 },
  visible: {
    opacity: 1,
    transition: {
      staggerChildren: 0.1,
      delayChildren: 0.2,
    },
  },
};

const itemVariants = {
  hidden: { opacity: 0, y: 20 },
  visible: {
    opacity: 1,
    y: 0,
    transition: {
      duration: 0.5,
      ease: 'easeOut',
    },
  },
};

export default function DashboardPage() {
  const [showLoader, setShowLoader] = useState(true);

  return (
    <>
      {showLoader && <CosmicPortalLoader onComplete={() => setShowLoader(false)} duration={2500} />}
      <AppShell>
      <motion.div 
        className="flex flex-col gap-6 md:gap-8 w-full"
        initial="hidden"
        animate="visible"
        variants={containerVariants}
      >
        <motion.header variants={itemVariants}>
          <h1 className="text-2xl sm:text-3xl md:text-4xl font-bold tracking-tight text-primary text-glow">
            NeuroShield Dashboard
          </h1>
          <p className="text-muted-foreground mt-2 text-sm sm:text-base">
            Welcome, <span className="text-accent font-semibold">Operator</span>. Your AI-driven malware intelligence hub.
          </p>
        </motion.header>

        <motion.div 
          className="grid gap-4 sm:gap-6 grid-cols-1 md:grid-cols-2 lg:grid-cols-3"
          variants={containerVariants}
        >
          <motion.div variants={itemVariants}>
            <ActionCard
              title="Scan File"
              description="Upload and analyze suspicious files for malware."
              icon={UploadCloud}
              href="/scan/file"
              actionText="Upload File"
            />
          </motion.div>
          <motion.div variants={itemVariants}>
            <ActionCard
              title="Scan URL"
              description="Check URLs for phishing, and malicious content."
              icon={Link2}
              href="/scan/url"
              actionText="Analyze URL"
            />
          </motion.div>
          <motion.div variants={itemVariants}>
            <ActionCard
              title="Threat Trends"
              description="Explore AI-generated summaries of global malware."
              icon={TrendingUp}
              href="/threat-trends"
              actionText="View Trends"
            />
          </motion.div>
        </motion.div>

        {/* System Status Card */}
        <motion.div variants={itemVariants}>
          <Card className="cosmic-card shadow-xl border-accent/20 card-hover-effect-accent relative overflow-hidden">
            <div className="absolute top-0 right-0 w-64 h-64 bg-gradient-to-br from-accent/10 to-transparent rounded-full blur-3xl" />
            <CardHeader className="relative">
              <CardTitle className="text-xl sm:text-2xl text-accent flex items-center gap-2">
                <div className="w-2 h-2 rounded-full bg-green-400 animate-pulse-glow" />
                System Status
              </CardTitle>
              <CardDescription className="text-xs sm:text-sm">Current operational status of NeuroShield services.</CardDescription>
            </CardHeader>
            <CardContent className="relative">
              <ul className="space-y-3 sm:space-y-4">
                <motion.li 
                  className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2 p-2.5 sm:p-3 rounded-lg bg-muted/20 border border-border/30"
                  whileHover={{ scale: 1.02, x: 5 }}
                  transition={{ duration: 0.2 }}
                >
                  <span className="text-foreground font-medium text-sm sm:text-base">NeuroShield Intelligence:</span>
                  <span className="text-green-400 font-semibold flex items-center gap-2 text-sm sm:text-base">
                    <div className="w-2 h-2 rounded-full bg-green-400 animate-pulse" />
                    Operational
                  </span>
                </motion.li>
                <motion.li 
                  className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2 p-2.5 sm:p-3 rounded-lg bg-muted/20 border border-border/30"
                  whileHover={{ scale: 1.02, x: 5 }}
                  transition={{ duration: 0.2 }}
                >
                  <span className="text-foreground font-medium text-sm sm:text-base">AI Analysis:</span>
                  <span className="text-green-400 font-semibold flex items-center gap-2 text-sm sm:text-base">
                    <div className="w-2 h-2 rounded-full bg-green-400 animate-pulse" />
                    Optimal
                  </span>
                </motion.li>
                <motion.li 
                  className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2 p-2.5 sm:p-3 rounded-lg bg-muted/20 border border-border/30"
                  whileHover={{ scale: 1.02, x: 5 }}
                  transition={{ duration: 0.2 }}
                >
                  <span className="text-foreground font-medium text-sm sm:text-base">Report Database:</span>
                  <span className="text-green-400 font-semibold flex items-center gap-2 text-sm sm:text-base">
                    <div className="w-2 h-2 rounded-full bg-green-400 animate-pulse" />
                    Connected
                  </span>
                </motion.li>
              </ul>
            </CardContent>
          </Card>
        </motion.div>
      </motion.div>
      </AppShell>
    </>
  );
}

interface ActionCardProps {
  title: string;
  description: string;
  icon: React.ElementType;
  href: string;
  actionText: string;
}

// Memoize ActionCard to prevent unnecessary re-renders
const ActionCard = React.memo(function ActionCard({ title, description, icon: Icon, href, actionText }: ActionCardProps) {
  return (
    <motion.div
      whileHover={{ scale: 1.03, y: -5 }}
      transition={{ duration: 0.3, ease: 'easeOut' }}
    >
      <Card className="cosmic-card border-primary/20 shadow-lg card-hover-effect-primary relative overflow-hidden h-full">
        <div className="absolute top-0 right-0 w-32 h-32 bg-gradient-to-br from-primary/10 to-transparent rounded-full blur-2xl" />
        <CardHeader className="flex flex-col sm:flex-row items-start sm:items-center gap-3 sm:gap-4 pb-3 sm:pb-4 relative">
          <motion.div
            whileHover={{ rotate: 360, scale: 1.1 }}
            transition={{ duration: 0.6, ease: 'easeInOut' }}
            className="p-2.5 sm:p-3 rounded-lg bg-primary/10 border border-primary/20 flex-shrink-0"
          >
            <Icon className="h-6 w-6 sm:h-8 sm:w-8 text-primary" />
          </motion.div>
          <div className="flex-1 min-w-0">
            <CardTitle className="text-lg sm:text-xl text-foreground">{title}</CardTitle>
            <CardDescription className="mt-1 text-xs sm:text-sm line-clamp-2">{description}</CardDescription>
          </div>
        </CardHeader>
        <CardContent className="relative pt-0">
          <Button asChild className="w-full btn-glow bg-primary hover:bg-primary/90 text-primary-foreground text-sm sm:text-base">
            <Link href={href}>{actionText}</Link>
          </Button>
        </CardContent>
      </Card>
    </motion.div>
  );
});
