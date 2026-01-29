'use client';

import { motion, AnimatePresence } from 'framer-motion';
import { useState, useEffect } from 'react';

interface CosmicPortalLoaderProps {
  onComplete?: () => void;
  duration?: number;
}

export function CosmicPortalLoader({ onComplete, duration = 2500 }: CosmicPortalLoaderProps) {
  const [isVisible, setIsVisible] = useState(true);

  useEffect(() => {
    const timer = setTimeout(() => {
      setIsVisible(false);
      onComplete?.();
    }, duration);

    return () => clearTimeout(timer);
  }, [duration, onComplete]);

  return (
    <AnimatePresence>
      {isVisible && (
        <motion.div
          className="fixed inset-0 z-50 flex items-center justify-center bg-background"
          initial={{ opacity: 1, scale: 1 }}
          exit={{ opacity: 0, scale: 2 }}
          transition={{ duration: 0.7, ease: 'circIn' }}
        >
          <div className="relative w-48 h-48">
            {/* SVG Portal Animation */}
            <motion.svg
              className="w-full h-full"
              viewBox="0 0 200 200"
              initial="initial"
              animate="animate"
              onAnimationComplete={() => {
                setTimeout(() => setIsVisible(false), 200);
              }}
            >
              {/* Glow Filter Definition */}
              <defs>
                <filter id="glow">
                  <feGaussianBlur stdDeviation="1.5" result="coloredBlur" />
                  <feMerge>
                    <feMergeNode in="coloredBlur" />
                    <feMergeNode in="SourceGraphic" />
                  </feMerge>
                </filter>
              </defs>

              {/* Static Outer Rings (Background) */}
              <circle
                cx="100"
                cy="100"
                r="80"
                fill="none"
                stroke="hsl(260 100% 44% / 0.2)"
                strokeWidth="1"
              />
              <circle
                cx="100"
                cy="100"
                r="60"
                fill="none"
                stroke="hsl(260 100% 44% / 0.2)"
                strokeWidth="1"
              />

              {/* Animated Drawing Rings */}
              <motion.path
                d="M 100 20 A 80 80 0 1 1 99.99 20"
                fill="none"
                stroke="hsl(211 100% 50%)"
                strokeWidth="2"
                strokeLinecap="round"
                filter="url(#glow)"
                variants={{
                  initial: { pathLength: 0, opacity: 0 },
                  animate: { pathLength: 1, opacity: 1 },
                }}
                transition={{ duration: 2.5, ease: 'easeInOut' }}
              />
              <motion.path
                d="M 100 40 A 60 60 0 1 1 99.99 40"
                fill="none"
                stroke="hsl(260 100% 44%)"
                strokeWidth="2"
                strokeLinecap="round"
                filter="url(#glow)"
                variants={{
                  initial: { pathLength: 0, opacity: 0 },
                  animate: { pathLength: 1, opacity: 1 },
                }}
                transition={{ duration: 2.5, ease: 'easeInOut', delay: 0.2 }}
              />

              {/* Center Dot */}
              <motion.circle
                cx="100"
                cy="100"
                r="3"
                fill="hsl(211 100% 50%)"
                filter="url(#glow)"
                initial={{ scale: 0, opacity: 0 }}
                animate={{ scale: 1, opacity: 1 }}
                transition={{ duration: 0.5, delay: 1 }}
              />
            </motion.svg>

            {/* Central Text */}
            <motion.h1
              className="absolute inset-0 flex items-center justify-center text-2xl font-bold text-glow"
              style={{ fontFamily: 'Space Grotesk, sans-serif' }}
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              transition={{ duration: 0.8, delay: 0.5 }}
            >
              NeuroShield
            </motion.h1>
          </div>
        </motion.div>
      )}
    </AnimatePresence>
  );
}
