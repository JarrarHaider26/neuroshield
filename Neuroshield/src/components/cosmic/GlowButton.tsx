'use client';

import { motion } from 'framer-motion';
import { Button, ButtonProps } from '@/components/ui/button';
import { forwardRef } from 'react';

export const GlowButton = forwardRef<HTMLButtonElement, ButtonProps>(
  ({ children, className = '', ...props }, ref) => {
    return (
      <motion.div
        whileHover={{ scale: 1.05 }}
        whileTap={{ scale: 0.95 }}
        transition={{ duration: 0.2 }}
      >
        <Button
          ref={ref}
          className={`btn-glow relative overflow-hidden ${className}`}
          {...props}
        >
          <span className="relative z-10">{children}</span>
          <motion.div
            className="absolute inset-0 bg-gradient-to-r from-transparent via-white/20 to-transparent"
            initial={{ x: '-100%' }}
            whileHover={{ x: '100%' }}
            transition={{ duration: 0.6, ease: 'easeInOut' }}
          />
        </Button>
      </motion.div>
    );
  }
);

GlowButton.displayName = 'GlowButton';
