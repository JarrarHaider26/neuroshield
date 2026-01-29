'use client';

import { motion } from 'framer-motion';
import { Input, InputProps } from '@/components/ui/input';
import { forwardRef, useState } from 'react';

export const GlowInput = forwardRef<HTMLInputElement, InputProps>(
  ({ className = '', ...props }, ref) => {
    const [isFocused, setIsFocused] = useState(false);

    return (
      <motion.div
        animate={{
          boxShadow: isFocused
            ? '0 0 15px hsl(var(--ring) / 0.5), 0 0 30px hsl(var(--ring) / 0.2)'
            : '0 0 0px transparent',
        }}
        transition={{ duration: 0.3 }}
        className="rounded-md"
      >
        <Input
          ref={ref}
          className={`input-glow transition-all duration-300 ${className}`}
          onFocus={() => setIsFocused(true)}
          onBlur={() => setIsFocused(false)}
          {...props}
        />
      </motion.div>
    );
  }
);

GlowInput.displayName = 'GlowInput';
