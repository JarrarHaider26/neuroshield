import type { ImgHTMLAttributes } from 'react';
import Image from 'next/image';

interface LogoProps extends ImgHTMLAttributes<HTMLImageElement> {
  // className is part of ImgHTMLAttributes
}

export function Logo(props: LogoProps) {
  const { className, width = 28, height = 28, alt = "NeuroShield Logo", ...rest } = props;
  // User should place their logo at public/images/neuroshield-logo.png
  const logoSrc = '/images/neuroshield-logo.png'; 

  return (
    <Image
      src={logoSrc}
      alt={alt}
      width={Number(width)} // next/image width and height must be numbers
      height={Number(height)}
      className={className}
      // For simplicity in this context, we assume the user will place the logo.
      // If not, Next/Image will show its default broken image icon.
      // Consider adding an onError fallback to a placeholder for better UX if the image might be missing.
      {...rest}
      data-ai-hint="logo shield" // Add hint for AI if it needs to replace this later
    />
  );
}
