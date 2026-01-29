'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { Home, Shield, TrendingUp, FileText, Settings } from 'lucide-react';
import { cn } from '@/lib/utils';

const mobileNavItems = [
  { href: '/', icon: Home, label: 'Home' },
  { href: '/scan/file', icon: Shield, label: 'Scan' },
  { href: '/threat-trends', icon: TrendingUp, label: 'Trends' },
  { href: '/reports', icon: FileText, label: 'Reports' },
  { href: '/profile', icon: Settings, label: 'Profile' },
];

export function MobileNav() {
  const pathname = usePathname();

  return (
    <nav className="fixed bottom-0 left-0 right-0 z-50 lg:hidden border-t bg-background/95 backdrop-blur-sm">
      <div className="flex items-center justify-around h-16 px-2">
        {mobileNavItems.map((item) => {
          const isActive = pathname === item.href;
          const Icon = item.icon;
          
          return (
            <Link
              key={item.href}
              href={item.href}
              className={cn(
                "flex flex-col items-center justify-center gap-1 px-3 py-2 rounded-lg transition-all min-w-[60px]",
                isActive
                  ? "text-accent bg-accent/10"
                  : "text-muted-foreground hover:text-foreground hover:bg-muted/50"
              )}
            >
              <Icon className={cn("h-5 w-5", isActive && "animate-pulse")} />
              <span className="text-xs font-medium">{item.label}</span>
            </Link>
          );
        })}
      </div>
    </nav>
  );
}
