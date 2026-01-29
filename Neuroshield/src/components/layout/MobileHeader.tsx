'use client';

import { useState, useEffect } from 'react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { Menu, X, LogOut, Settings, Sun, Moon } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Avatar, AvatarFallback, AvatarImage } from '@/components/ui/avatar';
import { Logo } from '@/components/icons/Logo';
import { Sheet, SheetContent, SheetHeader, SheetTitle, SheetTrigger } from '@/components/ui/sheet';
import { mainNav, adminNav } from '@/config/nav';
import { useTheme } from 'next-themes';
import { cn } from '@/lib/utils';

interface MobileHeaderProps {
  user: { displayName?: string | null; email?: string | null; photoURL?: string | null };
  isAdmin: boolean;
  onLogout: () => Promise<void>;
}

export function MobileHeader({ user, isAdmin, onLogout }: MobileHeaderProps) {
  const [open, setOpen] = useState(false);
  const pathname = usePathname();
  const { theme, setTheme } = useTheme();
  const [mounted, setMounted] = useState(false);

  useEffect(() => {
    setMounted(true);
  }, []);

  const isAdminPage = pathname.startsWith('/admin');
  const currentNav = isAdminPage ? adminNav : mainNav;

  const fallbackInitial = user.displayName
    ? user.displayName.charAt(0).toUpperCase()
    : user.email
    ? user.email.charAt(0).toUpperCase()
    : 'U';

  return (
    <header className="sticky top-0 z-40 w-full border-b bg-background/95 backdrop-blur-lg lg:hidden">
      <div className="flex h-14 items-center justify-between px-3 sm:px-4">
        {/* Logo */}
        <Link href="/" className="flex items-center gap-2">
          <Logo className="h-5 w-5 sm:h-6 sm:w-6 text-accent" />
          <span className="font-bold text-base sm:text-lg text-foreground">NeuroShield</span>
        </Link>

        {/* Menu Button */}
        <Sheet open={open} onOpenChange={setOpen}>
          <SheetTrigger asChild>
            <Button variant="ghost" size="icon" className="h-9 w-9">
              <Menu className="h-5 w-5" />
            </Button>
          </SheetTrigger>
          <SheetContent side="right" className="w-[300px] sm:w-[350px]">
            <SheetHeader>
              <SheetTitle className="flex items-center gap-3">
                <Avatar className="h-12 w-12 border-2 border-accent">
                  <AvatarImage src={user.photoURL || '/images/rr.png'} alt={user.displayName || 'User'} />
                  <AvatarFallback className="bg-accent/10 text-accent text-lg font-bold">
                    {fallbackInitial}
                  </AvatarFallback>
                </Avatar>
                <div className="flex flex-col items-start">
                  <span className="text-sm font-semibold">{user.displayName || 'User'}</span>
                  <span className="text-xs text-muted-foreground">{user.email}</span>
                </div>
              </SheetTitle>
            </SheetHeader>

            <div className="mt-6 flex flex-col gap-6">
              {/* Navigation Sections */}
              {currentNav.map((section, idx) => (
                <div key={idx}>
                  {section.title && (
                    <h3 className="mb-2 px-2 text-xs font-semibold text-muted-foreground uppercase tracking-wider">
                      {section.title}
                    </h3>
                  )}
                  <nav className="flex flex-col gap-1">
                    {section.items.map((item) => {
                      const isActive = pathname === item.href;
                      return (
                        <Link
                          key={item.href}
                          href={item.href}
                          onClick={() => setOpen(false)}
                          className={cn(
                            "flex items-center gap-3 px-3 py-2.5 rounded-lg transition-colors",
                            isActive
                              ? "bg-accent/10 text-accent font-medium"
                              : "text-foreground hover:bg-muted"
                          )}
                        >
                          <item.icon className="h-5 w-5" />
                          <span>{item.title}</span>
                        </Link>
                      );
                    })}
                  </nav>
                </div>
              ))}

              {/* Theme Toggle Section */}
              <div className="border-t pt-4">
                <div className="flex flex-col gap-1">
                  {mounted && (
                    <button
                      onClick={() => setTheme(theme === 'dark' ? 'light' : 'dark')}
                      className="flex items-center gap-3 px-3 py-2.5 rounded-lg text-foreground hover:bg-muted transition-colors"
                    >
                      {theme === 'dark' ? <Sun className="h-5 w-5" /> : <Moon className="h-5 w-5" />}
                      <span>{theme === 'dark' ? 'Light Mode' : 'Dark Mode'}</span>
                    </button>
                  )}

                  <button
                    onClick={() => {
                      setOpen(false);
                      onLogout();
                    }}
                    className="flex items-center gap-3 px-3 py-2.5 rounded-lg text-destructive hover:bg-destructive/10 transition-colors"
                  >
                    <LogOut className="h-5 w-5" />
                    <span>Log Out</span>
                  </button>
                </div>
              </div>
            </div>
          </SheetContent>
        </Sheet>
      </div>
    </header>
  );
}
