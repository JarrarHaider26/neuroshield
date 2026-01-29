
import type { LucideIcon } from 'lucide-react';
import { LayoutDashboard, UploadCloud, Link2, TrendingUp, FileText, UserCircle, ShieldAlert, Settings, LogIn, MessageSquare, Users, Chrome } from 'lucide-react';

export interface NavItem {
  title: string;
  href: string;
  icon: LucideIcon;
  label?: string;
  external?: boolean;
  disabled?: boolean;
  tooltip?: string;
}

export interface NavSection {
  title?: string;
  items: NavItem[];
}

export const mainNav: NavSection[] = [
  {
    items: [
      {
        title: 'Dashboard',
        href: '/',
        icon: LayoutDashboard,
        tooltip: 'Overview',
      },
    ],
  },
  {
    title: 'Analysis Tools',
    items: [
      {
        title: 'File Scan',
        href: '/scan/file',
        icon: UploadCloud,
        tooltip: 'Scan Files',
      },
      {
        title: 'URL Scan',
        href: '/scan/url',
        icon: Link2,
        tooltip: 'Scan URLs',
      },
      {
        title: 'Browser Extension',
        href: '/extension',
        icon: Chrome,
        tooltip: 'Download Extension',
      },
      {
        title: 'Threat Trends',
        href: '/threat-trends',
        icon: TrendingUp,
        tooltip: 'AI Insights',
      },
    ],
  },
  {
    title: 'User Area',
    items: [
      {
        title: 'Report Center',
        href: '/reports',
        icon: FileText,
        tooltip: 'View Reports',
      },
      {
        title: 'Profile',
        href: '/profile',
        icon: UserCircle,
        tooltip: 'User Profile',
      },
      {
        title: 'Feedback',
        href: '/feedback',
        icon: MessageSquare,
        tooltip: 'Provide Feedback',
      },
    ],
  },
];

export const adminNav: NavSection[] = [
  {
    title: 'Administration',
    items: [
      {
        title: 'Admin Dashboard',
        href: '/admin/dashboard',
        icon: ShieldAlert,
        tooltip: 'Manage App',
      },
      {
        title: 'User Management',
        href: '/admin/users',
        icon: Users,
        tooltip: 'Manage Users',
      },
      {
        title: 'System Reports',
        href: '/admin/reports',
        icon: FileText,
        tooltip: 'All Scan Reports',
        disabled: false, 
      },
    ],
  },
];

export const authNav: NavItem[] = [
    {
        title: 'Login',
        href: '/auth/login',
        icon: LogIn,
        tooltip: 'Sign In'
    }
]
