'use client';

import { AppShell } from '@/components/layout/AppShell';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { BarChart3, Users, FileCog, Activity, ShieldCheck, Loader2 } from 'lucide-react';
import Link from 'next/link';
import { Button } from '@/components/ui/button';
import {
  ChartContainer,
  ChartTooltip,
  ChartTooltipContent,
  ChartConfig,
} from '@/components/ui/chart';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, ResponsiveContainer } from 'recharts';
import { useAuthContext } from '@/contexts/AuthContext';
import { useRouter } from 'next/navigation';
import { useEffect, useState } from 'react';
import { collection, getCountFromServer, getDocs, query, where, Timestamp } from 'firebase/firestore';
import { db } from '@/lib/firebase';
import { subDays, format, startOfDay } from 'date-fns';

type WeeklyChartData = {
  day: string;
  date: string;
  scans: number;
  threats: number;
};

const chartConfig = {
  scans: {
    label: "Scans",
    color: "hsl(var(--primary))",
  },
  threats: {
    label: "Threats",
    color: "hsl(var(--destructive))",
  },
} satisfies ChartConfig

export default function AdminDashboardPage() {
  const { user, isAdmin, loading: authLoading } = useAuthContext();
  const router = useRouter();
  const [stats, setStats] = useState({ users: 0, scans: 0, threats: 0 });
  const [chartData, setChartData] = useState<WeeklyChartData[]>([]);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    if (authLoading) return;
    if (!user || !isAdmin) {
      router.push('/auth/admin-login');
      return;
    }

    const fetchStats = async () => {
      try {
        if (!db) {
            console.error("Firestore DB not available");
            setIsLoading(false);
            return;
        }
        
        // --- Generate date range for the last 7 days ---
        const last7Days = Array.from({ length: 7 }).map((_, i) => {
            const date = subDays(new Date(), i);
            return {
                day: format(date, 'EEE'), // e.g., 'Mon'
                date: format(date, 'yyyy-MM-dd'),
                scans: 0,
                threats: 0,
            };
        }).reverse(); // Reverse to have the oldest day first

        const sevenDaysAgo = startOfDay(subDays(new Date(), 6));
        const sevenDaysAgoTimestamp = Timestamp.fromDate(sevenDaysAgo);

        // --- Fetch all data needed in one go ---
        const usersColl = collection(db, 'users');
        const reportsColl = collection(db, 'scanReports');
        const recentReportsQuery = query(reportsColl, where('createdAt', '>=', sevenDaysAgoTimestamp));
        
        const [userSnapshot, allReportsSnapshot, recentReportsSnapshot] = await Promise.all([
          getDocs(usersColl), // Changed from getCountFromServer to getDocs to filter
          getDocs(reportsColl),
          getDocs(recentReportsQuery)
        ]);

        // Filter users to only count verified ones
        const verifiedUsersCount = userSnapshot.docs.filter(doc => {
          const userData = doc.data();
          return userData.emailVerified === true;
        }).length;

        // --- Process All Reports for Total Stats ---
        const scanCount = allReportsSnapshot.size;
        let totalThreatCount = 0;
        allReportsSnapshot.forEach(doc => {
            const data = doc.data();
            if (data.threatLabel && ['high', 'critical'].includes(data.threatLabel.toLowerCase())) {
                totalThreatCount++;
            }
        });

        // --- Process Recent Reports for Chart Data ---
        recentReportsSnapshot.forEach(doc => {
            const data = doc.data();
            const reportDate = (data.createdAt as Timestamp).toDate();
            const reportDateStr = format(reportDate, 'yyyy-MM-dd');

            const dayData = last7Days.find(d => d.date === reportDateStr);
            if (dayData) {
                dayData.scans++;
                if (data.threatLabel && ['high', 'critical'].includes(data.threatLabel.toLowerCase())) {
                    dayData.threats++;
                }
            }
        });
        
        setStats({ users: verifiedUsersCount, scans: scanCount, threats: totalThreatCount });
        setChartData(last7Days);

      } catch (error) {
        console.error("Error fetching admin stats:", error);
      } finally {
        setIsLoading(false);
      }
    };

    fetchStats();
  }, [user, isAdmin, authLoading, router]);

  if (authLoading || isLoading) {
    return (
      <AppShell>
        <div className="flex items-center justify-center h-full">
          <Loader2 className="h-16 w-16 animate-spin text-primary" />
          <p className="ml-3 text-muted-foreground">Loading Admin Dashboard...</p>
        </div>
      </AppShell>
    );
  }

  if (!isAdmin) {
    return (
      <AppShell>
        <div className="flex flex-col items-center justify-center h-full p-4 text-center">
          <ShieldCheck className="h-16 w-16 text-destructive mb-4" />
          <p className="text-lg text-muted-foreground">Access Denied. Administrator privileges required.</p>
          <p className="text-sm text-muted-foreground">Redirecting to login...</p>
        </div>
      </AppShell>
    );
  }

  const statCards = [
    { title: "Total Users", value: stats.users, icon: Users, href: "/admin/users" },
    { title: "Total Scans", value: stats.scans, icon: FileCog, href: "/admin/reports" },
    { title: "Threats Detected", value: stats.threats, icon: BarChart3, href: "/admin/reports" },
    { title: "Active Subscriptions", value: "N/A", icon: Activity, href: "#" },
  ];

  return (
    <AppShell>
      <div className="flex flex-col gap-8">
        <header>
          <h1 className="text-3xl font-bold tracking-tight text-primary">Admin Control Panel</h1>
          <p className="text-muted-foreground mt-1">
            Oversee NeuroShield operations and manage system parameters.
          </p>
        </header>

        <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-4">
          {statCards.map((stat, index) => (
            <Card key={index} className="shadow-lg border-primary/10 card-hover-effect-primary">
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium text-muted-foreground">{stat.title}</CardTitle>
                <stat.icon className="h-5 w-5 text-primary" />
              </CardHeader>
              <CardContent>
                <div className="text-3xl font-bold text-foreground">{stat.value}</div>
                <Button asChild variant="link" className="p-0 h-auto text-xs text-muted-foreground">
                    <Link href={stat.href}>View details &rarr;</Link>
                </Button>
              </CardContent>
            </Card>
          ))}
        </div>

        <div className="grid md:grid-cols-1 lg:grid-cols-2 gap-6">
            <Card className="shadow-lg border-accent/20 card-hover-effect-accent">
                <CardHeader>
                    <CardTitle className="text-xl text-accent">Weekly Activity</CardTitle>
                    <CardDescription>Scans and threats detected over the last 7 days.</CardDescription>
                </CardHeader>
                <CardContent>
                    <ChartContainer config={chartConfig} className="h-[250px] w-full">
                        <ResponsiveContainer width="100%" height="100%">
                            <BarChart data={chartData}>
                                <CartesianGrid vertical={false} />
                                <XAxis dataKey="day" tickLine={false} tickMargin={10} axisLine={false} />
                                <YAxis />
                                <ChartTooltip content={<ChartTooltipContent />} />
                                <Bar dataKey="scans" fill="var(--color-scans)" radius={4} />
                                <Bar dataKey="threats" fill="var(--color-threats)" radius={4} />
                            </BarChart>
                        </ResponsiveContainer>
                    </ChartContainer>
                </CardContent>
            </Card>


        </div>
      </div>
    </AppShell>
  );
}
