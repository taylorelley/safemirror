'use client';

import { useQuery } from '@tanstack/react-query';
import api from '@/lib/api';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Skeleton } from '@/components/ui/loading';
import { formatRelativeTime } from '@/lib/utils';
import {
  Package,
  ShieldAlert,
  CheckSquare,
  Database,
  AlertTriangle,
  ArrowRight,
  RefreshCw,
} from 'lucide-react';
import Link from 'next/link';

export default function DashboardPage() {
  const { data: metrics, isLoading, refetch, isRefetching } = useQuery({
    queryKey: ['dashboard-metrics'],
    queryFn: () => api.getDashboardMetrics(),
    refetchInterval: 30000, // Refresh every 30 seconds
  });

  const metricCards = [
    {
      title: 'Total Packages',
      value: metrics?.total_packages ?? 0,
      icon: Package,
      href: '/packages',
      color: 'text-blue-500',
    },
    {
      title: 'Vulnerabilities',
      value: metrics?.total_vulnerabilities ?? 0,
      icon: ShieldAlert,
      href: '/reports/vulnerabilities',
      color: 'text-red-500',
    },
    {
      title: 'Critical',
      value: metrics?.critical_vulnerabilities ?? 0,
      icon: AlertTriangle,
      href: '/reports/vulnerabilities?severity=critical',
      color: 'text-orange-500',
    },
    {
      title: 'Pending Approvals',
      value: metrics?.pending_approvals ?? 0,
      icon: CheckSquare,
      href: '/approvals',
      color: 'text-yellow-500',
    },
    {
      title: 'Active Mirrors',
      value: metrics?.active_mirrors ?? 0,
      icon: Database,
      href: '/settings/mirrors',
      color: 'text-green-500',
    },
  ];

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold">Dashboard</h1>
          <p className="text-muted-foreground">Overview of your security posture</p>
        </div>
        <Button onClick={() => refetch()} disabled={isRefetching} variant="outline">
          <RefreshCw className={isRefetching ? 'mr-2 h-4 w-4 animate-spin' : 'mr-2 h-4 w-4'} />
          Refresh
        </Button>
      </div>

      {/* Metrics Grid */}
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-5">
        {metricCards.map((card) => (
          <Link key={card.title} href={card.href}>
            <Card className="transition-shadow hover:shadow-md">
              <CardHeader className="flex flex-row items-center justify-between pb-2">
                <CardTitle className="text-sm font-medium text-muted-foreground">
                  {card.title}
                </CardTitle>
                <card.icon className={"h-5 w-5 " + card.color} />
              </CardHeader>
              <CardContent>
                {isLoading ? (
                  <Skeleton className="h-8 w-20" />
                ) : (
                  <p className="text-3xl font-bold">{card.value.toLocaleString()}</p>
                )}
              </CardContent>
            </Card>
          </Link>
        ))}
      </div>

      {/* Quick Actions */}
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        <Card>
          <CardHeader>
            <CardTitle className="text-lg">Quick Actions</CardTitle>
          </CardHeader>
          <CardContent className="space-y-2">
            <Link href="/packages" className="block">
              <Button variant="outline" className="w-full justify-between">
                View Packages
                <ArrowRight className="h-4 w-4" />
              </Button>
            </Link>
            <Link href="/approvals" className="block">
              <Button variant="outline" className="w-full justify-between">
                Review Approvals
                <ArrowRight className="h-4 w-4" />
              </Button>
            </Link>
            <Link href="/reports/vulnerabilities" className="block">
              <Button variant="outline" className="w-full justify-between">
                Security Report
                <ArrowRight className="h-4 w-4" />
              </Button>
            </Link>
          </CardContent>
        </Card>

        <Card className="md:col-span-2 lg:col-span-3">
          <CardHeader>
            <CardTitle className="text-lg">Recent Activity</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              {[
                { type: 'scan', message: 'Security scan completed for lodash@4.17.21', time: '5 minutes ago' },
                { type: 'approval', message: 'Package axios@1.6.0 approved by admin', time: '1 hour ago' },
                { type: 'vulnerability', message: 'New CVE-2024-1234 detected in express', time: '2 hours ago' },
                { type: 'sync', message: 'NPM mirror sync completed', time: '3 hours ago' },
              ].map((activity, i) => (
                <div key={i} className="flex items-center gap-4">
                  <div className="flex h-8 w-8 items-center justify-center rounded-full bg-muted">
                    {activity.type === 'scan' && <RefreshCw className="h-4 w-4" />}
                    {activity.type === 'approval' && <CheckSquare className="h-4 w-4" />}
                    {activity.type === 'vulnerability' && <ShieldAlert className="h-4 w-4 text-red-500" />}
                    {activity.type === 'sync' && <Database className="h-4 w-4" />}
                  </div>
                  <div className="flex-1">
                    <p className="text-sm">{activity.message}</p>
                    <p className="text-xs text-muted-foreground">{activity.time}</p>
                  </div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Status Banner */}
      {metrics && metrics.critical_vulnerabilities > 0 && (
        <Card className="border-destructive bg-destructive/10">
          <CardContent className="flex items-center gap-4 py-4">
            <AlertTriangle className="h-6 w-6 text-destructive" />
            <div className="flex-1">
              <p className="font-medium text-destructive">
                {metrics.critical_vulnerabilities} critical vulnerabilities require immediate attention
              </p>
            </div>
            <Link href="/reports/vulnerabilities?severity=critical">
              <Button variant="destructive" size="sm">
                View Details
              </Button>
            </Link>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
