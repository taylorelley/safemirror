'use client';

import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import api from '@/lib/api';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Select } from '@/components/ui/select';
import { PageLoading } from '@/components/ui/loading';
import { TrendChart } from '@/components/charts/trend-chart';
import { SeverityChart } from '@/components/charts/severity-chart';
import { BarChart3, TrendingUp } from 'lucide-react';

export default function AnalyticsPage() {
  const [days, setDays] = useState(30);

  const { data: trendData, isLoading: trendLoading } = useQuery({
    queryKey: ['trends', days],
    queryFn: () => api.getTrendData({ days }),
  });

  const { data: vulnReport, isLoading: vulnLoading } = useQuery({
    queryKey: ['vulnerability-report'],
    queryFn: () => api.getVulnerabilityReport(),
  });

  const daysOptions = [
    { value: '7', label: 'Last 7 days' },
    { value: '30', label: 'Last 30 days' },
    { value: '90', label: 'Last 90 days' },
  ];

  const isLoading = trendLoading || vulnLoading;

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold">Analytics</h1>
          <p className="text-muted-foreground">Vulnerability and package trends over time</p>
        </div>
        <Select
          options={daysOptions}
          value={String(days)}
          onChange={(e) => setDays(Number(e.target.value))}
          className="w-40"
        />
      </div>

      {isLoading ? (
        <PageLoading />
      ) : (
        <div className="grid gap-6 lg:grid-cols-2">
          {/* Trend Chart */}
          <Card className="lg:col-span-2">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <TrendingUp className="h-5 w-5" />
                Vulnerability Trends
              </CardTitle>
            </CardHeader>
            <CardContent>
              {trendData && <TrendChart data={trendData} />}
            </CardContent>
          </Card>

          {/* Severity Distribution */}
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <BarChart3 className="h-5 w-5" />
                Severity Distribution
              </CardTitle>
            </CardHeader>
            <CardContent>
              {vulnReport && <SeverityChart data={vulnReport.summary.by_severity} />}
            </CardContent>
          </Card>

          {/* Stats Cards */}
          <Card>
            <CardHeader>
              <CardTitle>Summary Statistics</CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              {vulnReport && (
                <>
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Total Vulnerabilities</span>
                    <span className="font-bold">{vulnReport.summary.total}</span>
                  </div>
                  {Object.entries(vulnReport.summary.by_severity).map(([severity, count]) => (
                    <div key={severity} className="flex justify-between">
                      <span className="capitalize text-muted-foreground">{severity}</span>
                      <span className="font-medium">{count as number}</span>
                    </div>
                  ))}
                </>
              )}
            </CardContent>
          </Card>
        </div>
      )}
    </div>
  );
}
