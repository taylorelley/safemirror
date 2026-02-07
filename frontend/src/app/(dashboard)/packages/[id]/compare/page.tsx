'use client';

import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { useParams } from 'next/navigation';
import api from '@/lib/api';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Select } from '@/components/ui/select';
import { Badge } from '@/components/ui/badge';
import { Table, TableHeader, TableBody, TableRow, TableHead, TableCell } from '@/components/ui/table';
import { PageLoading } from '@/components/ui/loading';
import { getSeverityColor } from '@/lib/utils';
import { GitCompare, Plus, Minus, Equal } from 'lucide-react';

export default function VersionComparePage() {
  const params = useParams();
  const id = params.id as string;
  const [version1, setVersion1] = useState('');
  const [version2, setVersion2] = useState('');

  const { data: versions, isLoading: versionsLoading } = useQuery({
    queryKey: ['package-versions', id],
    queryFn: () => api.getPackageVersions(id),
  });

  const { data: comparison, isLoading: comparisonLoading } = useQuery({
    queryKey: ['version-compare', id, version1, version2],
    queryFn: () => api.compareVersions(id, version1, version2),
    enabled: !!version1 && !!version2 && version1 !== version2,
  });

  const versionOptions = versions?.map((v) => ({ value: v, label: v })) || [];

  if (versionsLoading) return <PageLoading />;

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold">Version Comparison</h1>
        <p className="text-muted-foreground">Compare vulnerabilities between package versions</p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <GitCompare className="h-5 w-5" />
            Select Versions
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex items-center gap-4">
            <div className="flex-1">
              <Select
                options={[{ value: '', label: 'Select version' }, ...versionOptions]}
                value={version1}
                onChange={(e) => setVersion1(e.target.value)}
              />
            </div>
            <span className="text-muted-foreground">vs</span>
            <div className="flex-1">
              <Select
                options={[{ value: '', label: 'Select version' }, ...versionOptions]}
                value={version2}
                onChange={(e) => setVersion2(e.target.value)}
              />
            </div>
          </div>
        </CardContent>
      </Card>

      {comparisonLoading && <PageLoading />}

      {comparison && (
        <div className="grid gap-6 lg:grid-cols-3">
          {/* Added Vulnerabilities */}
          <Card className="border-red-200 bg-red-50 dark:border-red-900 dark:bg-red-950">
            <CardHeader>
              <CardTitle className="flex items-center gap-2 text-red-700 dark:text-red-400">
                <Plus className="h-5 w-5" />
                Added ({comparison.diff.added.length})
              </CardTitle>
            </CardHeader>
            <CardContent>
              {comparison.diff.added.length ? (
                <div className="space-y-2">
                  {comparison.diff.added.map((vuln) => (
                    <div
                      key={vuln.id}
                      className="rounded-md bg-white p-3 dark:bg-gray-900"
                    >
                      <div className="flex items-center justify-between">
                        <span className="font-mono text-sm">{vuln.cve_id || 'N/A'}</span>
                        <Badge className={getSeverityColor(vuln.severity)}>{vuln.severity}</Badge>
                      </div>
                      <p className="mt-1 text-sm text-muted-foreground">{vuln.title}</p>
                    </div>
                  ))}
                </div>
              ) : (
                <p className="text-muted-foreground">No new vulnerabilities</p>
              )}
            </CardContent>
          </Card>

          {/* Removed Vulnerabilities */}
          <Card className="border-green-200 bg-green-50 dark:border-green-900 dark:bg-green-950">
            <CardHeader>
              <CardTitle className="flex items-center gap-2 text-green-700 dark:text-green-400">
                <Minus className="h-5 w-5" />
                Fixed ({comparison.diff.removed.length})
              </CardTitle>
            </CardHeader>
            <CardContent>
              {comparison.diff.removed.length ? (
                <div className="space-y-2">
                  {comparison.diff.removed.map((vuln) => (
                    <div
                      key={vuln.id}
                      className="rounded-md bg-white p-3 dark:bg-gray-900"
                    >
                      <div className="flex items-center justify-between">
                        <span className="font-mono text-sm">{vuln.cve_id || 'N/A'}</span>
                        <Badge className={getSeverityColor(vuln.severity)}>{vuln.severity}</Badge>
                      </div>
                      <p className="mt-1 text-sm text-muted-foreground">{vuln.title}</p>
                    </div>
                  ))}
                </div>
              ) : (
                <p className="text-muted-foreground">No vulnerabilities fixed</p>
              )}
            </CardContent>
          </Card>

          {/* Unchanged Vulnerabilities */}
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Equal className="h-5 w-5" />
                Unchanged ({comparison.diff.unchanged.length})
              </CardTitle>
            </CardHeader>
            <CardContent>
              {comparison.diff.unchanged.length ? (
                <div className="space-y-2 max-h-96 overflow-y-auto">
                  {comparison.diff.unchanged.map((vuln) => (
                    <div
                      key={vuln.id}
                      className="rounded-md bg-muted p-3"
                    >
                      <div className="flex items-center justify-between">
                        <span className="font-mono text-sm">{vuln.cve_id || 'N/A'}</span>
                        <Badge className={getSeverityColor(vuln.severity)}>{vuln.severity}</Badge>
                      </div>
                      <p className="mt-1 text-sm text-muted-foreground">{vuln.title}</p>
                    </div>
                  ))}
                </div>
              ) : (
                <p className="text-muted-foreground">No common vulnerabilities</p>
              )}
            </CardContent>
          </Card>
        </div>
      )}

      {!comparison && version1 && version2 && version1 === version2 && (
        <Card>
          <CardContent className="py-12 text-center">
            <p className="text-muted-foreground">Please select two different versions to compare</p>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
