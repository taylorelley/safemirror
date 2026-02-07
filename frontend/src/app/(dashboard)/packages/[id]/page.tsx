'use client';

import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { useParams } from 'next/navigation';
import Link from 'next/link';
import api from '@/lib/api';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Table, TableHeader, TableBody, TableRow, TableHead, TableCell } from '@/components/ui/table';
import { PageLoading } from '@/components/ui/loading';
import { useToast } from '@/components/ui/toast';
import { getSeverityColor, formatDateTime } from '@/lib/utils';
import {
  Package,
  ShieldAlert,
  RefreshCw,
  ExternalLink,
  GitCompare,
  Clock,
  CheckCircle,
  XCircle,
} from 'lucide-react';

export default function PackageDetailPage() {
  const params = useParams();
  const id = params.id as string;
  const { addToast } = useToast();
  const queryClient = useQueryClient();

  const { data: pkg, isLoading } = useQuery({
    queryKey: ['package', id],
    queryFn: () => api.getPackage(id),
  });

  const { data: versions } = useQuery({
    queryKey: ['package-versions', id],
    queryFn: () => api.getPackageVersions(id),
  });

  const scanMutation = useMutation({
    mutationFn: () => api.triggerScan(id),
    onSuccess: () => {
      addToast({ title: 'Scan triggered', description: 'Security scan has been initiated', variant: 'success' });
      queryClient.invalidateQueries({ queryKey: ['package', id] });
    },
    onError: (error) => {
      addToast({ title: 'Scan failed', description: error.message, variant: 'destructive' });
    },
  });

  if (isLoading) return <PageLoading />;
  if (!pkg) return <div>Package not found</div>;

  return (
    <div className="space-y-6">
      <div className="flex items-start justify-between">
        <div>
          <div className="flex items-center gap-2">
            <Package className="h-6 w-6" />
            <h1 className="text-3xl font-bold">{pkg.name}</h1>
          </div>
          <p className="text-muted-foreground">Version {pkg.version}</p>
        </div>
        <div className="flex gap-2">
          <Button
            onClick={() => scanMutation.mutate()}
            disabled={scanMutation.isPending}
            variant="outline"
          >
            <RefreshCw className={scanMutation.isPending ? 'mr-2 h-4 w-4 animate-spin' : 'mr-2 h-4 w-4'} />
            Scan Now
          </Button>
          {versions && versions.length > 1 && (
            <Link href={'/packages/' + id + '/compare'}>
              <Button variant="outline">
                <GitCompare className="mr-2 h-4 w-4" />
                Compare Versions
              </Button>
            </Link>
          )}
        </div>
      </div>

      <div className="grid gap-6 md:grid-cols-2">
        {/* Package Info */}
        <Card>
          <CardHeader>
            <CardTitle>Package Information</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="grid grid-cols-2 gap-4">
              <div>
                <p className="text-sm text-muted-foreground">Status</p>
                <Badge className={pkg.status === 'approved' ? 'bg-green-500' : 'bg-yellow-500'}>
                  {pkg.status}
                </Badge>
              </div>
              <div>
                <p className="text-sm text-muted-foreground">Mirror</p>
                <p className="font-medium">{pkg.mirror_name || 'Unknown'}</p>
              </div>
              <div>
                <p className="text-sm text-muted-foreground">Vulnerabilities</p>
                <p className="font-medium">{pkg.vulnerability_count}</p>
              </div>
              <div>
                <p className="text-sm text-muted-foreground">Highest Severity</p>
                {pkg.highest_severity ? (
                  <Badge className={getSeverityColor(pkg.highest_severity)}>
                    {pkg.highest_severity}
                  </Badge>
                ) : (
                  <span className="text-muted-foreground">None</span>
                )}
              </div>
            </div>
            {pkg.description && (
              <div>
                <p className="text-sm text-muted-foreground">Description</p>
                <p className="text-sm">{pkg.description}</p>
              </div>
            )}
          </CardContent>
        </Card>

        {/* Dependencies */}
        <Card>
          <CardHeader>
            <CardTitle>Dependencies ({pkg.dependencies?.length || 0})</CardTitle>
          </CardHeader>
          <CardContent>
            {pkg.dependencies?.length ? (
              <div className="max-h-48 overflow-y-auto space-y-2">
                {pkg.dependencies.map((dep, i) => (
                  <div key={i} className="flex items-center justify-between rounded-md bg-muted p-2">
                    <span className="font-mono text-sm">{dep.name}</span>
                    <span className="text-sm text-muted-foreground">{dep.version}</span>
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-muted-foreground">No dependencies</p>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Vulnerabilities */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <ShieldAlert className="h-5 w-5" />
            Vulnerabilities
          </CardTitle>
        </CardHeader>
        <CardContent>
          {pkg.vulnerabilities?.length ? (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>CVE</TableHead>
                  <TableHead>Title</TableHead>
                  <TableHead>Severity</TableHead>
                  <TableHead>CVSS</TableHead>
                  <TableHead>Fixed In</TableHead>
                  <TableHead></TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {pkg.vulnerabilities.map((vuln) => (
                  <TableRow key={vuln.id}>
                    <TableCell className="font-mono">{vuln.cve_id || 'N/A'}</TableCell>
                    <TableCell className="max-w-xs truncate">{vuln.title}</TableCell>
                    <TableCell>
                      <Badge className={getSeverityColor(vuln.severity)}>{vuln.severity}</Badge>
                    </TableCell>
                    <TableCell>{vuln.cvss_score?.toFixed(1) || '-'}</TableCell>
                    <TableCell className="font-mono text-sm">{vuln.fixed_version || '-'}</TableCell>
                    <TableCell>
                      {vuln.cve_id && (
                        <a
                          href={'https://nvd.nist.gov/vuln/detail/' + vuln.cve_id}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-primary hover:underline"
                        >
                          <ExternalLink className="h-4 w-4" />
                        </a>
                      )}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          ) : (
            <div className="py-8 text-center text-muted-foreground">
              <CheckCircle className="mx-auto mb-2 h-8 w-8 text-green-500" />
              <p>No vulnerabilities detected</p>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Scan History */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Clock className="h-5 w-5" />
            Scan History
          </CardTitle>
        </CardHeader>
        <CardContent>
          {pkg.scans?.length ? (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Started</TableHead>
                  <TableHead>Completed</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Findings</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {pkg.scans.map((scan) => (
                  <TableRow key={scan.id}>
                    <TableCell>{formatDateTime(scan.started_at)}</TableCell>
                    <TableCell>
                      {scan.completed_at ? formatDateTime(scan.completed_at) : '-'}
                    </TableCell>
                    <TableCell>
                      <Badge
                        variant={
                          scan.status === 'completed'
                            ? 'success'
                            : scan.status === 'failed'
                            ? 'destructive'
                            : 'secondary'
                        }
                      >
                        {scan.status}
                      </Badge>
                    </TableCell>
                    <TableCell>{scan.vulnerability_count}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          ) : (
            <p className="py-4 text-center text-muted-foreground">No scans yet</p>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
