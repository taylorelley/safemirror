'use client';

import { useQuery } from '@tanstack/react-query';
import { useParams } from 'next/navigation';
import api from '@/lib/api';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Table, TableHeader, TableBody, TableRow, TableHead, TableCell } from '@/components/ui/table';
import { PageLoading } from '@/components/ui/loading';
import { getSeverityColor } from '@/lib/utils';
import { ShieldAlert, ExternalLink, AlertTriangle } from 'lucide-react';

export default function CVEDetailPage() {
  const params = useParams();
  const cveId = params.cve as string;

  const { data: vuln, isLoading } = useQuery({
    queryKey: ['vulnerability', cveId],
    queryFn: () => api.getVulnerability(cveId),
  });

  if (isLoading) return <PageLoading />;
  if (!vuln) return <div>Vulnerability not found</div>;

  return (
    <div className="space-y-6">
      <div>
        <div className="flex items-center gap-3">
          <ShieldAlert className="h-8 w-8 text-destructive" />
          <h1 className="text-3xl font-bold">{vuln.cve_id || 'Unknown CVE'}</h1>
          <Badge className={getSeverityColor(vuln.severity)}>{vuln.severity}</Badge>
        </div>
        <p className="mt-2 text-xl text-muted-foreground">{vuln.title}</p>
      </div>

      <div className="grid gap-6 md:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>Details</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div>
              <p className="text-sm text-muted-foreground">CVSS Score</p>
              <div className="flex items-center gap-2">
                <span className="text-3xl font-bold">{vuln.cvss_score?.toFixed(1) || 'N/A'}</span>
                {vuln.cvss_score && vuln.cvss_score >= 9 && (
                  <AlertTriangle className="h-5 w-5 text-red-500" />
                )}
              </div>
            </div>
            {vuln.fixed_version && (
              <div>
                <p className="text-sm text-muted-foreground">Fixed In Version</p>
                <p className="font-mono font-medium">{vuln.fixed_version}</p>
              </div>
            )}
            {vuln.published_at && (
              <div>
                <p className="text-sm text-muted-foreground">Published</p>
                <p>{new Date(vuln.published_at).toLocaleDateString()}</p>
              </div>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>External References</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              {vuln.cve_id && (
                <>
                  <a
                    href={'https://nvd.nist.gov/vuln/detail/' + vuln.cve_id}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="flex items-center gap-2 text-primary hover:underline"
                  >
                    <ExternalLink className="h-4 w-4" />
                    NVD Database
                  </a>
                  <a
                    href={'https://cve.mitre.org/cgi-bin/cvename.cgi?name=' + vuln.cve_id}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="flex items-center gap-2 text-primary hover:underline"
                  >
                    <ExternalLink className="h-4 w-4" />
                    MITRE CVE
                  </a>
                </>
              )}
              {vuln.references?.map((ref, i) => (
                <a
                  key={i}
                  href={ref}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="flex items-center gap-2 text-primary hover:underline"
                >
                  <ExternalLink className="h-4 w-4" />
                  {new URL(ref).hostname}
                </a>
              ))}
            </div>
          </CardContent>
        </Card>
      </div>

      {vuln.description && (
        <Card>
          <CardHeader>
            <CardTitle>Description</CardTitle>
          </CardHeader>
          <CardContent>
            <p className="whitespace-pre-wrap">{vuln.description}</p>
          </CardContent>
        </Card>
      )}

      <Card>
        <CardHeader>
          <CardTitle>Affected Packages ({vuln.affected_packages?.length || 0})</CardTitle>
        </CardHeader>
        <CardContent>
          {vuln.affected_packages?.length ? (
            <div className="grid gap-2 md:grid-cols-2 lg:grid-cols-3">
              {vuln.affected_packages.map((pkg, i) => (
                <div key={i} className="rounded-md bg-muted p-3 font-mono text-sm">
                  {pkg}
                </div>
              ))}
            </div>
          ) : (
            <p className="text-muted-foreground">No affected packages listed</p>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
