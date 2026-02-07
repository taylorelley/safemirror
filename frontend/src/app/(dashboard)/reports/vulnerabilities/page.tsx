'use client';

import { useQuery } from '@tanstack/react-query';
import Link from 'next/link';
import api from '@/lib/api';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Table, TableHeader, TableBody, TableRow, TableHead, TableCell } from '@/components/ui/table';
import { PageLoading } from '@/components/ui/loading';
import { SeverityChart } from '@/components/charts/severity-chart';
import { getSeverityColor, formatDate } from '@/lib/utils';
import { ShieldAlert, Download, ExternalLink } from 'lucide-react';
import { jsPDF } from 'jspdf';

export default function VulnerabilityReportPage() {
  const { data: report, isLoading } = useQuery({
    queryKey: ['vulnerability-report'],
    queryFn: () => api.getVulnerabilityReport(),
  });

  const exportPdf = () => {
    if (!report) return;

    const doc = new jsPDF();
    doc.setFontSize(20);
    doc.text('Vulnerability Report', 20, 20);
    doc.setFontSize(12);
    doc.text('Generated: ' + new Date().toLocaleString(), 20, 30);
    doc.text('Total Vulnerabilities: ' + report.summary.total, 20, 45);

    let y = 60;
    Object.entries(report.summary.by_severity).forEach(([severity, count]) => {
      doc.text(severity.charAt(0).toUpperCase() + severity.slice(1) + ': ' + count, 20, y);
      y += 10;
    });

    y += 10;
    doc.setFontSize(14);
    doc.text('Vulnerability Details', 20, y);
    y += 10;
    doc.setFontSize(10);

    report.vulnerabilities.slice(0, 20).forEach((vuln) => {
      if (y > 270) {
        doc.addPage();
        y = 20;
      }
      doc.text((vuln.cve_id || 'N/A') + ' - ' + vuln.title.substring(0, 60), 20, y);
      y += 7;
    });

    doc.save('vulnerability-report.pdf');
  };

  if (isLoading) return <PageLoading />;
  if (!report) return <div>Failed to load report</div>;

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold">Vulnerability Report</h1>
          <p className="text-muted-foreground">
            Generated {formatDate(report.generated_at)}
          </p>
        </div>
        <Button onClick={exportPdf}>
          <Download className="mr-2 h-4 w-4" />
          Export PDF
        </Button>
      </div>

      <div className="grid gap-6 md:grid-cols-2">
        {/* Summary Stats */}
        <Card>
          <CardHeader>
            <CardTitle>Summary</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <span className="text-2xl font-bold">{report.summary.total}</span>
                <span className="text-muted-foreground">Total Vulnerabilities</span>
              </div>
              <div className="space-y-2">
                {Object.entries(report.summary.by_severity).map(([severity, count]) => (
                  <div key={severity} className="flex items-center justify-between">
                    <Badge className={getSeverityColor(severity)}>{severity}</Badge>
                    <span className="font-medium">{count as number}</span>
                  </div>
                ))}
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Severity Chart */}
        <Card>
          <CardHeader>
            <CardTitle>Severity Distribution</CardTitle>
          </CardHeader>
          <CardContent>
            <SeverityChart data={report.summary.by_severity} />
          </CardContent>
        </Card>
      </div>

      {/* Vulnerability List */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <ShieldAlert className="h-5 w-5" />
            All Vulnerabilities
          </CardTitle>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>CVE ID</TableHead>
                <TableHead>Title</TableHead>
                <TableHead>Severity</TableHead>
                <TableHead>CVSS</TableHead>
                <TableHead>Affected Packages</TableHead>
                <TableHead></TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {report.vulnerabilities.map((vuln) => (
                <TableRow key={vuln.id}>
                  <TableCell className="font-mono">
                    {vuln.cve_id ? (
                      <Link
                        href={'/reports/vulnerabilities/' + vuln.cve_id}
                        className="text-primary hover:underline"
                      >
                        {vuln.cve_id}
                      </Link>
                    ) : (
                      'N/A'
                    )}
                  </TableCell>
                  <TableCell className="max-w-md truncate">{vuln.title}</TableCell>
                  <TableCell>
                    <Badge className={getSeverityColor(vuln.severity)}>{vuln.severity}</Badge>
                  </TableCell>
                  <TableCell>{vuln.cvss_score?.toFixed(1) || '-'}</TableCell>
                  <TableCell>{vuln.affected_packages?.length || 0}</TableCell>
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
        </CardContent>
      </Card>
    </div>
  );
}
