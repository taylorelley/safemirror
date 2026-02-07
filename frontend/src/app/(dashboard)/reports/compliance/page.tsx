'use client';

import { useQuery } from '@tanstack/react-query';
import api from '@/lib/api';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { PageLoading } from '@/components/ui/loading';
import { formatDate } from '@/lib/utils';
import { FileCheck, Download, CheckCircle, XCircle, AlertTriangle } from 'lucide-react';
import { jsPDF } from 'jspdf';

export default function ComplianceReportPage() {
  const { data: report, isLoading } = useQuery({
    queryKey: ['compliance-report'],
    queryFn: () => api.getComplianceReport(),
  });

  const exportPdf = () => {
    if (!report) return;

    const doc = new jsPDF();
    doc.setFontSize(20);
    doc.text('Compliance Report', 20, 20);
    doc.setFontSize(12);
    doc.text('Generated: ' + new Date().toLocaleString(), 20, 30);
    doc.text('Overall Status: ' + report.status.toUpperCase(), 20, 45);

    let y = 65;
    doc.setFontSize(14);
    doc.text('Policy Status', 20, y);
    y += 15;
    doc.setFontSize(10);

    report.policies.forEach((policy) => {
      if (y > 270) {
        doc.addPage();
        y = 20;
      }
      const icon = policy.status === 'pass' ? '[PASS]' : policy.status === 'fail' ? '[FAIL]' : '[WARN]';
      doc.text(icon + ' ' + policy.policy_name, 20, y);
      y += 7;
      if (policy.details) {
        doc.text('   ' + policy.details.substring(0, 80), 20, y);
        y += 7;
      }
    });

    doc.save('compliance-report.pdf');
  };

  if (isLoading) return <PageLoading />;
  if (!report) return <div>Failed to load report</div>;

  const StatusIcon = ({ status }: { status: string }) => {
    if (status === 'pass') return <CheckCircle className="h-5 w-5 text-green-500" />;
    if (status === 'fail') return <XCircle className="h-5 w-5 text-red-500" />;
    return <AlertTriangle className="h-5 w-5 text-yellow-500" />;
  };

  const getStatusBadge = (status: string) => {
    const variants: Record<string, string> = {
      compliant: 'bg-green-500 text-white',
      non_compliant: 'bg-red-500 text-white',
      partial: 'bg-yellow-500 text-black',
    };
    return variants[status] || 'bg-gray-500 text-white';
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold">Compliance Report</h1>
          <p className="text-muted-foreground">
            Generated {formatDate(report.generated_at)}
          </p>
        </div>
        <Button onClick={exportPdf}>
          <Download className="mr-2 h-4 w-4" />
          Export PDF
        </Button>
      </div>

      {/* Overall Status */}
      <Card>
        <CardContent className="py-8">
          <div className="flex items-center justify-center gap-4">
            {report.status === 'compliant' && (
              <CheckCircle className="h-16 w-16 text-green-500" />
            )}
            {report.status === 'non_compliant' && (
              <XCircle className="h-16 w-16 text-red-500" />
            )}
            {report.status === 'partial' && (
              <AlertTriangle className="h-16 w-16 text-yellow-500" />
            )}
            <div>
              <Badge className={getStatusBadge(report.status) + ' text-lg px-4 py-2'}>
                {report.status.replace('_', ' ').toUpperCase()}
              </Badge>
              <p className="mt-2 text-muted-foreground">
                {report.policies.filter((p) => p.status === 'pass').length} of {report.policies.length} policies passing
              </p>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Policy Details */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <FileCheck className="h-5 w-5" />
            Policy Status
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            {report.policies.map((policy) => (
              <div
                key={policy.policy_id}
                className="flex items-start gap-4 rounded-lg border p-4"
              >
                <StatusIcon status={policy.status} />
                <div className="flex-1">
                  <div className="flex items-center justify-between">
                    <h3 className="font-semibold">{policy.policy_name}</h3>
                    <Badge
                      variant={
                        policy.status === 'pass'
                          ? 'success'
                          : policy.status === 'fail'
                          ? 'destructive'
                          : 'warning'
                      }
                    >
                      {policy.status}
                    </Badge>
                  </div>
                  {policy.details && (
                    <p className="mt-1 text-sm text-muted-foreground">{policy.details}</p>
                  )}
                </div>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
