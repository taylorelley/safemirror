'use client';

import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import api from '@/lib/api';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Select } from '@/components/ui/select';
import { Badge } from '@/components/ui/badge';
import { Checkbox } from '@/components/ui/checkbox';
import { Table, TableHeader, TableBody, TableRow, TableHead, TableCell } from '@/components/ui/table';
import { PageLoading } from '@/components/ui/loading';
import { useToast } from '@/components/ui/toast';
import { getStatusColor, formatDateTime } from '@/lib/utils';
import { CheckSquare, Check, X, Loader2 } from 'lucide-react';

export default function ApprovalsPage() {
  const [status, setStatus] = useState('pending');
  const [page, setPage] = useState(1);
  const [selected, setSelected] = useState<string[]>([]);
  const { addToast } = useToast();
  const queryClient = useQueryClient();

  const { data, isLoading } = useQuery({
    queryKey: ['approvals', { status, page }],
    queryFn: () => api.getApprovals({ status, page }),
  });

  const approveMutation = useMutation({
    mutationFn: (id: string) => api.approveRequest(id),
    onSuccess: () => {
      addToast({ title: 'Approved', description: 'Request has been approved', variant: 'success' });
      queryClient.invalidateQueries({ queryKey: ['approvals'] });
      setSelected([]);
    },
  });

  const rejectMutation = useMutation({
    mutationFn: (id: string) => api.rejectRequest(id),
    onSuccess: () => {
      addToast({ title: 'Rejected', description: 'Request has been rejected' });
      queryClient.invalidateQueries({ queryKey: ['approvals'] });
      setSelected([]);
    },
  });

  const batchApproveMutation = useMutation({
    mutationFn: (ids: string[]) => api.batchApprove(ids),
    onSuccess: () => {
      addToast({ title: 'Batch approved', description: selected.length + ' requests approved', variant: 'success' });
      queryClient.invalidateQueries({ queryKey: ['approvals'] });
      setSelected([]);
    },
  });

  const batchRejectMutation = useMutation({
    mutationFn: (ids: string[]) => api.batchReject(ids),
    onSuccess: () => {
      addToast({ title: 'Batch rejected', description: selected.length + ' requests rejected' });
      queryClient.invalidateQueries({ queryKey: ['approvals'] });
      setSelected([]);
    },
  });

  const toggleSelect = (id: string) => {
    setSelected((prev) =>
      prev.includes(id) ? prev.filter((i) => i !== id) : [...prev, id]
    );
  };

  const toggleSelectAll = () => {
    if (data?.items) {
      if (selected.length === data.items.length) {
        setSelected([]);
      } else {
        setSelected(data.items.map((a) => a.id));
      }
    }
  };

  const statusOptions = [
    { value: 'pending', label: 'Pending' },
    { value: 'approved', label: 'Approved' },
    { value: 'rejected', label: 'Rejected' },
    { value: '', label: 'All' },
  ];

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold">Approval Queue</h1>
        <p className="text-muted-foreground">Review and manage package approval requests</p>
      </div>

      <Card>
        <CardHeader>
          <div className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
            <CardTitle className="flex items-center gap-2">
              <CheckSquare className="h-5 w-5" />
              Approval Requests
            </CardTitle>
            <div className="flex items-center gap-2">
              <Select
                options={statusOptions}
                value={status}
                onChange={(e) => {
                  setStatus(e.target.value);
                  setPage(1);
                }}
                className="w-40"
              />
              {selected.length > 0 && status === 'pending' && (
                <>
                  <Button
                    size="sm"
                    onClick={() => batchApproveMutation.mutate(selected)}
                    disabled={batchApproveMutation.isPending}
                  >
                    <Check className="mr-1 h-4 w-4" />
                    Approve ({selected.length})
                  </Button>
                  <Button
                    size="sm"
                    variant="destructive"
                    onClick={() => batchRejectMutation.mutate(selected)}
                    disabled={batchRejectMutation.isPending}
                  >
                    <X className="mr-1 h-4 w-4" />
                    Reject ({selected.length})
                  </Button>
                </>
              )}
            </div>
          </div>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <PageLoading />
          ) : !data?.items.length ? (
            <div className="py-12 text-center text-muted-foreground">
              No approval requests found
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  {status === 'pending' && (
                    <TableHead className="w-12">
                      <Checkbox
                        checked={data.items.length > 0 && selected.length === data.items.length}
                        onChange={toggleSelectAll}
                      />
                    </TableHead>
                  )}
                  <TableHead>Package</TableHead>
                  <TableHead>Requested By</TableHead>
                  <TableHead>Requested At</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Reviewed By</TableHead>
                  {status === 'pending' && <TableHead>Actions</TableHead>}
                </TableRow>
              </TableHeader>
              <TableBody>
                {data.items.map((approval) => (
                  <TableRow key={approval.id}>
                    {status === 'pending' && (
                      <TableCell>
                        <Checkbox
                          checked={selected.includes(approval.id)}
                          onChange={() => toggleSelect(approval.id)}
                        />
                      </TableCell>
                    )}
                    <TableCell className="font-medium">{approval.package_name}</TableCell>
                    <TableCell>{approval.requested_by}</TableCell>
                    <TableCell>{formatDateTime(approval.requested_at)}</TableCell>
                    <TableCell>
                      <Badge className={getStatusColor(approval.status)}>{approval.status}</Badge>
                    </TableCell>
                    <TableCell>{approval.reviewed_by || '-'}</TableCell>
                    {status === 'pending' && (
                      <TableCell>
                        <div className="flex gap-1">
                          <Button
                            size="sm"
                            variant="outline"
                            onClick={() => approveMutation.mutate(approval.id)}
                            disabled={approveMutation.isPending}
                          >
                            <Check className="h-4 w-4" />
                          </Button>
                          <Button
                            size="sm"
                            variant="outline"
                            onClick={() => rejectMutation.mutate(approval.id)}
                            disabled={rejectMutation.isPending}
                          >
                            <X className="h-4 w-4" />
                          </Button>
                        </div>
                      </TableCell>
                    )}
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
