'use client';

import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import api from '@/lib/api';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Badge } from '@/components/ui/badge';
import { Checkbox } from '@/components/ui/checkbox';
import { Table, TableHeader, TableBody, TableRow, TableHead, TableCell } from '@/components/ui/table';
import { PageLoading } from '@/components/ui/loading';
import { useToast } from '@/components/ui/toast';
import { formatDate } from '@/lib/utils';
import { ShieldAlert, Plus, Trash2, X, Power, PowerOff } from 'lucide-react';
import type { Policy } from '@/types';

export default function PoliciesPage() {
  const [showModal, setShowModal] = useState(false);
  const [formData, setFormData] = useState({
    name: '',
    description: '',
  });
  const { addToast } = useToast();
  const queryClient = useQueryClient();

  const { data: policies, isLoading } = useQuery({
    queryKey: ['policies'],
    queryFn: () => api.getPolicies(),
  });

  const createMutation = useMutation({
    mutationFn: (data: Partial<Policy>) => api.createPolicy(data),
    onSuccess: () => {
      addToast({ title: 'Policy created', variant: 'success' });
      queryClient.invalidateQueries({ queryKey: ['policies'] });
      setShowModal(false);
      setFormData({ name: '', description: '' });
    },
    onError: (error) => {
      addToast({ title: 'Failed to create policy', description: error.message, variant: 'destructive' });
    },
  });

  const toggleMutation = useMutation({
    mutationFn: ({ id, isActive }: { id: string; isActive: boolean }) =>
      api.togglePolicy(id, isActive),
    onSuccess: () => {
      addToast({ title: 'Policy updated', variant: 'success' });
      queryClient.invalidateQueries({ queryKey: ['policies'] });
    },
    onError: (error) => {
      addToast({ title: 'Failed to update policy', description: error.message, variant: 'destructive' });
    },
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => api.deletePolicy(id),
    onSuccess: () => {
      addToast({ title: 'Policy deleted', variant: 'success' });
      queryClient.invalidateQueries({ queryKey: ['policies'] });
    },
    onError: (error) => {
      addToast({ title: 'Failed to delete policy', description: error.message, variant: 'destructive' });
    },
  });

  if (isLoading) return <PageLoading />;

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold">Approval Policies</h1>
          <p className="text-muted-foreground">Configure automatic approval rules</p>
        </div>
        <Button onClick={() => setShowModal(true)}>
          <Plus className="mr-2 h-4 w-4" />
          Add Policy
        </Button>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <ShieldAlert className="h-5 w-5" />
            Policy List
          </CardTitle>
        </CardHeader>
        <CardContent>
          {!policies?.length ? (
            <div className="py-12 text-center text-muted-foreground">
              No policies configured
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Name</TableHead>
                  <TableHead>Description</TableHead>
                  <TableHead>Conditions</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Created</TableHead>
                  <TableHead></TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {policies.map((policy) => (
                  <TableRow key={policy.id}>
                    <TableCell className="font-medium">{policy.name}</TableCell>
                    <TableCell className="max-w-xs truncate text-muted-foreground">
                      {policy.description || '-'}
                    </TableCell>
                    <TableCell>
                      <Badge variant="outline">
                        {policy.conditions?.length || 0} conditions
                      </Badge>
                    </TableCell>
                    <TableCell>
                      <Badge variant={policy.is_active ? 'success' : 'secondary'}>
                        {policy.is_active ? 'Active' : 'Inactive'}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-muted-foreground">
                      {formatDate(policy.created_at)}
                    </TableCell>
                    <TableCell>
                      <div className="flex gap-1">
                        <Button
                          size="sm"
                          variant="outline"
                          onClick={() =>
                            toggleMutation.mutate({
                              id: policy.id,
                              isActive: !policy.is_active,
                            })
                          }
                          title={policy.is_active ? 'Disable' : 'Enable'}
                        >
                          {policy.is_active ? (
                            <PowerOff className="h-4 w-4" />
                          ) : (
                            <Power className="h-4 w-4" />
                          )}
                        </Button>
                        <Button
                          size="sm"
                          variant="outline"
                          onClick={() => {
                            if (confirm('Are you sure you want to delete this policy?')) {
                              deleteMutation.mutate(policy.id);
                            }
                          }}
                        >
                          <Trash2 className="h-4 w-4" />
                        </Button>
                      </div>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      {/* Add Policy Modal */}
      {showModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50">
          <Card className="w-full max-w-md">
            <CardHeader>
              <div className="flex items-center justify-between">
                <CardTitle>Add New Policy</CardTitle>
                <Button variant="ghost" size="icon" onClick={() => setShowModal(false)}>
                  <X className="h-4 w-4" />
                </Button>
              </div>
            </CardHeader>
            <CardContent>
              <form
                onSubmit={(e) => {
                  e.preventDefault();
                  createMutation.mutate({
                    name: formData.name,
                    description: formData.description,
                    is_active: true,
                    conditions: [],
                    actions: [],
                  });
                }}
                className="space-y-4"
              >
                <div className="space-y-2">
                  <Label htmlFor="name">Policy Name</Label>
                  <Input
                    id="name"
                    value={formData.name}
                    onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                    placeholder="Auto-approve low severity"
                    required
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="description">Description</Label>
                  <Input
                    id="description"
                    value={formData.description}
                    onChange={(e) => setFormData({ ...formData, description: e.target.value })}
                    placeholder="Automatically approve packages with only low severity vulnerabilities"
                  />
                </div>
                <div className="flex justify-end gap-2 pt-4">
                  <Button type="button" variant="outline" onClick={() => setShowModal(false)}>
                    Cancel
                  </Button>
                  <Button type="submit" disabled={createMutation.isPending}>
                    {createMutation.isPending ? 'Creating...' : 'Create Policy'}
                  </Button>
                </div>
              </form>
            </CardContent>
          </Card>
        </div>
      )}
    </div>
  );
}
