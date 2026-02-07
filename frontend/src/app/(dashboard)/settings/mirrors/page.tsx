'use client';

import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import api from '@/lib/api';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Select } from '@/components/ui/select';
import { Badge } from '@/components/ui/badge';
import { Table, TableHeader, TableBody, TableRow, TableHead, TableCell } from '@/components/ui/table';
import { PageLoading } from '@/components/ui/loading';
import { useToast } from '@/components/ui/toast';
import { getStatusColor, formatDateTime } from '@/lib/utils';
import { Database, Plus, RefreshCw, Trash2, X } from 'lucide-react';

export default function MirrorsPage() {
  const [showModal, setShowModal] = useState(false);
  const [formData, setFormData] = useState({
    name: '',
    type: 'npm' as const,
    url: '',
  });
  const { addToast } = useToast();
  const queryClient = useQueryClient();

  const { data: mirrors, isLoading } = useQuery({
    queryKey: ['mirrors'],
    queryFn: () => api.getMirrors(),
  });

  const createMutation = useMutation({
    mutationFn: (data: typeof formData) => api.createMirror(data),
    onSuccess: () => {
      addToast({ title: 'Mirror created', variant: 'success' });
      queryClient.invalidateQueries({ queryKey: ['mirrors'] });
      setShowModal(false);
      setFormData({ name: '', type: 'npm', url: '' });
    },
    onError: (error) => {
      addToast({ title: 'Failed to create mirror', description: error.message, variant: 'destructive' });
    },
  });

  const syncMutation = useMutation({
    mutationFn: (id: string) => api.syncMirror(id),
    onSuccess: () => {
      addToast({ title: 'Sync started', description: 'Mirror sync has been initiated', variant: 'success' });
      queryClient.invalidateQueries({ queryKey: ['mirrors'] });
    },
    onError: (error) => {
      addToast({ title: 'Sync failed', description: error.message, variant: 'destructive' });
    },
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => api.deleteMirror(id),
    onSuccess: () => {
      addToast({ title: 'Mirror deleted', variant: 'success' });
      queryClient.invalidateQueries({ queryKey: ['mirrors'] });
    },
    onError: (error) => {
      addToast({ title: 'Failed to delete mirror', description: error.message, variant: 'destructive' });
    },
  });

  const typeOptions = [
    { value: 'npm', label: 'NPM' },
    { value: 'pypi', label: 'PyPI' },
    { value: 'maven', label: 'Maven' },
    { value: 'docker', label: 'Docker' },
  ];

  if (isLoading) return <PageLoading />;

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold">Mirrors</h1>
          <p className="text-muted-foreground">Manage package repository mirrors</p>
        </div>
        <Button onClick={() => setShowModal(true)}>
          <Plus className="mr-2 h-4 w-4" />
          Add Mirror
        </Button>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Database className="h-5 w-5" />
            Mirror List
          </CardTitle>
        </CardHeader>
        <CardContent>
          {!mirrors?.length ? (
            <div className="py-12 text-center text-muted-foreground">
              No mirrors configured
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Name</TableHead>
                  <TableHead>Type</TableHead>
                  <TableHead>URL</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Packages</TableHead>
                  <TableHead>Last Sync</TableHead>
                  <TableHead></TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {mirrors.map((mirror) => (
                  <TableRow key={mirror.id}>
                    <TableCell className="font-medium">{mirror.name}</TableCell>
                    <TableCell>
                      <Badge variant="outline">{mirror.type.toUpperCase()}</Badge>
                    </TableCell>
                    <TableCell className="max-w-xs truncate font-mono text-sm">
                      {mirror.url}
                    </TableCell>
                    <TableCell>
                      <Badge className={getStatusColor(mirror.status)}>{mirror.status}</Badge>
                    </TableCell>
                    <TableCell>{mirror.package_count.toLocaleString()}</TableCell>
                    <TableCell className="text-muted-foreground">
                      {mirror.last_sync ? formatDateTime(mirror.last_sync) : 'Never'}
                    </TableCell>
                    <TableCell>
                      <div className="flex gap-1">
                        <Button
                          size="sm"
                          variant="outline"
                          onClick={() => syncMutation.mutate(mirror.id)}
                          disabled={syncMutation.isPending || mirror.status === 'syncing'}
                        >
                          <RefreshCw className="h-4 w-4" />
                        </Button>
                        <Button
                          size="sm"
                          variant="outline"
                          onClick={() => {
                            if (confirm('Are you sure you want to delete this mirror?')) {
                              deleteMutation.mutate(mirror.id);
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

      {/* Add Mirror Modal */}
      {showModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50">
          <Card className="w-full max-w-md">
            <CardHeader>
              <div className="flex items-center justify-between">
                <CardTitle>Add New Mirror</CardTitle>
                <Button variant="ghost" size="icon" onClick={() => setShowModal(false)}>
                  <X className="h-4 w-4" />
                </Button>
              </div>
            </CardHeader>
            <CardContent>
              <form
                onSubmit={(e) => {
                  e.preventDefault();
                  createMutation.mutate(formData);
                }}
                className="space-y-4"
              >
                <div className="space-y-2">
                  <Label htmlFor="name">Name</Label>
                  <Input
                    id="name"
                    value={formData.name}
                    onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                    placeholder="NPM Registry"
                    required
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="type">Type</Label>
                  <Select
                    options={typeOptions}
                    value={formData.type}
                    onChange={(e) => setFormData({ ...formData, type: e.target.value as typeof formData.type })}
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="url">Repository URL</Label>
                  <Input
                    id="url"
                    type="url"
                    value={formData.url}
                    onChange={(e) => setFormData({ ...formData, url: e.target.value })}
                    placeholder="https://registry.npmjs.org"
                    required
                  />
                </div>
                <div className="flex justify-end gap-2 pt-4">
                  <Button type="button" variant="outline" onClick={() => setShowModal(false)}>
                    Cancel
                  </Button>
                  <Button type="submit" disabled={createMutation.isPending}>
                    {createMutation.isPending ? 'Creating...' : 'Create Mirror'}
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
