'use client';

import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import api from '@/lib/api';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Checkbox } from '@/components/ui/checkbox';
import { PageLoading } from '@/components/ui/loading';
import { useToast } from '@/components/ui/toast';
import { Settings, Mail, Webhook, Key, Save } from 'lucide-react';

export default function SettingsPage() {
  const { addToast } = useToast();
  const queryClient = useQueryClient();

  const { data: settings, isLoading } = useQuery({
    queryKey: ['notification-settings'],
    queryFn: () => api.getNotificationSettings(),
  });

  const [emailEnabled, setEmailEnabled] = useState(false);
  const [emailRecipients, setEmailRecipients] = useState('');
  const [webhookEnabled, setWebhookEnabled] = useState(false);
  const [webhookUrl, setWebhookUrl] = useState('');

  // Initialize form when settings load
  useState(() => {
    if (settings) {
      setEmailEnabled(settings.email_enabled);
      setEmailRecipients(settings.email_recipients?.join(', ') || '');
      setWebhookEnabled(settings.webhook_enabled);
      setWebhookUrl(settings.webhook_url || '');
    }
  });

  const updateMutation = useMutation({
    mutationFn: () =>
      api.updateNotificationSettings({
        email_enabled: emailEnabled,
        email_recipients: emailRecipients.split(',').map((e) => e.trim()).filter(Boolean),
        webhook_enabled: webhookEnabled,
        webhook_url: webhookUrl || undefined,
      }),
    onSuccess: () => {
      addToast({ title: 'Settings saved', variant: 'success' });
      queryClient.invalidateQueries({ queryKey: ['notification-settings'] });
    },
    onError: (error) => {
      addToast({ title: 'Failed to save', description: error.message, variant: 'destructive' });
    },
  });

  if (isLoading) return <PageLoading />;

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold">System Settings</h1>
        <p className="text-muted-foreground">Configure notifications and integrations</p>
      </div>

      <div className="grid gap-6">
        {/* Email Notifications */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Mail className="h-5 w-5" />
              Email Notifications
            </CardTitle>
            <CardDescription>Configure email alerts for security events</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="flex items-center gap-3">
              <Checkbox
                id="email-enabled"
                checked={emailEnabled}
                onChange={(e) => setEmailEnabled(e.target.checked)}
              />
              <Label htmlFor="email-enabled">Enable email notifications</Label>
            </div>
            <div className="space-y-2">
              <Label htmlFor="email-recipients">Recipients (comma-separated)</Label>
              <Input
                id="email-recipients"
                type="text"
                placeholder="admin@example.com, security@example.com"
                value={emailRecipients}
                onChange={(e) => setEmailRecipients(e.target.value)}
                disabled={!emailEnabled}
              />
            </div>
          </CardContent>
        </Card>

        {/* Webhook Notifications */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Webhook className="h-5 w-5" />
              Webhook Integration
            </CardTitle>
            <CardDescription>Send events to external systems via webhooks</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="flex items-center gap-3">
              <Checkbox
                id="webhook-enabled"
                checked={webhookEnabled}
                onChange={(e) => setWebhookEnabled(e.target.checked)}
              />
              <Label htmlFor="webhook-enabled">Enable webhook notifications</Label>
            </div>
            <div className="space-y-2">
              <Label htmlFor="webhook-url">Webhook URL</Label>
              <Input
                id="webhook-url"
                type="url"
                placeholder="https://your-webhook.example.com/events"
                value={webhookUrl}
                onChange={(e) => setWebhookUrl(e.target.value)}
                disabled={!webhookEnabled}
              />
            </div>
          </CardContent>
        </Card>

        {/* SSO Configuration */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Key className="h-5 w-5" />
              SSO Configuration
            </CardTitle>
            <CardDescription>Configure Single Sign-On with your identity provider</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="sso-provider">Identity Provider</Label>
              <Input id="sso-provider" type="text" placeholder="OIDC / SAML" disabled />
            </div>
            <div className="space-y-2">
              <Label htmlFor="sso-issuer">Issuer URL</Label>
              <Input id="sso-issuer" type="url" placeholder="https://auth.example.com" disabled />
            </div>
            <p className="text-sm text-muted-foreground">
              SSO configuration is managed via environment variables. Contact your administrator.
            </p>
          </CardContent>
        </Card>
      </div>

      <div className="flex justify-end">
        <Button
          onClick={() => updateMutation.mutate()}
          disabled={updateMutation.isPending}
        >
          <Save className="mr-2 h-4 w-4" />
          {updateMutation.isPending ? 'Saving...' : 'Save Settings'}
        </Button>
      </div>
    </div>
  );
}
