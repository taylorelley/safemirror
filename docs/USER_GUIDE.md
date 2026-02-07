# SafeMirror Enterprise - User Guide

Welcome to SafeMirror Enterprise! This guide will help you get started with the platform.

## Table of Contents

1. [Getting Started](#getting-started)
2. [Dashboard Overview](#dashboard-overview)
3. [Package Management](#package-management)
4. [Approval Workflows](#approval-workflows)
5. [Reports](#reports)
6. [Settings](#settings)
7. [Role-Specific Workflows](#role-specific-workflows)
8. [FAQ](#faq)

---

## Getting Started

### Logging In

1. Navigate to your SafeMirror instance (e.g., `https://safemirror.example.com`)
2. Enter your email and password
3. Click **Sign In**

If you have SSO configured, click **Sign in with SSO** and follow your organization's login flow.

### First-Time Setup

After logging in for the first time:

1. **Update your password** (if using temporary credentials)
2. **Configure notifications** in Settings > Notifications
3. **Explore the dashboard** to see your organization's security posture

---

## Dashboard Overview

The dashboard provides a real-time view of your package security status.

### Key Metrics

| Metric | Description |
|--------|-------------|
| **Total Packages** | Number of packages in your mirrors |
| **Pending Approvals** | Packages awaiting review |
| **Critical Vulnerabilities** | High-priority security issues |
| **Approved This Week** | Recently approved packages |

### Severity Distribution

The pie chart shows vulnerability severity breakdown:
- 🔴 **Critical**: Immediate action required
- 🟠 **High**: Address within 24 hours
- 🟡 **Medium**: Address within 7 days
- 🔵 **Low**: Address as time permits

### Trend Chart

Shows vulnerability and package counts over time to identify trends.

---

## Package Management

### Viewing Packages

1. Navigate to **Packages** in the sidebar
2. Use filters to narrow results:
   - **Status**: Approved, Pending, Rejected
   - **Type**: deb, rpm, npm, etc.
   - **Mirror**: Filter by source mirror
   - **Severity**: Filter by vulnerability severity

### Package Details

Click any package to view:
- **Basic Info**: Name, version, type, maintainer
- **Vulnerabilities**: List of CVEs and severity
- **Scan Results**: Detailed security scan output
- **Approval History**: Past approval decisions

### Searching Packages

Use the search bar to find packages by:
- Package name
- CVE ID
- Maintainer

---

## Approval Workflows

### Understanding the Workflow

```
Package Uploaded → Scanned → Policy Evaluated → Pending Review → Approved/Rejected
```

### Approval Queue

Navigate to **Approvals** to see packages awaiting review.

#### Quick Actions
- ✅ **Approve**: Mark package as safe for use
- ❌ **Reject**: Block package from use
- 👁️ **View Details**: See full scan results

### Approving a Package

1. Click a package in the queue
2. Review:
   - Vulnerability list
   - Scan results
   - Policy evaluation
3. Add an optional comment
4. Click **Approve** or **Reject**

### Batch Approvals

For efficiency with multiple low-risk packages:

1. Select multiple packages using checkboxes
2. Click **Batch Approve** or **Batch Reject**
3. Confirm the action

**Note**: Batch actions are logged individually in the audit trail.

### Approval Policies

Policies automatically evaluate packages:

| Policy | Auto-Action | Description |
|--------|-------------|-------------|
| Strict | Review | No critical/high CVEs |
| Moderate | Review | Allows high with review |
| Permissive | Auto-Approve | Only blocks critical |

Contact your admin to configure policies.

---

## Reports

### Vulnerability Report

Navigate to **Reports > Vulnerabilities**

Features:
- **Summary**: Total CVEs by severity
- **Trend**: Vulnerability count over time
- **Details**: Sortable table of all CVEs
- **Export**: Download as CSV or PDF

### Compliance Report

Navigate to **Reports > Compliance**

Shows:
- Policy compliance percentage
- Failed policy checks
- Remediation recommendations

### Audit Log

Navigate to **Audit Log**

View all system actions:
- User logins
- Approval decisions
- Configuration changes
- API access

#### Filtering Audit Logs
- **Date Range**: Select time period
- **User**: Filter by specific user
- **Action**: Type of action (create, update, delete)
- **Resource**: Type of resource affected

---

## Settings

### Notification Preferences

Configure how you receive alerts:

1. Go to **Settings > Notifications**
2. Toggle preferences:
   - 📧 **Email**: Receive email notifications
   - 🔔 **In-App**: Browser notifications
   - 🌐 **Webhooks**: Send to external systems

3. Select events to be notified about:
   - New packages pending approval
   - Critical vulnerabilities detected
   - Approval requests for you
   - Policy violations

### Profile Settings

Update your profile:
- Display name
- Email address
- Password
- API keys (for automation)

### API Keys

For automation and integrations:

1. Go to **Settings > API Keys**
2. Click **Generate New Key**
3. Name your key and set expiration
4. Copy the key (shown only once!)

**API Key Format**: `sm_xxxxxxxxxxxxxxxxxxxx`

---

## Role-Specific Workflows

### For Security Analysts

Your daily workflow:

1. **Check Dashboard** for new critical vulnerabilities
2. **Review Approval Queue** - prioritize by severity
3. **Approve/Reject** packages with comments
4. **Generate Reports** for stakeholders

**Tips**:
- Use keyboard shortcuts: `a` to approve, `r` to reject
- Batch approve low-risk packages
- Add detailed comments for rejections

### For Developers

Your workflow:

1. **Search Packages** you need to use
2. **Check Status** - is it approved?
3. **Request Approval** if pending
4. **View Reports** for your project's dependencies

**Tips**:
- Subscribe to notifications for packages you use
- Check the vulnerability trend before choosing packages

### For Administrators

Your responsibilities:

1. **User Management**: Create/modify user accounts
2. **Role Assignment**: Assign appropriate roles
3. **Policy Configuration**: Set security policies
4. **System Monitoring**: Check audit logs regularly
5. **Report Generation**: Compliance reports for audits

See [ADMIN_GUIDE.md](ADMIN_GUIDE.md) for detailed instructions.

---

## FAQ

### How do I reset my password?

1. Go to the login page
2. Click **Forgot Password**
3. Enter your email
4. Check your email for reset link
5. Create new password

### Why was my package rejected?

View the rejection reason:
1. Find the package in **Packages**
2. Check **Approval History**
3. See the rejection comment and CVE list

### Can I request re-scan of a package?

Yes, if you have the `packages:scan` permission:
1. Open package details
2. Click **Request Re-scan**
3. New results will appear when complete

### How do I integrate with CI/CD?

Use the SafeMirror API:

```bash
# Check if package is approved
curl -X GET "https://safemirror.example.com/api/packages/check?name=nginx&version=1.24.0" \
  -H "X-API-Key: sm_your_api_key"

# Response
{"approved": true, "last_scan": "2026-02-07T12:00:00Z"}
```

### Who can I contact for help?

- **In-app**: Use the Help icon in the top right
- **Email**: support@safemirror.io
- **Documentation**: https://docs.safemirror.io

---

## Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| `g d` | Go to Dashboard |
| `g p` | Go to Packages |
| `g a` | Go to Approvals |
| `g r` | Go to Reports |
| `/` | Focus search |
| `a` | Approve (in detail view) |
| `r` | Reject (in detail view) |
| `?` | Show shortcuts |

---

*Need help? Contact support@safemirror.io*
