# SafeMirror Demo Video Script

**Duration:** 5 minutes  
**Resolution:** 1920x1080  
**Tools:** OBS Studio, QuickTime, or similar

## Overview (0:00 - 0:30)

### Script
"Welcome to SafeMirror Enterprise - your secure package management solution."

"SafeMirror helps security teams scan, approve, and manage software packages before they enter your environment."

### Screen
- Show landing/login page
- Brief logo/branding shot

## Login & Dashboard (0:30 - 1:00)

### Script
"Let me show you the main dashboard."

"After logging in, you see an overview of your security posture - total packages, pending approvals, and vulnerability distribution."

### Screen
1. Login with demo credentials
2. Show dashboard with:
   - Summary cards
   - Severity pie chart
   - Recent activity

## Package Scanning (1:00 - 2:30)

### Script
"SafeMirror automatically scans packages for vulnerabilities."

"Let me show you a package with findings..."

### Screen
1. Navigate to Packages
2. Click on a package with vulnerabilities
3. Show:
   - Package details
   - CVE list with severity
   - CVSS scores
4. Highlight critical/high findings

### Script (continued)
"You can see each CVE with its severity, CVSS score, and description."

"Our policy engine automatically categorizes packages based on your security rules."

## Approval Workflow (2:30 - 3:30)

### Script
"Now let's look at the approval queue."

### Screen
1. Navigate to Approvals
2. Show pending approvals list
3. Click on a package

### Script (continued)
"Security analysts review packages and make approval decisions."

### Screen
4. Show approval dialog
5. Add a comment
6. Click Approve

### Script
"For efficiency, you can also batch approve low-risk packages."

### Screen
7. Show batch selection
8. Batch approve demonstration

## Reports (3:30 - 4:30)

### Script
"SafeMirror provides comprehensive reporting for compliance."

### Screen
1. Navigate to Reports > Vulnerabilities
2. Show vulnerability summary
3. Show trend chart

### Script (continued)
"You can export reports as PDF or CSV for audits."

### Screen
4. Click Export PDF
5. Show generated PDF

### Script
"The audit log tracks every action in the system for compliance."

### Screen
6. Navigate to Audit Log
7. Show audit entries with filters

## Admin Features (4:30 - 5:00)

### Script
"Finally, administrators can manage users, roles, and policies."

### Screen
1. Navigate to Settings > Users
2. Show user list
3. Quick view of role assignment

### Script
"SafeMirror's role-based access control ensures the right people have the right permissions."

### Screen
4. Show roles list
5. Show a role's permissions

### Closing
"Thank you for watching! Visit safemirror.io to get started."

## Recording Checklist

Before recording:
- [ ] Clean demo environment with sample data
- [ ] Browser in incognito/private mode
- [ ] Close unnecessary tabs/apps
- [ ] Disable notifications
- [ ] Test audio levels

During recording:
- [ ] Speak clearly and at moderate pace
- [ ] Pause on important screens
- [ ] Avoid mouse jitter
- [ ] Highlight with cursor, not clicks

After recording:
- [ ] Trim start/end
- [ ] Add intro/outro cards
- [ ] Add captions if needed
- [ ] Export at 1080p

## Demo Data Setup

```bash
# Create demo data
docker compose -f docker-compose.prod.yml exec api python -m enterprise.db.seed --demo

# This creates:
# - Demo user: demo@safemirror.io / Demo123!
# - Sample mirrors
# - Sample packages with vulnerabilities
# - Sample approval requests
```

## Sample Credentials

For the demo, use:
- **Email:** demo@safemirror.io
- **Password:** Demo123!

---

*Recording tip: Practice the script 2-3 times before recording.*
