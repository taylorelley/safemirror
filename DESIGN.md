# Automated Security-Scanned APT Mirror

## 1. Purpose
This system creates an internal APT mirror that only publishes packages that pass security checks.
It gives controlled, repeatable, and audited package updates.
It uses existing tools where possible.
It avoids custom package formats and keeps Debian/Ubuntu compatibility.

## 2. Summary
The mirror has two layers:

1. Staging mirror: exact copy of upstream repositories.
2. Approved mirror: filtered repository containing only scanned and approved packages.

A pipeline keeps the mirrors up to date:

1. Sync upstream into staging.
2. Identify new or changed packages.
3. Extract and scan the packages.
4. Approve or block each package based on policy.
5. Publish only approved packages.
6. Rescan existing packages as CVE data changes.

## 3. Scope
**In Scope**
- Ubuntu/Debian mirroring
- Vulnerability scanning
- Policy enforcement
- Signed repo publishing
- Automatic updates
- Basic audit logging

**Out of Scope**
- Custom package builds
- Creating patches for blocked packages
- Full dashboard UI

## 4. Architecture
```
                Upstream Repositories
                     (Ubuntu, Debian)
                           |
                           v
                 Staging Mirror (aptly)
                           |
                     Snapshot + Diff
                           |
                           v
                     Scan Pipeline
                   (Extract + Scan)
                           |
                 Approved Packages Only
                           v
                Approved Mirror (aptly)
                           |
                           v
                    Internal Clients
```

## 5. Components

### 5.1 Aptly
Handles mirroring, snapshots, diffs, and publishing.

### 5.2 Vulnerability Scanners
Trivy or Grype. Both output JSON and support Debian/Ubuntu CVEs.

### 5.3 Scanner Worker
Downloads .deb, extracts it, scans, writes status.

### 5.4 Publisher
Builds filtered snapshots and publishes them.

### 5.5 Web Server
HTTPS server (nginx/Apache) serving /var/lib/aptly/public.

## 6. Workflow

### 6.1 Sync
```
aptly mirror update <mirror>
aptly snapshot create staging-YYYYMMDD
```

### 6.2 Detect Changes
```
aptly snapshot diff old new
```

### 6.3 Scan Packages
Extract and scan each changed package. Store results.

### 6.4 Build Approved List
List of approved package keys.

### 6.5 Publish Approved Mirror
```
aptly snapshot filter staging-20251119 approved-20251119 -include-file=approved.txt
aptly publish switch jammy approved-20251119
```

### 6.6 Client Updates
Clients use:
```
deb https://apt.internal.example.com jammy main restricted universe multiverse
```

## 7. Security Controls
- Harden mirror server
- Restricted GPG key
- HTTPS only
- Logging of sync, scan, publish events
- Optional firewall rules

## 8. Rescanning and CVE Drift
Nightly rescans. Remove packages that become unsafe.

## 9. Monitoring and Logging
Logs:
- Sync runs
- Scan results
- Publish events

## 10. Failure Modes
| Failure | Mitigation |
|--------|------------|
| Upstream unavailable | Retry or alternate mirrors |
| Scanner fails | Block by default |
| CVE feed outdated | Force update |
| GPG issues | Key rotation |
| Publish fails | Revert previous snapshot |

## 11. Future Extensions
- Metrics
- Web dashboard
- Manual review zone
- Multi-distro support
- Notifications

## 12. Example Directory Layout
```
/opt/apt-mirror-system/
    scans/
    snapshots/
    approvals/
    logs/
    scripts/
```

## 13. Risks
- False positives
- Scanner delays
- Strict policies may remove packages quickly
- CVE feed reliance

## 14. Conclusion
This design provides a controlled APT mirror that only publishes scanned packages, using standard tools and minimal custom code.
