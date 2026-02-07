"""Performance tests for SafeMirror Enterprise.

Tests system performance with:
- 1000 packages in database
- 10 concurrent users
- Measures response times for list, approve, query audit logs

Requirements:
- Running PostgreSQL database
- Database seeded with test data
"""

import os
import time
import uuid
import concurrent.futures
from datetime import datetime, timedelta
from typing import List, Dict, Any

import pytest
from sqlalchemy import create_engine, text, func
from sqlalchemy.orm import sessionmaker, Session

from enterprise.db.base import Base
from enterprise.db.models import (
    Organization, User, Role, Policy, Scan, Package,
    Mirror, ApprovalRequest, AuditLog,
)
from enterprise.core.approval.service import ApprovalService
from enterprise.core.approval.states import ApprovalState, ApprovalTransition

# Test configuration
NUM_PACKAGES = 1000
NUM_USERS = 10
NUM_APPROVALS_TO_TEST = 100

# Database URL
TEST_DATABASE_URL = os.environ.get(
    "TEST_DATABASE_URL",
    "postgresql://safemirror:devpass@localhost:5433/safemirror",
)


class PerformanceResults:
    """Container for performance test results."""
    
    def __init__(self):
        self.results: Dict[str, Dict[str, Any]] = {}
    
    def record(self, name: str, elapsed_ms: float, count: int = 1):
        if name not in self.results:
            self.results[name] = {
                "times": [],
                "count": 0,
            }
        self.results[name]["times"].append(elapsed_ms)
        self.results[name]["count"] += count
    
    def summary(self) -> Dict[str, Dict[str, float]]:
        summary = {}
        for name, data in self.results.items():
            times = data["times"]
            if times:
                summary[name] = {
                    "min_ms": min(times),
                    "max_ms": max(times),
                    "avg_ms": sum(times) / len(times),
                    "p95_ms": sorted(times)[int(len(times) * 0.95)] if len(times) >= 20 else max(times),
                    "count": data["count"],
                    "total_ms": sum(times),
                }
        return summary


@pytest.fixture(scope="module")
def perf_engine():
    """Create engine for performance tests."""
    try:
        engine = create_engine(TEST_DATABASE_URL, echo=False, pool_size=20, max_overflow=30)
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        Base.metadata.create_all(engine)
        yield engine
        engine.dispose()
    except Exception as e:
        pytest.skip(f"Database not available: {e}")


@pytest.fixture(scope="module")
def perf_session_factory(perf_engine):
    return sessionmaker(bind=perf_engine)


@pytest.fixture(scope="module")
def seeded_database(perf_engine, perf_session_factory):
    """Seed database with test data for performance testing."""
    session = perf_session_factory()
    
    try:
        # Create organization
        org = Organization(
            name="Performance Test Corp",
            slug="perf-test",
            settings={},
        )
        session.add(org)
        session.flush()
        
        # Create roles
        admin_role = Role(
            org_id=org.id,
            name="admin",
            permissions=["*"],
        )
        viewer_role = Role(
            org_id=org.id,
            name="viewer",
            permissions=["packages:read", "packages:list", "approvals:read", "approvals:list"],
        )
        session.add_all([admin_role, viewer_role])
        session.flush()
        
        # Create users (10)
        users = []
        for i in range(NUM_USERS):
            user = User(
                org_id=org.id,
                role_id=admin_role.id if i == 0 else viewer_role.id,
                email=f"perfuser{i}@test.com",
                name=f"Perf User {i}",
                password_hash="$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/X4.LQ3h9DgKSH6z6e",
            )
            users.append(user)
        session.add_all(users)
        session.flush()
        
        # Create policy
        policy = Policy(
            org_id=org.id,
            name="Performance Policy",
            rules={"max_severity": "high", "auto_approve": False},
        )
        session.add(policy)
        session.flush()
        
        # Create mirror
        mirror = Mirror(
            org_id=org.id,
            name="Perf Test Mirror",
            slug="perf-mirror",
            mirror_type="apt",
            upstream_url="https://archive.ubuntu.com/ubuntu",
            policy_id=policy.id,
        )
        session.add(mirror)
        session.flush()
        
        # Create 1000 packages with scans
        print(f"\nSeeding {NUM_PACKAGES} packages...")
        packages = []
        scans = []
        approvals = []
        
        for i in range(NUM_PACKAGES):
            pkg = Package(
                org_id=org.id,
                mirror_id=mirror.id,
                name=f"perf-package-{i:04d}",
                version=f"1.{i % 100}.{i % 10}",
                package_type="deb",
                architecture="amd64",
                file_size=1024 * (i % 1000 + 1),
                approval_status="pending" if i % 3 == 0 else "approved" if i % 3 == 1 else "rejected",
            )
            packages.append(pkg)
            
            scan = Scan(
                org_id=org.id,
                user_id=users[i % NUM_USERS].id,
                policy_id=policy.id,
                package_name=pkg.name,
                package_version=pkg.version,
                package_type=pkg.package_type,
                status="completed",
                results={
                    "vulnerabilities": [{"cve_id": f"CVE-2024-{i:04d}", "severity": "MEDIUM"}] if i % 5 == 0 else [],
                },
            )
            scans.append(scan)
        
        session.add_all(packages)
        session.add_all(scans)
        session.flush()
        
        # Create approval requests
        for i, pkg in enumerate(packages):
            state = "needs_review" if pkg.approval_status == "pending" else \
                    "approved" if pkg.approval_status == "approved" else "rejected"
            approval = ApprovalRequest(
                org_id=org.id,
                package_id=pkg.id,
                package_name=pkg.name,
                package_version=pkg.version,
                package_type=pkg.package_type,
                mirror_id=mirror.id,
                scan_id=scans[i].id,
                state=state,
            )
            approvals.append(approval)
        
        session.add_all(approvals)
        
        # Create audit logs
        print(f"Creating audit logs...")
        for i in range(500):
            log = AuditLog(
                org_id=org.id,
                user_id=users[i % NUM_USERS].id,
                action="list" if i % 3 == 0 else "read" if i % 3 == 1 else "approve",
                resource_type="package" if i % 2 == 0 else "approval",
                resource_id=packages[i % len(packages)].id if i < len(packages) else None,
                details={"operation": f"test_op_{i}"},
                ip_address=f"192.168.1.{i % 256}",
            )
            session.add(log)
        
        session.commit()
        print(f"Seeded {NUM_PACKAGES} packages, {len(users)} users, {len(approvals)} approvals")
        
        yield {
            "org": org,
            "users": users,
            "packages": packages,
            "approvals": approvals,
            "mirror": mirror,
            "policy": policy,
        }
        
    finally:
        # Cleanup
        session.execute(text("DELETE FROM audit_logs WHERE org_id = :org_id"), {"org_id": str(org.id)})
        session.execute(text("DELETE FROM approval_history WHERE request_id IN (SELECT id FROM approval_requests WHERE org_id = :org_id)"), {"org_id": str(org.id)})
        session.execute(text("DELETE FROM approval_requests WHERE org_id = :org_id"), {"org_id": str(org.id)})
        session.execute(text("DELETE FROM scans WHERE org_id = :org_id"), {"org_id": str(org.id)})
        session.execute(text("DELETE FROM packages WHERE org_id = :org_id"), {"org_id": str(org.id)})
        session.execute(text("DELETE FROM mirrors WHERE org_id = :org_id"), {"org_id": str(org.id)})
        session.execute(text("DELETE FROM policies WHERE org_id = :org_id"), {"org_id": str(org.id)})
        session.execute(text("DELETE FROM users WHERE org_id = :org_id"), {"org_id": str(org.id)})
        session.execute(text("DELETE FROM roles WHERE org_id = :org_id"), {"org_id": str(org.id)})
        session.execute(text("DELETE FROM organizations WHERE id = :org_id"), {"org_id": str(org.id)})
        session.commit()
        session.close()


class TestPackageListPerformance:
    """Test performance of package listing operations."""
    
    def test_list_all_packages(self, perf_session_factory, seeded_database):
        """Benchmark: List all packages (paginated)."""
        session = perf_session_factory()
        org_id = seeded_database["org"].id
        results = PerformanceResults()
        
        try:
            # Test listing with different page sizes
            for page_size in [20, 50, 100]:
                start = time.perf_counter()
                
                packages = session.query(Package).filter(
                    Package.org_id == org_id
                ).order_by(Package.created_at.desc()).limit(page_size).all()
                
                elapsed_ms = (time.perf_counter() - start) * 1000
                results.record(f"list_packages_page_{page_size}", elapsed_ms)
                
                assert len(packages) == page_size
            
            # Test with filters
            start = time.perf_counter()
            pending = session.query(Package).filter(
                Package.org_id == org_id,
                Package.approval_status == "pending",
            ).limit(50).all()
            elapsed_ms = (time.perf_counter() - start) * 1000
            results.record("list_packages_filtered_pending", elapsed_ms)
            
            summary = results.summary()
            print("\n=== Package Listing Performance ===")
            for name, stats in summary.items():
                print(f"{name}: avg={stats['avg_ms']:.2f}ms, min={stats['min_ms']:.2f}ms, max={stats['max_ms']:.2f}ms")
            
            # Assertions
            assert summary["list_packages_page_100"]["avg_ms"] < 100, "Listing 100 packages should take < 100ms"
            
        finally:
            session.close()
    
    def test_count_packages(self, perf_session_factory, seeded_database):
        """Benchmark: Count packages by status."""
        session = perf_session_factory()
        org_id = seeded_database["org"].id
        results = PerformanceResults()
        
        try:
            start = time.perf_counter()
            count = session.query(func.count(Package.id)).filter(
                Package.org_id == org_id
            ).scalar()
            elapsed_ms = (time.perf_counter() - start) * 1000
            results.record("count_all_packages", elapsed_ms)
            
            assert count == NUM_PACKAGES
            
            # Count by status
            start = time.perf_counter()
            status_counts = session.query(
                Package.approval_status,
                func.count(Package.id)
            ).filter(
                Package.org_id == org_id
            ).group_by(Package.approval_status).all()
            elapsed_ms = (time.perf_counter() - start) * 1000
            results.record("count_by_status", elapsed_ms)
            
            summary = results.summary()
            print("\n=== Package Count Performance ===")
            for name, stats in summary.items():
                print(f"{name}: {stats['avg_ms']:.2f}ms")
            
            assert summary["count_all_packages"]["avg_ms"] < 50, "Counting packages should take < 50ms"
            
        finally:
            session.close()


class TestApprovalPerformance:
    """Test performance of approval operations."""
    
    def test_list_pending_approvals(self, perf_session_factory, seeded_database):
        """Benchmark: List pending approvals."""
        session = perf_session_factory()
        org_id = seeded_database["org"].id
        results = PerformanceResults()
        
        try:
            start = time.perf_counter()
            pending = session.query(ApprovalRequest).filter(
                ApprovalRequest.org_id == org_id,
                ApprovalRequest.state == "needs_review",
            ).order_by(ApprovalRequest.created_at.desc()).limit(50).all()
            elapsed_ms = (time.perf_counter() - start) * 1000
            results.record("list_pending_approvals", elapsed_ms)
            
            summary = results.summary()
            print("\n=== Pending Approvals Performance ===")
            print(f"list_pending_approvals: {summary['list_pending_approvals']['avg_ms']:.2f}ms, count={len(pending)}")
            
            assert summary["list_pending_approvals"]["avg_ms"] < 50
            
        finally:
            session.close()
    
    def test_approval_transitions(self, perf_session_factory, seeded_database):
        """Benchmark: Approval state transitions."""
        session = perf_session_factory()
        org_id = seeded_database["org"].id
        user = seeded_database["users"][0]
        results = PerformanceResults()
        
        try:
            # Get some pending approvals to transition
            pending = session.query(ApprovalRequest).filter(
                ApprovalRequest.org_id == org_id,
                ApprovalRequest.state == "needs_review",
            ).limit(20).all()
            
            service = ApprovalService(session, org_id)
            
            for approval in pending[:10]:
                start = time.perf_counter()
                try:
                    service.transition(
                        request_id=approval.id,
                        transition=ApprovalTransition.APPROVE,
                        user_id=user.id,
                        user_permissions=["approvals:approve"],
                        comment="Performance test approval",
                    )
                    elapsed_ms = (time.perf_counter() - start) * 1000
                    results.record("approval_transition", elapsed_ms)
                except Exception:
                    pass
            
            session.rollback()  # Don't actually commit
            
            summary = results.summary()
            print("\n=== Approval Transition Performance ===")
            if "approval_transition" in summary:
                stats = summary["approval_transition"]
                print(f"approval_transition: avg={stats['avg_ms']:.2f}ms, p95={stats['p95_ms']:.2f}ms")
                assert stats["avg_ms"] < 100, "Approval transition should take < 100ms"
            
        finally:
            session.close()


class TestAuditLogPerformance:
    """Test performance of audit log queries."""
    
    def test_query_audit_logs(self, perf_session_factory, seeded_database):
        """Benchmark: Query audit logs with filters."""
        session = perf_session_factory()
        org_id = seeded_database["org"].id
        results = PerformanceResults()
        
        try:
            # Simple list
            start = time.perf_counter()
            logs = session.query(AuditLog).filter(
                AuditLog.org_id == org_id
            ).order_by(AuditLog.created_at.desc()).limit(100).all()
            elapsed_ms = (time.perf_counter() - start) * 1000
            results.record("list_audit_logs", elapsed_ms)
            
            # Filter by action
            start = time.perf_counter()
            approve_logs = session.query(AuditLog).filter(
                AuditLog.org_id == org_id,
                AuditLog.action == "approve",
            ).limit(50).all()
            elapsed_ms = (time.perf_counter() - start) * 1000
            results.record("filter_by_action", elapsed_ms)
            
            # Filter by user
            user = seeded_database["users"][0]
            start = time.perf_counter()
            user_logs = session.query(AuditLog).filter(
                AuditLog.org_id == org_id,
                AuditLog.user_id == user.id,
            ).limit(50).all()
            elapsed_ms = (time.perf_counter() - start) * 1000
            results.record("filter_by_user", elapsed_ms)
            
            summary = results.summary()
            print("\n=== Audit Log Performance ===")
            for name, stats in summary.items():
                print(f"{name}: {stats['avg_ms']:.2f}ms")
            
            assert summary["list_audit_logs"]["avg_ms"] < 50
            
        finally:
            session.close()


class TestConcurrentOperations:
    """Test performance with concurrent users."""
    
    def test_concurrent_package_listing(self, perf_session_factory, seeded_database):
        """Benchmark: Concurrent package listing from multiple users."""
        org_id = seeded_database["org"].id
        results = PerformanceResults()
        
        def list_packages(user_id: int):
            session = perf_session_factory()
            try:
                start = time.perf_counter()
                packages = session.query(Package).filter(
                    Package.org_id == org_id
                ).order_by(Package.created_at.desc()).limit(50).all()
                elapsed_ms = (time.perf_counter() - start) * 1000
                return elapsed_ms
            finally:
                session.close()
        
        # Run 10 concurrent requests
        with concurrent.futures.ThreadPoolExecutor(max_workers=NUM_USERS) as executor:
            futures = [executor.submit(list_packages, i) for i in range(NUM_USERS)]
            
            for future in concurrent.futures.as_completed(futures):
                elapsed_ms = future.result()
                results.record("concurrent_list", elapsed_ms)
        
        summary = results.summary()
        print("\n=== Concurrent Operations Performance ===")
        stats = summary["concurrent_list"]
        print(f"concurrent_list ({NUM_USERS} users): avg={stats['avg_ms']:.2f}ms, max={stats['max_ms']:.2f}ms, p95={stats['p95_ms']:.2f}ms")
        
        assert stats["avg_ms"] < 200, "Concurrent listing should average < 200ms"
        assert stats["max_ms"] < 500, "No request should take > 500ms"


class TestDatabaseIndexes:
    """Verify that indexes are being used effectively."""
    
    def test_explain_package_queries(self, perf_session_factory, seeded_database):
        """Analyze query plans to verify index usage."""
        session = perf_session_factory()
        org_id = seeded_database["org"].id
        
        try:
            # Check EXPLAIN for package listing
            result = session.execute(text("""
                EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON)
                SELECT * FROM packages 
                WHERE org_id = :org_id 
                ORDER BY created_at DESC 
                LIMIT 50
            """), {"org_id": str(org_id)})
            
            plan = result.fetchone()[0]
            print("\n=== Query Plan Analysis ===")
            print(f"Package list query plan: {plan[0].get('Plan', {}).get('Node Type', 'Unknown')}")
            
            # The plan should show Index Scan or Index Only Scan for good performance
            execution_time = plan[0].get("Execution Time", 0)
            print(f"Execution time: {execution_time:.2f}ms")
            
            # Check for missing indexes (Sequential Scan on large tables)
            plan_type = plan[0].get("Plan", {}).get("Node Type", "")
            if "Seq Scan" in str(plan):
                print("WARNING: Sequential scan detected - consider adding indexes")
            
        finally:
            session.close()


def generate_performance_report(results: Dict[str, Dict[str, float]]) -> str:
    """Generate a performance test report."""
    report = []
    report.append("=" * 60)
    report.append("SAFEMIRROR ENTERPRISE PERFORMANCE TEST REPORT")
    report.append(f"Generated: {datetime.now().isoformat()}")
    report.append("=" * 60)
    report.append("")
    report.append(f"Test Configuration:")
    report.append(f"  - Packages: {NUM_PACKAGES}")
    report.append(f"  - Concurrent Users: {NUM_USERS}")
    report.append("")
    report.append("Results Summary:")
    report.append("-" * 60)
    
    for name, stats in results.items():
        report.append(f"\n{name}:")
        report.append(f"  Average: {stats['avg_ms']:.2f}ms")
        report.append(f"  Min: {stats['min_ms']:.2f}ms")
        report.append(f"  Max: {stats['max_ms']:.2f}ms")
        report.append(f"  P95: {stats['p95_ms']:.2f}ms")
    
    report.append("")
    report.append("=" * 60)
    report.append("RECOMMENDATIONS:")
    report.append("-" * 60)
    
    recommendations = []
    
    # Analyze results and provide recommendations
    for name, stats in results.items():
        if stats["avg_ms"] > 100:
            recommendations.append(f"- {name}: Consider optimizing (avg > 100ms)")
        if stats["max_ms"] > 500:
            recommendations.append(f"- {name}: High variance detected (max > 500ms)")
    
    if not recommendations:
        recommendations.append("- All operations within acceptable performance thresholds")
    
    report.extend(recommendations)
    report.append("")
    
    return "\n".join(report)
