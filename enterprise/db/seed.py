"""Database seeding for SafeMirror Enterprise.

Creates default roles and initial organization setup.
"""

import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy.orm import Session
from sqlalchemy import and_

from enterprise.db.models import Role, Organization
from enterprise.core.rbac.roles import DEFAULT_ROLES


def seed_default_roles(db: Session, org_id: uuid.UUID) -> dict[str, Role]:
    """
    Create the 5 default roles for an organization.
    
    Roles are idempotent - if they already exist, returns existing roles.
    
    Args:
        db: Database session
        org_id: Organization ID to create roles for
        
    Returns:
        Dict mapping role key to Role object
    """
    created_roles = {}
    
    for role_key, role_config in DEFAULT_ROLES.items():
        # Check if role already exists
        existing = db.query(Role).filter(
            and_(
                Role.org_id == org_id,
                Role.name == role_config["name"],
                Role.is_system == True,
            )
        ).first()
        
        if existing:
            created_roles[role_key] = existing
            continue
        
        # Create new role
        role = Role(
            id=uuid.uuid4(),
            org_id=org_id,
            name=role_config["name"],
            permissions=role_config["permissions"],
            is_system=True,
        )
        db.add(role)
        created_roles[role_key] = role
    
    db.flush()
    return created_roles


def seed_organization(
    db: Session,
    name: str,
    slug: str,
    *,
    settings: Optional[dict] = None,
) -> Organization:
    """
    Create a new organization with default roles.
    
    Args:
        db: Database session
        name: Organization name
        slug: URL-friendly slug
        settings: Optional organization settings
        
    Returns:
        Created organization
    """
    # Check if org already exists
    existing = db.query(Organization).filter(
        Organization.slug == slug
    ).first()
    
    if existing:
        return existing
    
    org = Organization(
        id=uuid.uuid4(),
        name=name,
        slug=slug,
        settings=settings or {},
    )
    db.add(org)
    db.flush()
    
    # Create default roles for this org
    seed_default_roles(db, org.id)
    
    return org


def get_role_by_name(db: Session, org_id: uuid.UUID, name: str) -> Optional[Role]:
    """Get a role by name within an organization."""
    return db.query(Role).filter(
        and_(
            Role.org_id == org_id,
            Role.name == name,
        )
    ).first()


def get_admin_role(db: Session, org_id: uuid.UUID) -> Optional[Role]:
    """Get the Admin role for an organization."""
    return get_role_by_name(db, org_id, "Admin")


def get_viewer_role(db: Session, org_id: uuid.UUID) -> Optional[Role]:
    """Get the Viewer role for an organization."""
    return get_role_by_name(db, org_id, "Viewer")


# CLI script for seeding
if __name__ == "__main__":
    import sys
    from enterprise.db.session import SessionLocal
    
    db = SessionLocal()
    try:
        # Seed a default organization
        org = seed_organization(
            db,
            name="Default Organization",
            slug="default",
            settings={"theme": "light"},
        )
        print(f"Created organization: {org.name} (ID: {org.id})")
        
        # List created roles
        roles = db.query(Role).filter(Role.org_id == org.id).all()
        print(f"\nCreated {len(roles)} default roles:")
        for role in roles:
            perm_count = len(role.permissions) if role.permissions else 0
            perm_display = "all (*:*)" if perm_count == 1 and "*:*" in role.permissions else f"{perm_count} permissions"
            print(f"  - {role.name}: {perm_display}")
        
        db.commit()
        print("\nSeeding complete!")
        
    except Exception as e:
        db.rollback()
        print(f"Error: {e}")
        sys.exit(1)
    finally:
        db.close()
