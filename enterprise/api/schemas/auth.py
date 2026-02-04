from pydantic import BaseModel, EmailStr
from uuid import UUID
from datetime import datetime
from typing import Optional


class UserCreate(BaseModel):
    email: EmailStr
    password: str
    name: Optional[str] = None
    org_name: str  # For creating organization on registration


class UserLogin(BaseModel):
    email: EmailStr
    password: str


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


class TokenData(BaseModel):
    user_id: Optional[UUID] = None


class UserResponse(BaseModel):
    id: UUID
    email: str
    name: Optional[str]
    org_id: UUID
    role_id: UUID
    is_active: bool
    created_at: datetime

    class Config:
        from_attributes = True


class OrgResponse(BaseModel):
    id: UUID
    name: str
    slug: str
    created_at: datetime

    class Config:
        from_attributes = True
