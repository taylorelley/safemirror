from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from enterprise.core.config import get_settings
from enterprise.api.routers import auth, api_keys, roles, mirrors, packages, scans, audit, approvals, policies
from enterprise.api.middleware.audit import AuditMiddleware

settings = get_settings()

app = FastAPI(
    title=settings.app_name,
    description="Enterprise package security scanning platform",
    version="0.2.0",
    docs_url="/docs" if settings.debug else None,
    redoc_url="/redoc" if settings.debug else None,
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"] if settings.debug else [],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Audit middleware - logs all API requests
app.add_middleware(AuditMiddleware)

# Include routers
app.include_router(auth.router, prefix="/api")
app.include_router(api_keys.router, prefix="/api")
app.include_router(roles.router, prefix="/api")
app.include_router(mirrors.router, prefix="/api")
app.include_router(packages.router, prefix="/api")
app.include_router(scans.router, prefix="/api")
app.include_router(approvals.router, prefix="/api")
app.include_router(policies.router, prefix="/api")
app.include_router(audit.router, prefix="/api")


@app.get("/health")
async def health_check():
    return {"status": "healthy", "version": "0.2.0"}


@app.get("/")
async def root():
    return {
        "name": settings.app_name,
        "version": "0.2.0",
        "docs": "/docs" if settings.debug else None,
    }
