"""Rate limiting middleware for FastAPI.

Provides per-user and per-IP rate limiting using Redis as a backend.
Implements the token bucket algorithm for smooth rate limiting.

Features:
- Per-user limits for authenticated requests
- Per-IP limits for unauthenticated requests
- Configurable limits via environment variables
- Redis-based for distributed deployments
- Proper HTTP 429 responses with Retry-After header
- Rate limit headers (X-RateLimit-*)
- Excludes health check endpoints
"""

import time
import hashlib
from typing import Optional, Tuple
from datetime import datetime

from fastapi import Request, Response, HTTPException, status
from starlette.middleware.base import BaseHTTPMiddleware
import redis.asyncio as redis

from enterprise.core.config import get_settings


# Default rate limits
DEFAULT_RATE_LIMIT = 100  # requests
DEFAULT_RATE_WINDOW = 60  # seconds
DEFAULT_AUTH_RATE_LIMIT = 200  # higher for authenticated users
DEFAULT_LOGIN_RATE_LIMIT = 5  # stricter for login endpoint

# Paths excluded from rate limiting
EXCLUDED_PATHS = {
    "/health",
    "/health/live",
    "/health/ready",
    "/healthz",
    "/metrics",
}


class RateLimiter:
    """
    Token bucket rate limiter using Redis.
    
    Implements a sliding window rate limit with Redis for distributed
    deployments. Falls back to allowing requests if Redis is unavailable.
    """
    
    def __init__(self, redis_url: Optional[str] = None):
        self.settings = get_settings()
        self.redis_url = redis_url or self.settings.redis_url
        self._redis: Optional[redis.Redis] = None
        
        # Rate limit configuration
        self.default_limit = int(
            getattr(self.settings, "rate_limit_default", DEFAULT_RATE_LIMIT)
        )
        self.default_window = int(
            getattr(self.settings, "rate_limit_window", DEFAULT_RATE_WINDOW)
        )
        self.auth_limit = int(
            getattr(self.settings, "rate_limit_auth", DEFAULT_AUTH_RATE_LIMIT)
        )
        self.login_limit = int(
            getattr(self.settings, "rate_limit_login", DEFAULT_LOGIN_RATE_LIMIT)
        )
    
    async def get_redis(self) -> Optional[redis.Redis]:
        """Get or create Redis connection."""
        if self._redis is None:
            try:
                self._redis = redis.from_url(
                    self.redis_url,
                    encoding="utf-8",
                    decode_responses=True,
                    socket_connect_timeout=2,
                    socket_timeout=2,
                )
                # Test connection
                await self._redis.ping()
            except Exception:
                self._redis = None
        return self._redis
    
    def _get_key(self, identifier: str, endpoint: str = "default") -> str:
        """Generate Redis key for rate limiting."""
        # Hash the identifier for privacy
        hashed = hashlib.sha256(identifier.encode()).hexdigest()[:16]
        return f"ratelimit:{endpoint}:{hashed}"
    
    async def is_allowed(
        self,
        identifier: str,
        endpoint: str = "default",
        limit: Optional[int] = None,
        window: Optional[int] = None,
    ) -> Tuple[bool, int, int, int]:
        """
        Check if request is allowed under rate limit.
        
        Returns:
            Tuple of (allowed, remaining, limit, reset_time)
        """
        r = await self.get_redis()
        
        if r is None:
            # Redis unavailable - allow request but don't count it
            return True, limit or self.default_limit, limit or self.default_limit, 0
        
        limit = limit or self.default_limit
        window = window or self.default_window
        key = self._get_key(identifier, endpoint)
        now = int(time.time())
        window_start = now - window
        
        try:
            # Use Redis pipeline for atomic operations
            async with r.pipeline(transaction=True) as pipe:
                # Remove old entries
                await pipe.zremrangebyscore(key, 0, window_start)
                # Count current requests
                await pipe.zcard(key)
                # Add current request
                await pipe.zadd(key, {str(now): now})
                # Set expiry
                await pipe.expire(key, window)
                
                results = await pipe.execute()
                
            current_count = results[1]
            
            remaining = max(0, limit - current_count - 1)
            reset_time = now + window
            
            if current_count >= limit:
                return False, 0, limit, reset_time
            
            return True, remaining, limit, reset_time
            
        except Exception:
            # On error, allow request
            return True, limit, limit, 0
    
    async def close(self):
        """Close Redis connection."""
        if self._redis:
            await self._redis.close()


class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    FastAPI middleware for rate limiting.
    
    Applies different rate limits based on:
    - Authentication status (user ID vs IP)
    - Endpoint (stricter limits for login)
    """
    
    def __init__(self, app, limiter: Optional[RateLimiter] = None):
        super().__init__(app)
        self.limiter = limiter or RateLimiter()
    
    async def dispatch(self, request: Request, call_next) -> Response:
        # Skip excluded paths
        if request.url.path in EXCLUDED_PATHS:
            return await call_next(request)
        
        # Determine identifier and limits
        identifier, limit, endpoint = await self._get_rate_params(request)
        
        # Check rate limit
        allowed, remaining, total, reset_time = await self.limiter.is_allowed(
            identifier=identifier,
            endpoint=endpoint,
            limit=limit,
        )
        
        if not allowed:
            # Rate limit exceeded
            retry_after = reset_time - int(time.time())
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Rate limit exceeded. Please try again later.",
                headers={
                    "Retry-After": str(max(1, retry_after)),
                    "X-RateLimit-Limit": str(total),
                    "X-RateLimit-Remaining": "0",
                    "X-RateLimit-Reset": str(reset_time),
                },
            )
        
        # Process request
        response = await call_next(request)
        
        # Add rate limit headers
        response.headers["X-RateLimit-Limit"] = str(total)
        response.headers["X-RateLimit-Remaining"] = str(remaining)
        if reset_time:
            response.headers["X-RateLimit-Reset"] = str(reset_time)
        
        return response
    
    async def _get_rate_params(self, request: Request) -> Tuple[str, int, str]:
        """
        Determine rate limit parameters based on request.
        
        Returns:
            Tuple of (identifier, limit, endpoint_category)
        """
        path = request.url.path
        
        # Login endpoint has stricter limits
        if path.endswith("/auth/login") or path.endswith("/auth/register"):
            client_ip = self._get_client_ip(request)
            return client_ip, self.limiter.login_limit, "login"
        
        # Check for authenticated user
        user = getattr(request.state, "user", None)
        if user:
            return str(user.id), self.limiter.auth_limit, "auth"
        
        # Unauthenticated - use IP
        client_ip = self._get_client_ip(request)
        return client_ip, self.limiter.default_limit, "default"
    
    def _get_client_ip(self, request: Request) -> str:
        """Extract client IP from request, handling proxies."""
        # Check X-Forwarded-For header
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            return forwarded.split(",")[0].strip()
        
        # Check X-Real-IP header
        real_ip = request.headers.get("x-real-ip")
        if real_ip:
            return real_ip
        
        # Fall back to direct client
        if request.client:
            return request.client.host
        
        return "unknown"


# Dependency for route-level rate limiting
async def rate_limit_dependency(
    request: Request,
    limit: int = DEFAULT_RATE_LIMIT,
    window: int = DEFAULT_RATE_WINDOW,
):
    """
    FastAPI dependency for custom rate limiting on specific routes.
    
    Usage:
        @router.post("/expensive-operation")
        async def expensive_op(
            _: None = Depends(lambda r: rate_limit_dependency(r, limit=10, window=60))
        ):
            ...
    """
    limiter = RateLimiter()
    
    # Get identifier
    user = getattr(request.state, "user", None)
    if user:
        identifier = str(user.id)
    else:
        identifier = request.client.host if request.client else "unknown"
    
    allowed, remaining, total, reset_time = await limiter.is_allowed(
        identifier=identifier,
        endpoint=request.url.path,
        limit=limit,
        window=window,
    )
    
    if not allowed:
        retry_after = reset_time - int(time.time())
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded",
            headers={"Retry-After": str(max(1, retry_after))},
        )
