"""Main FastAPI application entrypoint for HOTFIX Privacy-by-Design Gateway."""

import logging
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.core.config import get_settings
from app.db.connection import init_database
from app.api.routes.system import router as system_router
from app.api.routes.mvp import router as mvp_router
from app.schemas.system import ErrorResponse

logger = logging.getLogger("hotfix")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifecycle hook: initialize SQLite schema and seed demo state on startup."""
    try:
        init_database()
        logger.info("Database and demonstration seed data successfully initialized.")
    except Exception as e:
        logger.error(f"Failed to initialize database: {e}", exc_info=True)
    yield


def create_application() -> FastAPI:
    """Application factory for HOTFIX Gateway."""
    settings = get_settings()

    # Configure root logging
    log_level = getattr(logging, settings.app_config.logging.level, logging.INFO)
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    )

    app = FastAPI(
        title=settings.app_config.app.name,
        version=settings.app_config.app.version,
        description="Privacy-by-Design Analytics Gateway for sensitive health and financial records.",
        docs_url="/docs",
        redoc_url="/redoc",
        lifespan=lifespan,
    )

    # Configure CORS for frontend access (supporting local dev, Vercel, Netlify, Render, Railway, etc.)
    cors_regex = os.getenv(
        "HOTFIX_CORS_REGEX",
        r"https?://.*(\.vercel\.app|\.netlify\.app|\.onrender\.com|\.pages\.dev|\.railway\.app|\.fly\.dev|localhost(:\d+)?|127\.0\.0\.1(:\d+)?)"
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.app_config.server.cors_origins,
        allow_origin_regex=cors_regex,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Security Headers & Resource Protection Middleware
    @app.middleware("http")
    async def security_hardening_middleware(request: Request, call_next):
        # 1. Enforce payload size limit (max 2MB)
        content_length = request.headers.get("content-length")
        if content_length:
            try:
                if int(content_length) > 2 * 1024 * 1024:
                    return JSONResponse(
                        status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                        content=ErrorResponse(
                            error="Payload Too Large",
                            detail="Request body exceeds maximum permitted limit of 2MB.",
                            code="413",
                            timestamp=datetime.now(timezone.utc)
                        ).model_dump(mode="json")
                    )
            except ValueError:
                pass

        # 2. Process request
        response = await call_next(request)

        # 3. Inject defense-in-depth HTTP security headers
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; connect-src 'self' https: http: ws: wss: data: blob:; frame-ancestors 'none';"
        )
        return response

    # Sanitize and standardize HTTP exceptions
    @app.exception_handler(StarletteHTTPException)
    async def http_exception_handler(request: Request, exc: StarletteHTTPException):
        return JSONResponse(
            status_code=exc.status_code,
            content=ErrorResponse(
                error="HTTP Error",
                detail=str(exc.detail),
                code=str(exc.status_code),
                timestamp=datetime.now(timezone.utc)
            ).model_dump(mode="json")
        )

    # Sanitize and standardize input validation errors
    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(request: Request, exc: RequestValidationError):
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content=ErrorResponse(
                error="Validation Error",
                detail="The submitted request payload failed schema validation.",
                code="422",
                timestamp=datetime.now(timezone.utc)
            ).model_dump(mode="json")
        )

    # Catch-all exception handler enforcing safe, non-leaking responses
    @app.exception_handler(Exception)
    async def unhandled_exception_handler(request: Request, exc: Exception):
        import traceback
        traceback.print_exc()
        logger.error("Unhandled internal server exception", exc_info=True)
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content=ErrorResponse(
                error="Internal Server Error",
                detail="An internal server error occurred. Sensitive diagnostics are retained securely in server logs.",
                code="500",
                timestamp=datetime.now(timezone.utc)
            ).model_dump(mode="json")
        )

    # Legacy raw-release guard route preserved from Phase 1 (Test B12)
    @app.api_route(
        "/api/v1/query/release",
        methods=["GET", "POST"],
        status_code=status.HTTP_403_FORBIDDEN,
        summary="Protected analytical release route (disabled in Phase 1)",
        include_in_schema=False
    )
    async def blocked_release_route():
        """Fail-closed guard route: forbids unmediated data release."""
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content=ErrorResponse(
                error="Privacy Release Disabled",
                detail="Unmediated raw query releases are strictly disabled. Approved queries must be submitted via /api/queries/run.",
                code="PRIVACY_RELEASE_DISABLED",
                timestamp=datetime.now(timezone.utc)
            ).model_dump(mode="json")
        )

    # Mount routers
    app.include_router(system_router)
    app.include_router(mvp_router)

    @app.get("/", summary="SentinelVault Gateway API Root")
    async def root_status():
        """Root status probe providing gateway metadata and documentation links."""
        return {
            "project": "SentinelVault — Zero-Trust Differential Privacy Gateway",
            "tagline": "Analyze Data. Don't Expose It.",
            "status": "OPERATIONAL",
            "documentation": "/docs",
            "openapi": "/openapi.json",
            "system_status": "/api/system/status",
            "health": "/health",
            "readiness": "/ready"
        }

    return app


app = create_application()
