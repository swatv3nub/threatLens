from __future__ import annotations

from collections.abc import Awaitable, Callable
from hmac import compare_digest
from uuid import uuid4

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, RedirectResponse
from starlette.responses import Response

from threatlens import __version__
from threatlens.api.dependencies import get_container_dep
from threatlens.api.routes_alerts import router as alerts_router
from threatlens.api.routes_health import router as health_router
from threatlens.api.routes_triage import router as triage_router
from threatlens.config import Settings, get_settings
from threatlens.container import Container, create_container
from threatlens.observability.logging import configure_logging, get_logger, request_id_var
from threatlens.security.allowlist import OutboundHostNotAllowedError
from threatlens.security.auth import Principal, principal_var

logger = get_logger("threatlens.api")


def create_app(
    *, settings: Settings | None = None, container: Container | None = None
) -> FastAPI:
    settings = settings or get_settings()
    container = container or create_container(settings)
    configure_logging(settings.log_level)
    app = FastAPI(
        title="ThreatLens",
        version=__version__,
        description="Agentic security alert triage platform",
        docs_url=None if settings.is_production else "/docs",
        redoc_url=None if settings.is_production else "/redoc",
        openapi_url=None if settings.is_production else "/openapi.json",
    )
    app.dependency_overrides[get_container_dep] = lambda: container

    @app.middleware("http")
    async def _api_auth(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        if request.url.path == "/api/v1" or request.url.path.startswith("/api/v1/"):
            target = "/v1" + request.url.path[len("/api/v1") :]
            if request.url.query:
                target += "?" + request.url.query
            return RedirectResponse(target, status_code=308)

        public_path = request.url.path == "/v1/health"
        principal = Principal(role="admin", authenticated=False)
        if settings.api_auth_enabled and request.url.path.startswith("/v1/") and not public_path:
            supplied = request.headers.get("X-API-Key")
            authorization = request.headers.get("Authorization", "")
            if supplied is None and authorization.lower().startswith("bearer "):
                supplied = authorization[7:].strip()
            if supplied:
                for configured_key, client in settings.api_clients.items():
                    if compare_digest(supplied, configured_key):
                        principal = Principal(
                            role=client.role, tenant_id=client.tenant_id, authenticated=True
                        )
                        break
                if (
                    not principal.authenticated
                    and settings.api_key is not None
                    and compare_digest(supplied, settings.api_key.get_secret_value())
                ):
                    principal = Principal(role="admin", authenticated=True)
            if not principal.authenticated:
                return JSONResponse(status_code=401, content={"detail": "authentication required"})
        token = principal_var.set(principal)
        try:
            return await call_next(request)
        finally:
            principal_var.reset(token)

    @app.middleware("http")
    async def _request_context(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        request_id = request.headers.get("X-Request-Id") or str(uuid4())
        token = request_id_var.set(request_id)
        try:
            response = await call_next(request)
            response.headers["X-Request-Id"] = request_id
            return response
        finally:
            request_id_var.reset(token)

    @app.middleware("http")
    async def _payload_limit(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        content_length = request.headers.get("content-length")
        if content_length is not None and content_length.isdigit() and int(content_length) > settings.max_payload_bytes:
            return JSONResponse(status_code=413, content={"detail": "request payload too large"})
        if request.method in {"POST", "PUT", "PATCH"}:
            body = await request.body()
            if len(body) > settings.max_payload_bytes:
                return JSONResponse(status_code=413, content={"detail": "request payload too large"})
        return await call_next(request)
    app.include_router(health_router)
    app.include_router(alerts_router)
    app.include_router(triage_router)

    @app.exception_handler(OutboundHostNotAllowedError)
    async def _ssrf_handler(
        request: Request, exc: OutboundHostNotAllowedError
    ) -> JSONResponse:
        logger.warning("blocked outbound request", extra={"extra_fields": {"error": str(exc)}})
        return JSONResponse(status_code=400, content={"detail": str(exc)})

    return app


app = create_app()
