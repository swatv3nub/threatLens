from __future__ import annotations

from collections.abc import AsyncIterator, Awaitable, Callable

from fastapi import Depends, Header, HTTPException, Request, status

from threatlens.container import Container, get_container
from threatlens.observability.logging import request_id_var
from threatlens.security.auth import Role, get_principal
from threatlens.security.rate_limiter import RateLimitExceeded


async def get_container_dep() -> Container:
    return get_container()


async def enforce_rate_limit(
    request: Request,
    x_client_id: str | None = Header(default=None, alias="X-Client-Id"),
    container: Container = Depends(get_container_dep),
) -> None:
    client_key = x_client_id or (request.client.host if request.client else "anonymous")
    try:
        container.api_rate_limiter.check(client_key)
    except RateLimitExceeded as exc:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail=str(exc)
        ) from exc


def require_role(required: Role) -> Callable[[], Awaitable[None]]:
    async def dependency() -> None:
        principal = get_principal()
        if not principal.can(required):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"{required} role required",
            )

    return dependency


async def set_request_context(
    x_request_id: str | None = Header(default=None, alias="X-Request-Id"),
) -> AsyncIterator[None]:
    from uuid import uuid4

    token = request_id_var.set(x_request_id or str(uuid4()))
    try:
        yield
    finally:
        request_id_var.reset(token)
