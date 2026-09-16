from __future__ import annotations

from contextvars import ContextVar
from dataclasses import dataclass
from typing import Literal

Role = Literal["viewer", "analyst", "admin"]


@dataclass(frozen=True)
class Principal:
    role: Role
    tenant_id: str | None = None
    authenticated: bool = False

    def can(self, required: Role) -> bool:
        levels = {"viewer": 1, "analyst": 2, "admin": 3}
        return levels[self.role] >= levels[required]


principal_var: ContextVar[Principal | None] = ContextVar("principal", default=None)


def get_principal() -> Principal:
    return principal_var.get() or Principal(role="admin", authenticated=False)


def tenant_id() -> str | None:
    return get_principal().tenant_id
