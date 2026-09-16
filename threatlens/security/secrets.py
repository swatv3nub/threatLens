from __future__ import annotations


class SecretStr:
    """Wrapper that prevents accidental secret disclosure via repr/logging."""

    __slots__ = ("_value",)

    def __init__(self, value: str | None) -> None:
        self._value = value or ""

    def get_secret_value(self) -> str:
        return self._value

    def __bool__(self) -> bool:
        return bool(self._value)

    def __repr__(self) -> str:
        return "SecretStr('**********')" if self._value else "SecretStr('')"

    __str__ = __repr__
