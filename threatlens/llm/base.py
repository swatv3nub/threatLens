from __future__ import annotations

from typing import Any, Protocol, TypeVar, runtime_checkable

from pydantic import BaseModel

T = TypeVar("T", bound=BaseModel)


class LLMError(RuntimeError):
    pass


class StructuredGenerationError(LLMError):
    pass


class LLMUnavailableError(LLMError):
    pass


@runtime_checkable
class LLMProvider(Protocol):
    name: str

    async def generate_structured(
        self,
        *,
        system_prompt: str,
        input_data: dict[str, Any],
        response_model: type[T],
    ) -> T: ...
