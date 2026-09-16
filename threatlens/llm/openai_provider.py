from __future__ import annotations

import json
from typing import Any, TypeVar

import httpx
from pydantic import BaseModel, ValidationError

from threatlens.llm.base import LLMUnavailableError, StructuredGenerationError
from threatlens.security.allowlist import Allowlist

T = TypeVar("T", bound=BaseModel)


class OpenAIProvider:
    name = "openai"

    def __init__(
        self,
        *,
        api_key: str,
        model: str,
        base_url: str = "https://api.openai.com/v1",
        timeout: float = 30.0,
        allowlist: Allowlist | None = None,
        max_retries: int = 2,
    ) -> None:
        self._api_key = api_key
        self._model = model
        self._base_url = base_url.rstrip("/")
        self._timeout = timeout
        self._max_retries = max_retries
        self._allowlist = allowlist

    async def generate_structured(
        self,
        *,
        system_prompt: str,
        input_data: dict[str, Any],
        response_model: type[T],
    ) -> T:
        schema = response_model.model_json_schema()
        payload = {
            "model": self._model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {
                    "role": "user",
                    "content": json.dumps(
                        {
                            "task": "Produce a triage decision as JSON matching the schema.",
                            "schema": schema,
                            "data": input_data,
                        }
                    ),
                },
            ],
            "response_format": {"type": "json_object"},
            "temperature": 0.0,
        }
        url = f"{self._base_url}/chat/completions"
        if self._allowlist is not None:
            self._allowlist.enforce(url)
        last_error: Exception | None = None
        for _attempt in range(1, self._max_retries + 1):
            try:
                async with httpx.AsyncClient(timeout=self._timeout) as client:
                    resp = await client.post(
                        url,
                        headers={
                            "Authorization": f"Bearer {self._api_key}",
                            "Content-Type": "application/json",
                        },
                        json=payload,
                    )
                if resp.status_code >= 500:
                    last_error = LLMUnavailableError(
                        f"provider returned {resp.status_code}"
                    )
                    continue
                resp.raise_for_status()
                content = resp.json()["choices"][0]["message"]["content"]
                parsed = json.loads(content)
                return response_model.model_validate(parsed)
            except ValidationError as exc:
                last_error = StructuredGenerationError(
                    f"LLM output failed schema validation: {exc}"
                )
            except (json.JSONDecodeError, KeyError) as exc:
                last_error = StructuredGenerationError(
                    f"LLM output was not valid JSON: {exc}"
                )
            except httpx.HTTPError as exc:
                last_error = LLMUnavailableError(str(exc))
        if last_error is None:
            raise LLMUnavailableError("LLM provider failed without an error detail")
        raise last_error
