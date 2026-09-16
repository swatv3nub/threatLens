from __future__ import annotations

from threatlens.config import Settings
from threatlens.llm.base import LLMProvider
from threatlens.llm.mock import MockLLMProvider
from threatlens.llm.openai_provider import OpenAIProvider
from threatlens.security.allowlist import Allowlist


def build_llm_provider(settings: Settings, allowlist: Allowlist) -> LLMProvider:
    if settings.llm_provider == "openai" and settings.openai_api_key:
        return OpenAIProvider(
            api_key=settings.openai_api_key,
            model=settings.llm_model,
            base_url=settings.openai_base_url,
            timeout=settings.tool_timeout_seconds * 3,
            allowlist=allowlist,
        )
    return MockLLMProvider()
