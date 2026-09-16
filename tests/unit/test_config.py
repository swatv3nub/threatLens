from __future__ import annotations

import pytest
from pydantic import ValidationError

from threatlens.config import Settings


def test_production_rejects_mock_configuration() -> None:
    with pytest.raises(ValidationError, match="LLM_PROVIDER=mock"):
        Settings(app_env="production")


def test_production_requires_api_auth_and_provider_keys() -> None:
    with pytest.raises(ValidationError, match="API_AUTH_ENABLED"):
        Settings(
            app_env="production",
            llm_provider="openai",
            mock_enrichment=False,
        )
