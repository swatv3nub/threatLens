from __future__ import annotations

import pytest

from threatlens.config import Settings


@pytest.fixture()
def settings(tmp_path) -> Settings:
    db_path = tmp_path / "test.db"
    return Settings(
        app_env="development",
        llm_provider="mock",
        mock_enrichment=True,
        database_url=f"sqlite:///{db_path.as_posix()}",
        rate_limit_per_minute=1000,
    )
