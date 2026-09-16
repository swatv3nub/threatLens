.PHONY: install dev test lint typecheck security check demo api migrate clean

install:
	pip install -e ".[dev]"

dev:
	uvicorn threatlens.api.app:app --reload --host 127.0.0.1 --port 8000

api:
	uvicorn threatlens.api.app:app --host 127.0.0.1 --port 8000

test:
	pytest

lint:
	ruff check .

typecheck:
	mypy threatlens

security:
	bandit -c pyproject.toml -r threatlens

check: lint typecheck test

demo:
	threatlens triage samples/synthetic/malicious_ip.json

evaluate:
	threatlens evaluate

migrate:
	alembic upgrade head

clean:
	rm -rf .pytest_cache .mypy_cache .ruff_cache reports_output *.db
